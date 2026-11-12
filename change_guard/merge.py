"""Explicit, trusted merge command; closes the stale green-status failure mode.

GitHub update rules allow only the repository deploy key to update main. This
command is invoked by an operator, never by the model or an untrusted PR. It
checks the current immutable report, approval, CI and exact Git parents, proves
that GitHub's synthetic merge tree equals the evaluated head tree, then performs
an exact-lease fast-forward push of that head commit.  No checkout, candidate
hook or candidate program runs in the credentialed process.
"""
from __future__ import annotations

import argparse
from collections.abc import Mapping
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import time
import requests

from .daemon import (
    ChangeGuardDaemon,
    SCHEMA_VERSION,
    chart_digest_from_files,
    current_policy_binding,
    is_workflow_path,
    load_config,
    workflow_tree_signature,
)


class MergeRefused(RuntimeError):
    pass


def validate_policy_binding(report, expected):
    """Refuse a report produced by another guard/rule/policy generation."""

    if not isinstance(report, Mapping) or not isinstance(expected, Mapping):
        raise MergeRefused('report policy binding is invalid')
    if report.get('schema_version') != SCHEMA_VERSION:
        raise MergeRefused('report schema version does not match the running guard')
    actual = report.get('policy_binding')
    if not isinstance(actual, Mapping) or dict(actual) != dict(expected):
        raise MergeRefused('report policy binding does not match the running guard/rule/policy')
    if report.get('guard_version') != expected.get('guard_version'):
        raise MergeRefused('report guard version does not match the running guard')
    if report.get('rule_version') != expected.get('rule_version'):
        raise MergeRefused('report rule version does not match the running rule engine')
    if report.get('policy_digest') != expected.get('policy_digest'):
        raise MergeRefused('report policy digest does not match the current policy configuration')


def validate_report(report, pr, base_sha, now, *, min_remaining=20, policy_binding=None):
    if report.get('head_sha') != pr.head_sha or report.get('base_sha') != base_sha:
        raise MergeRefused('report head/base no longer matches GitHub')
    if pr.state != 'open' or pr.draft:
        raise MergeRefused('PR must be open and ready for review')
    if report.get('pull_request', {}).get('number') != pr.number:
        raise MergeRefused('report belongs to a different PR')
    if report.get('decision') not in {'PASS', 'REVIEW'}:
        raise MergeRefused('BLOCK/ERROR cannot be merged')
    if float(report.get('evaluated_at', now + 1)) > now:
        raise MergeRefused('report evaluation time is in the future')
    if float(report.get('expires_at', 0)) - now < min_remaining:
        raise MergeRefused('report expired or insufficient validity remains for push')
    digest = report.get('report_digest')
    raw = json.dumps({k:v for k,v in report.items() if k != 'report_digest'},
                     sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)
    if digest != hashlib.sha256(raw.encode()).hexdigest():
        raise MergeRefused('report digest mismatch')
    if policy_binding is not None:
        validate_policy_binding(report, policy_binding)


def validate_ci(payload, required_name='Test, lint, render', expected_head_sha=None):
    """Require the latest *GitHub Actions* check run to be successful.

    Check runs are bound to the commit whose endpoint is queried.  When
    ``expected_head_sha`` is supplied, a check run that claims a different head
    (or omits ``head_sha``) is rejected, so a status from another commit cannot
    be replayed.  Only the GitHub Actions App can create these check runs; a
    repository token cannot forge one.
    """

    if not isinstance(payload, Mapping):
        raise MergeRefused('CI check-run payload is invalid')
    runs = payload.get('check_runs', [])
    if not isinstance(runs, list):
        raise MergeRefused('CI check-run payload is invalid')
    matches = []
    for run in runs:
        if not isinstance(run, Mapping):
            continue
        if run.get('name') != required_name:
            continue
        app = run.get('app') if isinstance(run.get('app'), Mapping) else {}
        if app.get('slug') != 'github-actions':
            continue
        if expected_head_sha is not None:
            if run.get('head_sha') != expected_head_sha:
                continue
        matches.append(run)
    if not matches:
        raise MergeRefused('required GitHub Actions CI check is missing for the evaluated head')
    latest = max(
        matches,
        key=lambda r: r.get('id') if isinstance(r.get('id'), int) and not isinstance(r.get('id'), bool) else 0,
    )
    if latest.get('status') != 'completed' or latest.get('conclusion') != 'success':
        raise MergeRefused('required GitHub Actions CI is not successful')


def validate_workflow_snapshots(base_snapshot, head_snapshot):
    """Require base/head workflow tree *content* to be identical.

    This is deliberately independent of the report decision.  It compares the
    GitHub Git tree entries (path, mode, type, blob object id) for
    ``.github/workflows/``; a forged PASS report cannot make a different
    workflow tree acceptable.
    """

    try:
        base_signature = workflow_tree_signature(getattr(base_snapshot, 'entries', {}))
        head_signature = workflow_tree_signature(getattr(head_snapshot, 'entries', {}))
    except Exception as error:
        raise MergeRefused('cannot read workflow tree entries: ' + str(error)[:500]) from None
    if base_signature != head_signature:
        changed = sorted(
            path
            for path in set(base_signature) | set(head_signature)
            if base_signature.get(path) != head_signature.get(path)
        )
        raise MergeRefused(
            '.github/workflows tree differs between base and head: ' + ', '.join(changed[:10])
        )
    return base_signature


def verify_base_head_workflows(github, base_sha, head_sha):
    """Re-fetch both trees from GitHub and reject any workflow difference."""

    try:
        base_snapshot = github.fetch_tree_snapshot(base_sha, include_argo=False)
        head_snapshot = github.fetch_tree_snapshot(head_sha, include_argo=False)
    except Exception as error:
        raise MergeRefused('cannot verify base/head workflow trees: ' + str(error)[:800]) from None
    validate_workflow_snapshots(base_snapshot, head_snapshot)
    return base_snapshot, head_snapshot


def validate_chart_pin(config, report, head_snapshot):
    """Independently verify the candidate chart bytes against the trusted pin."""

    approved_raw = config.get('approved_chart_digest') or []
    if isinstance(approved_raw, str):
        approved_raw = [approved_raw]
    if not isinstance(approved_raw, (list, tuple)):
        raise MergeRefused('approved_chart_digest is invalid; refusing merge')
    approved = [item.lower() for item in approved_raw if isinstance(item, str)]
    if not approved:
        raise MergeRefused('approved_chart_digest is not configured; refusing merge')
    files = getattr(head_snapshot, 'renderer_files', None)
    if not isinstance(files, Mapping):
        raise MergeRefused('head chart files are unavailable')
    try:
        actual = chart_digest_from_files(files)
    except Exception as error:
        raise MergeRefused('cannot digest candidate chart: ' + str(error)[:500]) from None
    if report.get('chart_digest') != actual:
        raise MergeRefused('report chart digest does not match the GitHub head tree')
    if actual not in approved:
        raise MergeRefused('candidate charts/demo digest is not operator-approved')
    return actual


def validate_synthetic_merge(github, repository, pull_request, base_sha, head_sha):
    """Prove GitHub's synthetic merge tree is exactly the evaluated head tree.

    PR checks are bound to the head SHA, while GitHub's synthetic merge commit
    is what a merge API would create.  A fast-forward push is only safe when the
    synthetic merge has parents ``[base, head]`` and its tree equals the head
    commit's tree: then the pushed head is the same code CI evaluated.
    """

    if not re.fullmatch(r'[0-9a-f]{40,64}', str(head_sha)):
        raise MergeRefused('evaluated head SHA is invalid')
    raw_sha = pull_request.get('merge_commit_sha') if isinstance(pull_request, Mapping) else None
    if not isinstance(raw_sha, str) or not re.fullmatch(r'[0-9a-f]{40,64}', raw_sha):
        raise MergeRefused('GitHub synthetic merge commit is unavailable')
    prefix = '/repos/' + str(repository)
    synthetic = github.get(prefix + '/git/commits/' + raw_sha)
    head_commit = github.get(prefix + '/git/commits/' + head_sha)
    if not isinstance(synthetic, Mapping) or not isinstance(head_commit, Mapping):
        raise MergeRefused('GitHub commit response is invalid')
    raw_parents = synthetic.get('parents')
    if not isinstance(raw_parents, list) or len(raw_parents) != 2:
        raise MergeRefused('synthetic merge commit parents are invalid')
    parents = []
    for item in raw_parents:
        if not isinstance(item, Mapping) or not isinstance(item.get('sha'), str):
            raise MergeRefused('synthetic merge commit parents are invalid')
        parents.append(item['sha'])
    if parents != [base_sha, head_sha]:
        raise MergeRefused('synthetic merge commit parents do not match evaluated head/base')
    synthetic_tree = synthetic.get('tree') if isinstance(synthetic.get('tree'), Mapping) else {}
    head_tree = head_commit.get('tree') if isinstance(head_commit.get('tree'), Mapping) else {}
    synthetic_tree_sha = synthetic_tree.get('sha')
    head_tree_sha = head_tree.get('sha')
    if (
        not isinstance(synthetic_tree_sha, str)
        or not re.fullmatch(r'[0-9a-f]{40,64}', synthetic_tree_sha)
        or not isinstance(head_tree_sha, str)
        or not re.fullmatch(r'[0-9a-f]{40,64}', head_tree_sha)
    ):
        raise MergeRefused('GitHub commit tree is invalid')
    if synthetic_tree_sha != head_tree_sha:
        raise MergeRefused(
            'synthetic merge tree does not equal the evaluated head tree; fast-forward unsafe'
        )
    return {
        'synthetic_sha': raw_sha,
        'synthetic_tree_sha': synthetic_tree_sha,
        'head_tree_sha': head_tree_sha,
        'parents': list(parents),
    }


def fetch_check_runs(repository, sha, *, http_get=None):
    """Read check runs for *sha* from the public GitHub API."""

    if not isinstance(sha, str) or not re.fullmatch(r'[0-9a-f]{40,64}', sha):
        raise MergeRefused('CI lookup SHA is invalid')
    getter = http_get or requests.get
    prefix = '/repos/' + str(repository)
    response = getter(
        'https://api.github.com' + prefix + '/commits/' + sha + '/check-runs',
        params={'per_page': 100},
        timeout=(5, 20),
        allow_redirects=False,
        headers={'Accept': 'application/vnd.github+json', 'User-Agent': 'change-guard'},
    )
    if response.status_code != 200 or len(response.content) > 2 * 1024 * 1024:
        raise MergeRefused('public CI check lookup failed')
    try:
        payload = response.json()
    except Exception:
        raise MergeRefused('public CI check payload is invalid') from None
    if not isinstance(payload, Mapping):
        raise MergeRefused('public CI check payload is invalid')
    runs = payload.get('check_runs')
    total = payload.get('total_count')
    if not isinstance(runs, list):
        raise MergeRefused('public CI check payload is invalid')
    if isinstance(total, int) and not isinstance(total, bool) and total > len(runs):
        raise MergeRefused('public CI check-run response is incomplete')
    return payload


def validate_head_ci(repository, head_sha, required_name, *, http_get=None):
    """Validate GitHub Actions checks bound to the evaluated head SHA."""

    payload = fetch_check_runs(repository, head_sha, http_get=http_get)
    validate_ci(payload, required_name, expected_head_sha=head_sha)
    return payload


def fetch_depth(config):
    raw = config.get('merge_fetch_depth', 128)
    if isinstance(raw, bool) or not isinstance(raw, int) or not 1 <= raw <= 10000:
        raise MergeRefused('merge_fetch_depth must be an integer between 1 and 10000')
    return raw


def fast_forward_push_argv(repository, base_sha, head_sha):
    return [
        'push',
        '--force-with-lease=refs/heads/main:' + str(base_sha),
        'ssh://git@ssh.github.com:443/' + str(repository) + '.git',
        str(head_sha) + ':refs/heads/main',
    ]


def _git_process(argv, *, cwd, config, timeout=45):
    allowed = {
        'PATH', 'HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY',
        'http_proxy', 'https_proxy', 'no_proxy', 'LANG',
        'SYSTEMROOT', 'WINDIR', 'COMSPEC', 'PATHEXT', 'TEMP', 'TMP',
    }
    env = {k:v for k,v in os.environ.items() if k in allowed or k.upper() in allowed}
    env.update({'HOME':str(cwd), 'GIT_CONFIG_NOSYSTEM':'1', 'GIT_CONFIG_GLOBAL':'/dev/null',
                'GIT_TERMINAL_PROMPT':'0', 'GIT_SSH_VARIANT':'ssh'})
    ssh = ['ssh', '-i', str(config['merge_deploy_key']), '-o', 'IdentitiesOnly=yes',
           '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
           '-o', 'UserKnownHostsFile='+str(config['merge_known_hosts']), '-p', '443']
    if config.get('merge_ssh_proxy'):
        proxy = str(config['merge_ssh_proxy'])
        if not re.fullmatch(r'[0-9.]+:[0-9]+', proxy):
            raise MergeRefused('invalid trusted SSH proxy configuration')
        ssh += ['-o', 'ProxyCommand=nc -X connect -x '+proxy+' %h %p']
    env['GIT_SSH_COMMAND'] = shlex.join(ssh)
    return subprocess.run(['git', '-c', 'core.hooksPath=/dev/null', *argv], cwd=cwd, env=env,
                          stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout)


def _git(argv, *, cwd, config, timeout=45):
    result = _git_process(argv, cwd=cwd, config=config, timeout=timeout)
    if result.returncode:
        # Git may echo URLs but this command never uses token-bearing URLs.
        raise MergeRefused('trusted git operation failed: '+result.stderr[-1000:])
    return result.stdout.strip()


def _git_returncode(argv, *, cwd, config, timeout=45):
    return _git_process(argv, cwd=cwd, config=config, timeout=timeout).returncode


def verify_local_fast_forward(directory, config, repository, base_sha, head_sha, expected_head_tree):
    """Verify the fetched head tree and, when not shallow-limited, ancestry."""

    depth = fetch_depth(config)
    url = 'https://github.com/' + str(repository) + '.git'
    _git(['fetch', '--no-tags', '--depth=' + str(depth), url, head_sha],
         cwd=directory, config=config)
    _git(['fetch', '--no-tags', '--depth=' + str(depth), url, base_sha],
         cwd=directory, config=config)
    local_head = _git(['rev-parse', head_sha + '^{commit}'], cwd=directory, config=config)
    if local_head != head_sha:
        raise MergeRefused('fetched Git head does not match the evaluated head')
    local_tree = _git(['rev-parse', head_sha + '^{tree}'], cwd=directory, config=config)
    if local_tree != expected_head_tree:
        raise MergeRefused('fetched Git head tree does not match the GitHub head tree')
    local_base = _git(['rev-parse', base_sha + '^{commit}'], cwd=directory, config=config)
    if local_base != base_sha:
        raise MergeRefused('fetched Git base does not match the current main')
    ancestor_status = _git_returncode(
        ['merge-base', '--is-ancestor', base_sha, head_sha],
        cwd=directory,
        config=config,
    )
    base_ancestor = None
    if ancestor_status == 0:
        base_ancestor = True
    elif ancestor_status == 1:
        shallow = _git(['rev-parse', '--is-shallow-repository'], cwd=directory, config=config)
        if shallow.strip() != 'true':
            raise MergeRefused('Git base is not an ancestor of the evaluated head')
        # The GitHub compare API already proved merge_base == base.  A shallow
        # local fetch may not contain enough graph edges to re-prove it.
        base_ancestor = None
    else:
        raise MergeRefused('local Git base-ancestor check failed')
    return {'head_tree_sha': local_tree, 'base_ancestor': base_ancestor}


def push_fast_forward(directory, config, repository, base_sha, head_sha):
    argv = fast_forward_push_argv(repository, base_sha, head_sha)
    _git(argv, cwd=directory, config=config, timeout=12)
    return argv


def build_merge_record(number, head_sha, base_sha, synthetic, local, report, *, now):
    return {
        'result': 'MERGED',
        'strategy': 'fast-forward',
        'pr': number,
        'head_sha': head_sha,
        'evaluated_head': head_sha,
        'base_sha': base_sha,
        # Post-deploy verification consumes the real commit now on main.
        'merge_sha': head_sha,
        'synthetic_merge_sha': synthetic['synthetic_sha'],
        'synthetic_tree_sha': synthetic['synthetic_tree_sha'],
        'head_tree_sha': local['head_tree_sha'],
        'base_ancestor': local['base_ancestor'],
        'evaluation_id': report['evaluation_id'],
        'decision': report['decision'],
        'merged_at': int(now),
        'evidence_expires_at': report['expires_at'],
        'github_merge_api_used': False,
        'rollback': {
            'strategy': 'git-revert',
            'commit': head_sha,
            'mainline': None,
            # The commit on main is a normal single-parent head commit, so a
            # rollback is a plain revert with no -m/--mainline.
            'command': 'git revert ' + head_sha,
        },
    }


def merge_pr(config, number, *, refresh=True):
    if not isinstance(number, int) or isinstance(number, bool) or number < 1:
        raise MergeRefused('invalid PR number')
    if config.get('base_branch', 'main') != 'main':
        raise MergeRefused('this merger only targets main')
    for key in ('merge_deploy_key', 'merge_known_hosts'):
        if not config.get(key) or not Path(config[key]).is_file():
            raise MergeRefused('missing trusted merge configuration: '+key)
    guard = ChangeGuardDaemon(config)
    if refresh:
        guard.run_once()  # reuses a still-valid evaluation; preserves scoped approvals
    with guard.store.acquire_lock():
        index = guard.store.load_index()
        entry = index.get('prs', {}).get(str(number), {})
        report = guard.store.read_report(entry.get('evaluation_id', ''))
        pr = guard.github.get_pull_request(number)
        base = guard.github.get_branch_head('main')
        binding = current_policy_binding(guard.config)
        validate_report(report, pr, base, time.time(), policy_binding=binding)
        if report['decision'] == 'REVIEW':
            approval, error = guard._resolve_approval(report, pr)
            if not approval:
                raise MergeRefused('current REVIEW approval missing: '+str(error or 'not approved'))
        # IR-01: re-fetch the Git trees independently.  A forged/incorrect PASS
        # report is still refused when a workflow blob differs between base and
        # head.  The candidate chart pin is re-verified from the same raw blobs.
        reported_paths = report.get('changed_paths')
        reported_workflow = [
            path for path in (reported_paths if isinstance(reported_paths, list) else [])
            if isinstance(path, str) and is_workflow_path(path)
        ]
        if reported_workflow or report.get('workflow_changed') is True:
            raise MergeRefused('report records a .github/workflows change; refusing merge')
        _base_snapshot, head_snapshot = verify_base_head_workflows(
            guard.github, base, pr.head_sha
        )
        validate_chart_pin(guard.config, report, head_snapshot)
        prefix = '/repos/'+str(config['repository'])
        repository = str(config['repository'])
        compare = guard.github.get(prefix+'/compare/'+base+'...'+pr.head_sha)
        if compare.get('merge_base_commit', {}).get('sha') != base:
            raise MergeRefused('update PR with current main before merging')
        raw = guard.github.get(prefix+'/pulls/'+str(number))
        synthetic = validate_synthetic_merge(
            guard.github, repository, raw, base, pr.head_sha
        )
        # pull_request checks are attached to the head SHA.  Querying the
        # synthetic merge commit returns [] on GitHub and cannot be accepted.
        required_ci = str(config.get('merge_required_ci', 'Test, lint, render'))
        validate_head_ci(repository, pr.head_sha, required_ci)
        with tempfile.TemporaryDirectory(prefix='change-guard-merge-') as temp:
            directory = Path(temp)
            _git(['init', '--bare', '.'], cwd=directory, config=config)
            local = verify_local_fast_forward(
                directory,
                config,
                repository,
                base,
                pr.head_sha,
                synthetic['head_tree_sha'],
            )
            fresh = guard.github.get_pull_request(number)
            current_base = guard.github.get_branch_head('main')
            validate_report(report, fresh, current_base, time.time(), min_remaining=15,
                            policy_binding=binding)
            if report['decision'] == 'REVIEW' and not guard._resolve_approval(report, fresh)[0]:
                raise MergeRefused('approval was revoked before push')
            guard.github.create_commit_status(pr.head_sha, 'success',
                'Fresh '+str(report['decision'])+' '+str(report['evaluation_id']),
                str(config.get('status_context','change-guard/release')))
            validate_report(report, fresh, current_base, time.time(), min_remaining=13,
                            policy_binding=binding)
            # The compare API proved base is an ancestor of head, so this is a
            # fast-forward.  The exact lease still prevents a concurrent main
            # update between validation and push.
            push_fast_forward(directory, config, repository, base, pr.head_sha)
        record = build_merge_record(
            number,
            pr.head_sha,
            base,
            synthetic,
            local,
            report,
            now=time.time(),
        )
        output = Path(config['state_dir'])/'merges'
        output.mkdir(mode=0o700, exist_ok=True)
        path = output/(pr.head_sha+'.json')
        with path.open('x', encoding='utf-8') as handle:
            json.dump(record, handle, ensure_ascii=False, indent=2)
        path.chmod(0o600)
        return record


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',required=True)
    parser.add_argument('--pr',type=int,required=True)
    args=parser.parse_args(argv)
    try:
        print(json.dumps(merge_pr(load_config(args.config),args.pr),indent=2))
        return 0
    except Exception as error:
        print(json.dumps({'result':'REFUSED','error':str(error)[:1200]}))
        return 1


if __name__=='__main__':
    raise SystemExit(main())
