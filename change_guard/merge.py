"""Explicit, trusted merge command; closes the stale green-status failure mode.

GitHub update rules allow only the repository deploy key to update main. This
command is invoked by an operator, never by the model or an untrusted PR. It
checks the current immutable report, approval, CI and exact Git parents, then
performs a compare-and-swap push of GitHub's synthetic merge commit. No checkout,
candidate hook or candidate program runs in the credentialed process.
"""
from __future__ import annotations

import argparse
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

from .daemon import ChangeGuardDaemon, load_config


class MergeRefused(RuntimeError):
    pass


def validate_report(report, pr, base_sha, now, *, min_remaining=20):
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


def validate_ci(payload, required_name='Test, lint, render'):
    runs = payload.get('check_runs', [])
    matches = [r for r in runs if r.get('name') == required_name
               and r.get('app', {}).get('slug') == 'github-actions']
    if not matches:
        raise MergeRefused('required GitHub Actions CI check is missing')
    latest = max(matches, key=lambda r:r.get('id', 0))
    if latest.get('status') != 'completed' or latest.get('conclusion') != 'success':
        raise MergeRefused('required GitHub Actions CI is not successful')


def _git(argv, *, cwd, config, timeout=45):
    env = {k:v for k,v in os.environ.items() if k in
           {'PATH','HTTP_PROXY','HTTPS_PROXY','NO_PROXY','http_proxy','https_proxy','no_proxy','LANG'}}
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
    result = subprocess.run(['git', '-c', 'core.hooksPath=/dev/null', *argv], cwd=cwd, env=env,
                            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        # Git may echo URLs but this command never uses token-bearing URLs.
        raise MergeRefused('trusted git operation failed: '+result.stderr[-1000:])
    return result.stdout.strip()


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
        validate_report(report, pr, base, time.time())
        if report['decision'] == 'REVIEW':
            approval, error = guard._resolve_approval(report, pr)
            if not approval:
                raise MergeRefused('current REVIEW approval missing: '+str(error or 'not approved'))
        prefix = '/repos/'+str(config['repository'])
        compare = guard.github.get(prefix+'/compare/'+base+'...'+pr.head_sha)
        if compare.get('merge_base_commit', {}).get('sha') != base:
            raise MergeRefused('update PR with current main before merging')
        raw = guard.github.get(prefix+'/pulls/'+str(number))
        merge_sha = raw.get('merge_commit_sha', '')
        if not re.fullmatch('[0-9a-f]{40}', merge_sha):
            raise MergeRefused('GitHub synthetic merge commit is unavailable')
        commit = guard.github.get(prefix+'/git/commits/'+merge_sha)
        if [p.get('sha') for p in commit.get('parents', [])] != [base, pr.head_sha]:
            raise MergeRefused('synthetic merge commit parents do not match evaluated head/base')
        # CI for pull_request executes on this synthetic merge commit.
        # This lab protects a public repository. Anonymous access avoids giving
        # the status writer Checks permissions simply to read public CI results.
        response = requests.get('https://api.github.com'+prefix+'/commits/'+merge_sha+'/check-runs',
                                params={'per_page':100}, timeout=(5,20), allow_redirects=False,
                                headers={'Accept':'application/vnd.github+json','User-Agent':'change-guard'})
        if response.status_code != 200 or len(response.content) > 2*1024*1024:
            raise MergeRefused('public CI check lookup failed')
        validate_ci(response.json(), str(config.get('merge_required_ci', 'Test, lint, render')))
        with tempfile.TemporaryDirectory(prefix='change-guard-merge-') as temp:
            directory = Path(temp)
            _git(['init', '--bare', '.'], cwd=directory, config=config)
            repository = str(config['repository'])
            _git(['fetch', '--no-tags', '--depth=2', 'https://github.com/'+repository+'.git', merge_sha],
                 cwd=directory, config=config)
            parents = _git(['show', '-s', '--format=%P', merge_sha], cwd=directory, config=config).split()
            if parents != [base, pr.head_sha]:
                raise MergeRefused('fetched Git parents mismatch')
            fresh = guard.github.get_pull_request(number)
            current_base = guard.github.get_branch_head('main')
            validate_report(report, fresh, current_base, time.time(), min_remaining=15)
            if report['decision'] == 'REVIEW' and not guard._resolve_approval(report, fresh)[0]:
                raise MergeRefused('approval was revoked before push')
            guard.github.create_commit_status(merge_sha, 'success',
                'Fresh '+str(report['decision'])+' '+str(report['evaluation_id']),
                str(config.get('status_context','change-guard/release')))
            validate_report(report, fresh, current_base, time.time(), min_remaining=13)
            # Exact lease prevents a concurrent main update even if it is a
            # fast-forward. The chosen commit must be the two-parent merge above.
            _git(['push', '--force-with-lease=refs/heads/main:'+base,
                  'ssh://git@ssh.github.com:443/'+repository+'.git',
                  merge_sha+':refs/heads/main'], cwd=directory, config=config, timeout=12)
        record = {'result':'MERGED', 'pr':number, 'head_sha':pr.head_sha, 'base_sha':base,
                  'merge_sha':merge_sha, 'evaluation_id':report['evaluation_id'],
                  'decision':report['decision'], 'merged_at':int(time.time()),
                  'evidence_expires_at':report['expires_at']}
        output = Path(config['state_dir'])/'merges'
        output.mkdir(mode=0o700, exist_ok=True)
        path = output/(merge_sha+'.json')
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
