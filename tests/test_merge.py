import copy
import hashlib
import json
from types import SimpleNamespace
import unittest
from unittest import mock
from change_guard import daemon
from change_guard.merge import (
    MergeRefused,
    build_merge_record,
    fast_forward_push_argv,
    push_fast_forward,
    validate_chart_pin,
    validate_ci,
    validate_head_ci,
    validate_policy_binding,
    validate_report,
    validate_synthetic_merge,
    validate_workflow_snapshots,
    verify_base_head_workflows,
    verify_local_fast_forward,
)


POLICY_CONFIG = {
    'repository': 'o/r',
    'base_branch': 'main',
    'status_context': 'change-guard/release',
    'namespace': 'demo',
    'deployment': 'demo',
    'approvers': ['alice'],
    'approved_chart_digest': [hashlib.sha256(b'{}').hexdigest()],
}


def sign(report):
    report = copy.deepcopy(report)
    report.pop('report_digest', None)
    raw = json.dumps(report, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)
    report['report_digest'] = hashlib.sha256(raw.encode()).hexdigest()
    return report


def snapshot(paths):
    return SimpleNamespace(
        entries={
            path: SimpleNamespace(mode='100644', kind='blob', sha=sha)
            for path, sha in paths.items()
        },
        renderer_files={},
    )


def commit_object(sha, tree, parents):
    return {
        'sha': sha,
        'tree': {'sha': tree},
        'parents': [{'sha': parent} for parent in parents],
    }


class CommitGitHub:
    def __init__(self, synthetic, head):
        self.commits = {synthetic['sha']: synthetic, head['sha']: head}
        self.paths = []

    def get(self, path):
        self.paths.append(path)
        return self.commits[path.rsplit('/', 1)[-1]]


class CheckResponse:
    def __init__(self, payload):
        self.status_code = 200
        self.content = json.dumps(payload).encode('utf-8')
        self._payload = payload

    def json(self):
        return self._payload


class MergeValidationTests(unittest.TestCase):
    def setUp(self):
        self.pr=SimpleNamespace(number=3,head_sha='a'*40,state='open',draft=False)
        self.report={'head_sha':'a'*40,'base_sha':'b'*40,'pull_request':{'number':3},
                     'decision':'PASS','evaluated_at':900,'expires_at':1200}
        self.sign()

    def sign(self):
        raw=json.dumps({k:v for k,v in self.report.items() if k!='report_digest'},
                       sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)
        self.report['report_digest']=hashlib.sha256(raw.encode()).hexdigest()

    def test_current_report_valid(self):
        validate_report(self.report,self.pr,'b'*40,1000)

    def test_head_update_invalidates(self):
        self.pr.head_sha='c'*40
        with self.assertRaises(MergeRefused):validate_report(self.report,self.pr,'b'*40,1000)

    def test_base_update_invalidates(self):
        with self.assertRaises(MergeRefused):validate_report(self.report,self.pr,'c'*40,1000)

    def test_expired_and_nearly_expired_reports_refused(self):
        for now in (1201,1190):
            with self.subTest(now=now),self.assertRaises(MergeRefused):
                validate_report(self.report,self.pr,'b'*40,now)

    def test_hard_block_and_error_refused(self):
        for decision in ('BLOCK','ERROR'):
            self.report['decision']=decision;self.sign()
            with self.subTest(decision=decision),self.assertRaises(MergeRefused):
                validate_report(self.report,self.pr,'b'*40,1000)

    def test_draft_closed_wrong_pr_refused(self):
        for change in ({'draft':True},{'state':'closed'},{'number':99}):
            pr=copy.copy(self.pr)
            for key,value in change.items():setattr(pr,key,value)
            with self.subTest(change=change),self.assertRaises(MergeRefused):
                validate_report(self.report,pr,'b'*40,1000)

    def test_tampering_refused(self):
        self.report['expires_at']=5000
        with self.assertRaises(MergeRefused):validate_report(self.report,self.pr,'b'*40,1000)

    def test_new_ci_failure_cannot_be_hidden_by_old_success(self):
        check={'id':1,'name':'Test, lint, render','app':{'slug':'github-actions'},
               'status':'completed','conclusion':'success'}
        validate_ci({'check_runs':[check]})
        failed={**check,'id':2,'conclusion':'failure'}
        with self.assertRaises(MergeRefused):validate_ci({'check_runs':[check,failed]})

    def test_missing_forged_or_pending_check_refused(self):
        for checks in ([],[{'name':'Test, lint, render','app':{'slug':'other'},'conclusion':'success'}],
                       [{'name':'Test, lint, render','app':{'slug':'github-actions'},'status':'in_progress'}]):
            with self.subTest(checks=checks),self.assertRaises(MergeRefused):validate_ci({'check_runs':checks})


class SecurityRegressionTests(unittest.TestCase):
    def setUp(self):
        self.pr = SimpleNamespace(number=3, head_sha='a' * 40, state='open', draft=False)
        self.report = sign({
            'schema_version': daemon.SCHEMA_VERSION,
            'evaluation_id': 'ev-' + 'a' * 24,
            'head_sha': 'a' * 40,
            'base_sha': 'b' * 40,
            'pull_request': {'number': 3},
            'decision': 'PASS',
            'evaluated_at': 900,
            'expires_at': 1200,
            'changed_paths': [],
            'chart_digest': hashlib.sha256(b'{}').hexdigest(),
        })

    def bound_report(self):
        binding = daemon.current_policy_binding(POLICY_CONFIG)
        return sign({
            **self.report,
            'guard_version': binding['guard_version'],
            'rule_version': binding['rule_version'],
            'policy_binding': binding,
            'policy_digest': binding['policy_digest'],
        })

    def test_code_upgrade_invalidates_old_pass_report(self):
        binding = daemon.current_policy_binding(POLICY_CONFIG)
        with self.assertRaises(MergeRefused):
            validate_report(self.report, self.pr, 'b' * 40, 1000, policy_binding=binding)
        report = self.bound_report()
        validate_report(report, self.pr, 'b' * 40, 1000, policy_binding=binding)
        with mock.patch.object(daemon, 'GUARD_VERSION', '9.9.9'):
            new_binding = daemon.current_policy_binding(POLICY_CONFIG)
        self.assertNotEqual(binding, new_binding)
        with self.assertRaises(MergeRefused):
            validate_report(report, self.pr, 'b' * 40, 1000, policy_binding=new_binding)
        with self.assertRaises(MergeRefused):
            validate_policy_binding(report, {**binding, 'policy_digest': '0' * 64})

    def test_forged_pass_cannot_hide_a_workflow_tree_change(self):
        base = snapshot({'.github/workflows/ci.yml': '1' * 40})
        same = snapshot({'.github/workflows/ci.yml': '1' * 40})
        changed = snapshot({'.github/workflows/ci.yml': '2' * 40})
        validate_workflow_snapshots(base, same)

        class FakeGitHub:
            def fetch_tree_snapshot(self, sha, *, include_argo=True):
                self.calls.append((sha, include_argo))
                return base if sha == 'b' * 40 else changed

            def __init__(self):
                self.calls = []

        github = FakeGitHub()
        # The report is already a signed PASS; the independent tree check still
        # refuses the merge because the workflow blob differs.
        self.assertEqual(self.report['decision'], 'PASS')
        with self.assertRaises(MergeRefused):
            verify_base_head_workflows(github, 'b' * 40, 'a' * 40)
        self.assertEqual(len(github.calls), 2)

        added = snapshot({
            '.github/workflows/ci.yml': '1' * 40,
            '.github/workflows/evil.yml': '3' * 40,
        })
        with self.assertRaises(MergeRefused):
            validate_workflow_snapshots(base, added)

    def test_chart_pin_is_reverified_from_head_blobs(self):
        files = {
            'charts/demo/Chart.yaml': b'apiVersion: v2\n',
            'charts/demo/templates/deployment.yaml': b'kind: Deployment\n',
            'gitops/demo/values.yaml': b'replicas: 1\n',
        }
        digest = daemon.chart_digest_from_files(files)
        head = SimpleNamespace(renderer_files=files)
        report = {**self.report, 'chart_digest': digest}
        config = {**POLICY_CONFIG, 'approved_chart_digest': [digest]}
        self.assertEqual(validate_chart_pin(config, report, head), digest)

        with self.assertRaises(MergeRefused):
            validate_chart_pin(
                {**config, 'approved_chart_digest': ['0' * 64]}, report, head
            )
        with self.assertRaises(MergeRefused):
            validate_chart_pin(config, {**report, 'chart_digest': '0' * 64}, head)
        with self.assertRaises(MergeRefused):
            validate_chart_pin({**config, 'approved_chart_digest': []}, report, head)

    def test_synthetic_tree_must_equal_head_tree(self):
        base = 'b' * 40
        head = 'a' * 40
        synthetic_sha = 'c' * 40
        pull_request = {'merge_commit_sha': synthetic_sha}
        head_commit = commit_object(head, '1' * 40, [base])
        good_synthetic = commit_object(synthetic_sha, '1' * 40, [base, head])
        result = validate_synthetic_merge(
            CommitGitHub(good_synthetic, head_commit), 'o/r', pull_request, base, head
        )
        self.assertEqual(result['synthetic_sha'], synthetic_sha)
        self.assertEqual(result['head_tree_sha'], '1' * 40)

        # GitHub can return a synthetic merge whose tree differs (for example a
        # merge strategy or an out-of-date merge base).  Fast-forwarding head
        # would then not be the tree CI saw; refuse it.
        bad_synthetic = commit_object(synthetic_sha, '2' * 40, [base, head])
        with self.assertRaises(MergeRefused):
            validate_synthetic_merge(
                CommitGitHub(bad_synthetic, head_commit), 'o/r', pull_request, base, head
            )
        wrong_parents = commit_object(synthetic_sha, '1' * 40, [head, base])
        with self.assertRaises(MergeRefused):
            validate_synthetic_merge(
                CommitGitHub(wrong_parents, head_commit), 'o/r', pull_request, base, head
            )

    def test_ci_is_read_from_head_sha_not_synthetic(self):
        head = 'a' * 40
        synthetic = 'c' * 40
        calls = []

        def http_get(url, **kwargs):
            calls.append(url)
            return CheckResponse({
                'check_runs': [{
                    'id': 1,
                    'name': 'Test, lint, render',
                    'head_sha': head,
                    'app': {'slug': 'github-actions'},
                    'status': 'completed',
                    'conclusion': 'success',
                }]
            })

        validate_head_ci('o/r', head, 'Test, lint, render', http_get=http_get)
        self.assertEqual(
            calls,
            ['https://api.github.com/repos/o/r/commits/' + head + '/check-runs'],
        )
        self.assertNotIn(synthetic, calls[0])

        # A successful check that claims a different head is not replayable.
        def wrong_head(url, **kwargs):
            return CheckResponse({
                'check_runs': [{
                    'id': 1,
                    'name': 'Test, lint, render',
                    'head_sha': synthetic,
                    'app': {'slug': 'github-actions'},
                    'status': 'completed',
                    'conclusion': 'success',
                }]
            })

        with self.assertRaises(MergeRefused):
            validate_head_ci('o/r', head, 'Test, lint, render', http_get=wrong_head)
        # Only the GitHub Actions App can create this check run.
        with self.assertRaises(MergeRefused):
            validate_ci({
                'check_runs': [{
                    'id': 1,
                    'name': 'Test, lint, render',
                    'head_sha': head,
                    'app': {'slug': 'not-github-actions'},
                    'status': 'completed',
                    'conclusion': 'success',
                }]
            }, expected_head_sha=head)

    def test_fast_forward_push_uses_head_and_exact_lease(self):
        base = 'b' * 40
        head = 'a' * 40
        argv = fast_forward_push_argv('o/r', base, head)
        self.assertIn('--force-with-lease=refs/heads/main:' + base, argv)
        self.assertEqual(argv[-1], head + ':refs/heads/main')
        self.assertNotIn('refs/heads/main:' + head, argv)

        with mock.patch('change_guard.merge._git') as git:
            push_fast_forward('.', {'merge_deploy_key': 'k', 'merge_known_hosts': 'h'},
                              'o/r', base, head)
        self.assertEqual(git.call_args.args[0], argv)
        self.assertEqual(git.call_args.kwargs['timeout'], 12)

    def test_merge_record_points_to_head_and_plain_revert(self):
        head = 'a' * 40
        base = 'b' * 40
        synthetic = {
            'synthetic_sha': 'c' * 40,
            'synthetic_tree_sha': '1' * 40,
        }
        local = {'head_tree_sha': '1' * 40, 'base_ancestor': True}
        report = {'evaluation_id': 'ev-' + 'd' * 24, 'decision': 'PASS', 'expires_at': 1200}
        record = build_merge_record(3, head, base, synthetic, local, report, now=1000)
        self.assertEqual(record['strategy'], 'fast-forward')
        self.assertEqual(record['merge_sha'], head)
        self.assertEqual(record['evaluated_head'], head)
        self.assertEqual(record['synthetic_merge_sha'], synthetic['synthetic_sha'])
        self.assertFalse(record['github_merge_api_used'])
        self.assertEqual(record['rollback']['commit'], head)
        self.assertIsNone(record['rollback']['mainline'])
        self.assertNotIn('-m', record['rollback']['command'])
        self.assertNotIn('--mainline', record['rollback']['command'])

    def test_local_git_tree_mismatch_is_refused(self):
        base = 'b' * 40
        head = 'a' * 40
        with mock.patch('change_guard.merge._git') as git, \
                mock.patch('change_guard.merge._git_returncode', return_value=0):
            git.side_effect = [head, base, head, '9' * 40, base]
            with self.assertRaises(MergeRefused):
                verify_local_fast_forward(
                    '.', {'merge_deploy_key': 'k', 'merge_known_hosts': 'h'},
                    'o/r', base, head, '1' * 40,
                )


if __name__=='__main__':unittest.main()
