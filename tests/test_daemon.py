from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from change_guard import daemon
from change_guard import github as gh


NOW = 1_800_000_000
HEAD = "a" * 40
BASE = "b" * 40
IMAGE = "ghcr.io/hey-mmm/observability-demo:sha-" + "c" * 40


def pr_info(*, state="open", draft=False, number=7):
    return gh.PullRequestInfo(
        number=number,
        title="Change demo",
        author="alice",
        state=state,
        draft=draft,
        head_sha=HEAD,
        head_ref="feature",
        head_repo="o/r",
        base_sha=BASE,
        base_ref="main",
        base_repo="o/r",
    )


def tree(sha=HEAD, files=None):
    files = files or {}
    return gh.TreeSnapshot(
        sha=sha,
        tree_sha="d" * 40,
        entries={},
        renderer_files=files,
        argo_files={},
        tree_digest="e" * 64,
        entry_count=0,
        renderer_bytes=sum(len(value) for value in files.values()),
        argo_bytes=0,
    )


def candidate(pr=None):
    pr = pr or pr_info()
    return gh.PullRequestCandidate(
        pull_request=pr,
        base_sha=BASE,
        base_snapshot=tree(BASE),
        head_snapshot=tree(HEAD),
        changed_paths=(),
        changed_count=0,
        tree_diff_truncated=False,
        argo=gh.ArgoAnalysis(),
        pr_base_sha=BASE,
    )


def config(tmp):
    return {
        "repository": "o/r",
        "base_branch": "main",
        "status_context": "change-guard/release",
        "state_dir": str(tmp),
        "poll_seconds": 30,
        "evidence_ttl_seconds": 300,
        "approvers": ["alice"],
        "namespace": "demo",
        "deployment": "demo",
        "report_comment": False,
        "use_proxy_env": False,
    }


class FakeGitHub:
    def __init__(
        self,
        *,
        owner=None,
        permission="write",
        verification_error=None,
        status_error=None,
        statuses=None,
        comments=None,
        prs=None,
    ):
        self.pr = pr_info()
        self.owner = owner
        self.permission = permission
        self.verification_error = verification_error
        self.status_error = status_error
        self.statuses = statuses if statuses is not None else []
        self.comments = comments if comments is not None else []
        self.prs = prs if prs is not None else [self.pr]
        self.permission_calls = []
        self.identity_calls = 0

    def verify_credentials(self, *, probe_status_sha=None):
        if self.verification_error:
            raise self.verification_error
        return {
            "status": "ok",
            "login": "guard",
            "repository": "o/r",
            "private": False,
            "token_kind": "fine-grained",
            "scopes": [],
            "permissions": {"push": True, "admin": False},
            "statuses_write": "inferred",
            "default_branch": "main",
        }

    def list_open_pull_requests(self, base_branch):
        return list(self.prs)

    def get_pull_request(self, number):
        return self.pr

    def get_branch_head(self, branch):
        return BASE

    def fetch_pull_request_candidate(self, number, *, allow_fork=False):
        return candidate(self.pr)

    def list_issue_comments(self, number):
        return list(self.comments)

    def get_repository_identity(self):
        self.identity_calls += 1
        if isinstance(self.owner, Exception):
            raise self.owner
        return self.owner

    def get_user_permission(self, login):
        self.permission_calls.append(login)
        if isinstance(self.permission, Exception):
            raise self.permission
        return self.permission

    def create_commit_status(self, sha, state, description, context, *, target_url=None):
        if self.status_error:
            raise self.status_error
        self.statuses.append(
            {
                "sha": sha,
                "state": state,
                "description": description,
                "context": context,
            }
        )
        return {"id": len(self.statuses)}


class FakeClock:
    def __init__(self, value=NOW):
        self.value = value

    def __call__(self):
        return self.value


def evaluator_for(decision="PASS", findings=None):
    def evaluate(old, new, evidence, cfg, context, ai_result):
        return {
            "decision": decision,
            "findings": findings or [],
            "changes": [],
            "render_digest": "1" * 64,
            "old_render_digest": "2" * 64,
            "evaluated_at": NOW,
            "expires_at": NOW + 300,
            "rule_version": "test",
        }

    return evaluate


def collector(_config):
    return {
        "collected_at": NOW,
        "errors": [],
        "nodes": [],
        "pods": [],
        "deployment": {"name": "demo", "namespace": "demo", "replicas": 1, "ready_replicas": 1, "images": []},
        "metrics": {"request_rate": 0.5, "error_ratio": 0.01, "p95_seconds": 0.2, "alerts": []},
        "capacity": {},
    }


def analyzer(_inputs, _config):
    return {"status": "ok", "model": "test", "summary": "ok", "additional_risks": [], "citations": []}


def render(_path, _config):
    return [{"kind": "Deployment", "metadata": {"name": "demo", "namespace": "demo"}, "spec": {}}]


def make_daemon(tmp, fake, decision="PASS", findings=None):
    return daemon.ChangeGuardDaemon(
        config(tmp),
        github_client=fake,
        collector=collector,
        analyzer=analyzer,
        render=render,
        evaluator=evaluator_for(decision, findings),
        clock=FakeClock(),
        sleep=lambda _seconds: None,
    )


def approval_comment(evaluation_id, *, login="alice", association="OWNER", created=NOW + 1):
    stamp = gh.iso_utc(created)
    return {
        "id": 42,
        "body": f"/guard approve {evaluation_id}",
        "user": {"login": login},
        "author_association": association,
        "created_at": stamp,
        "updated_at": stamp,
    }


class ConfigTests(unittest.TestCase):
    def test_defaults_and_bounded_values(self):
        with tempfile.TemporaryDirectory() as temporary:
            cfg = daemon.validate_config(config(temporary))
            self.assertEqual(cfg["base_branch"], "main")
            self.assertFalse(cfg["report_comment"])
            self.assertEqual(cfg["approvers"], ["alice"])
            for key, value in (
                ("repository", "not-a-repo"),
                ("poll_seconds", 0),
                ("evidence_ttl_seconds", 10),
                ("state_dir", ""),
                ("approvers", ["../bad"]),
                ("namespace", "Bad_Name"),
            ):
                broken = config(temporary)
                broken[key] = value
                with self.assertRaises(daemon.DaemonError):
                    daemon.validate_config(broken)

    def test_cli_config_file_is_yaml_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "config.yaml"
            path.write_text("repository: o/r\n", encoding="utf-8")
            self.assertEqual(daemon.load_config(path)["repository"], "o/r")
            path.write_text("- not-a-mapping\n", encoding="utf-8")
            with self.assertRaises(daemon.DaemonError):
                daemon.validate_config(daemon.load_config(path))


class StateStoreTests(unittest.TestCase):
    def test_reports_are_immutable_and_paths_are_validated(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = daemon.StateStore(temporary)
            report = {"evaluation_id": "ev-" + "a" * 24, "decision": "PASS"}
            path, created = store.write_report(report)
            self.assertTrue(created)
            self.assertEqual(path, store.report_path(report["evaluation_id"]))
            same_path, created_again = store.write_report(report)
            self.assertFalse(created_again)
            self.assertEqual(same_path, path)
            with self.assertRaises(daemon.DaemonError):
                store.write_report({**report, "decision": "BLOCK"})
            for bad in ("../x", "ev-nothex", "ev-" + "a" * 8):
                with self.assertRaises(daemon.DaemonError):
                    store.report_path(bad)

    def test_report_values_are_sanitized(self):
        value = daemon._sanitize_value(
            {"github_token": "ghp_1234567890abcdefghijklmnop", "nested": {"password": "x"}, "ok": "yes"}
        )
        self.assertEqual(value["github_token"], "<redacted>")
        self.assertEqual(value["nested"]["password"], "<redacted>")
        self.assertEqual(value["ok"], "yes")


class ApprovalAndStatusTests(unittest.TestCase):
    def test_pass_publishes_pending_then_success_and_reuses_cache(self):
        with tempfile.TemporaryDirectory() as temporary:
            fake = FakeGitHub()
            guard = make_daemon(Path(temporary), fake, "PASS")
            first = guard.run_once()
            self.assertEqual(first["status"], "ok")
            self.assertEqual([item["state"] for item in fake.statuses], ["pending", "success"])
            report_id = first["prs"][0]["evaluation_id"]
            self.assertTrue(guard.store.report_path(report_id).is_file())
            count = len(fake.statuses)
            second = guard.run_once()
            self.assertEqual(second["status"], "ok")
            self.assertEqual(len(fake.statuses), count)
            self.assertTrue(second["prs"][0]["reused"])

    def test_review_requires_allowlisted_exact_owner_approval(self):
        with tempfile.TemporaryDirectory() as temporary:
            fake = FakeGitHub(
                owner={"owner_login": "alice", "owner_type": "User", "full_name": "o/r"},
                permission=gh.GitHubAuthError("forbidden", status=403, code="forbidden"),
                comments=[],
            )
            guard = make_daemon(Path(temporary), fake, "REVIEW")
            first = guard.run_once()
            evaluation_id = first["prs"][0]["evaluation_id"]
            self.assertEqual(fake.statuses[-1]["state"], "pending")
            self.assertEqual(fake.identity_calls, 0)

            fake.comments = [approval_comment(evaluation_id)]
            second = guard.run_once()
            self.assertEqual(second["status"], "ok")
            self.assertEqual(fake.statuses[-1]["state"], "success")
            self.assertEqual(second["prs"][0]["approval"]["permission"], gh.OWNER_APPROVAL_PERMISSION)
            self.assertEqual(fake.permission_calls, [])
            self.assertEqual(fake.identity_calls, 2)  # resolve + recheck before success

    def test_non_owner_needs_permission_api_and_org_owner_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            fake = FakeGitHub(
                owner={"owner_login": "org", "owner_type": "Organization", "full_name": "o/r"},
                permission=gh.GitHubAuthError("Resource not accessible", status=403, code="forbidden"),
            )
            guard = make_daemon(Path(temporary), fake, "REVIEW")
            first = guard.run_once()
            evaluation_id = first["prs"][0]["evaluation_id"]
            fake.comments = [approval_comment(evaluation_id, association="MEMBER")]
            second = guard.run_once()
            self.assertEqual(fake.statuses[-1]["state"], "pending")
            self.assertEqual(fake.permission_calls, ["alice"])
            self.assertIn("cannot verify current write permission", second["prs"][0]["approval_error"])

    def test_owner_rename_or_transfer_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            fake = FakeGitHub(
                owner=gh.GitHubError("repository identity changed", code="repository_identity_changed"),
                permission=gh.GitHubAuthError("forbidden", status=403, code="forbidden"),
            )
            guard = make_daemon(Path(temporary), fake, "REVIEW")
            first = guard.run_once()
            evaluation_id = first["prs"][0]["evaluation_id"]
            fake.comments = [approval_comment(evaluation_id)]
            second = guard.run_once()
            self.assertEqual(fake.statuses[-1]["state"], "pending")
            self.assertIn("cannot verify current repository owner", second["prs"][0]["approval_error"])

    def test_approver_allowlist_and_timestamp_are_enforced(self):
        with tempfile.TemporaryDirectory() as temporary:
            fake = FakeGitHub(
                owner={"owner_login": "alice", "owner_type": "User", "full_name": "o/r"},
                permission="write",
            )
            guard = make_daemon(Path(temporary), fake, "REVIEW")
            first = guard.run_once()
            evaluation_id = first["prs"][0]["evaluation_id"]
            # Wrong login, edited/too-old comment, and a prefix body are ignored.
            fake.comments = [
                approval_comment(evaluation_id, login="mallory"),
                {**approval_comment(evaluation_id), "body": f"prefix /guard approve {evaluation_id}"},
                {**approval_comment(evaluation_id), "created_at": gh.iso_utc(NOW - 10), "updated_at": gh.iso_utc(NOW - 10)},
            ]
            second = guard.run_once()
            self.assertEqual(fake.statuses[-1]["state"], "pending")
            fake.permission = "read"
            fake.comments = [{**approval_comment(evaluation_id), "author_association": "CONTRIBUTOR"}]
            third = guard.run_once()
            self.assertEqual(fake.statuses[-1]["state"], "pending")
            # The explicit permission API is authoritative for non-owner associations.
            self.assertEqual(fake.permission_calls, ["alice"])

    def test_credential_failure_is_isolated_before_any_status(self):
        with tempfile.TemporaryDirectory() as temporary:
            fake = FakeGitHub(verification_error=gh.GitHubAuthError("bad token", code="unauthorized"))
            guard = make_daemon(Path(temporary), fake, "PASS")
            result = guard.run_once()
            self.assertEqual(result["status"], "error")
            self.assertIn("credential verification failed", result["error"])
            self.assertEqual(fake.statuses, [])

    def test_closed_pr_revokes_a_previous_status(self):
        with tempfile.TemporaryDirectory() as temporary:
            fake = FakeGitHub()
            guard = make_daemon(Path(temporary), fake, "PASS")
            guard.run_once()
            fake.prs = []
            result = guard.run_once()
            self.assertEqual(result["status"], "ok")
            self.assertEqual(result["closed_invalidated"], 1)
            self.assertEqual(fake.statuses[-1]["state"], "error")
            self.assertIn("closed or merged", fake.statuses[-1]["description"])

    def test_block_and_error_status_mapping(self):
        with tempfile.TemporaryDirectory() as temporary:
            fake = FakeGitHub()
            guard = make_daemon(
                Path(temporary),
                fake,
                "BLOCK",
                findings=[{"rule_id": "R", "severity": "BLOCK", "message": "no"}],
            )
            result = guard.run_once()
            self.assertEqual(result["prs"][0]["state"], "failure")
            self.assertEqual(fake.statuses[-1]["state"], "failure")

        with tempfile.TemporaryDirectory() as temporary:
            fake = FakeGitHub()
            guard = make_daemon(
                Path(temporary),
                fake,
                "ERROR",
                findings=[{"rule_id": "E", "severity": "ERROR", "message": "bad"}],
            )
            result = guard.run_once()
            self.assertEqual(result["prs"][0]["state"], "error")
            self.assertEqual(fake.statuses[-1]["state"], "error")


class ConfigFileIntegrationTests(unittest.TestCase):
    def test_config_example_is_valid_and_comments_are_off(self):
        path = Path(__file__).resolve().parent.parent / "config.example.yaml"
        import yaml

        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        self.assertFalse(raw["report_comment"])
        self.assertEqual(raw["ready_path"], "/readyz")
        self.assertEqual(raw["kubectl"], "/usr/bin/kubectl")
        validated = daemon.validate_config(raw)
        self.assertEqual(validated["approvers"], ["hey-mmm"])


if __name__ == "__main__":
    unittest.main()
