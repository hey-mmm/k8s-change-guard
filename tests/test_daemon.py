from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from change_guard import daemon
from change_guard import github as gh


NOW = 1_800_000_000
HEAD = "a" * 40
BASE = "b" * 40
IMAGE = "ghcr.io/hey-mmm/observability-demo:sha-" + "c" * 40
EMPTY_CHART_DIGEST = hashlib.sha256(b"{}").hexdigest()


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


def tree(sha=HEAD, files=None, entries=None):
    files = files or {}
    return gh.TreeSnapshot(
        sha=sha,
        tree_sha="d" * 40,
        entries=entries or {},
        renderer_files=files,
        argo_files={},
        tree_digest="e" * 64,
        entry_count=0,
        renderer_bytes=sum(len(value) for value in files.values()),
        argo_bytes=0,
    )


def candidate(pr=None, *, changed_paths=(), head_files=None, base_entries=None, head_entries=None):
    pr = pr or pr_info()
    return gh.PullRequestCandidate(
        pull_request=pr,
        base_sha=BASE,
        base_snapshot=tree(BASE, entries=base_entries),
        head_snapshot=tree(HEAD, head_files, entries=head_entries),
        changed_paths=tuple(changed_paths),
        changed_count=len(changed_paths),
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
        "approved_chart_digest": [EMPTY_CHART_DIGEST],
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
        self.candidate = candidate(self.pr)
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
        return self.candidate

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
            "rule_version": daemon.RULE_VERSION,
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


def make_daemon(tmp, fake, decision="PASS", findings=None, config_overrides=None):
    cfg = config(tmp)
    cfg.update(config_overrides or {})
    return daemon.ChangeGuardDaemon(
        cfg,
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

    def test_policy_binding_excludes_state_and_credentials_but_tracks_policy(self):
        with tempfile.TemporaryDirectory() as temporary:
            baseline = daemon.policy_digest(daemon.validate_config(config(temporary)))
            for key, value in (
                ("state_dir", str(Path(temporary) / "other-state")),
                ("poll_seconds", 60),
                ("github_token_file", "/etc/change-guard/other-token"),
                ("github_token_env", "OTHER_TOKEN"),
                ("deepseek_token_file", "/etc/change-guard/other-deepseek"),
                ("merge_deploy_key", "/etc/change-guard/other-key"),
                ("report_comment", True),
            ):
                changed = config(temporary)
                changed[key] = value
                self.assertEqual(
                    daemon.policy_digest(daemon.validate_config(changed)), baseline, key
                )
            for key, value in (
                ("approved_chart_digest", ["0" * 64]),
                ("require_digest", False),
                ("max_error_ratio", 0.01),
                ("max_p95_seconds", 0.2),
                ("memory_headroom_factor", 1.5),
                ("low_traffic_rps", 0.2),
                ("prometheus_url", "http://prometheus.example:9090"),
                ("deepseek_url", "https://api.deepseek.com/v1/chat/completions"),
                ("deepseek_timeout_seconds", 31),
                ("deepseek_total_timeout_seconds", 241),
                ("kubectl_timeout_seconds", 21),
                ("postdeploy_timeout_seconds", 301),
            ):
                changed = config(temporary)
                changed[key] = value
                self.assertNotEqual(
                    daemon.policy_digest(daemon.validate_config(changed)), baseline, key
                )

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


class SecurityRegressionTests(unittest.TestCase):
    def _rule_ids(self, guard, result):
        report = guard.store.read_report(result["prs"][0]["evaluation_id"])
        evaluation = report.get("evaluation") if isinstance(report.get("evaluation"), dict) else {}
        findings = report.get("findings") or evaluation.get("findings") or []
        return report, {finding["rule_id"] for finding in findings}

    def test_workflow_change_is_hard_block_even_when_engine_says_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            fake = FakeGitHub()
            fake.candidate = candidate(changed_paths=(".github/workflows/ci.yml",))
            guard = make_daemon(Path(temporary), fake, "PASS")
            result = guard.run_once()
            self.assertEqual(result["prs"][0]["decision"], "BLOCK")
            self.assertEqual(fake.statuses[-1]["state"], "failure")
            report, rules = self._rule_ids(guard, result)
            self.assertIn("WORKFLOW_CHANGE_BLOCKED", rules)
            self.assertEqual(report["workflow_changed"], True)
            # A BLOCK is never eligible for the REVIEW approval path.
            self.assertIsNone(guard._resolve_approval(report, fake.pr)[0])

    def test_workflow_tree_signature_blocks_even_without_a_complete_path_list(self):
        base_entry = gh.TreeEntry(
            path=".github/workflows/ci.yml", mode="100644", kind="blob", sha="1" * 40, size=10
        )
        head_entry = gh.TreeEntry(
            path=".github/workflows/ci.yml", mode="100644", kind="blob", sha="2" * 40, size=10
        )
        with tempfile.TemporaryDirectory() as temporary:
            fake = FakeGitHub()
            # Simulate a path list that does not surface the workflow edit; the
            # base/head tree signature must still produce a hard BLOCK.
            fake.candidate = candidate(
                changed_paths=(),
                base_entries={base_entry.path: base_entry},
                head_entries={head_entry.path: head_entry},
            )
            guard = make_daemon(Path(temporary), fake, "PASS")
            result = guard.run_once()
            self.assertEqual(result["prs"][0]["decision"], "BLOCK")
            report, rules = self._rule_ids(guard, result)
            self.assertIn("WORKFLOW_CHANGE_BLOCKED", rules)
            self.assertIn(".github/workflows/ci.yml", report["context"]["workflow_paths"])

    def test_chart_digest_mismatch_is_hard_block_but_matching_pin_passes(self):
        files = {"charts/demo/Chart.yaml": b"apiVersion: v2\nname: demo\n"}
        with tempfile.TemporaryDirectory() as temporary:
            fake = FakeGitHub()
            fake.candidate = candidate(head_files=files)
            mismatch = make_daemon(Path(temporary), fake, "PASS")
            result = mismatch.run_once()
            self.assertEqual(result["prs"][0]["decision"], "BLOCK")
            self.assertEqual(fake.statuses[-1]["state"], "failure")
            _report, rules = self._rule_ids(mismatch, result)
            self.assertIn("APPROVED_CHART_DIGEST_MISMATCH", rules)

        with tempfile.TemporaryDirectory() as temporary:
            fake = FakeGitHub()
            fake.candidate = candidate(head_files=files)
            pinned = daemon.chart_digest_from_files(files)
            guard = make_daemon(
                Path(temporary), fake, "PASS",
                config_overrides={"approved_chart_digest": [pinned]},
            )
            result = guard.run_once()
            self.assertEqual(result["prs"][0]["decision"], "PASS")
            self.assertEqual(fake.statuses[-1]["state"], "success")

    def test_missing_chart_pin_is_error_and_values_are_not_pinned(self):
        with tempfile.TemporaryDirectory() as temporary:
            fake = FakeGitHub()
            guard = make_daemon(
                Path(temporary), fake, "PASS",
                config_overrides={"approved_chart_digest": []},
            )
            result = guard.run_once()
            self.assertEqual(result["prs"][0]["decision"], "ERROR")
            self.assertEqual(fake.statuses[-1]["state"], "error")
            _report, rules = self._rule_ids(guard, result)
            self.assertIn("APPROVED_CHART_DIGEST_NOT_CONFIGURED", rules)

        chart = {"charts/demo/Chart.yaml": b"apiVersion: v2\n"}
        first = daemon.chart_digest_from_files({**chart, "gitops/demo/values.yaml": b"replicas: 1\n"})
        second = daemon.chart_digest_from_files({**chart, "gitops/demo/values.yaml": b"replicas: 2\n"})
        self.assertEqual(first, second)
        # The pin is over raw Git blob bytes: a CRLF conversion is a different
        # chart and must not be silently normalized to the LF digest.
        self.assertNotEqual(
            daemon.chart_digest_from_files({"charts/demo/Chart.yaml": b"a\n"}),
            daemon.chart_digest_from_files({"charts/demo/Chart.yaml": b"a\r\n"}),
        )

    def test_guard_rule_or_policy_upgrade_invalidates_cached_report(self):
        for change in ("guard", "rule", "policy"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
                fake = FakeGitHub()
                guard = make_daemon(Path(temporary), fake, "PASS")
                first = guard.run_once()
                second = guard.run_once()
                self.assertTrue(second["prs"][0]["reused"])
                first_id = first["prs"][0]["evaluation_id"]
                if change == "guard":
                    context = mock.patch.object(daemon, "GUARD_VERSION", "9.9.9")
                elif change == "rule":
                    context = mock.patch.object(daemon, "RULE_VERSION", "2099.1")
                else:
                    context = mock.patch.object(daemon, "RULE_VERSION", daemon.RULE_VERSION)
                with context:
                    if change == "policy":
                        # Same code/rules, different trusted policy config.
                        upgraded = make_daemon(
                            Path(temporary), fake, "PASS",
                            config_overrides={"max_error_ratio": 0.01},
                        )
                        third = upgraded.run_once()
                    else:
                        third = guard.run_once()
                self.assertFalse(third["prs"][0]["reused"])
                self.assertNotEqual(third["prs"][0]["evaluation_id"], first_id)
                self.assertEqual(fake.statuses[-1]["state"], "success")

    def test_forged_pass_report_with_workflow_change_is_not_reused(self):
        with tempfile.TemporaryDirectory() as temporary:
            fake = FakeGitHub()
            guard = make_daemon(Path(temporary), fake, "PASS")
            first = guard.run_once()
            report = guard.store.read_report(first["prs"][0]["evaluation_id"])

            def resign(value):
                value = copy.deepcopy(value)
                value["report_digest"] = daemon._sha256_json(
                    {key: item for key, item in value.items() if key != "report_digest"}
                )
                return value

            # Control: a re-signed PASS report with a fresh id is still usable.
            control = resign({**report, "evaluation_id": "ev-" + "c" * 24})
            guard.store.write_report(control)
            control_entry = {
                "evaluation_id": control["evaluation_id"],
                "head_sha": HEAD,
                "base_sha": BASE,
            }
            self.assertIsNotNone(guard._load_valid_cached(control_entry, fake.pr, BASE, NOW))

            forged = resign(
                {
                    **report,
                    "evaluation_id": "ev-" + "f" * 24,
                    "changed_paths": [".github/workflows/ci.yml"],
                    "context": {**report["context"], "workflow_changed": True},
                }
            )
            guard.store.write_report(forged)
            forged_entry = {
                "evaluation_id": forged["evaluation_id"],
                "head_sha": HEAD,
                "base_sha": BASE,
            }
            self.assertIsNone(guard._load_valid_cached(forged_entry, fake.pr, BASE, NOW))


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
