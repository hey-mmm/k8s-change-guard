from __future__ import annotations

import base64
import hashlib
import json
import tempfile
import time
import unittest
from pathlib import Path

from change_guard import github as gh


TOKEN = "ghp_1234567890abcdefghijklmnop"


class FakeResponse:
    def __init__(self, status=200, body=b"", headers=None, chunks=None):
        self.status_code = status
        self._body = body.encode("utf-8") if isinstance(body, str) else body
        self.headers = dict(headers or {})
        self._chunks = chunks
        self.closed = False

    def iter_content(self, chunk_size=32768):
        if self._chunks is not None:
            yield from self._chunks
        else:
            for index in range(0, len(self._body), chunk_size):
                yield self._body[index : index + chunk_size]

    def close(self):
        self.closed = True


class FakeSession:
    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def request(self, method, url, **kwargs):
        path = url.split("https://api.github.com", 1)[1]
        self.calls.append({"method": method, "path": path, "kwargs": kwargs})
        handler = self.routes.get((method, path))
        if handler is None:
            return FakeResponse(404, '{"message":"not found"}')
        if callable(handler):
            return handler(kwargs)
        if isinstance(handler, list):
            return handler.pop(0)
        return handler


def client(routes, *, retries=0, max_bytes=1024 * 1024, sleep=None):
    return gh.GitHubClient(
        "o/r",
        TOKEN,
        session=FakeSession(routes),
        retries=retries,
        max_response_bytes=max_bytes,
        sleep=sleep or (lambda _seconds: None),
    )


def pr_payload(number=1, head_sha="a" * 40, base_sha="b" * 40, base="main", head_repo="o/r", state="open"):
    return {
        "number": number,
        "title": "Change",
        "state": state,
        "draft": False,
        "user": {"login": "alice"},
        "head": {"sha": head_sha, "ref": "feature", "repo": {"full_name": head_repo}},
        "base": {"sha": base_sha, "ref": base, "repo": {"full_name": "o/r"}},
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z",
    }


def git_blob(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\x00" + data).hexdigest()


def tree_entries(files):
    entries = []
    for path, data in files.items():
        blob = git_blob(data)
        entries.append({"path": path, "mode": "100644", "type": "blob", "sha": blob, "size": len(data)})
    return entries


def tree_routes(tree_sha, entries, contents=None):
    contents = contents or {}

    def tree_handler(_kwargs):
        return FakeResponse(200, json.dumps({"tree": entries, "truncated": False}))

    routes = {
        ("GET", f"/repos/o/r/git/trees/{tree_sha}"): tree_handler,
    }
    for entry in entries:
        if entry.get("type") != "blob":
            continue
        data = contents.get(entry["path"], b"")
        blob = entry["sha"]
        routes[("GET", f"/repos/o/r/git/blobs/{blob}")] = FakeResponse(
            200,
            json.dumps(
                {
                    "encoding": "base64",
                    "content": base64.b64encode(data).decode("ascii"),
                    "size": len(data),
                }
            ),
        )
    return routes


def snapshot(sha="a" * 40, tree="t" * 40, files=None, argo=None, entries=None, digest="d"):
    return gh.TreeSnapshot(
        sha=sha,
        tree_sha=tree,
        entries=entries or {},
        renderer_files=files or {},
        argo_files=argo or {},
        tree_digest=digest,
        entry_count=len(entries or {}),
        renderer_bytes=sum(len(v) for v in (files or {}).values()),
        argo_bytes=sum(len(v) for v in (argo or {}).values()),
    )


class GitHubCoreTests(unittest.TestCase):
    def test_repr_never_contains_token(self):
        value = client({})
        self.assertNotIn(TOKEN, repr(value))
        self.assertNotIn(TOKEN, str(value))

    def test_pagination_and_exact_base_filter(self):
        def pulls(kwargs):
            page = kwargs["params"]["page"]
            if page == 1:
                return FakeResponse(200, json.dumps([pr_payload(1), pr_payload(2, base="other")]))
            if page == 2:
                return FakeResponse(200, json.dumps([pr_payload(3)]))
            return FakeResponse(200, "[]")

        value = client({("GET", "/repos/o/r/pulls"): pulls})
        result = value.list_open_pull_requests("main", per_page=2)
        self.assertEqual([item.number for item in result], [1, 3])
        self.assertEqual(value.session.calls[0]["kwargs"]["params"]["base"], "main")

    def test_fetch_snapshot_materialises_only_renderer_paths(self):
        values = b"replicaCount: 2\n"
        chart = b"apiVersion: v2\nname: demo\n"
        entries = tree_entries({"charts/demo/Chart.yaml": chart, "gitops/demo/values.yaml": values, "README.md": b"x"})
        tree_sha = "c" * 40
        routes = tree_routes(tree_sha, entries, {"charts/demo/Chart.yaml": chart, "gitops/demo/values.yaml": values})
        routes[("GET", "/repos/o/r/git/commits/" + "a" * 40)] = FakeResponse(200, json.dumps({"tree": {"sha": tree_sha}}))
        value = client(routes, max_bytes=1024 * 1024)
        result = value.fetch_tree_snapshot("a" * 40)
        self.assertEqual(set(result.renderer_files), {"charts/demo/Chart.yaml", "gitops/demo/values.yaml"})
        with tempfile.TemporaryDirectory() as temporary:
            written = result.materialize(temporary)
            self.assertEqual(written, ["charts/demo/Chart.yaml", "gitops/demo/values.yaml"])
            self.assertTrue((Path(temporary) / "gitops/demo/values.yaml").is_file())
            self.assertFalse((Path(temporary) / "README.md").exists())
            with self.assertRaises(gh.TreeSecurityError):
                result.materialize(temporary)

    def test_untrusted_tree_entries_are_rejected(self):
        base_entries = [{"path": "../escape", "mode": "100644", "type": "blob", "sha": "a" * 40, "size": 1}]
        routes = tree_routes("c" * 40, base_entries)
        routes[("GET", "/repos/o/r/git/commits/" + "a" * 40)] = FakeResponse(200, json.dumps({"tree": {"sha": "c" * 40}}))
        with self.assertRaises(gh.TreeSecurityError):
            client(routes).fetch_tree_snapshot("a" * 40)

        for bad in (
            {"path": "link", "mode": "120000", "type": "blob", "sha": "a" * 40, "size": 1},
            {"path": "sub", "mode": "160000", "type": "commit", "sha": "a" * 40},
            {"path": "dup", "mode": "100644", "type": "blob", "sha": "a" * 40, "size": 1},
            {"path": "dup", "mode": "100644", "type": "blob", "sha": "b" * 40, "size": 1},
        ):
            entries = [bad] if bad["path"] != "dup" else [bad, {**bad, "sha": "c" * 40}]
            routes = tree_routes("c" * 40, entries)
            routes[("GET", "/repos/o/r/git/commits/" + "a" * 40)] = FakeResponse(200, json.dumps({"tree": {"sha": "c" * 40}}))
            with self.assertRaises(gh.TreeSecurityError):
                client(routes).fetch_tree_snapshot("a" * 40)

    def test_truncated_tree_is_rejected(self):
        routes = {
            ("GET", "/repos/o/r/git/commits/" + "a" * 40): FakeResponse(200, json.dumps({"tree": {"sha": "c" * 40}})),
            ("GET", "/repos/o/r/git/trees/" + "c" * 40): FakeResponse(200, json.dumps({"tree": [], "truncated": True})),
        }
        with self.assertRaises(gh.TreeSecurityError):
            client(routes).fetch_tree_snapshot("a" * 40)

    def test_oversized_blob_is_rejected_before_download(self):
        entries = [{"path": "charts/demo/Chart.yaml", "mode": "100644", "type": "blob", "sha": "a" * 40, "size": 3 * 1024 * 1024}]
        routes = tree_routes("c" * 40, entries)
        routes[("GET", "/repos/o/r/git/commits/" + "a" * 40)] = FakeResponse(200, json.dumps({"tree": {"sha": "c" * 40}}))
        with self.assertRaises(gh.TreeSecurityError):
            client(routes).fetch_tree_snapshot("a" * 40)

    def test_blob_object_id_mismatch_is_rejected(self):
        data = b"real"
        entries = [{"path": "gitops/demo/values.yaml", "mode": "100644", "type": "blob", "sha": "0" * 40, "size": len(data)}]
        routes = tree_routes("c" * 40, entries, {"gitops/demo/values.yaml": data})
        routes[("GET", "/repos/o/r/git/commits/" + "a" * 40)] = FakeResponse(200, json.dumps({"tree": {"sha": "c" * 40}}))
        with self.assertRaises(gh.TreeSecurityError):
            client(routes).fetch_tree_snapshot("a" * 40)

    def test_path_normalisation_rejects_traversal_and_backslashes(self):
        for value in ("../x", "a/../b", "/abs", "a//b", "a/", "a\\b", "", "a/\x00b"):
            with self.assertRaises(gh.TreeSecurityError):
                gh.normalize_repo_path(value)
        self.assertEqual(gh.normalize_repo_path("charts/demo/templates/x.yaml"), "charts/demo/templates/x.yaml")


class CredentialTests(unittest.TestCase):
    def _routes(self, scopes=None, private=True, permissions=None, probe=False):
        headers = {} if scopes is None else {"X-OAuth-Scopes": scopes}
        repo = {
            "full_name": "o/r",
            "private": private,
            "default_branch": "main",
            "permissions": permissions or {"push": True, "admin": False, "pull": True},
        }
        routes = {
            ("GET", "/user"): FakeResponse(200, json.dumps({"login": "guard"}), headers),
            ("GET", "/repos/o/r"): FakeResponse(200, json.dumps(repo)),
            ("GET", "/repos/o/r/pulls"): FakeResponse(200, "[]"),
            ("GET", "/repos/o/r/git/ref/heads/main"): FakeResponse(200, json.dumps({"object": {"sha": "c" * 40}})),
            ("GET", "/repos/o/r/commits/" + "c" * 40 + "/statuses"): FakeResponse(200, "[]"),
        }
        if probe:
            routes[("POST", "/repos/o/r/statuses/" + "c" * 40)] = FakeResponse(201, json.dumps({"id": 7}))
        return routes

    def test_classic_scope_is_verified(self):
        value = client(self._routes(scopes="repo,read:user"))
        result = value.verify_credentials()
        self.assertEqual(result["token_kind"], "classic")
        self.assertEqual(result["statuses_write"], "verified-by-scope")
        self.assertIn("repo", result["scopes"])

    def test_classic_missing_status_scope_fails_closed(self):
        value = client(self._routes(scopes="read:user"))
        with self.assertRaises(gh.GitHubAuthError):
            value.verify_credentials()

    def test_fine_grained_push_is_inferred_and_probe_verifies_write(self):
        value = client(self._routes(scopes=None, permissions={"push": True}, probe=True))
        result = value.verify_credentials()
        self.assertEqual(result["statuses_write"], "inferred")
        probed = value.verify_credentials(probe_status_sha="c" * 40)
        self.assertEqual(probed["statuses_write"], "verified-by-write")
        self.assertTrue(any(call["method"] == "POST" for call in value.session.calls))

    def test_fine_grained_without_write_permission_fails(self):
        value = client(self._routes(scopes=None, permissions={"pull": True}))
        with self.assertRaises(gh.GitHubAuthError):
            value.verify_credentials()

    def test_private_repo_rejects_public_repo_scope(self):
        value = client(self._routes(scopes="public_repo", private=True))
        with self.assertRaises(gh.GitHubAuthError):
            value.verify_credentials()


class ApiFailureTests(unittest.TestCase):
    def test_retry_then_success(self):
        sleeps = []
        routes = {("GET", "/user"): [FakeResponse(500, "boom"), FakeResponse(200, '{"login":"x"}')]}
        value = client(routes, retries=1, sleep=sleeps.append)
        self.assertEqual(value.get("/user"), {"login": "x"})
        self.assertEqual(len(sleeps), 1)

    def test_retry_exhaustion_does_not_leak_token(self):
        routes = {("GET", "/user"): FakeResponse(500, "boom")}
        value = client(routes, retries=1)
        with self.assertRaises(gh.GitHubError) as caught:
            value.get("/user")
        self.assertNotIn(TOKEN, str(caught.exception))
        self.assertNotIn(TOKEN, repr(caught.exception))

    def test_redirects_are_refused(self):
        routes = {("GET", "/user"): FakeResponse(302, "", {"Location": "https://evil.invalid"})}
        with self.assertRaises(gh.GitHubError) as caught:
            client(routes).get("/user")
        self.assertEqual(caught.exception.code, "redirect_refused")

    def test_rate_limit_wait_is_bounded(self):
        routes = {
            ("GET", "/user"): FakeResponse(
                403,
                "rate limited",
                {
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(int(time.time()) + 3600),
                },
            )
        }
        with self.assertRaises(gh.GitHubRateLimitError):
            client(routes, retries=1).get("/user")

    def test_response_size_and_json_are_bounded(self):
        routes = {("GET", "/user"): FakeResponse(200, b"x" * 10000)}
        with self.assertRaises(gh.GitHubError) as caught:
            client(routes, max_bytes=4096).get("/user")
        self.assertEqual(caught.exception.code, "response_too_large")
        routes = {("GET", "/user"): FakeResponse(200, b"not-json")}
        with self.assertRaises(gh.GitHubError) as caught:
            client(routes).get("/user")
        self.assertEqual(caught.exception.code, "invalid_json")

    def test_status_payload_and_exact_approval(self):
        captured = {}

        def status_handler(kwargs):
            captured.update(kwargs)
            return FakeResponse(201, json.dumps({"id": 1}))

        value = client({("POST", "/repos/o/r/statuses/" + "a" * 40): status_handler})
        value.create_commit_status("a" * 40, "pending", "review required", "change-guard/release")
        body = captured["json"]
        self.assertEqual(body["state"], "pending")
        self.assertEqual(body["context"], "change-guard/release")
        with self.assertRaises(gh.GitHubError):
            value.create_commit_status("a" * 40, "success", "x", "ctx", target_url="http://insecure")
        self.assertEqual(gh.parse_approval_body("/guard approve ev-0123456789abcdef"), "ev-0123456789abcdef")
        for body in (
            "label: approved",
            "/guard approve",
            "/guard approve ev-1 extra",
            "please /guard approve ev-0123456789abcdef",
            "/guard approve ev-0123456789abcdef\nmore",
        ):
            self.assertIsNone(gh.parse_approval_body(body))

    def test_user_permission_is_read(self):
        value = client(
            {("GET", "/repos/o/r/collaborators/alice/permission"): FakeResponse(200, '{"permission":"write"}')}
        )
        self.assertEqual(value.get_user_permission("alice"), "write")
        with self.assertRaises(gh.GitHubError):
            value.get_user_permission("../bad")

    def test_fine_grained_permission_403_is_not_treated_as_write(self):
        value = client(
            {
                ("GET", "/repos/o/r/collaborators/alice/permission"): FakeResponse(
                    403, '{"message":"Resource not accessible by personal access token"}'
                )
            }
        )
        with self.assertRaises(gh.GitHubAuthError):
            value.get_user_permission("alice")

    def test_repository_identity_detects_transfer_and_reports_owner_type(self):
        user_repo = {
            "full_name": "o/r",
            "default_branch": "main",
            "owner": {"login": "alice", "type": "User"},
        }
        value = client({("GET", "/repos/o/r"): FakeResponse(200, json.dumps(user_repo))})
        identity = value.get_repository_identity()
        self.assertEqual(identity["owner_login"], "alice")
        self.assertEqual(identity["owner_type"], "User")

        org_repo = {**user_repo, "owner": {"login": "o", "type": "Organization"}}
        value = client({("GET", "/repos/o/r"): FakeResponse(200, json.dumps(org_repo))})
        self.assertEqual(value.get_repository_identity()["owner_type"], "Organization")

        moved = {**user_repo, "full_name": "someone-else/r"}
        value = client({("GET", "/repos/o/r"): FakeResponse(200, json.dumps(moved))})
        with self.assertRaises(gh.GitHubError) as caught:
            value.get_repository_identity()
        self.assertEqual(caught.exception.code, "repository_identity_changed")


class ArgoAnalysisTests(unittest.TestCase):
    def _snapshot(self, app_source, project=None, path="gitops/argocd/application.yaml"):
        documents = [
            {
                "apiVersion": "argoproj.io/v1alpha1",
                "kind": "Application",
                "metadata": {"name": "demo", "namespace": "argocd"},
                "spec": {"source": app_source},
            }
        ]
        if project is not None:
            documents.append(
                {
                    "apiVersion": "argoproj.io/v1alpha1",
                    "kind": "AppProject",
                    "metadata": {"name": "demo", "namespace": "argocd"},
                    "spec": {"description": project},
                }
            )
        import yaml

        return snapshot(
            argo={path: yaml.safe_dump_all(documents).encode("utf-8")},
            entries={path: gh.TreeEntry(path, "100644", "blob", "a" * 40, 1)},
        )

    def test_source_change_is_explicit_block_signal(self):
        base = self._snapshot({"repoURL": "https://github.com/o/r", "path": "gitops/demo", "targetRevision": "main"})
        head = self._snapshot({"repoURL": "https://github.com/evil/r", "path": "gitops/demo", "targetRevision": "main"})
        result = gh.analyze_argo(base, head, ["gitops/argocd/application.yaml"])
        self.assertTrue(result.argo_source_changed)
        self.assertTrue(result.argo_application_changed)
        self.assertFalse(result.argo_manifest_error)

    def test_project_change_is_review_signal(self):
        base = self._snapshot({"repoURL": "https://github.com/o/r", "path": "x"}, project="old")
        head = self._snapshot({"repoURL": "https://github.com/o/r", "path": "x"}, project="new")
        result = gh.analyze_argo(base, head, ["gitops/argocd/project.yaml"])
        self.assertTrue(result.argo_project_changed)
        self.assertFalse(result.argo_source_changed)

    def test_invalid_argo_manifest_is_reported_not_ignored(self):
        base = snapshot()
        head = snapshot(argo={"gitops/argocd/application.yaml": b"kind: [broken"}, entries={})
        result = gh.analyze_argo(base, head, ["gitops/argocd/application.yaml"])
        self.assertTrue(result.argo_manifest_error)


if __name__ == "__main__":
    unittest.main()
