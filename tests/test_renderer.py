"""Renderer security, fixture, and bounded-input tests (no Helm required)."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

from change_guard import renderer
from change_guard.renderer import RenderError, load_rendered_manifests, render_tree


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def make_tree(root: Path) -> None:
    _write(root / "charts/demo/Chart.yaml", "apiVersion: v2\nname: demo\nversion: 0.1.0\n")
    _write(
        root / "charts/demo/templates/deployment.yaml",
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: demo\n",
    )
    _write(root / "gitops/demo/values.yaml", "replicaCount: 1\n")


RENDERED = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo
  namespace: demo
spec:
  replicas: 1
---
apiVersion: v1
kind: Service
metadata:
  name: demo
  namespace: demo
"""


class LoadedManifestTests(unittest.TestCase):
    def test_loads_valid_multi_document_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "rendered.yaml"
            path.write_text(RENDERED, encoding="utf-8")
            resources = load_rendered_manifests(path, {})
            self.assertEqual([item["kind"] for item in resources], ["Deployment", "Service"])

    def test_flattens_list_and_rejects_missing_name(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "rendered.yaml"
            path.write_text(
                "apiVersion: v1\nkind: List\nitems:\n"
                "  - apiVersion: v1\n    kind: Service\n    metadata:\n      name: demo\n",
                encoding="utf-8",
            )
            resources = load_rendered_manifests(path, {})
            self.assertEqual(len(resources), 1)
            path.write_text("apiVersion: v1\nkind: Service\nmetadata: {}\n", encoding="utf-8")
            with self.assertRaises(RenderError):
                load_rendered_manifests(path, {})

    def test_duplicate_yaml_keys_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "rendered.yaml"
            path.write_text(
                "apiVersion: v1\nkind: Service\nmetadata:\n  name: one\n  name: two\n",
                encoding="utf-8",
            )
            with self.assertRaises(RenderError) as raised:
                load_rendered_manifests(path, {})
            self.assertEqual(raised.exception.code, "invalid_yaml")

    def test_directory_and_symlink_inputs_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with self.assertRaises(RenderError):
                load_rendered_manifests(root, {})
            target = root / "real.yaml"
            target.write_text(RENDERED, encoding="utf-8")
            link = root / "link.yaml"
            try:
                link.symlink_to(target)
            except OSError:
                self.skipTest("symlink creation is not permitted on this platform")
            with self.assertRaises(RenderError) as raised:
                load_rendered_manifests(link, {})
            self.assertEqual(raised.exception.code, "symlink_not_permitted")

    def test_nonfinite_and_oversized_documents_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "rendered.yaml"
            path.write_text(
                "apiVersion: v1\nkind: Service\nmetadata:\n  name: demo\n"
                "spec:\n  clusterIP: .nan\n",
                encoding="utf-8",
            )
            with self.assertRaises(RenderError):
                load_rendered_manifests(path, {})
            path.write_text(RENDERED * 500, encoding="utf-8")
            with self.assertRaises(RenderError) as raised:
                load_rendered_manifests(path, {"render_output_limit_bytes": 1024})
            self.assertEqual(raised.exception.code, "input_too_large")

    def test_fixture_mode_requires_explicit_allow(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "rendered.yaml"
            path.write_text(RENDERED, encoding="utf-8")
            with self.assertRaises(RenderError) as raised:
                render_tree(path, {})
            self.assertIn(raised.exception.code, {"bwrap_required", "bwrap_missing", "tree_missing"})
            resources = render_tree(
                path,
                {"allow_pre_rendered": True, "fixture_mode": True, "pre_rendered": path},
            )
            self.assertEqual(len(resources), 2)


class ProductionPathTests(unittest.TestCase):
    def test_renderer_requires_linux_bubblewrap_without_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            make_tree(root)
            with mock.patch.object(renderer, "_is_linux", return_value=False):
                with self.assertRaises(RenderError) as raised:
                    render_tree(root, {})
            self.assertEqual(raised.exception.code, "bwrap_required")

    def test_linux_missing_bwrap_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            make_tree(root)
            with mock.patch.object(renderer, "_is_linux", return_value=True):
                with self.assertRaises(RenderError) as raised:
                    render_tree(root, {"bwrap": str(root / "missing-bwrap"), "helm": "/bin/true"})
            self.assertEqual(raised.exception.code, "bwrap_missing")

    def test_bwrap_command_has_hard_isolation_and_no_plugins(self) -> None:
        settings = renderer._validate_config(
            {"helm": "/usr/local/bin/helm", "bwrap": "/usr/bin/bwrap", "namespace": "demo"}
        )
        with tempfile.TemporaryDirectory() as temp:
            command = renderer._build_bwrap_command(settings, Path(temp))
        joined = " ".join(command)
        self.assertIn("--unshare-all", command)
        self.assertIn("--clearenv", command)
        self.assertIn("--cap-drop", command)
        self.assertIn("--die-with-parent", command)
        self.assertNotIn("--no-hooks", command)
        self.assertNotIn("--skip-tests", command)
        self.assertNotIn("--size", command)
        self.assertIn("--tmpfs", command)
        self.assertEqual(command[command.index("--tmpfs") + 1], "/tmp")
        self.assertIn("HELM_PLUGINS", command)
        self.assertNotIn("--share-net", command)
        self.assertNotIn("--post-renderer", command)
        self.assertNotIn("--dependency-update", command)
        self.assertNotIn("/home", joined)
        self.assertNotIn("/root", joined)
        self.assertIn("/work/chart", command)
        self.assertIn("/work/values.yaml", command)

    def test_render_copies_only_permitted_tree_and_parses_helm_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            make_tree(root)
            config = {
                "bwrap": "/usr/bin/bwrap",
                "helm": "/usr/local/bin/helm",
                "namespace": "demo",
            }
            with mock.patch.object(renderer, "_is_linux", return_value=True), mock.patch.object(
                renderer, "_require_sandbox"
            ), mock.patch.object(renderer, "_execute", return_value=(RENDERED, "")) as execute:
                resources = render_tree(root, config)
            self.assertEqual([item["kind"] for item in resources], ["Deployment", "Service"])
            self.assertTrue(execute.called)
            copied_command = execute.call_args.args[0]
            self.assertIn("template", copied_command)

    def test_render_rejects_extra_chart_entries(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            make_tree(root)
            (root / "charts/demo/charts").mkdir()
            with mock.patch.object(renderer, "_is_linux", return_value=True), mock.patch.object(
                renderer, "_require_sandbox"
            ):
                with self.assertRaises(RenderError) as raised:
                    render_tree(root, {})
            self.assertEqual(raised.exception.code, "unsupported_chart_entry")

    def test_render_rejects_symlinked_values_and_templates(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            make_tree(root)
            values = root / "gitops/demo/values.yaml"
            target = root / "outside-values.yaml"
            target.write_text("replicaCount: 2\n", encoding="utf-8")
            values.unlink()
            try:
                values.symlink_to(target)
            except OSError:
                self.skipTest("symlink creation is not permitted on this platform")
            with mock.patch.object(renderer, "_is_linux", return_value=True), mock.patch.object(
                renderer, "_require_sandbox"
            ):
                with self.assertRaises(RenderError) as raised:
                    render_tree(root, {})
            self.assertEqual(raised.exception.code, "symlink_not_permitted")

    def test_values_must_be_data_mapping_and_safe_yaml(self) -> None:
        cases = {
            "sequence": "- one\n- two\n",
            "python tag": "x: !!python/object/apply:os.system ['id']\n",
            "duplicate key": "replicaCount: 1\nreplicaCount: 2\n",
            "oversized": "x: " + "a" * (2 * 1024 * 1024 + 10) + "\n",
        }
        for name, text in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                make_tree(root)
                (root / "gitops/demo/values.yaml").write_text(text, encoding="utf-8")
                with mock.patch.object(renderer, "_is_linux", return_value=True), mock.patch.object(
                    renderer, "_require_sandbox"
                ):
                    with self.assertRaises(RenderError):
                        render_tree(root, {})

    def test_path_override_is_not_permitted(self) -> None:
        with self.assertRaises(RenderError) as raised:
            renderer._validate_config({"chart_rel_path": "charts/other"})
        self.assertEqual(raised.exception.code, "path_not_permitted")

    def test_output_size_and_document_limits(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            make_tree(root)
            huge = RENDERED + "\n# " + "x" * 5000
            with mock.patch.object(renderer, "_is_linux", return_value=True), mock.patch.object(
                renderer, "_require_sandbox"
            ), mock.patch.object(renderer, "_execute", return_value=(huge, "")):
                with self.assertRaises(RenderError) as raised:
                    render_tree(root, {"render_output_limit_bytes": 1024})
            self.assertEqual(raised.exception.code, "output_too_large")

    def test_no_shell_or_candidate_execution_surface(self) -> None:
        command = renderer._build_bwrap_command(
            renderer._validate_config({"helm": "/usr/local/bin/helm", "bwrap": "/usr/bin/bwrap"}),
            Path("."),
        )
        self.assertEqual(command[command.index("--") + 1], renderer.HELM_TARGET)
        self.assertIn("template", command)
        self.assertFalse(any(part in {"sh", "bash", "python", "python3"} for part in command))


    def test_hook_annotations_are_forbidden_even_when_rendered(self) -> None:
        hook_manifest = (
            RENDERED
            + "\n---\napiVersion: batch/v1\nkind: Job\nmetadata:\n  name: hidden-hook\n"
            "  namespace: demo\n  annotations:\n    helm.sh/hook: post-install\n"
            "spec:\n  template:\n    spec:\n      containers:\n"
            "        - name: evil\n          image: busybox\n"
        )
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            make_tree(root)
            with mock.patch.object(renderer, "_is_linux", return_value=True), mock.patch.object(
                renderer, "_require_sandbox"
            ), mock.patch.object(renderer, "_execute", return_value=(hook_manifest, "")):
                with self.assertRaises(RenderError) as raised:
                    render_tree(root, {})
        self.assertEqual(raised.exception.code, "hooks_forbidden")

    def test_dynamic_and_capability_templates_are_forbidden(self) -> None:
        for snippet in (
            "{{ .Capabilities.APIVersions.Has \"example.com/v1\" }}",
            "{{ lookup \"v1\" \"Service\" \"demo\" \"demo\" }}",
            "{{ tpl .Values.someTemplate . }}",
        ):
            with self.subTest(snippet=snippet), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                make_tree(root)
                (root / "charts/demo/templates/dynamic.yaml").write_text(
                    "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\n# " + snippet + "\n",
                    encoding="utf-8",
                )
                with mock.patch.object(renderer, "_is_linux", return_value=True), mock.patch.object(
                    renderer, "_require_sandbox"
                ):
                    with self.assertRaises(RenderError) as raised:
                        render_tree(root, {})
                self.assertEqual(raised.exception.code, "dynamic_template_forbidden")

    def test_helm_symlink_is_resolved_to_a_fixed_mount_path(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "real-helm"
            target.write_text("#!/bin/sh\n", encoding="utf-8")
            link = root / "helm-link"
            try:
                link.symlink_to(target)
            except OSError:
                self.skipTest("symlink creation is not permitted on this platform")
            settings = renderer._validate_config({"helm": str(link), "bwrap": "/usr/bin/bwrap"})
            command = renderer._build_bwrap_command(settings, root)
        self.assertIn("/guard-helm", command)
        self.assertIn(str(target.resolve()), command)


if __name__ == "__main__":
    unittest.main()
