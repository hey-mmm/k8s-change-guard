"""Read-only evidence collector tests using mocked subprocess/HTTP boundaries."""

from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from change_guard import evidence


def node_payload(*, ready=True):
    return {
        "items": [
            {
                "metadata": {"name": "worker-1", "labels": {}},
                "spec": {},
                "status": {
                    "conditions": [{"type": "Ready", "status": "True" if ready else "False"}],
                    "allocatable": {"cpu": "4", "memory": "8Gi"},
                    "capacity": {"cpu": "4", "memory": "8Gi"},
                },
            }
        ]
    }


def deployment_payload():
    return {
        "metadata": {"name": "demo", "namespace": "demo"},
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": {"app": "demo"}},
            "strategy": {"type": "RollingUpdate", "rollingUpdate": {"maxSurge": 1, "maxUnavailable": 0}},
            "template": {
                "spec": {
                    "containers": [
                        {
                            "name": "demo",
                            "image": "ghcr.io/hey-mmm/observability-demo@sha256:" + "a" * 64,
                            "resources": {
                                "requests": {"cpu": "50m", "memory": "64Mi"},
                                "limits": {"cpu": "250m", "memory": "192Mi"},
                            },
                            "env": [{"name": "SECRET_VALUE", "value": "LEAKME"}],
                        }
                    ]
                }
            },
        },
        "status": {"readyReplicas": 1, "availableReplicas": 1, "updatedReplicas": 1},
    }


def pod_payload():
    return {
        "items": [
            {
                "metadata": {
                    "name": "demo-old",
                    "namespace": "demo",
                    "ownerReferences": [{"kind": "ReplicaSet", "name": "demo-abc"}],
                },
                "spec": {
                    "nodeName": "worker-1",
                    "containers": [
                        {
                            "name": "demo",
                            "image": "demo",
                            "resources": {
                                "requests": {"cpu": "50m", "memory": "64Mi"},
                                "limits": {"cpu": "250m", "memory": "192Mi"},
                            },
                            "env": [{"name": "SECRET_VALUE", "value": "LEAKME"}],
                        }
                    ],
                    "initContainers": [
                        {
                            "name": "init",
                            "resources": {"requests": {"cpu": "100m", "memory": "16Mi"}},
                        }
                    ],
                    "overhead": {"cpu": "10m", "memory": "1Mi"},
                },
                "status": {
                    "phase": "Running",
                    "conditions": [{"type": "Ready", "status": "True"}],
                    "containerStatuses": [{"restartCount": 0}],
                },
            }
        ]
    }


def query_payload(value, timestamp, result_type="vector"):
    if result_type == "vector":
        result = [{"metric": {"pod": "demo-old"}, "value": [timestamp, str(value)]}]
    elif result_type == "scalar":
        result = {"value": [timestamp, str(value)]}
    else:
        result = []
    return {"status": "success", "data": {"resultType": result_type, "result": result}}


def empty_vector():
    return {"status": "success", "data": {"resultType": "vector", "result": []}}


EMPTY = empty_vector()


def config_for(temp: Path):
    kube = temp / "kubeconfig"
    kube.write_text("apiVersion: v1\n", encoding="utf-8")
    return {
        "kubectl": "/usr/bin/kubectl",
        "kubeconfig": str(kube),
        "namespace": "demo",
        "deployment": "demo",
        "prometheus_url": "http://prometheus.example:9090",
        "kubectl_timeout_seconds": 5,
        "prometheus_timeout_seconds": 5,
        "evidence_ttl_seconds": 300,
    }


class CollectorTests(unittest.TestCase):
    def test_collects_metrics_capacity_and_fixed_read_only_commands(self) -> None:
        now = int(time.time())
        calls = []

        def fake_kubectl(args, config, home, *, max_bytes, timeout):
            calls.append(list(args))
            if args[0] == "get" and args[1] == "nodes":
                return node_payload(), None
            if args[0] == "get" and args[1] == "pods":
                return pod_payload(), None
            return deployment_payload(), None

        def fake_query(session, base_url, expression, *, timeout, max_bytes):
            if "timestamp(" in expression:
                if "timestamp(up" in expression or "timestamp(container_memory" in expression:
                    return query_payload(now - 5, now - 5)
                if "timestamp(demo_http_requests_total" in expression:
                    return query_payload(now - 5, now - 5)
                return query_payload(now - 5, now - 5)
            if "max(up{" in expression:
                return query_payload(1, now - 5)
            if "container_memory_working_set_bytes" in expression:
                # Deliberately stale evaluation timestamp; source timestamp
                # must come from timestamp(raw memory series) above.
                return query_payload(100 * 1024 * 1024, now - 50)
            if 'status=~"5.."' in expression:
                return query_payload(0.1, now - 40)
            if "histogram_quantile" in expression:
                return query_payload(0.2, now - 40)
            return query_payload(2.5, now - 40)

        with tempfile.TemporaryDirectory() as temp:
            config = config_for(Path(temp))
            with mock.patch.object(evidence, "_run_kubectl", side_effect=fake_kubectl), mock.patch.object(
                evidence, "_prom_query", side_effect=fake_query
            ), mock.patch.object(evidence, "_prom_alerts", return_value=[]):
                result = evidence.collect(config)

        self.assertEqual(result["errors"], [])
        self.assertEqual(result["metrics"]["request_rate"], 2.5)
        self.assertAlmostEqual(result["metrics"]["error_ratio"], 0.04)
        self.assertEqual(result["metrics"]["p95_seconds"], 0.2)
        self.assertEqual(result["metrics"]["memory_working_set_bytes"], 100 * 1024 * 1024)
        self.assertEqual(result["capacity"]["workers_ready"], 1)
        self.assertEqual(result["capacity"]["existing_pods_requests_cpu_millicores"], 110.0)
        queries = result["sources"]["prometheus"]["queries"]
        self.assertIn("max_over_time", queries["memory_working_set_bytes"]["expr"])
        self.assertIn("15m", queries["memory_working_set_bytes"]["expr"])
        self.assertIn("rate(", queries["request_rate"]["expr"])
        self.assertIn("5m", queries["request_rate"]["expr"])
        self.assertIn("histogram_quantile", queries["p95_seconds"]["expr"])
        self.assertEqual(len(result["sources"]["prometheus"]["raw"]), 9)
        self.assertEqual(result["metrics"]["up"], 1.0)
        self.assertEqual(
            result["metrics"]["series_presence"],
            {"up": True, "memory": True, "requests_total": True, "latency_bucket": True},
        )
        self.assertIn("timestamp(up", queries["up_source"]["expr"])
        self.assertIn("timestamp(demo_http_requests_total", queries["request_counter_source"]["expr"])
        self.assertIn("timestamp(demo_http_request_duration_seconds_bucket", queries["latency_bucket_source"]["expr"])
        self.assertEqual(result["metrics"]["source_timestamps"]["memory_working_set_bytes"], now - 5)
        self.assertEqual(result["metrics"]["source_timestamps"]["request_rate"], now - 5)
        self.assertEqual(result["metrics"]["source_timestamps"]["p95_seconds"], now - 5)
        self.assertNotIn("LEAKME", json.dumps(result))
        self.assertEqual(calls[0], ["get", "nodes", "-o", "json"])
        self.assertEqual(calls[1], ["-n", "demo", "get", "deployment", "demo", "-o", "json"])
        self.assertEqual(calls[2], ["get", "pods", "--all-namespaces", "-o", "json"])
        for command in result["sources"]["kubernetes"]["commands"]:
            self.assertEqual(command[0], "get" if command[0] == "get" else "-n")
            self.assertNotIn(command[0], {"apply", "delete", "exec", "logs", "patch"})

    def test_low_traffic_is_evidence_without_assuming_zero_health(self) -> None:
        now = int(time.time())

        def fake_kubectl(args, config, home, *, max_bytes, timeout):
            if args[0] == "get" and args[1] == "nodes":
                return node_payload(), None
            if args[0] == "get" and args[1] == "pods":
                return pod_payload(), None
            return deployment_payload(), None

        def fake_query(session, base_url, expression, *, timeout, max_bytes):
            if "timestamp(" in expression:
                return query_payload(now - 5, now - 5)
            if "max(up{" in expression:
                return query_payload(1, now - 5)
            if "container_memory_working_set_bytes" in expression:
                return query_payload(100 * 1024 * 1024, now - 5)
            return EMPTY

        with tempfile.TemporaryDirectory() as temp:
            with mock.patch.object(evidence, "_run_kubectl", side_effect=fake_kubectl), mock.patch.object(
                evidence, "_prom_query", side_effect=fake_query
            ), mock.patch.object(evidence, "_prom_alerts", return_value=[]):
                result = evidence.collect(config_for(Path(temp)))
        self.assertEqual(result["metrics"]["request_rate"], 0.0)
        self.assertIsNone(result["metrics"]["error_ratio"])
        self.assertIsNone(result["metrics"]["p95_seconds"])
        self.assertIn("request_rate", result["metrics"]["source_timestamps"])
        self.assertEqual(result["errors"], [])

    def test_nan_p95_at_zero_rate_with_fresh_histogram_is_not_error(self) -> None:
        now = int(time.time())

        def fake_kubectl(args, config, home, *, max_bytes, timeout):
            if args[0] == "get" and args[1] == "nodes":
                return node_payload(), None
            if args[0] == "get" and args[1] == "pods":
                return pod_payload(), None
            return deployment_payload(), None

        def fake_query(session, base_url, expression, *, timeout, max_bytes):
            if "timestamp(" in expression:
                return query_payload(now - 5, now - 5)
            if "max(up{" in expression:
                return query_payload(1, now - 5)
            if "container_memory_working_set_bytes" in expression:
                return query_payload(100 * 1024 * 1024, now - 5)
            if "histogram_quantile" in expression:
                return {
                    "status": "success",
                    "data": {
                        "resultType": "vector",
                        "result": [{"metric": {}, "value": [now - 5, "NaN"]}],
                    },
                }
            return EMPTY

        with tempfile.TemporaryDirectory() as temp:
            with mock.patch.object(evidence, "_run_kubectl", side_effect=fake_kubectl), mock.patch.object(
                evidence, "_prom_query", side_effect=fake_query
            ), mock.patch.object(evidence, "_prom_alerts", return_value=[]):
                result = evidence.collect(config_for(Path(temp)))
        self.assertEqual(result["errors"], [])
        self.assertEqual(result["metrics"]["request_rate"], 0.0)
        self.assertIsNone(result["metrics"]["p95_seconds"])
        self.assertTrue(result["metrics"]["series_presence"]["latency_bucket"])
        self.assertEqual(result["metrics"]["source_timestamps"]["p95_seconds"], now - 5)

    def test_query_failure_missing_or_stale_data_records_errors(self) -> None:
        now = int(time.time())

        def fake_kubectl(args, config, home, *, max_bytes, timeout):
            if args[0] == "get" and args[1] == "nodes":
                return node_payload(), None
            if args[0] == "get" and args[1] == "pods":
                return pod_payload(), None
            return deployment_payload(), None

        def failing_error_query(session, base_url, expression, *, timeout, max_bytes):
            if "timestamp(" in expression:
                return query_payload(now - 5, now - 5)
            if "max(up{" in expression:
                return query_payload(1, now - 5)
            if 'status=~"5.."' in expression:
                raise evidence.EvidenceError("error numerator query failed")
            if "container_memory_working_set_bytes" in expression:
                return query_payload(100 * 1024 * 1024, now - 5)
            return query_payload(2.5, now - 5)

        with tempfile.TemporaryDirectory() as temp:
            with mock.patch.object(evidence, "_run_kubectl", side_effect=fake_kubectl), mock.patch.object(
                evidence, "_prom_query", side_effect=failing_error_query
            ), mock.patch.object(evidence, "_prom_alerts", return_value=[]):
                result = evidence.collect(config_for(Path(temp)))
        self.assertIsNone(result["metrics"]["error_ratio"])
        self.assertTrue(any("error_numerator" in error for error in result["errors"]))

        def stale_memory(session, base_url, expression, *, timeout, max_bytes):
            if "container_memory_working_set_bytes" in expression:
                return query_payload(100 * 1024 * 1024, now - 400)
            return query_payload(2.5, now - 5)

        with tempfile.TemporaryDirectory() as temp:
            with mock.patch.object(evidence, "_run_kubectl", side_effect=fake_kubectl), mock.patch.object(
                evidence, "_prom_query", side_effect=stale_memory
            ), mock.patch.object(evidence, "_prom_alerts", return_value=[]):
                result = evidence.collect(config_for(Path(temp)))
        self.assertTrue(any("stale" in error for error in result["errors"]))

    def test_kubectl_failures_missing_workers_and_missing_capacity(self) -> None:
        def fake_kubectl(args, config, home, *, max_bytes, timeout):
            if args[0] == "get" and args[1] == "nodes":
                return node_payload(ready=False), None
            if args[0] == "get" and args[1] == "pods":
                return pod_payload(), None
            return deployment_payload(), None

        with tempfile.TemporaryDirectory() as temp:
            with mock.patch.object(evidence, "_run_kubectl", side_effect=fake_kubectl), mock.patch.object(
                evidence, "_prom_query", return_value=empty_vector()
            ), mock.patch.object(evidence, "_prom_alerts", return_value=[]):
                result = evidence.collect(config_for(Path(temp)))
        self.assertEqual(result["capacity"]["workers_ready"], 0)
        self.assertTrue(result["errors"])  # metrics are absent for this fixture

        failures = iter([(None, "kubectl exited 1: forbidden"), (None, "kubectl exited 1: forbidden"), (None, "kubectl exited 1: forbidden")])
        with tempfile.TemporaryDirectory() as temp:
            with mock.patch.object(evidence, "_run_kubectl", side_effect=lambda *a, **k: next(failures)), mock.patch.object(
                evidence, "_prom_query", return_value=empty_vector()
            ), mock.patch.object(evidence, "_prom_alerts", return_value=[]):
                result = evidence.collect(config_for(Path(temp)))
        self.assertTrue(result["errors"])
        self.assertEqual(result["capacity"], {})

    def test_prometheus_url_credentials_are_rejected_and_bounded_raw(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            config = config_for(Path(temp))
            config["prometheus_url"] = "http://user:pass@prometheus.example:9090"
            with mock.patch.object(evidence, "_run_kubectl", return_value=(None, "no cluster")), mock.patch.object(
                evidence, "_prom_alerts", return_value=[]
            ):
                result = evidence.collect(config)
        self.assertTrue(any("credentials" in error for error in result["errors"]))

        payload = {
            "status": "success",
            "data": {
                "resultType": "vector",
                "result": [{"metric": {"pod": f"p{i}"}, "value": [1, "1"]} for i in range(100)],
            },
        }
        raw = evidence._bounded_raw(payload)
        self.assertLessEqual(len(raw["data"]["result"]), 20)
        self.assertTrue(raw.get("_truncated"))

    def test_quantity_and_cpu_memory_parsing(self) -> None:
        self.assertEqual(evidence._cpu("250m"), 250.0)
        self.assertEqual(evidence._cpu("0.5"), 500.0)
        self.assertEqual(evidence._memory("1Gi"), 1024.0**3)
        self.assertEqual(evidence._memory("512Mi"), 512.0 * 1024 * 1024)
        self.assertIsNone(evidence._memory("NaN"))

    def test_fixed_command_builder_has_no_shell_and_uses_request_timeout(self) -> None:
        command = evidence._kubectl_command(
            {"kubectl": "/usr/bin/kubectl", "kubeconfig": "/etc/change-guard/kubeconfig"},
            ["get", "nodes", "-o", "json"],
        )
        self.assertEqual(command[0], "/usr/bin/kubectl")
        self.assertIn("--kubeconfig=/etc/change-guard/kubeconfig", command)
        self.assertIn("--request-timeout=20s", command)
        self.assertEqual(command[-4:], ["get", "nodes", "-o", "json"])
        self.assertNotIn("sh", command)
        self.assertNotIn("-c", command)


if __name__ == "__main__":
    unittest.main()
