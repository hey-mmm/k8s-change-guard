from __future__ import annotations

import json
import unittest

from change_guard import postdeploy


NOW = 1_800_000_000
SHA = "b" * 40
IMAGE = "ghcr.io/hey-mmm/observability-demo@sha256:" + "a" * 64
POD_IMAGE_ID = "docker-pullable://ghcr.io/hey-mmm/observability-demo@sha256:" + "a" * 64


def config():
    return {
        "namespace": "demo",
        "deployment": "demo",
        "argocd_namespace": "argocd",
        "argo_application": "demo",
        "demo_url": "http://10.104.233.119:8080",
        "version_path": "/version",
        "ready_path": "/readyz",
        "container_name": "demo",
        "pod_label_selector": "app.kubernetes.io/name=demo,app.kubernetes.io/instance=demo",
        "allowed_image_repository": "ghcr.io/hey-mmm/observability-demo",
        "require_digest": True,
        "require_pod_image_id": True,
        "strict_image_id_digest": False,
        "postdeploy_timeout_seconds": 2,
        "postdeploy_poll_seconds": 1,
        "observation_seconds": 0,
        "max_error_ratio": 0.05,
        "max_p95_seconds": 0.5,
        "min_request_rate": 0.1,
        "kubectl": "/usr/bin/kubectl",
        "kubeconfig": "/etc/change-guard/kubeconfig",
        "use_proxy_env": False,
    }


def argo(revision=SHA, sync="Synced", health="Healthy", phase="Succeeded"):
    return {
        "metadata": {"name": "demo", "namespace": "argocd"},
        "status": {
            "sync": {"revision": revision, "status": sync},
            "health": {"status": health},
            "operationState": {"phase": phase},
        },
    }


def deployment(image=IMAGE, replicas=1, ready=1):
    return {
        "metadata": {"name": "demo", "namespace": "demo", "generation": 2},
        "spec": {"replicas": replicas, "template": {"spec": {"containers": [{"name": "demo", "image": image}]}}},
        "status": {
            "observedGeneration": 2,
            "updatedReplicas": ready,
            "readyReplicas": ready,
            "availableReplicas": ready,
        },
    }


def pods(image_id=POD_IMAGE_ID, ready=True):
    return {
        "items": [
            {
                "metadata": {"name": "demo-abc", "namespace": "demo"},
                "spec": {"nodeName": "worker"},
                "status": {
                    "phase": "Running",
                    "conditions": [{"type": "Ready", "status": "True" if ready else "False"}],
                    "containerStatuses": [
                        {"name": "demo", "ready": ready, "image": IMAGE, "imageID": image_id}
                    ],
                },
            }
        ]
    }


def endpoints(ready=True):
    return {
        "subsets": [
            {
                "addresses": [{"ip": "10.244.0.10"}] if ready else [],
                "notReadyAddresses": [] if ready else [{"ip": "10.244.0.10"}],
            }
        ]
    }


def metrics(*, rate=1.0, error_ratio=0.0, p95=0.1, alerts=None, errors=None):
    return {
        "collected_at": NOW,
        "errors": list(errors or []),
        "metrics": {
            "request_rate": rate,
            "error_ratio": error_ratio,
            "p95_seconds": p95,
            "alerts": list(alerts or []),
        },
    }


class Runner:
    def __init__(self, *, argo_payload=None, deployment_payload=None, pods_payload=None, endpoints_payload=None):
        self.payloads = {
            "application": argo_payload or argo(),
            "deployment": deployment_payload or deployment(),
            "pods": pods_payload or pods(),
            "endpoints": endpoints_payload or endpoints(),
        }
        self.calls = []

    def __call__(self, args, timeout):
        self.calls.append((list(args), timeout))
        for name, payload in self.payloads.items():
            if name in args:
                return payload
        raise AssertionError(f"unexpected kubectl arguments: {args}")


def http_get(path, timeout):
    if path == "/version":
        return 200, json.dumps({"gitSha": SHA, "version": "1.0"}).encode()
    if path == "/readyz":
        return 200, b"ok"
    raise AssertionError(f"unexpected path {path}")


class Clock:
    def __init__(self):
        self.value = NOW

    def __call__(self):
        self.value += 1
        return self.value


class ValidationTests(unittest.TestCase):
    def test_valid_config_and_url_image_rules(self):
        cfg = postdeploy.validate_config(config())
        self.assertEqual(cfg["namespace"], "demo")
        self.assertEqual(cfg["ready_path"], "/readyz")
        self.assertEqual(cfg["container_name"], "demo")

        broken = config()
        broken["demo_url"] = "http://user:password@example.invalid"
        with self.assertRaises(postdeploy.PostDeploySetupError):
            postdeploy.validate_config(broken)
        broken = config()
        broken["version_path"] = "/../etc/passwd"
        with self.assertRaises(postdeploy.PostDeploySetupError):
            postdeploy.validate_config(broken)
        broken = config()
        broken["allowed_image_repository"] = "ghcr.io/other/demo"
        with self.assertRaises(postdeploy.PostDeploySetupError):
            postdeploy._validate_expected_image(IMAGE, broken)
        with self.assertRaises(postdeploy.PostDeploySetupError):
            postdeploy._validate_expected_image("ghcr.io/hey-mmm/observability-demo:latest", config())
        self.assertEqual(
            postdeploy._validate_expected_image(IMAGE, config()),
            IMAGE,
        )

    def test_postdeploy_redacts_secret_like_keys(self):
        value = postdeploy._redact(
            {"kubeconfig": "apiVersion: v1", "nested": {"token": "x"}, "normal": "ok"}
        )
        self.assertEqual(value["kubeconfig"], "<redacted>")
        self.assertEqual(value["nested"]["token"], "<redacted>")
        self.assertEqual(value["normal"], "ok")


class ReadOnlyKubectlTests(unittest.TestCase):
    def test_only_gets_with_json_are_accepted(self):
        postdeploy._assert_read_only_kubectl_args(
            ["-n", "demo", "get", "deployment", "demo", "-o", "json"]
        )
        for args in (
            ["-n", "demo", "delete", "deployment", "demo", "-o", "json"],
            ["-n", "demo", "get", "secrets", "-o", "json"],
            ["-n", "demo", "get", "pods/log", "-o", "json"],
            ["-n", "demo", "get", "pods", "-o", "yaml"],
            ["get", "pods", "--token=secret", "-o", "json"],
            ["config", "view", "-o", "json"],
        ):
            with self.assertRaises(postdeploy.PostDeploySetupError):
                postdeploy._assert_read_only_kubectl_args(args)


class CheckTests(unittest.TestCase):
    def test_argo_checks_sync_health_and_revision(self):
        result = postdeploy._check_argo(config(), SHA, lambda args, timeout: argo())
        self.assertEqual(result["status"], "pass")
        failed = postdeploy._check_argo(
            config(), SHA, lambda args, timeout: argo(revision="c" * 40, sync="OutOfSync", health="Degraded")
        )
        self.assertEqual(failed["status"], "fail")
        self.assertIn("revision", failed["detail"])
        self.assertIn("OutOfSync", failed["detail"])

    def test_deployment_checks_image_and_replicas(self):
        result = postdeploy._check_deployment(config(), SHA, IMAGE, lambda args, timeout: deployment())
        self.assertEqual(result["status"], "pass")
        failed = postdeploy._check_deployment(
            config(), SHA, IMAGE, lambda args, timeout: deployment(image="other", ready=0)
        )
        self.assertEqual(failed["status"], "fail")
        self.assertIn("image", failed["detail"])

    def test_pods_check_readiness_and_multiarch_caveat(self):
        result = postdeploy._check_pods(config(), IMAGE, lambda args, timeout: pods())
        self.assertEqual(result["status"], "pass")
        caveat = postdeploy._check_pods(
            config(),
            IMAGE,
            lambda args, timeout: pods(image_id="docker-pullable://ghcr.io/hey-mmm/observability-demo@sha256:" + "d" * 64),
        )
        self.assertEqual(caveat["status"], "pass")
        self.assertTrue(caveat["evidence"]["digest_caveats"])
        strict = config()
        strict["strict_image_id_digest"] = True
        failed = postdeploy._check_pods(
            strict,
            IMAGE,
            lambda args, timeout: pods(image_id="docker-pullable://ghcr.io/hey-mmm/observability-demo@sha256:" + "d" * 64),
        )
        self.assertEqual(failed["status"], "fail")
        not_ready = postdeploy._check_pods(config(), IMAGE, lambda args, timeout: pods(ready=False))
        self.assertEqual(not_ready["status"], "fail")

    def test_endpoints_require_a_ready_address(self):
        self.assertEqual(
            postdeploy._check_endpoints(config(), lambda args, timeout: endpoints())["status"],
            "pass",
        )
        self.assertEqual(
            postdeploy._check_endpoints(config(), lambda args, timeout: endpoints(False))["status"],
            "fail",
        )

    def test_http_checks_provenance_and_readiness(self):
        result = postdeploy._check_http(config(), SHA, http_get)
        self.assertEqual(result["status"], "pass")

        def wrong_version(path, timeout):
            return 200, json.dumps({"gitSha": "c" * 40}).encode()

        failed = postdeploy._check_http(config(), SHA, wrong_version)
        self.assertEqual(failed["status"], "fail")
        self.assertIn("gitSha", failed["detail"])

        def missing_ready(path, timeout):
            return (200, json.dumps({"gitSha": SHA}).encode()) if path == "/version" else (404, b"no")

        self.assertEqual(postdeploy._check_http(config(), SHA, missing_ready)["status"], "fail")

    def test_metrics_require_positive_traffic_and_bounded_slo(self):
        result = postdeploy._check_metrics(config(), lambda cfg: metrics(), observation_seconds=0)
        self.assertEqual(result["status"], "pass")
        for payload in (
            metrics(rate=0.0),
            metrics(error_ratio=0.5),
            metrics(p95=2.0),
            metrics(alerts=[{"name": "HighErrorRate", "state": "firing", "labels": {"namespace": "demo"}}]),
            metrics(errors=["prometheus query failed"]),
        ):
            failed = postdeploy._check_metrics(config(), lambda cfg, payload=payload: payload, observation_seconds=0)
            self.assertEqual(failed["status"], "fail", payload)


class VerifyDeploymentTests(unittest.TestCase):
    def test_ok_report_contains_all_checks(self):
        result = postdeploy.verify_deployment(
            config(),
            SHA,
            IMAGE,
            kubectl_runner=Runner(),
            http_get=http_get,
            metrics_provider=lambda cfg: metrics(),
            clock=Clock(),
            sleep=lambda seconds: None,
        )
        self.assertEqual(result["status"], "ok")
        self.assertEqual(
            [item["name"] for item in result["checks"]],
            ["argo", "deployment", "pods", "endpoints", "http_version", "metrics"],
        )
        self.assertIsNone(result["recommendation"])
        self.assertEqual(result["expected_image"], IMAGE)

    def test_failure_returns_revert_recommendation_without_mutation(self):
        runner = Runner(deployment_payload=deployment(ready=0))
        result = postdeploy.verify_deployment(
            config(),
            SHA,
            IMAGE,
            kubectl_runner=runner,
            http_get=http_get,
            metrics_provider=lambda cfg: metrics(),
            clock=Clock(),
            sleep=lambda seconds: None,
        )
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["recommendation"]["action"], "open_revert_pr")
        self.assertIn("deployment", result["recommendation"]["failing_checks"])
        self.assertIn("read-only", result["recommendation"]["note"])
        self.assertTrue(all(call[0][2] == "get" for call in runner.calls))
        self.assertTrue(any(call[0][:2] == ["-n", "demo"] for call in runner.calls))

    def test_metrics_failure_is_reported(self):
        result = postdeploy.verify_deployment(
            config(),
            SHA,
            IMAGE,
            kubectl_runner=Runner(),
            http_get=http_get,
            metrics_provider=lambda cfg: metrics(rate=0.0),
            clock=Clock(),
            sleep=lambda seconds: None,
        )
        self.assertEqual(result["status"], "failed")
        self.assertIn("metrics", result["recommendation"]["failing_checks"])

    def test_setup_errors_are_fail_closed(self):
        result = postdeploy.verify_deployment(config(), "not-a-sha", IMAGE)
        self.assertEqual(result["status"], "error")
        result = postdeploy.verify_deployment(config(), SHA, "ghcr.io/hey-mmm/observability-demo:latest")
        self.assertEqual(result["status"], "error")

    def test_expected_image_from_report(self):
        report = {"deployment_images": [{"container": "demo", "init": False, "image": IMAGE}]}
        self.assertEqual(postdeploy.expected_image_from_report(report, config()), IMAGE)
        with self.assertRaises(postdeploy.PostDeploySetupError):
            postdeploy.expected_image_from_report({"deployment_images": []}, config())


if __name__ == "__main__":
    unittest.main()
