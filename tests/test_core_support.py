"""Shared fixtures for the change_guard unit tests (no external cluster)."""

from __future__ import annotations

import copy
from typing import Any

NOW = 1_800_000_000
DIGEST = "sha256:" + "a" * 64
NEW_DIGEST = "sha256:" + "b" * 64
REPOSITORY = "ghcr.io/hey-mmm/observability-demo"
MI = 1024 * 1024


def base_deployment(*, digest: str = DIGEST) -> dict[str, Any]:
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": "demo",
            "namespace": "demo",
            "labels": {
                "app.kubernetes.io/name": "demo",
                "app.kubernetes.io/instance": "demo",
            },
        },
        "spec": {
            "replicas": 1,
            "revisionHistoryLimit": 3,
            "strategy": {
                "type": "RollingUpdate",
                "rollingUpdate": {"maxUnavailable": 0, "maxSurge": 1},
            },
            "selector": {
                "matchLabels": {
                    "app.kubernetes.io/name": "demo",
                    "app.kubernetes.io/instance": "demo",
                }
            },
            "template": {
                "metadata": {
                    "labels": {
                        "app.kubernetes.io/name": "demo",
                        "app.kubernetes.io/instance": "demo",
                    },
                    "annotations": {"demo/version": "baseline"},
                },
                "spec": {
                    "automountServiceAccountToken": False,
                    "terminationGracePeriodSeconds": 20,
                    "securityContext": {
                        "runAsNonRoot": True,
                        "runAsUser": 10001,
                        "runAsGroup": 10001,
                        "fsGroup": 10001,
                        "seccompProfile": {"type": "RuntimeDefault"},
                    },
                    "containers": [
                        {
                            "name": "demo-service",
                            "image": f"{REPOSITORY}@{digest}",
                            "imagePullPolicy": "IfNotPresent",
                            "ports": [{"name": "http", "containerPort": 8080, "protocol": "TCP"}],
                            "env": [
                                {"name": "APP_VERSION", "value": "0.1.0"},
                                {"name": "GIT_SHA", "value": "c0bff8abf5625903e5b9b19b586e9660b9fe7a8c"},
                                {"name": "TMPDIR", "value": "/tmp"},
                                {"name": "APP_ENV", "value": "production"},
                                {"name": "DEMO_ERROR_RATE", "value": "0"},
                                {"name": "DEMO_LATENCY_MS", "value": "0"},
                                {"name": "DEMO_STARTUP_FAIL", "value": "false"},
                            ],
                            "livenessProbe": {
                                "httpGet": {"path": "/healthz", "port": "http"},
                                "initialDelaySeconds": 5,
                                "periodSeconds": 10,
                                "timeoutSeconds": 2,
                                "failureThreshold": 3,
                            },
                            "readinessProbe": {
                                "httpGet": {"path": "/readyz", "port": "http"},
                                "initialDelaySeconds": 2,
                                "periodSeconds": 5,
                                "timeoutSeconds": 2,
                                "failureThreshold": 3,
                            },
                            "startupProbe": {
                                "httpGet": {"path": "/healthz", "port": "http"},
                                "periodSeconds": 2,
                                "timeoutSeconds": 2,
                                "failureThreshold": 30,
                            },
                            "resources": {
                                "requests": {"cpu": "50m", "memory": "64Mi"},
                                "limits": {"cpu": "250m", "memory": "192Mi"},
                            },
                            "securityContext": {
                                "allowPrivilegeEscalation": False,
                                "privileged": False,
                                "readOnlyRootFilesystem": True,
                                "runAsNonRoot": True,
                                "runAsUser": 10001,
                                "capabilities": {"drop": ["ALL"]},
                            },
                            "volumeMounts": [{"name": "tmp", "mountPath": "/tmp"}],
                        }
                    ],
                    "volumes": [{"name": "tmp", "emptyDir": {"sizeLimit": "16Mi"}}],
                },
            },
        },
    }


def base_service() -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": "demo", "namespace": "demo"},
        "spec": {
            "type": "ClusterIP",
            "selector": {
                "app.kubernetes.io/name": "demo",
                "app.kubernetes.io/instance": "demo",
            },
            "ports": [{"name": "http", "port": 8080, "targetPort": "http", "protocol": "TCP"}],
        },
    }


def base_resources(*, digest: str = DIGEST) -> list[dict[str, Any]]:
    return [base_deployment(digest=digest), base_service()]


def base_config(**overrides: Any) -> dict[str, Any]:
    config: dict[str, Any] = {
        "namespace": "demo",
        "deployment": "demo",
        "allowed_image_repository": REPOSITORY,
        "require_digest": True,
        "evidence_ttl_seconds": 300,
        "ai_required": False,
        "allow_pre_rendered": False,
    }
    config.update(overrides)
    return config


def base_evidence(
    *,
    now: int = NOW,
    request_rate: float = 1.0,
    error_ratio: float | None = 0.0,
    p95: float | None = 0.1,
    memory: float | None = 100 * MI,
    available_cpu_millicores: float = 4000,
    available_memory_bytes: float = 4096 * MI,
    workers_ready: int = 1,
    errors: list[str] | None = None,
    collected_at: int | None = None,
    timestamps: dict[str, float] | None = None,
    alerts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    source_timestamps = {
        "memory_working_set_bytes": now - 5,
        "request_rate": now - 5,
        "error_ratio": now - 5,
        "p95_seconds": now - 5,
        "alerts": now - 5,
        "up": now - 5,
    }
    if timestamps:
        source_timestamps.update(timestamps)
    return {
        "collected_at": now - 10 if collected_at is None else collected_at,
        "errors": list(errors or []),
        "nodes": [],
        "deployment": {
            "namespace": "demo",
            "name": "demo",
            "replicas": 1,
            "ready_replicas": 1,
            "available_replicas": 1,
            "updated_replicas": 1,
            "containers": [
                {
                    "name": "demo-service",
                    "image": f"{REPOSITORY}@{DIGEST}",
                    "resources": {
                        "requests": {"cpu": "50m", "memory": "64Mi"},
                        "limits": {"cpu": "250m", "memory": "192Mi"},
                    },
                }
            ],
        },
        "pods": [],
        "metrics": {
            "memory_working_set_bytes": memory,
            "request_rate": request_rate,
            "error_ratio": error_ratio,
            "p95_seconds": p95,
            "up": 1.0,
            "series_presence": {
                "up": True,
                "memory": True,
                "requests_total": True,
                "latency_bucket": True,
            },
            "alerts": [] if alerts is None else alerts,
            "source_timestamps": source_timestamps,
        },
        "capacity": {
            "available_cpu_millicores": available_cpu_millicores,
            "available_memory_bytes": available_memory_bytes,
            "workers_ready": workers_ready,
        },
        "sources": {
            "prometheus": {
                "url": "http://prometheus.invalid:9090",
                "queries": {"memory_working_set_bytes": {"expr": "max_over_time(...[15m:])"}},
            }
        },
    }


def base_context(*, now: int = NOW, tree_changes: list[str] | None = None) -> dict[str, Any]:
    context: dict[str, Any] = {
        "evaluated_at": now,
        "pr_number": 42,
        "head_sha": "1" * 40,
        "base_sha": "2" * 40,
    }
    if tree_changes is not None:
        context["tree_changes"] = tree_changes
    return context


def ai_ok(*, risks: list[dict[str, str]] | None = None) -> dict[str, Any]:
    return {
        "status": "ok",
        "model": "deepseek-chat",
        "summary": "No additional concerns beyond the deterministic rules.",
        "additional_risks": list(risks or []),
        "citations": [],
    }


def clone(value: Any) -> Any:
    return copy.deepcopy(value)
