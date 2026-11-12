"""Read-only Kubernetes and Prometheus evidence collection.

Only fixed ``kubectl get`` commands and fixed PromQL expressions are used.  There
is no shell, no arbitrary command execution, no ``exec``, no ``logs``, and no
write operation.  Kubeconfig credentials are passed to kubectl but never
included in the returned evidence.

The returned structure follows the implementation contract::

    {
      "collected_at": <unix seconds>,
      "errors": [...],
      "nodes": [...], "deployment": {...}, "pods": [...],
      "metrics": {
        "memory_working_set_bytes": <max_over_time 15m>,
        "request_rate": <rate 5m>,
        "error_ratio": <5m>, "p95_seconds": <5m>,
        "alerts": [...],
        "source_timestamps": {...}
      },
      "capacity": {
        "available_cpu_millicores": ..., "available_memory_bytes": ...
      },
      "sources": {...}
    }
"""

from __future__ import annotations

import json
import math
import os
import re
import shutil
import subprocess
import tempfile
import time
import hashlib
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit, urlunsplit

import requests

DEFAULT_KUBECTL_TIMEOUT_SECONDS = 20
DEFAULT_PROMETHEUS_TIMEOUT_SECONDS = 10
DEFAULT_MAX_RESPONSE_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_PROM_BYTES = 2 * 1024 * 1024
MAX_RAW_QUERY_BYTES = 32 * 1024
MAX_PODS = 2000
MAX_NODES = 500
MAX_ALERTS = 100
_EVIDENCE_VERSION = "1.0"
_CLOCK_SKEW_TOLERANCE_SECONDS = 120


class EvidenceError(RuntimeError):
    """Raised for invalid collector configuration (fail closed)."""


def _safe_name(value: str, field: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[a-z0-9]([-a-z0-9]*[a-z0-9])?", value) or len(value) > 63:
        raise EvidenceError(f"{field} is not a valid Kubernetes DNS label")
    return value


def _bounded_int(config: Mapping[str, Any], key: str, default: int, minimum: int, maximum: int) -> int:
    raw = config.get(key, default)
    if isinstance(raw, bool) or not isinstance(raw, int) or raw < minimum or raw > maximum:
        raise EvidenceError(f"{key} must be an integer between {minimum} and {maximum}")
    return raw


def _json_loads(text: str, *, source: str) -> Any:
    try:
        return json.loads(text)
    except (TypeError, ValueError) as exc:
        raise EvidenceError(f"{source} did not return valid JSON: {exc}") from exc


def _kubectl_command(config: Mapping[str, Any], args: Sequence[str]) -> list[str]:
    """Build a fixed, read-only kubectl invocation.

    ``args`` is deliberately not accepted from report/PR data; callers only use
    the module-level constants in :func:`collect`.
    """

    kubectl = str(config.get("kubectl", "/usr/bin/kubectl"))
    kubeconfig = str(config.get("kubeconfig", ""))
    timeout = _bounded_int(config, "kubectl_timeout_seconds", DEFAULT_KUBECTL_TIMEOUT_SECONDS, 1, 120)
    command = [kubectl]
    if kubeconfig:
        command.append(f"--kubeconfig={kubeconfig}")
    command.extend([f"--request-timeout={timeout}s"])
    command.extend(args)
    return command


def _kubectl_env(config: Mapping[str, Any], home: Path) -> dict[str, str]:
    kubeconfig = str(config.get("kubeconfig", ""))
    env = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": str(home),
        "XDG_CACHE_HOME": str(home / "cache"),
        "XDG_CONFIG_HOME": str(home / "config"),
        "LANG": "C",
        "LC_ALL": "C",
    }
    if kubeconfig:
        env["KUBECONFIG"] = kubeconfig
    return env


def _run_kubectl(
    args: Sequence[str],
    config: Mapping[str, Any],
    home: Path,
    *,
    max_bytes: int,
    timeout: int,
) -> tuple[Any | None, str | None]:
    kubectl = str(config.get("kubectl", "/usr/bin/kubectl"))
    if not kubectl:
        return None, "kubectl path is not configured"
    resolved = kubectl if os.path.isabs(kubectl) else shutil.which(kubectl)
    if not resolved:
        return None, "kubectl executable was not found"
    kubeconfig = str(config.get("kubeconfig", ""))
    if kubeconfig and not Path(kubeconfig).exists():
        return None, "kubeconfig file does not exist"
    command = _kubectl_command({**config, "kubectl": resolved}, args)
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
            env=_kubectl_env(config, home),
        )
    except subprocess.TimeoutExpired:
        return None, "kubectl timed out"
    except OSError as exc:
        return None, f"kubectl could not start: {exc}"
    stdout = completed.stdout or b""
    stderr = completed.stderr or b""
    if len(stdout) > max_bytes or len(stderr) > max_bytes:
        return None, "kubectl output exceeded the configured size limit"
    if completed.returncode != 0:
        message = stderr.decode("utf-8", errors="replace").strip().splitlines()
        detail = " ".join(message[-2:])[:600] if message else "no stderr"
        return None, f"kubectl exited {completed.returncode}: {detail}"
    try:
        text = stdout.decode("utf-8")
    except UnicodeDecodeError:
        return None, "kubectl returned non-UTF-8 output"
    try:
        return json.loads(text), None
    except ValueError as exc:
        return None, f"kubectl returned invalid JSON: {exc}"


def _prometheus_base_url(config: Mapping[str, Any]) -> str:
    raw = config.get("prometheus_url")
    if not isinstance(raw, str) or not raw.strip():
        raise EvidenceError("prometheus_url is not configured")
    parsed = urlsplit(raw.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise EvidenceError("prometheus_url must be an http(s) URL")
    if parsed.username is not None or parsed.password is not None:
        raise EvidenceError("prometheus_url must not contain credentials")
    if parsed.query or parsed.fragment:
        raise EvidenceError("prometheus_url must not contain a query or fragment")
    path = parsed.path.rstrip("/")
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def _prom_query(
    session: requests.Session,
    base_url: str,
    expression: str,
    *,
    timeout: int,
    max_bytes: int,
) -> dict[str, Any]:
    query_url = base_url + "/api/v1/query"
    response = session.get(
        query_url,
        params={"query": expression},
        timeout=(3, timeout),
        headers={"Accept": "application/json", "User-Agent": "change-guard-evidence/1"},
        allow_redirects=False,
        stream=True,
        verify=True,
    )
    if response.status_code != 200:
        raise EvidenceError(f"Prometheus returned HTTP {response.status_code}")
    content_length = response.headers.get("Content-Length")
    if content_length is not None:
        try:
            if int(content_length) > max_bytes:
                raise EvidenceError("Prometheus response exceeded the size limit")
        except ValueError:
            pass
    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_content(chunk_size=32 * 1024):
        if not chunk:
            continue
        total += len(chunk)
        if total > max_bytes:
            raise EvidenceError("Prometheus response exceeded the size limit")
        chunks.append(chunk)
    raw = b"".join(chunks)
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise EvidenceError(f"Prometheus returned invalid JSON: {exc}") from exc
    if not isinstance(payload, Mapping):
        raise EvidenceError("Prometheus returned a non-object response")
    if payload.get("status") != "success":
        raise EvidenceError(f"Prometheus query failed: {str(payload.get('error', 'unknown'))[:300]}")
    return payload


def _prom_alerts(
    session: requests.Session,
    base_url: str,
    *,
    timeout: int,
    max_bytes: int,
) -> list[dict[str, Any]]:
    alerts_url = base_url + "/api/v1/alerts"
    response = session.get(
        alerts_url,
        timeout=(3, timeout),
        headers={"Accept": "application/json", "User-Agent": "change-guard-evidence/1"},
        allow_redirects=False,
        stream=True,
        verify=True,
    )
    if response.status_code != 200:
        raise EvidenceError(f"Prometheus alerts endpoint returned HTTP {response.status_code}")
    total = 0
    chunks: list[bytes] = []
    for chunk in response.iter_content(chunk_size=32 * 1024):
        if not chunk:
            continue
        total += len(chunk)
        if total > max_bytes:
            raise EvidenceError("Prometheus alerts response exceeded the size limit")
        chunks.append(chunk)
    try:
        payload = json.loads(b"".join(chunks).decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise EvidenceError(f"Prometheus alerts returned invalid JSON: {exc}") from exc
    if not isinstance(payload, Mapping) or payload.get("status") != "success":
        raise EvidenceError("Prometheus alerts query failed")
    data = payload.get("data")
    raw_alerts = data.get("alerts") if isinstance(data, Mapping) else None
    if not isinstance(raw_alerts, list):
        raise EvidenceError("Prometheus alerts response has no alerts list")
    normalized: list[dict[str, Any]] = []
    for alert in raw_alerts[:MAX_ALERTS]:
        if not isinstance(alert, Mapping):
            continue
        labels = alert.get("labels") if isinstance(alert.get("labels"), Mapping) else {}
        safe_labels = {
            str(key): str(value)
            for key, value in labels.items()
            if str(key)
            in {
                "alertname",
                "namespace",
                "deployment",
                "app",
                "app_kubernetes_io_name",
                "severity",
                "job",
                "pod",
            }
        }
        normalized.append(
            {
                "name": str(safe_labels.get("alertname", "")),
                "state": str(alert.get("state", alert.get("status", "firing"))),
                "activeAt": alert.get("activeAt"),
                "labels": safe_labels,
            }
        )
    return normalized


def _prom_result_values(payload: Mapping[str, Any]) -> tuple[list[tuple[float, float]], str]:
    data = payload.get("data")
    if not isinstance(data, Mapping):
        raise EvidenceError("Prometheus response has no data object")
    result_type = str(data.get("resultType", ""))
    result = data.get("result")
    values: list[tuple[float, float]] = []
    if result_type == "vector" and isinstance(result, list):
        for series in result:
            if not isinstance(series, Mapping):
                continue
            pair = series.get("value")
            if isinstance(pair, list) and len(pair) == 2:
                timestamp = _float(pair[0])
                value = _float(pair[1])
                if timestamp is not None and value is not None:
                    values.append((timestamp, value))
    elif result_type == "scalar":
        pair = result.get("value") if isinstance(result, Mapping) else None
        if isinstance(pair, list) and len(pair) == 2:
            timestamp = _float(pair[0])
            value = _float(pair[1])
            if timestamp is not None and value is not None:
                values.append((timestamp, value))
    elif result_type == "matrix":
        result = result if isinstance(result, list) else []
        for series in result:
            if not isinstance(series, Mapping):
                continue
            points = series.get("values")
            if isinstance(points, list) and points:
                pair = points[-1]
                if isinstance(pair, list) and len(pair) == 2:
                    timestamp = _float(pair[0])
                    value = _float(pair[1])
                    if timestamp is not None and value is not None:
                        values.append((timestamp, value))
    return values, result_type


def _float(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        candidate = float(value)
        return candidate if math.isfinite(candidate) else None
    if isinstance(value, str):
        if value.strip().lower() in {"nan", "inf", "+inf", "-inf"}:
            return None
        try:
            candidate = float(value)
        except ValueError:
            return None
        return candidate if math.isfinite(candidate) else None
    return None


def _quantity(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value) if math.isfinite(float(value)) else None
    if not isinstance(value, str):
        return None
    match = re.fullmatch(r"([+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?)([a-zA-Z]*)", value.strip())
    if not match:
        return None
    number = float(match.group(1))
    suffix = match.group(2)
    multipliers = {
        "": 1.0,
        "n": 1e-9,
        "u": 1e-6,
        "m": 1e-3,
        "k": 1e3,
        "K": 1e3,
        "M": 1e6,
        "G": 1e9,
        "T": 1e12,
        "P": 1e15,
        "E": 1e18,
        "Ki": 1024.0,
        "Mi": 1024.0**2,
        "Gi": 1024.0**3,
        "Ti": 1024.0**4,
        "Pi": 1024.0**5,
        "Ei": 1024.0**6,
    }
    multiplier = multipliers.get(suffix)
    return number * multiplier if multiplier is not None else None


def _cpu(value: Any) -> float | None:
    parsed = _quantity(value)
    return parsed * 1000.0 if parsed is not None else None


def _memory(value: Any) -> float | None:
    return _quantity(value)


def _metadata(item: Mapping[str, Any]) -> Mapping[str, Any]:
    value = item.get("metadata")
    return value if isinstance(value, Mapping) else {}


def _node_info(node: Mapping[str, Any]) -> dict[str, Any]:
    metadata = _metadata(node)
    labels = metadata.get("labels") if isinstance(metadata.get("labels"), Mapping) else {}
    spec = node.get("spec") if isinstance(node.get("spec"), Mapping) else {}
    status = node.get("status") if isinstance(node.get("status"), Mapping) else {}
    ready = False
    conditions = status.get("conditions")
    if isinstance(conditions, list):
        for condition in conditions:
            if isinstance(condition, Mapping) and condition.get("type") == "Ready":
                ready = str(condition.get("status", "")).lower() == "true"
    control_plane = bool(
        labels.get("node-role.kubernetes.io/control-plane") or labels.get("node-role.kubernetes.io/master")
    )
    taints = spec.get("taints") if isinstance(spec.get("taints"), list) else []
    no_schedule = any(
        isinstance(taint, Mapping) and taint.get("effect") == "NoSchedule" for taint in taints
    )
    allocatable = status.get("allocatable") if isinstance(status.get("allocatable"), Mapping) else {}
    capacity = status.get("capacity") if isinstance(status.get("capacity"), Mapping) else {}
    schedulable = ready and not control_plane and not spec.get("unschedulable", False) and not no_schedule
    return {
        "name": str(metadata.get("name", "")),
        "ready": ready,
        "control_plane": control_plane,
        "schedulable": schedulable,
        "unschedulable": bool(spec.get("unschedulable", False)),
        "taints": [
            {"key": taint.get("key"), "effect": taint.get("effect")}
            for taint in taints
            if isinstance(taint, Mapping)
        ],
        "labels": {
            str(key): str(value)
            for key, value in labels.items()
            if str(key).startswith("node-role.kubernetes.io/")
            or str(key) in {"kubernetes.io/hostname", "topology.kubernetes.io/zone"}
        },
        "allocatable": {"cpu": allocatable.get("cpu"), "memory": allocatable.get("memory")},
        "allocatable_cpu_millicores": _cpu(allocatable.get("cpu")),
        "allocatable_memory_bytes": _memory(allocatable.get("memory")),
        "capacity": {"cpu": capacity.get("cpu"), "memory": capacity.get("memory")},
    }


def _container_resources(container: Mapping[str, Any]) -> dict[str, Any]:
    resources = container.get("resources") if isinstance(container.get("resources"), Mapping) else {}
    requests = resources.get("requests") if isinstance(resources.get("requests"), Mapping) else {}
    limits = resources.get("limits") if isinstance(resources.get("limits"), Mapping) else {}
    return {
        "name": str(container.get("name", "")),
        "image": str(container.get("image", "")),
        "resources": {
            "requests": {"cpu": requests.get("cpu"), "memory": requests.get("memory")},
            "limits": {"cpu": limits.get("cpu"), "memory": limits.get("memory")},
        },
    }


def _pod_info(pod: Mapping[str, Any]) -> dict[str, Any]:
    metadata = _metadata(pod)
    spec = pod.get("spec") if isinstance(pod.get("spec"), Mapping) else {}
    status = pod.get("status") if isinstance(pod.get("status"), Mapping) else {}
    owner = metadata.get("ownerReferences")
    owner_info = None
    if isinstance(owner, list) and owner:
        first = owner[0]
        if isinstance(first, Mapping):
            owner_info = {"kind": first.get("kind"), "name": first.get("name")}
    ready = False
    conditions = status.get("conditions")
    if isinstance(conditions, list):
        for condition in conditions:
            if isinstance(condition, Mapping) and condition.get("type") == "Ready":
                ready = str(condition.get("status", "")).lower() == "true"
    containers = spec.get("containers") if isinstance(spec.get("containers"), list) else []
    init_containers = spec.get("initContainers") if isinstance(spec.get("initContainers"), list) else []
    return {
        "namespace": str(metadata.get("namespace", "")),
        "name": str(metadata.get("name", "")),
        "node": str(spec.get("nodeName", "")),
        "phase": str(status.get("phase", "")),
        "ready": ready,
        "deleting": bool(metadata.get("deletionTimestamp")),
        "owner": owner_info,
        "spec": {
            "containers": [
                _container_resources(container)
                for container in containers
                if isinstance(container, Mapping)
            ],
            "initContainers": [
                _container_resources(container)
                for container in init_containers
                if isinstance(container, Mapping)
            ],
            "overhead": spec.get("overhead") if isinstance(spec.get("overhead"), Mapping) else {},
        },
        "container_names": [
            str(container.get("name", ""))
            for container in containers
            if isinstance(container, Mapping)
        ],
        "restart_count": sum(
            int(container_status.get("restartCount", 0))
            for container_status in (status.get("containerStatuses") or [])
            if isinstance(container_status, Mapping)
            and isinstance(container_status.get("restartCount", 0), int)
        ),
    }


def _deployment_info(deployment: Mapping[str, Any]) -> dict[str, Any]:
    metadata = _metadata(deployment)
    spec = deployment.get("spec") if isinstance(deployment.get("spec"), Mapping) else {}
    status = deployment.get("status") if isinstance(deployment.get("status"), Mapping) else {}
    template = spec.get("template") if isinstance(spec.get("template"), Mapping) else {}
    template_spec = template.get("spec") if isinstance(template.get("spec"), Mapping) else {}
    containers = template_spec.get("containers") if isinstance(template_spec.get("containers"), list) else []
    return {
        "namespace": str(metadata.get("namespace", "")),
        "name": str(metadata.get("name", "")),
        "replicas": spec.get("replicas"),
        "ready_replicas": status.get("readyReplicas", 0),
        "available_replicas": status.get("availableReplicas", 0),
        "updated_replicas": status.get("updatedReplicas", 0),
        "images": [
            str(container.get("image", ""))
            for container in containers
            if isinstance(container, Mapping)
        ],
        "containers": [
            _container_resources(container)
            for container in containers
            if isinstance(container, Mapping)
        ],
        "strategy": spec.get("strategy") if isinstance(spec.get("strategy"), Mapping) else {},
        "selector": spec.get("selector") if isinstance(spec.get("selector"), Mapping) else {},
        "pod_template_sha256": hashlib.sha256(
            json.dumps(template, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
    }


def _pod_requests_typed(pod: Mapping[str, Any], resource: str, *, section: str) -> tuple[float, int]:
    spec = pod.get("spec") if isinstance(pod.get("spec"), Mapping) else {}
    containers = spec.get("containers") if isinstance(spec.get("containers"), list) else []
    init_containers = spec.get("initContainers") if isinstance(spec.get("initContainers"), list) else []
    parser = _cpu if resource == "cpu" else _memory

    def container_value(container: Mapping[str, Any]) -> Any:
        resources = container.get("resources")
        if isinstance(resources, Mapping):
            values = resources.get(section)
            if isinstance(values, Mapping):
                return values.get(resource)
        values = container.get(section)
        return values.get(resource) if isinstance(values, Mapping) else None

    missing = 0
    total = 0.0
    for container in containers:
        if not isinstance(container, Mapping):
            missing += 1
            continue
        raw = container_value(container)
        # The API omits an unreserved resource; Kubernetes schedules that as
        # zero requests. A malformed explicit quantity is different.
        parsed = 0.0 if raw is None else parser(raw)
        if parsed is None:
            missing += 1
            parsed = 0.0
        total += parsed
    init_max = 0.0
    for container in init_containers:
        if not isinstance(container, Mapping):
            missing += 1
            continue
        raw = container_value(container)
        parsed = 0.0 if raw is None else parser(raw)
        if parsed is None:
            missing += 1
            parsed = 0.0
        init_max = max(init_max, parsed)
    overhead = spec.get("overhead") if isinstance(spec.get("overhead"), Mapping) else {}
    overhead_value = parser(overhead.get(resource)) or 0.0
    return max(total, init_max) + overhead_value, missing


def _compute_capacity(
    nodes: list[dict[str, Any]],
    pods: list[dict[str, Any]],
    *,
    add_error: Any,
) -> dict[str, Any]:
    workers = [node for node in nodes if node.get("ready") and node.get("schedulable")]
    worker_names = {node["name"] for node in workers if node.get("name")}
    alloc_cpu = sum(float(node.get("allocatable_cpu_millicores") or 0.0) for node in workers)
    alloc_memory = sum(float(node.get("allocatable_memory_bytes") or 0.0) for node in workers)
    used_cpu = 0.0
    used_memory = 0.0
    missing = 0
    for pod in pods:
        if pod.get("phase") in {"Succeeded", "Failed"}:
            continue
        if pod.get("node") not in worker_names:
            continue
        cpu, cpu_missing = _pod_requests_typed(pod, "cpu", section="requests")
        memory, memory_missing = _pod_requests_typed(pod, "memory", section="requests")
        used_cpu += cpu
        used_memory += memory
        missing += cpu_missing + memory_missing
    if missing:
        add_error(f"{missing} scheduled Pod resource requests are missing; free capacity cannot be proven")
    available_cpu = alloc_cpu - used_cpu
    available_memory = alloc_memory - used_memory
    return {
        "available_cpu_millicores": max(0.0, available_cpu),
        "available_memory_bytes": max(0.0, available_memory),
        "allocatable_cpu_millicores": alloc_cpu,
        "allocatable_memory_bytes": alloc_memory,
        "existing_pods_requests_cpu_millicores": used_cpu,
        "existing_pods_requests_memory_bytes": used_memory,
        "workers_ready": len(workers),
        "worker_names": sorted(worker_names),
        "overcommitted": available_cpu < 0 or available_memory < 0,
    }


def _bounded_raw(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Keep a small, reviewable raw query response without unbounded vectors."""

    data = payload.get("data") if isinstance(payload.get("data"), Mapping) else {}
    result = data.get("result")
    bounded_result: Any = result
    truncated = False
    if isinstance(result, list) and len(result) > 20:
        bounded_result = result[:20]
        truncated = True
    encoded = json.dumps(
        {"status": payload.get("status"), "data": {"resultType": data.get("resultType"), "result": bounded_result}},
        ensure_ascii=False,
        separators=(",", ":"),
    )
    if len(encoded.encode("utf-8")) > MAX_RAW_QUERY_BYTES:
        encoded = encoded[: MAX_RAW_QUERY_BYTES - 20].encode("utf-8", errors="ignore").decode(
            "utf-8", errors="ignore"
        ) + ',"truncated":true}'
        truncated = True
    try:
        decoded = json.loads(encoded)
    except ValueError:
        decoded = {"truncated": True}
    if truncated:
        decoded["_truncated"] = True
    return decoded


def collect(config: dict) -> dict:
    """Collect real Kubernetes and Prometheus evidence using read-only calls."""

    if not isinstance(config, dict):
        raise EvidenceError("evidence config must be a mapping")
    namespace = _safe_name(str(config.get("namespace", "demo")), "namespace")
    deployment_name = _safe_name(str(config.get("deployment", "demo")), "deployment")
    kubectl_timeout = _bounded_int(
        config, "kubectl_timeout_seconds", DEFAULT_KUBECTL_TIMEOUT_SECONDS, 1, 120
    )
    prom_timeout = _bounded_int(
        config, "prometheus_timeout_seconds", DEFAULT_PROMETHEUS_TIMEOUT_SECONDS, 1, 60
    )
    ttl = _bounded_int(config, "evidence_ttl_seconds", 300, 1, 86400)
    max_kube_bytes = _bounded_int(
        config, "kubectl_max_output_bytes", DEFAULT_MAX_RESPONSE_BYTES, 4096, 128 * 1024 * 1024
    )
    max_prom_bytes = _bounded_int(
        config, "prometheus_max_response_bytes", DEFAULT_MAX_PROM_BYTES, 4096, 16 * 1024 * 1024
    )
    started_at = time.time()
    errors: list[str] = []
    error_set: set[str] = set()

    def add_error(message: str) -> None:
        text = str(message).replace("\n", " ").strip()[:800]
        if text and text not in error_set:
            error_set.add(text)
            errors.append(text)

    nodes: list[dict[str, Any]] = []
    pods: list[dict[str, Any]] = []
    deployment: dict[str, Any] = {}
    capacity: dict[str, Any] | None = None
    nodes_ok = False
    pods_ok = False
    deployment_ok = False
    metrics: dict[str, Any] = {
        "memory_working_set_bytes": None,
        "request_rate": None,
        "error_ratio": None,
        "p95_seconds": None,
        "alerts": [],
        "source_timestamps": {},
    }
    prom_queries: dict[str, Any] = {}
    raw_queries: dict[str, Any] = {}
    kubectl_commands: list[list[str]] = []
    kube_timestamps: dict[str, float] = {}
    prom_url: str | None = None

    with tempfile.TemporaryDirectory(prefix="change-guard-evidence-") as temporary:
        home = Path(temporary)
        (home / "cache").mkdir()
        (home / "config").mkdir()
        try:
            nodes_payload, error = _run_kubectl(
                ["get", "nodes", "-o", "json"],
                config,
                home,
                max_bytes=max_kube_bytes,
                timeout=kubectl_timeout,
            )
            kubectl_commands.append(["get", "nodes", "-o", "json"])
            if error:
                add_error(error)
            elif isinstance(nodes_payload, Mapping):
                items = nodes_payload.get("items")
                if isinstance(items, list):
                    nodes = [_node_info(item) for item in items[:MAX_NODES] if isinstance(item, Mapping)]
                nodes_ok = True
                kube_timestamps["nodes"] = time.time()
        except Exception as exc:  # defensive: never crash the whole collection
            add_error(f"node evidence failed: {exc}")

        try:
            deployment_payload, error = _run_kubectl(
                ["-n", namespace, "get", "deployment", deployment_name, "-o", "json"],
                config,
                home,
                max_bytes=max_kube_bytes,
                timeout=kubectl_timeout,
            )
            kubectl_commands.append(
                ["-n", namespace, "get", "deployment", deployment_name, "-o", "json"]
            )
            if error:
                add_error(error)
            elif isinstance(deployment_payload, Mapping):
                deployment = _deployment_info(deployment_payload)
                deployment_ok = True
                kube_timestamps["deployment"] = time.time()
        except Exception as exc:
            add_error(f"deployment evidence failed: {exc}")

        try:
            pods_payload, error = _run_kubectl(
                ["get", "pods", "--all-namespaces", "-o", "json"],
                config,
                home,
                max_bytes=max_kube_bytes,
                timeout=kubectl_timeout,
            )
            kubectl_commands.append(["get", "pods", "--all-namespaces", "-o", "json"])
            if error:
                add_error(error)
            elif isinstance(pods_payload, Mapping):
                items = pods_payload.get("items")
                if isinstance(items, list):
                    pods = [_pod_info(item) for item in items[:MAX_PODS] if isinstance(item, Mapping)]
                pods_ok = True
                kube_timestamps["pods"] = time.time()
        except Exception as exc:
            add_error(f"pod evidence failed: {exc}")

    if nodes_ok and pods_ok:
        capacity = _compute_capacity(nodes, pods, add_error=add_error)
        # Zero Ready workers is insufficient scheduling capacity, which the
        # engine classifies as REVIEW, not missing evidence/ERROR.
    else:
        if not nodes_ok:
            add_error("node capacity evidence is unavailable")
        if not pods_ok:
            add_error("scheduled Pod evidence is unavailable")

    try:
        prom_url = _prometheus_base_url(config)
    except EvidenceError as exc:
        add_error(str(exc))
        prom_url = None

    session: requests.Session | None = None
    if prom_url is not None:
        session = requests.Session()
        session.trust_env = False
        try:
            pod_selector = f'namespace="{namespace}",pod=~"{re.escape(deployment_name)}-.*"'
            expressions = {
                "memory_working_set_bytes": (
                    "max_over_time((sum by (pod) "
                    f'(container_memory_working_set_bytes{{{pod_selector},container!=""}}))[15m:])'
                ),
                "request_rate": (
                    f'sum(rate(demo_http_requests_total{{namespace="{namespace}",route="/work"}}[5m]))'
                ),
                "error_numerator": (
                    f'sum(rate(demo_http_requests_total{{namespace="{namespace}",route="/work",'
                    'status=~"5.."}[5m]))'
                ),
                "p95_seconds": (
                    "histogram_quantile(0.95, sum by (le) "
                    "(rate(demo_http_request_duration_seconds_bucket"
                    f'{{namespace="{namespace}",route="/work"}}[5m])))'
                ),
                # Evaluation timestamps are not source freshness.  These raw
                # timestamp() queries prove that up, memory, request counter,
                # and latency histogram series actually exist and were scraped.
                "up": f"max(up{{{pod_selector}}})",
                "up_source": f"max(timestamp(up{{{pod_selector}}}))",
                "memory_source": (
                    f'max(timestamp(container_memory_working_set_bytes{{{pod_selector},container!=""}}))'
                ),
                "request_counter_source": (
                    f'max(timestamp(demo_http_requests_total{{namespace="{namespace}",route="/work"}}))'
                ),
                "latency_bucket_source": (
                    "max(timestamp(demo_http_request_duration_seconds_bucket"
                    f'{{namespace="{namespace}",route="/work"}}))'
                ),
            }
            query_values: dict[str, dict[str, Any]] = {}
            for name, expression in expressions.items():
                query_started = time.time()
                try:
                    payload = _prom_query(
                        session,
                        prom_url,
                        expression,
                        timeout=prom_timeout,
                        max_bytes=max_prom_bytes,
                    )
                    values, result_type = _prom_result_values(payload)
                    query_values[name] = {
                        "values": values,
                        "query_time": query_started,
                        "raw": _bounded_raw(payload),
                        "result_type": result_type,
                    }
                    prom_queries[name] = {
                        "expr": expression,
                        "timestamp": int(query_started),
                        "status": "success",
                        "result_type": result_type,
                        "series_count": len(values),
                    }
                    raw_queries[name] = _bounded_raw(payload)
                except (EvidenceError, requests.RequestException, OSError) as exc:
                    add_error(f"Prometheus query {name} failed: {exc}")
                    prom_queries[name] = {
                        "expr": expression,
                        "timestamp": int(query_started),
                        "status": "error",
                    }

            def source_timestamp(name: str) -> float | None:
                values = query_values.get(name, {}).get("values", [])
                timestamps = [
                    value
                    for _evaluation_time, value in values
                    if isinstance(value, (int, float)) and math.isfinite(float(value)) and value > 0
                ]
                return max(timestamps) if timestamps else None

            def source_number(name: str) -> float | None:
                values = query_values.get(name, {}).get("values", [])
                numbers = [
                    value
                    for _evaluation_time, value in values
                    if isinstance(value, (int, float)) and math.isfinite(float(value))
                ]
                return max(numbers) if numbers else None

            up_value = source_number("up")
            up_source_ts = source_timestamp("up_source")
            memory_source_ts = source_timestamp("memory_source")
            counter_source_ts = source_timestamp("request_counter_source")
            bucket_source_ts = source_timestamp("latency_bucket_source")
            presence = {
                "up": up_source_ts is not None,
                "memory": memory_source_ts is not None,
                "requests_total": counter_source_ts is not None,
                "latency_bucket": bucket_source_ts is not None,
            }
            metrics["up"] = up_value
            metrics["series_presence"] = presence
            metrics["source_timestamps"]["up"] = up_source_ts
            if not presence["up"]:
                add_error("target up metric is missing or has no raw scrape timestamp")

            memory_samples = query_values.get("memory_working_set_bytes", {}).get("values", [])
            if memory_samples:
                _memory_ts, memory_value = max(memory_samples, key=lambda pair: pair[1])
                if math.isfinite(memory_value) and memory_value >= 0:
                    metrics["memory_working_set_bytes"] = memory_value
                    if memory_source_ts is not None:
                        # Use timestamp(raw memory series), not the evaluation
                        # timestamp of max_over_time.
                        metrics["source_timestamps"]["memory_working_set_bytes"] = memory_source_ts
                    else:
                        add_error("memory source series has no raw sample timestamp")
                else:
                    add_error("memory measurement is non-finite")
            else:
                add_error("memory max_over_time query returned no samples")
            if memory_source_ts is None:
                add_error("memory source series is missing")

            rate_samples = query_values.get("request_rate", {}).get("values", [])
            rate_result = query_values.get("request_rate", {}).get("raw", {}).get("data", {}).get("result")
            rate_series_count = len(rate_result) if isinstance(rate_result, list) else (1 if rate_result else 0)
            if rate_samples:
                _evaluation_ts, rate_value = max(rate_samples, key=lambda pair: pair[0])
                if rate_value < 0:
                    add_error("request rate is negative")
                else:
                    metrics["request_rate"] = rate_value
                    if counter_source_ts is not None:
                        metrics["source_timestamps"]["request_rate"] = counter_source_ts
            elif prom_queries.get("request_rate", {}).get("status") == "success":
                if rate_series_count == 0 and counter_source_ts is not None:
                    # The request counter exists and is fresh but rate is zero:
                    # that is genuinely low traffic, never assumed health.
                    metrics["request_rate"] = 0.0
                    metrics["source_timestamps"]["request_rate"] = counter_source_ts
                elif rate_series_count > 0:
                    add_error("request rate query returned a non-finite value")
                else:
                    add_error("request counter series is missing; zero rate cannot be established")
            if metrics["request_rate"] is not None and counter_source_ts is None:
                add_error("request counter source series is missing")

            rate = metrics["request_rate"]
            error_query_ok = prom_queries.get("error_numerator", {}).get("status") == "success"
            error_samples = query_values.get("error_numerator", {}).get("values", [])
            error_result = query_values.get("error_numerator", {}).get("raw", {}).get("data", {}).get("result")
            error_series_count = len(error_result) if isinstance(error_result, list) else (1 if error_result else 0)
            if error_samples and isinstance(rate, (int, float)) and rate > 0:
                _error_ts, error_value = max(error_samples, key=lambda pair: pair[0])
                ratio = error_value / rate
                if math.isfinite(ratio) and 0 <= ratio <= 1:
                    metrics["error_ratio"] = ratio
                    if counter_source_ts is not None:
                        metrics["source_timestamps"]["error_ratio"] = counter_source_ts
                else:
                    add_error("error ratio is non-finite or outside [0,1]")
            elif error_query_ok and isinstance(rate, (int, float)) and rate > 0 and error_series_count == 0:
                # No 5xx series is a valid zero, not missing data.
                metrics["error_ratio"] = 0.0
                if counter_source_ts is not None:
                    metrics["source_timestamps"]["error_ratio"] = counter_source_ts
            elif error_query_ok and isinstance(rate, (int, float)) and rate > 0:
                add_error("error numerator query returned a non-finite value")
            elif isinstance(rate, (int, float)) and rate <= 0:
                # Low traffic: ratio/p95 are intentionally undefined, not zero.
                metrics["error_ratio"] = None
            elif not error_query_ok:
                add_error("error ratio evidence is unavailable because the query failed")

            p95_samples = query_values.get("p95_seconds", {}).get("values", [])
            p95_result = query_values.get("p95_seconds", {}).get("raw", {}).get("data", {}).get("result")
            p95_series_count = len(p95_result) if isinstance(p95_result, list) else (1 if p95_result else 0)
            source_ready = (
                up_value == 1
                and up_source_ts is not None
                and counter_source_ts is not None
                and bucket_source_ts is not None
            )
            if bucket_source_ts is not None:
                metrics["source_timestamps"]["p95_seconds"] = bucket_source_ts
            if p95_samples:
                _p95_eval_ts, p95_value = max(p95_samples, key=lambda pair: pair[0])
                if math.isfinite(p95_value) and p95_value >= 0:
                    metrics["p95_seconds"] = p95_value
                else:
                    add_error("p95 latency is non-finite")
            elif prom_queries.get("p95_seconds", {}).get("status") != "success":
                add_error("p95 latency evidence is unavailable")
            elif isinstance(rate, (int, float)) and rate == 0 and source_ready and p95_series_count >= 0:
                # histogram_quantile returns NaN at zero rate even though the
                # histogram series exists.  Engine turns this into LOW_TRAFFIC
                # REVIEW; it is not missing evidence.
                metrics["p95_seconds"] = None
            elif p95_series_count > 0:
                add_error("p95 latency query returned a non-finite value")
            elif isinstance(rate, (int, float)) and rate == 0:
                add_error("p95 histogram source series is missing or target is not up")
            else:
                add_error("p95 latency query returned no samples at non-low traffic")

            if isinstance(rate, (int, float)) and rate == 0:
                if counter_source_ts is None:
                    add_error("request counter source series is missing at zero rate")
                if bucket_source_ts is None:
                    add_error("latency histogram source series is missing at zero rate")
                if up_value != 1 or up_source_ts is None:
                    add_error("target up scrape is missing or not healthy at zero rate")

            try:
                alerts = _prom_alerts(
                    session,
                    prom_url,
                    timeout=prom_timeout,
                    max_bytes=max_prom_bytes,
                )
                metrics["alerts"] = alerts
                metrics["source_timestamps"]["alerts"] = time.time()
                prom_queries["alerts"] = {
                    "endpoint": "/api/v1/alerts",
                    "timestamp": int(time.time()),
                    "status": "success",
                    "count": len(alerts),
                }
            except (EvidenceError, requests.RequestException, OSError) as exc:
                add_error(f"Prometheus alerts query failed: {exc}")
                prom_queries["alerts"] = {
                    "endpoint": "/api/v1/alerts",
                    "timestamp": int(time.time()),
                    "status": "error",
                }
        finally:
            session.close()

    collected_at = time.time()
    # Refuse to bless stale source samples.  The engine repeats these checks
    # defensively, but the collector reports the problem as evidence errors too.
    for key, timestamp in metrics.get("source_timestamps", {}).items():
        if not isinstance(timestamp, (int, float)) or not math.isfinite(float(timestamp)):
            add_error(f"source timestamp for {key} is invalid")
            continue
        if collected_at - timestamp > ttl:
            add_error(f"source timestamp for {key} is stale")
        if timestamp - collected_at > _CLOCK_SKEW_TOLERANCE_SECONDS:
            add_error(f"source timestamp for {key} is in the future")

    if deployment_ok is False and not deployment:
        # The command failure has already been recorded; this only makes the
        # missing current state explicit in the returned deployment field.
        deployment = {}
        add_error("deployment evidence is unavailable")

    if metrics["memory_working_set_bytes"] is None:
        add_error("memory evidence is missing")
    if metrics["request_rate"] is None:
        add_error("request rate evidence is missing")
    if isinstance(metrics["request_rate"], (int, float)) and metrics["request_rate"] > 0.1:
        if metrics["error_ratio"] is None:
            add_error("error ratio evidence is missing at non-low traffic")
        if metrics["p95_seconds"] is None:
            add_error("p95 evidence is missing at non-low traffic")
    if "alerts" not in metrics or metrics.get("source_timestamps", {}).get("alerts") is None:
        add_error("alert evidence is missing")
    if capacity is None:
        add_error("capacity evidence is missing")

    sources = {
        "schema_version": _EVIDENCE_VERSION,
        "collection_started_at": int(started_at),
        "kubernetes": {
            "kubeconfig_path": str(config.get("kubeconfig", "")),
            "commands": kubectl_commands,
            "timestamps": {key: int(value) for key, value in kube_timestamps.items()},
        },
        "prometheus": {
            "url": prom_url,
            "queries": prom_queries,
            "raw": raw_queries,
        },
    }
    return {
        "schema_version": _EVIDENCE_VERSION,
        "collected_at": int(collected_at),
        "errors": errors[:50],
        "nodes": nodes,
        "deployment": deployment,
        "pods": pods,
        "metrics": metrics,
        "capacity": capacity or {},
        "sources": sources,
    }
