"""Fail-closed risk evaluation over *rendered* Kubernetes resources.

The engine intentionally knows nothing about Helm values files.  Callers pass
the complete old and new rendered object lists, current Prometheus/Kubernetes
evidence, config, PR context, and (optionally) the DeepSeek result.

Decision priority is ``BLOCK > ERROR > REVIEW > PASS``.  A model failure is an
``ERROR`` and can never weaken a hard ``BLOCK``.  Model-added risks are capped
at ``REVIEW``.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Sequence

RULE_VERSION = "2026.11.1"
SCHEMA_VERSION = "1.0"

DEFAULT_NAMESPACE = "demo"
DEFAULT_DEPLOYMENT = "demo"
DEFAULT_ALLOWED_IMAGE_REPOSITORY = "ghcr.io/hey-mmm/observability-demo"
DEFAULT_EVIDENCE_TTL_SECONDS = 300
DEFAULT_LOW_TRAFFIC_RPS = 0.1
DEFAULT_MAX_ERROR_RATIO = 0.05
DEFAULT_MAX_P95_SECONDS = 0.5
DEFAULT_MEMORY_HEADROOM_FACTOR = 1.25
CLOCK_SKEW_TOLERANCE_SECONDS = 120

FAULT_ENV_NAMES = frozenset({"DEMO_ERROR_RATE", "DEMO_LATENCY_MS", "DEMO_STARTUP_FAIL"})
DEMO_CONTAINER_NAME = "demo-service"
ALLOWED_EXEC_PROBE_COMMANDS = frozenset({("/bin/true",), ("/usr/bin/true",), ("true",)})
SENSITIVE_VOLUME_SOURCES = frozenset({"secret", "projected", "configMap"})
CLUSTER_SCOPED_KINDS = frozenset(
    {
        "Namespace",
        "Node",
        "PersistentVolume",
        "StorageClass",
        "CustomResourceDefinition",
        "ClusterRole",
        "ClusterRoleBinding",
        "IngressClass",
        "PriorityClass",
        "MutatingWebhookConfiguration",
        "ValidatingWebhookConfiguration",
        "PodSecurityPolicy",
        "RuntimeClass",
        "VolumeAttachment",
        "APIService",
    }
)
FORBIDDEN_WORKLOAD_KINDS = frozenset(
    {"Pod", "DaemonSet", "StatefulSet", "Job", "CronJob", "ReplicaSet", "ReplicationController"}
)
EXPOSURE_KINDS = frozenset(
    {"Ingress", "Gateway", "HTTPRoute", "TCPRoute", "TLSRoute", "VirtualService", "Route"}
)
ARGO_KINDS = frozenset({"Application", "AppProject", "ApplicationSet"})
ALLOWED_KINDS = frozenset({"Deployment", "Service", "ServiceMonitor"})
SENSITIVE_PATH_PARTS = (
    "secret",
    "password",
    "passwd",
    "token",
    "authorization",
    "credential",
    "privatekey",
    "api_key",
    "apikey",
)

_SEVERITY_RANK = {"BLOCK": 3, "ERROR": 2, "REVIEW": 1}
_MISSING = object()


# ---------------------------------------------------------------------------
# Generic helpers


def _canonical_json(value: Any) -> str:
    return json.dumps(
        _json_safe(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _json_safe(value: Any, *, depth: int = 0) -> Any:
    if depth > 30:
        return "<depth-limit>"
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else "<non-finite>"
    if isinstance(value, bytes):
        return "<bytes>"
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, child in value.items():
            result[str(key)] = _json_safe(child, depth=depth + 1)
        return result
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_json_safe(child, depth=depth + 1) for child in value]
    if isinstance(value, (datetime,)):
        return value.isoformat()
    return str(value)


def digest_resources(resources: Sequence[dict[str, Any]]) -> str:
    """Order-independent digest of rendered resources."""

    ordered = sorted((_json_safe(item) for item in resources), key=_canonical_json)
    return hashlib.sha256(_canonical_json(ordered).encode("utf-8")).hexdigest()


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        candidate = float(value)
        return candidate if math.isfinite(candidate) else None
    if isinstance(value, str):
        text = value.strip()
        if not text or text.lower() in {"nan", "+nan", "-nan", "inf", "+inf", "-inf", "infinity"}:
            return None
        try:
            candidate = float(text)
        except ValueError:
            return None
        return candidate if math.isfinite(candidate) else None
    return None


def _timestamp(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        candidate = float(value)
        if not math.isfinite(candidate):
            return None
        # Accept accidental millisecond timestamps without weakening checks.
        if candidate > 100_000_000_000:
            candidate /= 1000.0
        return candidate
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            candidate = float(text)
        except ValueError:
            try:
                parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
            except ValueError:
                return None
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            candidate = parsed.timestamp()
        if not math.isfinite(candidate):
            return None
        if candidate > 100_000_000_000:
            candidate /= 1000.0
        return candidate
    return None


def _metric(metrics: Mapping[str, Any], key: str) -> tuple[float | None, float | None, Any]:
    raw = metrics.get(key)
    embedded_ts: float | None = None
    value: Any = raw
    if isinstance(raw, Mapping):
        if "value" in raw:
            value = raw.get("value")
        elif "values" in raw and isinstance(raw.get("values"), list) and raw["values"]:
            value = raw["values"][-1]
        embedded_ts = _timestamp(raw.get("timestamp", raw.get("time", raw.get("ts"))))
    number = _number(value)
    return number, embedded_ts, raw


def _source_timestamp(
    evidence: Mapping[str, Any],
    metrics: Mapping[str, Any],
    key: str,
    embedded: float | None,
) -> float | None:
    sources = evidence.get("source_timestamps")
    if not isinstance(sources, Mapping):
        sources = metrics.get("source_timestamps")
    if isinstance(sources, Mapping):
        aliases = {
            "memory_working_set_bytes": ("memory_working_set_bytes", "memory", "memory_max_over_15m"),
            "request_rate": ("request_rate", "rate", "requests_rate"),
            "error_ratio": ("error_ratio", "error_rate"),
            "p95_seconds": ("p95_seconds", "p95", "latency_p95"),
            "alerts": ("alerts",),
        }.get(key, (key,))
        for alias in aliases:
            candidate = sources.get(alias)
            if isinstance(candidate, Mapping):
                candidate = candidate.get("timestamp", candidate.get("ts"))
            parsed = _timestamp(candidate)
            if parsed is not None:
                return parsed
    if embedded is not None:
        return embedded
    return None


def _parse_quantity(value: Any) -> float | None:
    """Parse a Kubernetes quantity into a finite float (base units)."""

    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        candidate = float(value)
        return candidate if math.isfinite(candidate) else None
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    match = re.fullmatch(
        r"([+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?)([a-zA-Z]*)", text
    )
    if not match:
        return None
    try:
        numeric = float(match.group(1))
    except ValueError:
        return None
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
        "mK": 1.0,
    }
    multiplier = multipliers.get(suffix)
    if multiplier is None:
        return None
    candidate = numeric * multiplier
    return candidate if math.isfinite(candidate) else None


def _cpu_millicores(value: Any) -> float | None:
    parsed = _parse_quantity(value)
    if parsed is None:
        return None
    return parsed * 1000.0


def _memory_bytes(value: Any) -> float | None:
    return _parse_quantity(value)


def _resource_key(resource: Mapping[str, Any], default_namespace: str) -> tuple[str, str, str]:
    kind = str(resource.get("kind", ""))
    metadata = resource.get("metadata") if isinstance(resource.get("metadata"), Mapping) else {}
    name = str(metadata.get("name", ""))
    namespace = str(metadata.get("namespace", "") or "")
    if not namespace and kind not in CLUSTER_SCOPED_KINDS:
        namespace = default_namespace
    return kind, namespace, name


def _flatten_resources(resources: Iterable[Any]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []

    def add(item: Any) -> None:
        if not isinstance(item, dict):
            raise ValueError("rendered resources must be mappings")
        if item.get("kind") == "List":
            children = item.get("items")
            if not isinstance(children, list):
                raise ValueError("rendered List must contain items")
            for child in children:
                add(child)
            return
        if not isinstance(item.get("kind"), str) or not item.get("kind"):
            raise ValueError("rendered resource is missing kind")
        metadata = item.get("metadata")
        if not isinstance(metadata, dict) or not isinstance(metadata.get("name"), str) or not metadata.get("name"):
            raise ValueError("rendered resource is missing metadata.name")
        output.append(item)

    for resource in resources:
        add(resource)
    return output


def _index_resources(
    resources: Sequence[dict[str, Any]],
    config: Mapping[str, Any],
) -> dict[tuple[str, str, str], list[dict[str, Any]]]:
    namespace = str(config.get("namespace", DEFAULT_NAMESPACE))
    index: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for resource in resources:
        key = _resource_key(resource, namespace)
        index.setdefault(key, []).append(resource)
    return index


def _target_resource(
    index: Mapping[tuple[str, str, str], list[dict[str, Any]]],
    kind: str,
    namespace: str,
    name: str,
) -> dict[str, Any] | None:
    entries = index.get((kind, namespace, name))
    return entries[0] if entries else None


def _pod_spec(deployment: Mapping[str, Any] | None) -> Mapping[str, Any]:
    if not isinstance(deployment, Mapping):
        return {}
    spec = deployment.get("spec")
    if not isinstance(spec, Mapping):
        return {}
    template = spec.get("template")
    if not isinstance(template, Mapping):
        return {}
    pod_spec = template.get("spec")
    return pod_spec if isinstance(pod_spec, Mapping) else {}


def _containers(deployment: Mapping[str, Any] | None) -> list[Mapping[str, Any]]:
    pod_spec = _pod_spec(deployment)
    value = pod_spec.get("containers")
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, Mapping)]


def _init_containers(deployment: Mapping[str, Any] | None) -> list[Mapping[str, Any]]:
    pod_spec = _pod_spec(deployment)
    value = pod_spec.get("initContainers")
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, Mapping)]


def _replicas(deployment: Mapping[str, Any] | None, default: int = 1) -> int | None:
    if not isinstance(deployment, Mapping):
        return None
    spec = deployment.get("spec")
    if not isinstance(spec, Mapping):
        return None
    value = spec.get("replicas", default)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _pod_requests_from_spec(
    pod_spec: Mapping[str, Any],
    *,
    quantity: str,
    parser: Any,
    section: str = "requests",
) -> tuple[float | None, int, int]:
    """Return (schedulable amount, invalid containers, unreserved containers).

    The real Kubernetes API omits a resource that was not requested.  The
    scheduler treats that omission as a zero request, so a missing request is
    *unreserved* risk (REVIEW), not lost evidence.  A present but malformed
    quantity is still a hard data error.
    """

    total = 0.0
    invalid = 0
    unreserved = 0

    def container_value(container: Mapping[str, Any]) -> Any:
        resources = container.get("resources")
        values = resources.get(section) if isinstance(resources, Mapping) else None
        return values.get(quantity) if isinstance(values, Mapping) else None

    def sum_containers(items: Any) -> float | None:
        nonlocal invalid, unreserved
        if not isinstance(items, list):
            return 0.0
        subtotal = 0.0
        for container in items:
            if not isinstance(container, Mapping):
                invalid += 1
                continue
            raw = container_value(container)
            if raw is None:
                # API omission == zero request in the scheduler.
                unreserved += 1
                continue
            parsed = parser(raw)
            if parsed is None:
                invalid += 1
                continue
            subtotal += parsed
        return subtotal

    containers = pod_spec.get("containers")
    init_containers = pod_spec.get("initContainers")
    regular = sum_containers(containers) or 0.0
    # Kubernetes scheduling uses max(sum(containers), max(initContainer)) + overhead.
    init_max = 0.0
    if isinstance(init_containers, list):
        for container in init_containers:
            if not isinstance(container, Mapping):
                invalid += 1
                continue
            raw = container_value(container)
            if raw is None:
                unreserved += 1
                continue
            parsed = parser(raw)
            if parsed is None:
                invalid += 1
                continue
            init_max = max(init_max, parsed)
    overhead = pod_spec.get("overhead")
    overhead_value = 0.0
    if isinstance(overhead, Mapping):
        raw = overhead.get(quantity)
        if raw is not None:
            parsed = parser(raw)
            if parsed is None:
                invalid += 1
            else:
                overhead_value = parsed
    total = max(regular, init_max) + overhead_value
    return total, invalid, unreserved


def _pod_totals(deployment: Mapping[str, Any] | None, quantity: str, parser: Any) -> tuple[float | None, bool]:
    """Limit totals for one Pod and whether every container was specified."""

    pod_spec = _pod_spec(deployment)
    containers = pod_spec.get("containers")
    if not isinstance(containers, list) or not containers:
        return None, False
    value, missing, unreserved = _pod_requests_from_spec(
        pod_spec, quantity=quantity, parser=parser, section="limits"
    )
    return value, missing == 0 and unreserved == 0


def _pod_resources(deployment: Mapping[str, Any] | None) -> dict[str, Any]:
    cpu_request, cpu_invalid, cpu_unreserved = _pod_requests_from_spec(
        _pod_spec(deployment), quantity="cpu", parser=_cpu_millicores
    )
    mem_request, mem_invalid, mem_unreserved = _pod_requests_from_spec(
        _pod_spec(deployment), quantity="memory", parser=_memory_bytes
    )
    cpu_limit, cpu_limit_complete = _pod_totals(deployment, "cpu", _cpu_millicores)
    mem_limit, mem_limit_complete = _pod_totals(deployment, "memory", _memory_bytes)
    return {
        "cpu_request_millicores": cpu_request,
        "memory_request_bytes": mem_request,
        "cpu_limit_millicores": cpu_limit,
        "memory_limit_bytes": mem_limit,
        "cpu_request_invalid_containers": cpu_invalid,
        "memory_request_invalid_containers": mem_invalid,
        "cpu_request_unreserved_containers": cpu_unreserved,
        "memory_request_unreserved_containers": mem_unreserved,
        # Backwards-compatible names now mean *invalid* quantities only.
        "cpu_request_missing_containers": cpu_invalid,
        "memory_request_missing_containers": mem_invalid,
        "cpu_limit_complete": cpu_limit_complete,
        "memory_limit_complete": mem_limit_complete,
    }


def _strategy_surge(deployment: Mapping[str, Any] | None, replicas: int) -> tuple[int, bool]:
    """Return (surge pods, strategy_valid)."""

    spec = deployment.get("spec") if isinstance(deployment, Mapping) else None
    strategy = spec.get("strategy") if isinstance(spec, Mapping) else None
    if not isinstance(strategy, Mapping):
        return math.ceil(replicas * 0.25), True
    strategy_type = strategy.get("type", "RollingUpdate")
    if strategy_type == "Recreate":
        return 0, True
    if strategy_type != "RollingUpdate":
        return 0, False
    rolling = strategy.get("rollingUpdate")
    if not isinstance(rolling, Mapping):
        return math.ceil(replicas * 0.25), True
    raw = rolling.get("maxSurge", "25%")
    if isinstance(raw, bool):
        return 0, False
    if isinstance(raw, int):
        if raw < 0:
            return 0, False
        return raw, True
    if isinstance(raw, str):
        if raw.endswith("%"):
            try:
                percent = float(raw[:-1])
            except ValueError:
                return 0, False
            if not math.isfinite(percent) or percent < 0:
                return 0, False
            return math.ceil(replicas * percent / 100.0), True
        try:
            parsed = int(raw)
        except ValueError:
            return 0, False
        return (parsed, True) if parsed >= 0 else (0, False)
    return 0, False


# ---------------------------------------------------------------------------
# Diff + redaction


def _is_sensitive_path(path: str, kind: str) -> bool:
    lowered = path.lower()
    if any(part in lowered for part in SENSITIVE_PATH_PARTS):
        return True
    if kind == "Secret" and (".data" in lowered or ".stringdata" in lowered):
        return True
    if re.search(r"\.env\[\d+\]\.value$", lowered):
        # Do not echo arbitrary environment values into an audit/report artifact.
        return True
    return False


def _safe_diff_value(value: Any, *, path: str, kind: str) -> Any:
    if value is _MISSING:
        return None
    if _is_sensitive_path(path, kind):
        return "<redacted>"
    if isinstance(value, Mapping) and re.search(r"\.env\[\d+\]$", path.lower()):
        # Adding/removing an env list entry must not echo its literal value.
        sanitized = {str(key): child for key, child in value.items()}
        if "value" in sanitized:
            sanitized["value"] = "<redacted>"
        if "valueFrom" in sanitized:
            sanitized["valueFrom"] = "<redacted>"
        return sanitized
    if isinstance(value, str):
        return value if len(value) <= 800 else value[:797] + "..."
    if isinstance(value, float) and not math.isfinite(value):
        return "<non-finite>"
    if isinstance(value, (Mapping, list, tuple)):
        try:
            encoded = _canonical_json(value)
        except (TypeError, ValueError):
            return "<unserializable>"
        return encoded if len(encoded) <= 1500 else encoded[:1497] + "..."
    return _json_safe(value)


def _diff_values(
    old: Any,
    new: Any,
    path: str,
    output: list[dict[str, Any]],
    *,
    kind: str,
    limit: int = 1000,
) -> None:
    if len(output) >= limit:
        return
    if old is _MISSING or new is _MISSING:
        output.append(
            {
                "path": path,
                "operation": "add" if old is _MISSING else "remove",
                "old": _safe_diff_value(old, path=path, kind=kind),
                "new": _safe_diff_value(new, path=path, kind=kind),
                "pod_template": path.startswith("spec.template"),
            }
        )
        return
    if isinstance(old, Mapping) and isinstance(new, Mapping):
        keys = sorted(set(old.keys()) | set(new.keys()), key=lambda item: str(item))
        for key in keys:
            child_path = f"{path}.{key}" if path else str(key)
            old_child = old.get(key, _MISSING) if key in old else _MISSING
            new_child = new.get(key, _MISSING) if key in new else _MISSING
            _diff_values(old_child, new_child, child_path, output, kind=kind, limit=limit)
            if len(output) >= limit:
                return
        return
    if isinstance(old, list) and isinstance(new, list):
        for index in range(max(len(old), len(new))):
            child_path = f"{path}[{index}]" if path else f"[{index}]"
            old_child = old[index] if index < len(old) else _MISSING
            new_child = new[index] if index < len(new) else _MISSING
            _diff_values(old_child, new_child, child_path, output, kind=kind, limit=limit)
            if len(output) >= limit:
                return
        return
    if _canonical_json(old) != _canonical_json(new):
        output.append(
            {
                "path": path,
                "operation": "replace",
                "old": _safe_diff_value(old, path=path, kind=kind),
                "new": _safe_diff_value(new, path=path, kind=kind),
                "pod_template": path.startswith("spec.template"),
            }
        )


def _changes_between(
    old_index: Mapping[tuple[str, str, str], list[dict[str, Any]]],
    new_index: Mapping[tuple[str, str, str], list[dict[str, Any]]],
) -> tuple[list[dict[str, Any]], bool, bool]:
    changes: list[dict[str, Any]] = []
    pod_template_changed = False
    truncated = False
    keys = sorted(set(old_index.keys()) | set(new_index.keys()))
    for key in keys:
        kind, namespace, name = key
        old_entries = old_index.get(key, [])
        new_entries = new_index.get(key, [])
        resource_label = f"{kind}/{namespace}/{name}" if namespace else f"{kind}/{name}"
        if not old_entries:
            changes.append(
                {
                    "resource": resource_label,
                    "kind": kind,
                    "namespace": namespace,
                    "name": name,
                    "operation": "add",
                    "path": "$",
                    "old": None,
                    "new": "resource present",
                    "pod_template": kind == "Deployment",
                }
            )
            pod_template_changed = pod_template_changed or kind == "Deployment"
            continue
        if not new_entries:
            changes.append(
                {
                    "resource": resource_label,
                    "kind": kind,
                    "namespace": namespace,
                    "name": name,
                    "operation": "remove",
                    "path": "$",
                    "old": "resource present",
                    "new": None,
                    "pod_template": kind == "Deployment",
                }
            )
            pod_template_changed = pod_template_changed or kind == "Deployment"
            continue
        field_changes: list[dict[str, Any]] = []
        _diff_values(old_entries[0], new_entries[0], "", field_changes, kind=kind, limit=1000)
        if len(field_changes) >= 1000:
            truncated = True
        for change in field_changes:
            if change["pod_template"]:
                pod_template_changed = True
            changes.append(
                {
                    "resource": resource_label,
                    "kind": kind,
                    "namespace": namespace,
                    "name": name,
                    "operation": "modify",
                    **change,
                }
            )
        if len(changes) >= 2000:
            truncated = True
            changes = changes[:2000]
            break
    return changes, pod_template_changed, truncated


# ---------------------------------------------------------------------------
# Evaluation internals


@dataclass
class _Findings:
    items: list[dict[str, Any]] = field(default_factory=list)
    _seen: set[tuple[str, str, str]] = field(default_factory=set)

    def add(
        self,
        rule_id: str,
        severity: str,
        field_name: str,
        message: str,
        evidence: Mapping[str, Any] | None = None,
    ) -> None:
        if severity not in _SEVERITY_RANK:
            raise ValueError(f"invalid severity {severity}")
        key = (rule_id, field_name, message)
        if key in self._seen:
            return
        self._seen.add(key)
        self.items.append(
            {
                "rule_id": rule_id,
                "severity": severity,
                "field": field_name,
                "message": message,
                "evidence": _json_safe(dict(evidence or {})),
            }
        )

    def decision(self) -> str:
        if any(item["severity"] == "BLOCK" for item in self.items):
            return "BLOCK"
        if any(item["severity"] == "ERROR" for item in self.items):
            return "ERROR"
        if any(item["severity"] == "REVIEW" for item in self.items):
            return "REVIEW"
        return "PASS"

    def sorted(self) -> list[dict[str, Any]]:
        return sorted(
            self.items,
            key=lambda item: (-_SEVERITY_RANK[item["severity"]], item["rule_id"], item["field"], item["message"]),
        )


def _check_service_resource(
    resource: Mapping[str, Any],
    key: tuple[str, str, str],
    config: Mapping[str, Any],
    findings: _Findings,
) -> None:
    _kind, namespace, name = key
    field_name = f"Service/{namespace}/{name}" if namespace else f"Service/{name}"
    if namespace != str(config["namespace"]) or name != str(config["deployment"]):
        findings.add(
            "UNEXPECTED_RESOURCE",
            "REVIEW",
            field_name,
            "an additional Service is outside the configured demo release",
        )
    spec = resource.get("spec")
    if not isinstance(spec, Mapping):
        findings.add("SERVICE_INVALID", "BLOCK", field_name, "the Service has no spec")
        return
    service_type = spec.get("type", "ClusterIP")
    if service_type not in {"ClusterIP", "ExternalName"}:
        findings.add(
            "SERVICE_EXPOSURE",
            "BLOCK",
            field_name + ".spec.type",
            "NodePort/LoadBalancer exposure is not approved",
            {"type": service_type},
        )
    if spec.get("externalIPs"):
        findings.add(
            "SERVICE_EXPOSURE",
            "BLOCK",
            field_name + ".spec.externalIPs",
            "external service IPs are not approved",
            {"externalIPs": spec.get("externalIPs")},
        )
    ports = spec.get("ports")
    if isinstance(ports, list):
        for index, port in enumerate(ports):
            if isinstance(port, Mapping) and port.get("nodePort") is not None:
                findings.add(
                    "SERVICE_EXPOSURE",
                    "BLOCK",
                    f"{field_name}.spec.ports[{index}].nodePort",
                    "nodePort is not approved",
                    {"nodePort": port.get("nodePort")},
                )


def _check_resource_scope(
    new: Sequence[dict[str, Any]],
    new_index: Mapping[tuple[str, str, str], list[dict[str, Any]]],
    config: Mapping[str, Any],
    findings: _Findings,
) -> None:
    namespace = str(config["namespace"])
    deployment = str(config["deployment"])
    for key, entries in new_index.items():
        kind, item_namespace, name = key
        field_name = f"{kind}/{item_namespace}/{name}" if item_namespace else f"{kind}/{name}"
        if len(entries) > 1:
            findings.add(
                "DUPLICATE_RESOURCE",
                "BLOCK",
                field_name,
                "the rendered release contains duplicate resources with the same identity",
                {"count": len(entries)},
            )
        if kind in ALLOWED_KINDS:
            if kind == "Deployment" and (item_namespace != namespace or name != deployment):
                findings.add(
                    "UNEXPECTED_WORKLOAD",
                    "BLOCK",
                    field_name,
                    "only the configured demo Deployment may be rendered",
                    {"expected_namespace": namespace, "expected_name": deployment},
                )
            elif kind == "Service":
                _check_service_resource(entries[0], key, config, findings)
            continue
        if kind in CLUSTER_SCOPED_KINDS or kind in {"Role", "RoleBinding"}:
            findings.add(
                "FORBIDDEN_RESOURCE_KIND",
                "BLOCK",
                field_name,
                "the release may not render RBAC or cluster-scoped resources",
                {"kind": kind},
            )
        elif kind in FORBIDDEN_WORKLOAD_KINDS:
            findings.add(
                "FORBIDDEN_RESOURCE_KIND",
                "BLOCK",
                field_name,
                "the release may not render additional workload controllers",
                {"kind": kind},
            )
        elif kind in EXPOSURE_KINDS:
            findings.add(
                "SERVICE_EXPOSURE",
                "BLOCK",
                field_name,
                "Ingress/Gateway exposure is not approved for the demo release",
                {"kind": kind},
            )
        elif kind in ARGO_KINDS:
            findings.add(
                "ARGOCD_RESOURCE_CHANGE",
                "REVIEW",
                field_name,
                "an Argo CD source/application object appears in the release",
                {"kind": kind},
            )
        else:
            findings.add(
                "UNEXPECTED_RESOURCE",
                "BLOCK",
                field_name,
                "the protected demo chart rendered an unknown resource kind",
                {"kind": kind},
            )


def _split_image(image: str) -> tuple[str, str | None, str | None]:
    name_part = image
    digest: str | None = None
    if "@" in image:
        name_part, digest = image.rsplit("@", 1)
    tag: str | None = None
    last_slash = name_part.rfind("/")
    last_colon = name_part.rfind(":")
    if last_colon > last_slash:
        tag = name_part[last_colon + 1 :]
        name_part = name_part[:last_colon]
    return name_part, tag, digest


def _check_image(
    image: Any,
    field_name: str,
    config: Mapping[str, Any],
    findings: _Findings,
) -> None:
    if not isinstance(image, str) or not image.strip() or any(char.isspace() for char in image):
        findings.add("IMAGE_INVALID", "BLOCK", field_name, "container image is empty or malformed")
        return
    repository, tag, digest = _split_image(image.strip())
    allowed = str(config["allowed_image_repository"])
    if repository != allowed:
        findings.add(
            "IMAGE_REPOSITORY_NOT_ALLOWED",
            "BLOCK",
            field_name,
            "container image repository is not allowlisted",
            {"repository": repository, "allowed": allowed},
        )
    if digest is None:
        if config["require_digest"]:
            findings.add(
                "IMAGE_DIGEST_REQUIRED",
                "BLOCK",
                field_name,
                "an immutable sha256 image digest is required",
                {"image": image, "tag": tag},
            )
        else:
            findings.add(
                "IMAGE_TAG_ONLY",
                "REVIEW",
                field_name,
                "image is tag-only; a digest is preferred",
                {"tag": tag},
            )
    elif not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        findings.add(
            "IMAGE_DIGEST_INVALID",
            "BLOCK",
            field_name,
            "image digest must be sha256:<64 lowercase hex>",
            {"digest": digest},
        )
    if digest is None and tag == "latest":
        findings.add(
            "IMAGE_MUTABLE_TAG",
            "BLOCK",
            field_name,
            "the mutable 'latest' tag is not permitted",
        )
    if digest is None and tag is None:
        findings.add(
            "IMAGE_INVALID",
            "BLOCK",
            field_name,
            "image has neither an immutable digest nor an explicit tag",
        )


def _parse_bool(value: str) -> bool | None:
    lowered = value.strip().lower()
    if lowered in {"1", "true", "yes", "on"}:
        return True
    if lowered in {"0", "false", "no", "off"}:
        return False
    return None


def _check_env(
    container: Mapping[str, Any],
    container_field: str,
    findings: _Findings,
) -> None:
    env = container.get("env")
    if env is None:
        env = []
    if not isinstance(env, list):
        findings.add("ENV_INVALID", "BLOCK", f"{container_field}.env", "env must be a list")
        return
    env_from = container.get("envFrom")
    if env_from is not None and not isinstance(env_from, list):
        findings.add(
            "ENV_FROM_INVALID",
            "BLOCK",
            f"{container_field}.envFrom",
            "envFrom must be a list",
        )
    elif isinstance(env_from, list) and env_from:
        findings.add(
            "ENV_FROM_NOT_ALLOWED",
            "BLOCK",
            f"{container_field}.envFrom",
            "envFrom can inject values that are not visible to the guard and is not permitted",
            {"sources": len(env_from)},
        )
    seen: dict[str, int] = {}
    for index, entry in enumerate(env):
        path = f"{container_field}.env[{index}]"
        if not isinstance(entry, Mapping):
            findings.add("ENV_INVALID", "BLOCK", path, "environment entry must be a mapping")
            continue
        name = entry.get("name")
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            findings.add("ENV_NAME_INVALID", "BLOCK", path + ".name", "environment variable name is invalid")
            continue
        if name in seen:
            findings.add(
                "DUPLICATE_ENV",
                "BLOCK",
                path + ".name",
                "environment variable name is duplicated",
                {"name": name, "first_index": seen[name]},
            )
        else:
            seen[name] = index
        value_from = entry.get("valueFrom")
        if name in FAULT_ENV_NAMES:
            if isinstance(value_from, Mapping):
                findings.add(
                    "FAULT_VALUE_FROM",
                    "BLOCK",
                    path,
                    "fault-injection knobs may not be sourced through valueFrom",
                    {"name": name},
                )
                continue
            if value_from is not None:
                findings.add(
                    "FAULT_VALUE_FROM",
                    "BLOCK",
                    path,
                    "fault-injection knobs may not use valueFrom",
                    {"name": name},
                )
                continue
            if "value" not in entry:
                findings.add(
                    "FAULT_ENV_INVALID",
                    "BLOCK",
                    path,
                    "fault-injection knob has no literal value",
                    {"name": name},
                )
                continue
            raw = entry.get("value")
            if not isinstance(raw, str):
                findings.add(
                    "FAULT_ENV_INVALID",
                    "BLOCK",
                    path + ".value",
                    "fault-injection knob must be a string",
                    {"name": name},
                )
                continue
            if name == "DEMO_ERROR_RATE":
                parsed = _number(raw)
                if parsed is None or parsed < 0 or parsed > 1:
                    findings.add(
                        "FAULT_ENV_INVALID",
                        "BLOCK",
                        path + ".value",
                        "DEMO_ERROR_RATE must be between 0 and 1",
                        {"value": raw},
                    )
                elif parsed > 0:
                    findings.add(
                        "FAULT_INJECTION",
                        "BLOCK",
                        path + ".value",
                        "DEMO_ERROR_RATE requests deliberate HTTP 500 injection",
                        {"name": name, "value": raw},
                    )
            elif name == "DEMO_LATENCY_MS":
                if not re.fullmatch(r"[0-9]+", raw.strip()):
                    findings.add(
                        "FAULT_ENV_INVALID",
                        "BLOCK",
                        path + ".value",
                        "DEMO_LATENCY_MS must be a non-negative integer",
                        {"value": raw},
                    )
                elif int(raw.strip()) > 0:
                    findings.add(
                        "FAULT_INJECTION",
                        "BLOCK",
                        path + ".value",
                        "DEMO_LATENCY_MS requests deliberate latency injection",
                        {"name": name, "value": raw},
                    )
            elif name == "DEMO_STARTUP_FAIL":
                parsed_bool = _parse_bool(raw)
                if parsed_bool is None:
                    findings.add(
                        "FAULT_ENV_INVALID",
                        "BLOCK",
                        path + ".value",
                        "DEMO_STARTUP_FAIL must be a boolean",
                        {"value": raw},
                    )
                elif parsed_bool:
                    findings.add(
                        "FAULT_INJECTION",
                        "BLOCK",
                        path + ".value",
                        "DEMO_STARTUP_FAIL requests deliberate startup failure",
                        {"name": name, "value": raw},
                    )


def _check_probe(
    container: Mapping[str, Any],
    container_field: str,
    probe_name: str,
    severity: str,
    findings: _Findings,
) -> None:
    probe = container.get(probe_name)
    path = f"{container_field}.{probe_name}"
    if probe is None:
        findings.add(
            "PROBE_MISSING",
            severity,
            path,
            f"{probe_name} is required for safe rollout behavior",
        )
        return
    if not isinstance(probe, Mapping):
        findings.add("PROBE_INVALID", "BLOCK", path, f"{probe_name} must be a mapping")
        return
    handler_keys = [key for key in ("httpGet", "tcpSocket", "exec", "grpc") if key in probe]
    if len(handler_keys) != 1:
        findings.add(
            "PROBE_INVALID",
            "BLOCK",
            path,
            f"{probe_name} must contain exactly one handler",
            {"handlers": handler_keys},
        )
        return
    handler_key = handler_keys[0]
    handler = probe.get(handler_key)
    if not isinstance(handler, Mapping):
        findings.add("PROBE_INVALID", "BLOCK", f"{path}.{handler_key}", "probe handler must be a mapping")
    else:
        if handler_key in {"httpGet", "tcpSocket", "grpc"}:
            port = handler.get("port")
            valid_port = (
                isinstance(port, int)
                and not isinstance(port, bool)
                and 1 <= port <= 65535
            ) or (isinstance(port, str) and bool(re.fullmatch(r"[a-z0-9]([-a-z0-9]*[a-z0-9])?", port)))
            if not valid_port:
                findings.add(
                    "PROBE_INVALID",
                    "BLOCK",
                    f"{path}.{handler_key}.port",
                    "probe port is invalid",
                    {"port": port},
                )
            if handler_key == "httpGet":
                if handler.get("scheme", "HTTP") not in {"HTTP", "HTTPS"}:
                    findings.add("PROBE_INVALID", "BLOCK", f"{path}.httpGet.scheme", "probe scheme is invalid")
                if not isinstance(handler.get("path", "/"), str):
                    findings.add("PROBE_INVALID", "BLOCK", f"{path}.httpGet.path", "probe path is invalid")
        if handler_key == "exec":
            command = handler.get("command")
            if not isinstance(command, list) or not command or not all(isinstance(part, str) for part in command):
                findings.add(
                    "PROBE_INVALID",
                    "BLOCK",
                    f"{path}.exec.command",
                    "exec probe command must be a non-empty string list",
                )
            elif tuple(command) not in ALLOWED_EXEC_PROBE_COMMANDS:
                findings.add(
                    "PROBE_EXEC_COMMAND_NOT_ALLOWED",
                    "BLOCK",
                    f"{path}.exec.command",
                    "exec probe command is not in the fixed allowlist",
                    {"command": command},
                )
    for numeric_name, minimum in (
        ("periodSeconds", 1),
        ("timeoutSeconds", 1),
        ("failureThreshold", 1),
        ("successThreshold", 1),
    ):
        if numeric_name in probe:
            value = probe[numeric_name]
            if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
                findings.add(
                    "PROBE_INVALID",
                    "BLOCK",
                    f"{path}.{numeric_name}",
                    f"{numeric_name} is invalid",
                    {"value": value},
                )
    if "initialDelaySeconds" in probe:
        value = probe["initialDelaySeconds"]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            findings.add(
                "PROBE_INVALID",
                "BLOCK",
                f"{path}.initialDelaySeconds",
                "initialDelaySeconds is invalid",
                {"value": value},
            )


def _check_security(
    deployment: Mapping[str, Any],
    findings: _Findings,
) -> None:
    pod_spec = _pod_spec(deployment)
    pod_sc = pod_spec.get("securityContext") if isinstance(pod_spec.get("securityContext"), Mapping) else {}
    deployment_field = "Deployment"
    for flag in ("hostNetwork", "hostPID", "hostIPC"):
        if pod_spec.get(flag) is True:
            findings.add(
                "POD_HOST_NAMESPACE",
                "BLOCK",
                f"{deployment_field}.spec.template.spec.{flag}",
                f"{flag} shares a host namespace and is not permitted",
            )
    if pod_spec.get("shareProcessNamespace") is True:
        findings.add(
            "SHARED_PROCESS_NAMESPACE",
            "REVIEW",
            f"{deployment_field}.spec.template.spec.shareProcessNamespace",
            "process namespace sharing increases container-to-container exposure",
        )
    if pod_spec.get("automountServiceAccountToken") is not False:
        findings.add(
            "SERVICE_ACCOUNT_TOKEN_AUTOMOUNT",
            "REVIEW",
            f"{deployment_field}.spec.template.spec.automountServiceAccountToken",
            "automountServiceAccountToken should be explicitly false",
            {"value": pod_spec.get("automountServiceAccountToken")},
        )
    volumes = pod_spec.get("volumes")
    if isinstance(volumes, list):
        for index, volume in enumerate(volumes):
            if not isinstance(volume, Mapping):
                continue
            if "hostPath" in volume:
                findings.add(
                    "HOST_PATH_VOLUME",
                    "BLOCK",
                    f"{deployment_field}.spec.template.spec.volumes[{index}].hostPath",
                    "hostPath volumes are not permitted",
                    {"name": volume.get("name")},
                )
            for source in SENSITIVE_VOLUME_SOURCES:
                if source in volume:
                    findings.add(
                        "SENSITIVE_VOLUME",
                        "BLOCK",
                        f"{deployment_field}.spec.template.spec.volumes[{index}].{source}",
                        "secret/projected/configMap volumes are not permitted for the demo workload",
                        {"name": volume.get("name"), "source": source},
                    )
    containers = list(_containers(deployment))
    regular_count = len(containers)
    containers.extend(_init_containers(deployment))
    for index, container in enumerate(containers):
        container_name = container.get("name", f"container-{index}")
        if index < regular_count:
            field_prefix = f"Deployment.spec.template.spec.containers[{index}]"
        else:
            field_prefix = f"Deployment.spec.template.spec.initContainers[{index - regular_count}]"
        sc = container.get("securityContext") if isinstance(container.get("securityContext"), Mapping) else {}
        if sc.get("privileged") is True:
            findings.add(
                "PRIVILEGED_CONTAINER",
                "BLOCK",
                f"{field_prefix}.securityContext.privileged",
                "privileged containers are not permitted",
                {"container": container_name},
            )
        if sc.get("allowPrivilegeEscalation") is not False:
            findings.add(
                "PRIVILEGE_ESCALATION_ALLOWED",
                "BLOCK",
                f"{field_prefix}.securityContext.allowPrivilegeEscalation",
                "allowPrivilegeEscalation must be explicitly false",
                {"container": container_name, "value": sc.get("allowPrivilegeEscalation")},
            )
        if sc.get("runAsUser") == 0 or pod_sc.get("runAsUser") == 0:
            findings.add(
                "RUN_AS_ROOT",
                "BLOCK",
                f"{field_prefix}.securityContext.runAsUser",
                "running as UID 0 is not permitted",
                {"container": container_name},
            )
        non_root = sc.get("runAsNonRoot") if "runAsNonRoot" in sc else pod_sc.get("runAsNonRoot")
        if non_root is not True:
            findings.add(
                "RUN_AS_NONROOT_REQUIRED",
                "BLOCK",
                f"{field_prefix}.securityContext.runAsNonRoot",
                "runAsNonRoot must be explicitly true",
                {"container": container_name, "value": non_root},
            )
        capabilities = sc.get("capabilities")
        if isinstance(capabilities, Mapping):
            added = capabilities.get("add")
            if isinstance(added, list) and added:
                findings.add(
                    "CAPABILITIES_ADDED",
                    "BLOCK",
                    f"{field_prefix}.securityContext.capabilities.add",
                    "adding Linux capabilities is not permitted",
                    {"capabilities": added},
                )
            dropped = capabilities.get("drop")
            normalized_drop = [str(item).upper() for item in dropped] if isinstance(dropped, list) else []
            if "ALL" not in normalized_drop:
                findings.add(
                    "CAPABILITIES_NOT_DROPPED",
                    "REVIEW",
                    f"{field_prefix}.securityContext.capabilities.drop",
                    "all Linux capabilities should be dropped",
                    {"drop": dropped},
                )
        else:
            findings.add(
                "CAPABILITIES_NOT_DROPPED",
                "REVIEW",
                f"{field_prefix}.securityContext.capabilities",
                "capabilities.drop: [ALL] is missing",
            )
        if sc.get("readOnlyRootFilesystem") is not True:
            findings.add(
                "ROOT_FILESYSTEM_WRITABLE",
                "REVIEW",
                f"{field_prefix}.securityContext.readOnlyRootFilesystem",
                "readOnlyRootFilesystem should be true",
                {"container": container_name},
            )
        seccomp = sc.get("seccompProfile") if isinstance(sc.get("seccompProfile"), Mapping) else None
        if seccomp is None and isinstance(pod_sc.get("seccompProfile"), Mapping):
            seccomp = pod_sc.get("seccompProfile")
        seccomp_type = seccomp.get("type") if isinstance(seccomp, Mapping) else None
        if seccomp_type == "Unconfined":
            findings.add(
                "SECCOMP_UNCONFINED",
                "BLOCK",
                f"{field_prefix}.securityContext.seccompProfile.type",
                "Unconfined seccomp is not permitted",
                {"container": container_name},
            )
        elif seccomp_type not in {"RuntimeDefault", "Localhost"}:
            findings.add(
                "SECCOMP_PROFILE_MISSING",
                "REVIEW",
                f"{field_prefix}.securityContext.seccompProfile",
                "a RuntimeDefault seccomp profile should be set",
                {"container": container_name},
            )
        ports = container.get("ports")
        if isinstance(ports, list):
            for port_index, port in enumerate(ports):
                if isinstance(port, Mapping) and "hostPort" in port:
                    findings.add(
                        "HOST_PORT",
                        "BLOCK",
                        f"{field_prefix}.ports[{port_index}].hostPort",
                        "hostPort is not permitted",
                        {"container": container_name, "hostPort": port.get("hostPort")},
                    )


def _check_deployment(
    old_deployment: Mapping[str, Any] | None,
    new_deployment: Mapping[str, Any] | None,
    config: Mapping[str, Any],
    findings: _Findings,
) -> bool:
    if new_deployment is None:
        findings.add(
            "DEPLOYMENT_MISSING",
            "BLOCK",
            f"Deployment/{config['namespace']}/{config['deployment']}",
            "the configured Deployment would be deleted or is not rendered",
        )
        return False

    namespace = str(config["namespace"])
    name = str(config["deployment"])
    base = f"Deployment/{namespace}/{name}"
    spec = new_deployment.get("spec")
    if not isinstance(spec, Mapping):
        findings.add("DEPLOYMENT_INVALID", "BLOCK", base + ".spec", "Deployment spec is missing")
        return False

    replicas = _replicas(new_deployment)
    if replicas is None:
        findings.add(
            "REPLICAS_INVALID",
            "BLOCK",
            base + ".spec.replicas",
            "replicas must be a non-negative integer",
            {"value": spec.get("replicas")},
        )
    elif replicas == 0:
        findings.add(
            "REPLICAS_ZERO",
            "BLOCK",
            base + ".spec.replicas",
            "zero replicas is not an approved release",
        )

    selector = spec.get("selector")
    template = spec.get("template")
    if not isinstance(template, Mapping):
        findings.add(
            "POD_TEMPLATE_MISSING",
            "BLOCK",
            base + ".spec.template",
            "Pod template is missing",
        )
        return False
    template_metadata = template.get("metadata") if isinstance(template.get("metadata"), Mapping) else {}
    template_labels = template_metadata.get("labels") if isinstance(template_metadata.get("labels"), Mapping) else {}
    selector_labels = selector.get("matchLabels") if isinstance(selector, Mapping) else None
    if not isinstance(selector_labels, Mapping) or not selector_labels:
        findings.add(
            "SELECTOR_INVALID",
            "BLOCK",
            base + ".spec.selector.matchLabels",
            "Deployment selector must have matchLabels",
        )
    else:
        for label_key, label_value in selector_labels.items():
            if template_labels.get(label_key) != label_value:
                findings.add(
                    "SELECTOR_MISMATCH",
                    "BLOCK",
                    base + ".spec.selector.matchLabels",
                    "Pod template labels do not satisfy the immutable selector",
                    {"label": label_key, "expected": label_value, "actual": template_labels.get(label_key)},
                )
                break

    if old_deployment is not None:
        old_spec = old_deployment.get("spec") if isinstance(old_deployment.get("spec"), Mapping) else {}
        if _canonical_json(old_spec.get("selector")) != _canonical_json(selector):
            findings.add(
                "SELECTOR_CHANGED",
                "BLOCK",
                base + ".spec.selector",
                "changing a Deployment selector is immutable and risks orphaned Pods",
            )

    pod_spec = _pod_spec(new_deployment)
    if not isinstance(pod_spec.get("containers"), list) or not pod_spec.get("containers"):
        findings.add("CONTAINERS_MISSING", "BLOCK", base + ".spec.template.spec.containers", "no containers")
        return False
    regular_containers = list(_containers(new_deployment))
    init_containers = list(_init_containers(new_deployment))
    if len(regular_containers) != 1:
        findings.add(
            "CONTAINER_SET_NOT_ALLOWED",
            "BLOCK",
            base + ".spec.template.spec.containers",
            "exactly one fixed demo-service container is permitted",
            {"count": len(regular_containers), "expected": DEMO_CONTAINER_NAME},
        )
    if init_containers:
        findings.add(
            "INIT_CONTAINER_NOT_ALLOWED",
            "BLOCK",
            base + ".spec.template.spec.initContainers",
            "init containers are not permitted for the demo workload",
            {"count": len(init_containers)},
        )
    for index, container in enumerate(regular_containers):
        container_name = str(container.get("name", f"container-{index}"))
        field_prefix = f"Deployment.spec.template.spec.containers[{index}]"
        if container_name != DEMO_CONTAINER_NAME:
            findings.add(
                "CONTAINER_NAME_NOT_ALLOWED",
                "BLOCK",
                field_prefix + ".name",
                "only the fixed demo-service container is permitted",
                {"name": container_name, "expected": DEMO_CONTAINER_NAME},
            )
        for key in ("command", "args"):
            value = container.get(key)
            if value is not None and value != []:
                findings.add(
                    "CONTAINER_COMMAND_NOT_ALLOWED",
                    "BLOCK",
                    f"{field_prefix}.{key}",
                    "command/args overrides are not permitted for the fixed demo container",
                    {"container": container_name, key: value},
                )
        lifecycle = container.get("lifecycle")
        if lifecycle not in (None, {}):
            findings.add(
                "LIFECYCLE_NOT_ALLOWED",
                "BLOCK",
                field_prefix + ".lifecycle",
                "lifecycle hooks (including exec postStart/preStop) are not permitted",
                {"container": container_name},
            )
    for index, init_container in enumerate(init_containers):
        init_name = str(init_container.get("name", f"init-container-{index}"))
        findings.add(
            "INIT_CONTAINER_COMMAND_NOT_ALLOWED",
            "BLOCK",
            f"Deployment.spec.template.spec.initContainers[{index}]",
            "init containers may not run candidate commands",
            {"name": init_name},
        )
    names: set[str] = set()
    for container in _containers(new_deployment):
        container_name = container.get("name")
        if not isinstance(container_name, str) or not container_name:
            findings.add("CONTAINER_NAME_INVALID", "BLOCK", base + ".containers", "container name is missing")
            continue
        if container_name in names:
            findings.add(
                "CONTAINER_NAME_DUPLICATE",
                "BLOCK",
                base + ".containers",
                "container name is duplicated",
                {"name": container_name},
            )
        names.add(container_name)
    for init_container in _init_containers(new_deployment):
        init_name = init_container.get("name")
        if not isinstance(init_name, str) or not init_name:
            findings.add("CONTAINER_NAME_INVALID", "BLOCK", base + ".initContainers", "init container name missing")
        elif init_name in names:
            findings.add(
                "CONTAINER_NAME_DUPLICATE",
                "BLOCK",
                base + ".initContainers",
                "init container name collides with a container",
                {"name": init_name},
            )
        else:
            names.add(init_name)

    container_groups = (
        ("containers", list(_containers(new_deployment))),
        ("initContainers", list(_init_containers(new_deployment))),
    )
    for group_name, group_containers in container_groups:
        for index, container in enumerate(group_containers):
            container_name = str(container.get("name", f"container-{index}"))
            prefix = f"Deployment.spec.template.spec.{group_name}[{index}]"
            _check_image(container.get("image"), prefix + ".image", config, findings)
            _check_env(container, prefix, findings)
            if not isinstance(container.get("resources"), Mapping):
                findings.add(
                    "RESOURCE_REQUESTS_MISSING",
                    "REVIEW",
                    prefix + ".resources",
                    "resource requests are missing; capacity cannot be reserved",
                    {"container": container_name},
                )
            else:
                resources = container["resources"]
                requests = resources.get("requests") if isinstance(resources.get("requests"), Mapping) else {}
                limits = resources.get("limits") if isinstance(resources.get("limits"), Mapping) else {}
                if "cpu" not in requests or "memory" not in requests:
                    findings.add(
                        "RESOURCE_REQUESTS_MISSING",
                        "REVIEW",
                        prefix + ".resources.requests",
                        "CPU and memory requests should both be set",
                        {"container": container_name},
                    )
                for resource_name, parser in (("cpu", _cpu_millicores), ("memory", _memory_bytes)):
                    request_value = requests.get(resource_name)
                    limit_value = limits.get(resource_name)
                    if request_value is not None and parser(request_value) is None:
                        findings.add(
                            "INVALID_RESOURCE_QUANTITY",
                            "BLOCK",
                            f"{prefix}.resources.requests.{resource_name}",
                            "invalid Kubernetes resource quantity",
                            {"value": request_value},
                        )
                    if limit_value is not None and parser(limit_value) is None:
                        findings.add(
                            "INVALID_RESOURCE_QUANTITY",
                            "BLOCK",
                            f"{prefix}.resources.limits.{resource_name}",
                            "invalid Kubernetes resource quantity",
                            {"value": limit_value},
                        )
                    parsed_request = parser(request_value) if request_value is not None else None
                    parsed_limit = parser(limit_value) if limit_value is not None else None
                    if parsed_request is not None and parsed_limit is not None and parsed_limit < parsed_request:
                        findings.add(
                            "RESOURCE_LIMIT_BELOW_REQUEST",
                            "BLOCK",
                            f"{prefix}.resources",
                            f"{resource_name} limit is below its request",
                        )

    for index, container in enumerate(_containers(new_deployment)):
        prefix = f"Deployment.spec.template.spec.containers[{index}]"
        _check_probe(container, prefix, "readinessProbe", "BLOCK", findings)
        _check_probe(container, prefix, "livenessProbe", "BLOCK", findings)
        _check_probe(container, prefix, "startupProbe", "REVIEW", findings)

    _check_security(new_deployment, findings)
    return True


def _check_memory(metrics: Mapping[str, Any], new_deployment: Mapping[str, Any] | None, config: Mapping[str, Any], findings: _Findings) -> None:
    if new_deployment is None:
        return
    memory, _ts, _raw = _metric(metrics, "memory_working_set_bytes")
    if memory is None:
        return
    pod_resources = _pod_resources(new_deployment)
    limit = pod_resources["memory_limit_bytes"]
    if limit is None or not pod_resources["memory_limit_complete"]:
        findings.add(
            "MEMORY_LIMIT_MISSING",
            "ERROR",
            "Deployment.spec.template.spec.containers[].resources.limits.memory",
            "cannot assess the memory safety threshold without a complete Pod memory limit",
            {"measured_max_over_15m": memory},
        )
        return
    factor = _number(config.get("memory_headroom_factor")) or DEFAULT_MEMORY_HEADROOM_FACTOR
    threshold = factor * memory
    if limit < threshold:
        findings.add(
            "MEMORY_LIMIT_TOO_LOW",
            "BLOCK",
            "Deployment.spec.template.spec.containers[].resources.limits.memory",
            "Pod memory limit is below the required headroom over the 15m observed maximum",
            {
                "memory_limit_bytes": limit,
                "max_over_15m_bytes": memory,
                "headroom_factor": factor,
                "required_at_least_bytes": threshold,
            },
        )


def _check_resource_reduction(
    old_deployment: Mapping[str, Any] | None,
    new_deployment: Mapping[str, Any] | None,
    findings: _Findings,
) -> None:
    if old_deployment is None or new_deployment is None:
        return
    old = _pod_resources(old_deployment)
    new = _pod_resources(new_deployment)
    keys = (
        ("cpu_request_millicores", "CPU request"),
        ("memory_request_bytes", "memory request"),
        ("cpu_limit_millicores", "CPU limit"),
        ("memory_limit_bytes", "memory limit"),
    )
    for key, label in keys:
        old_value = old.get(key)
        new_value = new.get(key)
        if not isinstance(old_value, (int, float)) or old_value <= 0:
            continue
        if not isinstance(new_value, (int, float)):
            continue
        if new_value < old_value * 0.5:
            findings.add(
                "RESOURCE_REDUCTION",
                "REVIEW",
                f"Deployment.spec.template.spec.containers[].resources.{key}",
                f"the Pod {label} is reduced by more than 50%",
                {
                    "resource": key,
                    "old": old_value,
                    "new": new_value,
                    "reduction_fraction": 1.0 - (new_value / old_value),
                },
            )


def _node_ready(node: Mapping[str, Any]) -> bool:
    if isinstance(node.get("ready"), bool):
        return bool(node["ready"])
    status = node.get("status") if isinstance(node.get("status"), Mapping) else {}
    conditions = status.get("conditions")
    if isinstance(conditions, list):
        for condition in conditions:
            if isinstance(condition, Mapping) and condition.get("type") == "Ready":
                return str(condition.get("status", "")).lower() == "true"
    return False


def _node_is_worker(node: Mapping[str, Any]) -> bool:
    if "control_plane" in node:
        return not bool(node.get("control_plane"))
    labels = node.get("labels") if isinstance(node.get("labels"), Mapping) else {}
    if "node-role.kubernetes.io/control-plane" in labels or "node-role.kubernetes.io/master" in labels:
        return False
    if node.get("spec", {}).get("unschedulable") if isinstance(node.get("spec"), Mapping) else False:
        return False
    taints = node.get("taints")
    if not isinstance(taints, list) and isinstance(node.get("spec"), Mapping):
        taints = node["spec"].get("taints")
    if isinstance(taints, list):
        for taint in taints:
            if isinstance(taint, Mapping) and taint.get("effect") == "NoSchedule":
                return False
    if node.get("schedulable") is False:
        return False
    return True


def _node_allocatable(node: Mapping[str, Any], resource: str) -> float | None:
    if resource == "cpu":
        for key in ("allocatable_cpu_millicores", "cpu_millicores"):
            if key in node:
                parsed = _number(node.get(key))
                if parsed is not None:
                    return parsed
    else:
        for key in ("allocatable_memory_bytes", "memory_bytes"):
            if key in node:
                parsed = _number(node.get(key))
                if parsed is not None:
                    return parsed
    allocatable = node.get("allocatable")
    if not isinstance(allocatable, Mapping):
        status = node.get("status") if isinstance(node.get("status"), Mapping) else {}
        allocatable = status.get("allocatable") if isinstance(status.get("allocatable"), Mapping) else {}
    if not isinstance(allocatable, Mapping):
        return None
    return _cpu_millicores(allocatable.get("cpu")) if resource == "cpu" else _memory_bytes(allocatable.get("memory"))


def _pod_phase_done(pod: Mapping[str, Any]) -> bool:
    phase = pod.get("phase") or (pod.get("status", {}).get("phase") if isinstance(pod.get("status"), Mapping) else None)
    return phase in {"Succeeded", "Failed"}


def _pod_node(pod: Mapping[str, Any]) -> str:
    if pod.get("node"):
        return str(pod["node"])
    spec = pod.get("spec") if isinstance(pod.get("spec"), Mapping) else {}
    return str(spec.get("nodeName") or "")


def _current_demo_pod_requests(evidence: Mapping[str, Any]) -> tuple[float | None, float | None]:
    """Current target Deployment Pod requests from collected evidence."""

    deployment = evidence.get("deployment")
    if not isinstance(deployment, Mapping):
        return None, None
    containers = deployment.get("containers")
    if not isinstance(containers, list) or not containers:
        return None, None
    spec = {"containers": containers}
    cpu, cpu_invalid, _ = _pod_requests_from_spec(spec, quantity="cpu", parser=_cpu_millicores)
    memory, memory_invalid, _ = _pod_requests_from_spec(spec, quantity="memory", parser=_memory_bytes)
    if cpu_invalid or memory_invalid:
        return None, None
    return cpu, memory


def _check_scheduling(
    new_deployment: Mapping[str, Any] | None,
    evidence: Mapping[str, Any],
    findings: _Findings,
) -> None:
    if not isinstance(new_deployment, Mapping):
        return
    pod_spec = _pod_spec(new_deployment)
    field_base = "Deployment.spec.template.spec"
    markers = ("control-plane", "node-role.kubernetes.io/master", "master")

    def claims_control_plane(value: Any) -> bool:
        try:
            text = _canonical_json(value).lower()
        except (TypeError, ValueError):
            text = str(value).lower()
        return any(marker in text for marker in markers)

    nodes = evidence.get("nodes")
    worker_labels: list[Mapping[str, Any]] = []
    if isinstance(nodes, list):
        for node in nodes:
            if isinstance(node, Mapping) and _node_ready(node) and _node_is_worker(node):
                labels = node.get("labels")
                worker_labels.append(labels if isinstance(labels, Mapping) else {})

    node_selector = pod_spec.get("nodeSelector")
    if isinstance(node_selector, Mapping) and node_selector:
        if claims_control_plane(node_selector):
            findings.add(
                "CONTROL_PLANE_SCHEDULING",
                "BLOCK",
                field_base + ".nodeSelector",
                "nodeSelector targets the control plane, which is outside the capacity model",
                {"nodeSelector": node_selector},
            )
        elif not any(
            all(labels.get(str(key)) == str(value) for key, value in node_selector.items())
            for labels in worker_labels
        ):
            findings.add(
                "SCHEDULING_UNVERIFIED",
                "REVIEW",
                field_base + ".nodeSelector",
                "nodeSelector cannot be matched to a Ready schedulable worker from evidence",
                {"nodeSelector": node_selector},
            )

    affinity = pod_spec.get("affinity")
    if isinstance(affinity, Mapping) and affinity:
        if claims_control_plane(affinity):
            findings.add(
                "CONTROL_PLANE_SCHEDULING",
                "BLOCK",
                field_base + ".affinity",
                "affinity targets the control plane, which is outside the capacity model",
            )
        else:
            findings.add(
                "SCHEDULING_UNVERIFIED",
                "REVIEW",
                field_base + ".affinity",
                "affinity rules cannot be proven to stay on workers already counted for capacity",
            )

    tolerations = pod_spec.get("tolerations")
    if isinstance(tolerations, list) and tolerations:
        control_toleration = False
        broad_toleration = False
        for toleration in tolerations:
            if not isinstance(toleration, Mapping):
                continue
            key = str(toleration.get("key", ""))
            operator = str(toleration.get("operator", "Equal"))
            if key.startswith("node-role.kubernetes.io/control-plane") or key.startswith(
                "node-role.kubernetes.io/master"
            ):
                control_toleration = True
            if not key and operator == "Exists":
                broad_toleration = True
        if control_toleration or broad_toleration:
            findings.add(
                "CONTROL_PLANE_TOLERATION",
                "BLOCK",
                field_base + ".tolerations",
                "toleration can place the workload on a tainted control-plane node",
                {"tolerations": tolerations},
            )
        else:
            findings.add(
                "SCHEDULING_UNVERIFIED",
                "REVIEW",
                field_base + ".tolerations",
                "toleration intent cannot be verified against the counted worker set",
                {"tolerations": tolerations},
            )


def _check_scheduled_pod_requests(evidence: Mapping[str, Any], findings: _Findings) -> None:
    """Record invalid/unreserved requests even when capacity is precomputed."""

    nodes = evidence.get("nodes")
    pods = evidence.get("pods")
    if not isinstance(nodes, list) or not isinstance(pods, list):
        return
    worker_names = {
        str(node.get("name") or "")
        for node in nodes
        if isinstance(node, Mapping) and _node_ready(node) and _node_is_worker(node)
    }
    worker_names.discard("")
    if not worker_names:
        return
    invalid_requests = 0
    unreserved_requests = 0
    for pod in pods:
        if not isinstance(pod, Mapping) or _pod_phase_done(pod):
            continue
        if _pod_node(pod) not in worker_names:
            continue
        spec = pod.get("spec") if isinstance(pod.get("spec"), Mapping) else pod
        _cpu, cpu_invalid, cpu_unreserved = _pod_requests_from_spec(
            spec, quantity="cpu", parser=_cpu_millicores
        )
        _memory, memory_invalid, memory_unreserved = _pod_requests_from_spec(
            spec, quantity="memory", parser=_memory_bytes
        )
        invalid_requests += cpu_invalid + memory_invalid
        unreserved_requests += cpu_unreserved + memory_unreserved
    if invalid_requests:
        findings.add(
            "CAPACITY_POD_REQUESTS_INVALID",
            "ERROR",
            "evidence.pods[].spec.containers[].resources.requests",
            "some scheduled Pods have malformed resource requests, so free capacity cannot be proven",
            {"invalid_requests": invalid_requests},
        )
    if unreserved_requests:
        findings.add(
            "CAPACITY_POD_REQUESTS_UNRESERVED",
            "REVIEW",
            "evidence.pods[].spec.containers[].resources.requests",
            "some scheduled Pods have no CPU/memory requests and are treated as zero; free capacity may be overstated",
            {"unreserved_requests": unreserved_requests},
        )


def _capacity_from_nodes_and_pods(evidence: Mapping[str, Any], findings: _Findings) -> dict[str, Any] | None:
    nodes = evidence.get("nodes")
    pods = evidence.get("pods")
    if not isinstance(nodes, list) or not nodes:
        return None
    if not isinstance(pods, list):
        return None
    workers = [node for node in nodes if isinstance(node, Mapping) and _node_ready(node) and _node_is_worker(node)]
    worker_names = {str(node.get("name") or node.get("metadata", {}).get("name") or "") for node in workers}
    worker_names.discard("")
    if not workers:
        return {
            "available_cpu_millicores": 0.0,
            "available_memory_bytes": 0.0,
            "workers_ready": 0,
            "allocatable_cpu_millicores": 0.0,
            "allocatable_memory_bytes": 0.0,
            "existing_pods_requests_cpu_millicores": 0.0,
            "existing_pods_requests_memory_bytes": 0.0,
            "worker_names": [],
            "source": "nodes",
            "overcommitted": False,
        }
    alloc_cpu = 0.0
    alloc_memory = 0.0
    incomplete_nodes = 0
    for node in workers:
        cpu = _node_allocatable(node, "cpu")
        memory = _node_allocatable(node, "memory")
        if cpu is None or memory is None:
            incomplete_nodes += 1
            continue
        alloc_cpu += cpu
        alloc_memory += memory
    if incomplete_nodes:
        findings.add(
            "CAPACITY_NODE_DATA_INCOMPLETE",
            "ERROR",
            "evidence.nodes[].allocatable",
            "Ready worker allocatable CPU/memory is incomplete",
            {"incomplete_workers": incomplete_nodes},
        )
    used_cpu = 0.0
    used_memory = 0.0
    invalid_requests = 0
    unreserved_requests = 0
    for pod in pods:
        if not isinstance(pod, Mapping) or _pod_phase_done(pod):
            continue
        if _pod_node(pod) not in worker_names:
            continue
        spec = pod.get("spec") if isinstance(pod.get("spec"), Mapping) else pod
        cpu, cpu_invalid, cpu_unreserved = _pod_requests_from_spec(
            spec, quantity="cpu", parser=_cpu_millicores
        )
        memory, memory_invalid, memory_unreserved = _pod_requests_from_spec(
            spec, quantity="memory", parser=_memory_bytes
        )
        used_cpu += cpu or 0.0
        used_memory += memory or 0.0
        invalid_requests += cpu_invalid + memory_invalid
        unreserved_requests += cpu_unreserved + memory_unreserved
    if invalid_requests:
        findings.add(
            "CAPACITY_POD_REQUESTS_INVALID",
            "ERROR",
            "evidence.pods[].spec.containers[].resources.requests",
            "some scheduled Pods have malformed resource requests, so free capacity cannot be proven",
            {"invalid_requests": invalid_requests},
        )
    if unreserved_requests:
        # The API omits an unreserved request and the scheduler treats it as
        # zero.  Record the overstatement risk as REVIEW; this is not missing
        # telemetry.
        findings.add(
            "CAPACITY_POD_REQUESTS_UNRESERVED",
            "REVIEW",
            "evidence.pods[].spec.containers[].resources.requests",
            "some scheduled Pods have no CPU/memory requests and are treated as zero; free capacity may be overstated",
            {"unreserved_requests": unreserved_requests},
        )
    available_cpu = alloc_cpu - used_cpu
    available_memory = alloc_memory - used_memory
    return {
        "available_cpu_millicores": max(0.0, available_cpu),
        "available_memory_bytes": max(0.0, available_memory),
        "workers_ready": len(workers),
        "allocatable_cpu_millicores": alloc_cpu,
        "allocatable_memory_bytes": alloc_memory,
        "existing_pods_requests_cpu_millicores": used_cpu,
        "existing_pods_requests_memory_bytes": used_memory,
        "unreserved_request_containers": unreserved_requests,
        "invalid_request_containers": invalid_requests,
        "worker_names": sorted(worker_names),
        "source": "nodes+pods",
        "overcommitted": available_cpu < 0 or available_memory < 0,
    }


def _capacity_snapshot(evidence: Mapping[str, Any], findings: _Findings) -> dict[str, Any] | None:
    explicit = evidence.get("capacity")
    if isinstance(explicit, Mapping):
        cpu = _parse_quantity(explicit.get("available_cpu_millicores"))
        memory = _parse_quantity(explicit.get("available_memory_bytes"))
        if cpu is not None and memory is not None and cpu >= 0 and memory >= 0:
            _check_scheduled_pod_requests(evidence, findings)
            workers = explicit.get("workers_ready")
            if isinstance(workers, bool) or not isinstance(workers, int):
                workers = explicit.get("workers")
            if isinstance(workers, bool) or not isinstance(workers, int):
                workers = None
            return {
                "available_cpu_millicores": cpu,
                "available_memory_bytes": memory,
                "workers_ready": workers,
                "allocatable_cpu_millicores": _parse_quantity(explicit.get("allocatable_cpu_millicores")),
                "allocatable_memory_bytes": _parse_quantity(explicit.get("allocatable_memory_bytes")),
                "existing_pods_requests_cpu_millicores": _parse_quantity(
                    explicit.get("existing_pods_requests_cpu_millicores")
                ),
                "existing_pods_requests_memory_bytes": _parse_quantity(
                    explicit.get("existing_pods_requests_memory_bytes")
                ),
                "worker_names": explicit.get("worker_names") if isinstance(explicit.get("worker_names"), list) else [],
                "source": "evidence.capacity",
                "overcommitted": bool(explicit.get("overcommitted", False)),
            }
    computed = _capacity_from_nodes_and_pods(evidence, findings)
    if computed is not None:
        return computed
    return None


def _check_capacity(
    evidence: Mapping[str, Any],
    old_deployment: Mapping[str, Any] | None,
    new_deployment: Mapping[str, Any] | None,
    findings: _Findings,
) -> dict[str, Any]:
    if new_deployment is None:
        return {}
    replicas = _replicas(new_deployment)
    if replicas is None:
        return {}
    resources = _pod_resources(new_deployment)
    cpu_invalid = resources["cpu_request_invalid_containers"]
    memory_invalid = resources["memory_request_invalid_containers"]
    cpu_unreserved = resources["cpu_request_unreserved_containers"]
    memory_unreserved = resources["memory_request_unreserved_containers"]
    if cpu_invalid or memory_invalid:
        findings.add(
            "CAPACITY_REQUESTS_INVALID",
            "ERROR",
            "Deployment.spec.template.spec.containers[].resources.requests",
            "Pod resource requests contain malformed quantities, so capacity cannot be proven",
            {"cpu_invalid_containers": cpu_invalid, "memory_invalid_containers": memory_invalid},
        )
    if cpu_unreserved or memory_unreserved:
        findings.add(
            "CAPACITY_REQUESTS_UNRESERVED",
            "REVIEW",
            "Deployment.spec.template.spec.containers[].resources.requests",
            "CPU/memory requests are omitted; Kubernetes schedules them as zero and they remain unreserved",
            {"cpu_unreserved_containers": cpu_unreserved, "memory_unreserved_containers": memory_unreserved},
        )
    pod_cpu = float(resources["cpu_request_millicores"] or 0.0)
    pod_memory = float(resources["memory_request_bytes"] or 0.0)
    surge, strategy_valid = _strategy_surge(new_deployment, replicas)
    if not strategy_valid:
        findings.add(
            "ROLLOUT_STRATEGY_INVALID",
            "BLOCK",
            "Deployment.spec.strategy",
            "rolling update strategy is invalid",
        )
        surge = 0
    old_replicas = _replicas(old_deployment) if old_deployment is not None else 0
    rolling = old_deployment is not None and old_replicas is not None and old_replicas > 0

    old_pod_cpu = 0.0
    old_pod_memory = 0.0
    if old_deployment is not None:
        old_resources = _pod_resources(old_deployment)
        old_pod_cpu = float(old_resources["cpu_request_millicores"] or 0.0)
        old_pod_memory = float(old_resources["memory_request_bytes"] or 0.0)
    current_cpu, current_memory = _current_demo_pod_requests(evidence)
    current_target = evidence.get("deployment")
    current_replicas = (
        _number(current_target.get("replicas")) if isinstance(current_target, Mapping) else None
    )
    if (
        current_cpu is not None
        and current_memory is not None
        and rolling
        and current_replicas is not None
        and int(current_replicas) == int(old_replicas or 0)
    ):
        # Current rollout Pods are authoritative only when they correspond to
        # the same replica set as the old rendered Deployment.  A stale or
        # mismatched fixture must not hide retained-old reservations.
        old_pod_cpu = float(current_cpu)
        old_pod_memory = float(current_memory)

    if rolling:
        old_count = int(old_replicas or 0)
        # A rolling update can temporarily retain every old Pod while adding
        # surge/new Pods, so reserve old requests + new Pod requests.  This is
        # deliberately conservative for maxUnavailable.
        peak_total_pods = max(old_count, replicas) + surge
        new_pods_at_peak = max(0, peak_total_pods - old_count)
        peak_demo_cpu = old_count * old_pod_cpu + new_pods_at_peak * pod_cpu
        peak_demo_memory = old_count * old_pod_memory + new_pods_at_peak * pod_memory
        old_cpu_total = old_count * old_pod_cpu
        old_memory_total = old_count * old_pod_memory
        required_cpu = max(0.0, peak_demo_cpu - old_cpu_total)
        required_memory = max(0.0, peak_demo_memory - old_memory_total)
        additional_pods = new_pods_at_peak
    else:
        old_count = 0
        peak_total_pods = replicas
        new_pods_at_peak = replicas
        peak_demo_cpu = replicas * pod_cpu
        peak_demo_memory = replicas * pod_memory
        old_cpu_total = 0.0
        old_memory_total = 0.0
        required_cpu = peak_demo_cpu
        required_memory = peak_demo_memory
        additional_pods = replicas
    capacity = _capacity_snapshot(evidence, findings)
    audit = {
        "pod_request_cpu_millicores": pod_cpu,
        "pod_request_memory_bytes": pod_memory,
        "old_pod_request_cpu_millicores": old_pod_cpu if rolling else 0.0,
        "old_pod_request_memory_bytes": old_pod_memory if rolling else 0.0,
        "replicas": replicas,
        "surge_pods": surge,
        "new_pods_reserved": additional_pods,
        "additional_pods_reserved": additional_pods,
        "peak_total_pods": peak_total_pods,
        "peak_demo_cpu_millicores": peak_demo_cpu,
        "peak_demo_memory_bytes": peak_demo_memory,
        "retained_old_replicas": old_count if rolling else 0,
        "required_cpu_millicores": required_cpu,
        "required_memory_bytes": required_memory,
        "source": None,
    }
    if capacity is None:
        findings.add(
            "CAPACITY_MISSING",
            "ERROR",
            "evidence.capacity",
            "scheduling capacity evidence is missing",
        )
        return audit
    audit.update(capacity)
    workers = capacity.get("workers_ready")
    if workers == 0:
        findings.add(
            "NO_SCHEDULABLE_WORKER",
            "REVIEW",
            "evidence.capacity.workers_ready",
            "no Ready, schedulable worker is available for the rollout",
            {"capacity": capacity},
        )
    elif capacity.get("overcommitted"):
        findings.add(
            "CAPACITY_OVERCOMMITTED",
            "REVIEW",
            "evidence.capacity",
            "existing Pod requests already exceed worker allocatable capacity",
            {"capacity": capacity},
        )
    cpu_available = float(capacity["available_cpu_millicores"])
    memory_available = float(capacity["available_memory_bytes"])
    insufficient = required_cpu > cpu_available or required_memory > memory_available

    allocatable_cpu = _number(capacity.get("allocatable_cpu_millicores"))
    allocatable_memory = _number(capacity.get("allocatable_memory_bytes"))
    existing_cpu = _number(capacity.get("existing_pods_requests_cpu_millicores"))
    existing_memory = _number(capacity.get("existing_pods_requests_memory_bytes"))
    projected_cpu: float | None = None
    projected_memory: float | None = None
    if rolling:
        if existing_cpu is not None and old_cpu_total:
            projected_cpu = max(0.0, existing_cpu - old_cpu_total) + peak_demo_cpu
        if existing_memory is not None and old_memory_total:
            projected_memory = max(0.0, existing_memory - old_memory_total) + peak_demo_memory
        if projected_cpu is not None and allocatable_cpu is not None and projected_cpu > allocatable_cpu:
            insufficient = True
        if (
            projected_memory is not None
            and allocatable_memory is not None
            and projected_memory > allocatable_memory
        ):
            insufficient = True
        # Minimal external capacity fixtures only carry the available number.
        # When the new request is lower than the retained old request, compare
        # the conservative old+surge peak against that budget as well.
        if (
            allocatable_cpu is None
            and existing_cpu is None
            and old_pod_cpu > pod_cpu
            and peak_demo_cpu > cpu_available
        ):
            insufficient = True
        if (
            allocatable_memory is None
            and existing_memory is None
            and old_pod_memory > pod_memory
            and peak_demo_memory > memory_available
        ):
            insufficient = True
    audit["projected_total_cpu_millicores"] = projected_cpu
    audit["projected_total_memory_bytes"] = projected_memory
    if insufficient:
        findings.add(
            "CAPACITY_INSUFFICIENT",
            "REVIEW",
            "evidence.capacity",
            "rolling rollout with old Pods retained and surge Pods does not fit available worker capacity",
            {
                "required_cpu_millicores": required_cpu,
                "available_cpu_millicores": cpu_available,
                "required_memory_bytes": required_memory,
                "available_memory_bytes": memory_available,
                "surge_pods": surge,
                "additional_pods_reserved": additional_pods,
                "peak_total_pods": peak_total_pods,
                "retained_old_replicas": old_count if rolling else 0,
                "peak_demo_cpu_millicores": peak_demo_cpu,
                "peak_demo_memory_bytes": peak_demo_memory,
                "projected_total_cpu_millicores": projected_cpu,
                "projected_total_memory_bytes": projected_memory,
                "allocatable_cpu_millicores": allocatable_cpu,
                "allocatable_memory_bytes": allocatable_memory,
            },
        )
    return audit


def _relevant_firing_alerts(alerts: Any, namespace: str, deployment: str) -> list[dict[str, Any]]:
    if isinstance(alerts, bool):
        return []
    if isinstance(alerts, int):
        return [{"name": "<unspecified>", "state": "firing", "count": alerts}] if alerts > 0 else []
    if not isinstance(alerts, list):
        return []
    relevant: list[dict[str, Any]] = []
    for alert in alerts:
        if isinstance(alert, str):
            if alert.strip().lower() in {"firing", "active"}:
                relevant.append({"name": alert, "state": "firing"})
            continue
        if not isinstance(alert, Mapping):
            continue
        state = str(alert.get("state", alert.get("status", alert.get("alertstate", "firing")))).lower()
        if state not in {"firing", "active"}:
            continue
        labels = alert.get("labels") if isinstance(alert.get("labels"), Mapping) else {}
        alert_name = str(alert.get("name") or labels.get("alertname") or "")
        if alert_name == "Watchdog" or labels.get("severity") == "none":
            continue
        alert_namespace = labels.get("namespace")
        alert_deployment = labels.get("deployment") or labels.get("app") or labels.get("app_kubernetes_io_name")
        if alert_namespace not in (None, "", namespace):
            continue
        if alert_deployment not in (None, "", deployment):
            continue
        relevant.append(_json_safe(dict(alert)))
    return relevant


def _check_metrics(
    evidence: Mapping[str, Any],
    config: Mapping[str, Any],
    new_deployment: Mapping[str, Any] | None,
    findings: _Findings,
    now: float,
    ttl: int,
) -> tuple[dict[str, Any], float | None]:
    audit: dict[str, Any] = {}
    errors = evidence.get("errors")
    if isinstance(errors, list):
        for index, error in enumerate(errors[:25]):
            text = str(error)
            findings.add(
                "EVIDENCE_ERROR",
                "ERROR",
                f"evidence.errors[{index}]",
                "evidence collection reported an error",
                {"error": text[:800]},
            )
    elif errors:
        findings.add(
            "EVIDENCE_ERROR",
            "ERROR",
            "evidence.errors",
            "evidence collection reported an error",
            {"error": str(errors)[:800]},
        )

    target = evidence.get("deployment")
    if not isinstance(target, Mapping) or not target:
        findings.add(
            "TARGET_EVIDENCE_MISSING",
            "ERROR",
            "evidence.deployment",
            "current target Deployment health evidence is missing",
        )
    else:
        desired = _number(target.get("replicas"))
        ready = _number(target.get("ready_replicas"))
        available = _number(target.get("available_replicas"))
        if desired is None or ready is None or available is None:
            findings.add(
                "TARGET_HEALTH_MISSING",
                "ERROR",
                "evidence.deployment",
                "ready/available/desired replica fields are missing or invalid",
                {"replicas": target.get("replicas"), "ready_replicas": target.get("ready_replicas"), "available_replicas": target.get("available_replicas")},
            )
        elif desired <= 0 or ready < 1:
            findings.add(
                "TARGET_NOT_READY",
                "REVIEW",
                "evidence.deployment.ready_replicas",
                "the target Deployment is offline (zero Ready replicas), so healthy metrics cannot be attributed to it",
                {"replicas": desired, "ready_replicas": ready, "available_replicas": available},
            )
        elif ready < desired or available < desired:
            findings.add(
                "TARGET_DEGRADED",
                "REVIEW",
                "evidence.deployment",
                "the target Deployment has fewer Ready/available replicas than desired",
                {"replicas": desired, "ready_replicas": ready, "available_replicas": available},
            )

    collected_at = _timestamp(evidence.get("collected_at"))
    min_timestamp: float | None = collected_at
    if collected_at is None:
        findings.add(
            "EVIDENCE_TIMESTAMP_MISSING",
            "ERROR",
            "evidence.collected_at",
            "evidence has no valid collection timestamp",
        )
    else:
        if now - collected_at > ttl:
            findings.add(
                "EVIDENCE_STALE",
                "ERROR",
                "evidence.collected_at",
                "evidence is older than the configured TTL",
                {"age_seconds": now - collected_at, "ttl_seconds": ttl},
            )
        if collected_at - now > CLOCK_SKEW_TOLERANCE_SECONDS:
            findings.add(
                "EVIDENCE_TIMESTAMP_FUTURE",
                "ERROR",
                "evidence.collected_at",
                "evidence timestamp is in the future",
                {"delta_seconds": collected_at - now},
            )

    metrics = evidence.get("metrics")
    if not isinstance(metrics, Mapping):
        findings.add(
            "METRICS_MISSING",
            "ERROR",
            "evidence.metrics",
            "metrics evidence is missing",
        )
        return audit, min_timestamp

    thresholds = {
        "low_traffic_rps": _number(config.get("low_traffic_rps")) or DEFAULT_LOW_TRAFFIC_RPS,
        "max_error_ratio": _number(config.get("max_error_ratio")) or DEFAULT_MAX_ERROR_RATIO,
        "max_p95_seconds": _number(config.get("max_p95_seconds")) or DEFAULT_MAX_P95_SECONDS,
    }
    memory, memory_ts, _ = _metric(metrics, "memory_working_set_bytes")
    request_rate, request_ts, _ = _metric(metrics, "request_rate")
    error_ratio, error_ts, _ = _metric(metrics, "error_ratio")
    p95, p95_ts, _ = _metric(metrics, "p95_seconds")
    up_metric, up_ts, _ = _metric(metrics, "up")

    low_traffic = request_rate is not None and request_rate < thresholds["low_traffic_rps"]
    required_metrics: list[tuple[str, float | None, float | None, str]] = [
        ("memory_working_set_bytes", memory, memory_ts, "memory_working_set_bytes"),
        ("request_rate", request_rate, request_ts, "request_rate"),
    ]
    if error_ratio is not None or not low_traffic:
        required_metrics.append(("error_ratio", error_ratio, error_ts, "error_ratio"))
    if p95 is not None or not low_traffic:
        required_metrics.append(("p95_seconds", p95, p95_ts, "p95_seconds"))
    if "up" in metrics and up_metric is not None:
        required_metrics.append(("up", up_metric, up_ts, "up"))

    if memory is None:
        findings.add(
            "METRIC_MISSING_OR_INVALID",
            "ERROR",
            "evidence.metrics.memory_working_set_bytes",
            "memory max-over-15m is missing or non-finite",
            {"raw": _json_safe(metrics.get("memory_working_set_bytes"))},
        )
    elif memory < 0:
        findings.add(
            "METRIC_MISSING_OR_INVALID",
            "ERROR",
            "evidence.metrics.memory_working_set_bytes",
            "memory measurement is negative",
            {"value": memory},
        )
    if request_rate is None:
        findings.add(
            "METRIC_MISSING_OR_INVALID",
            "ERROR",
            "evidence.metrics.request_rate",
            "request rate is missing or non-finite",
            {"raw": _json_safe(metrics.get("request_rate"))},
        )
    elif request_rate < 0:
        findings.add(
            "METRIC_MISSING_OR_INVALID",
            "ERROR",
            "evidence.metrics.request_rate",
            "request rate is negative",
            {"value": request_rate},
        )
    if error_ratio is None:
        if not low_traffic:
            findings.add(
                "METRIC_MISSING_OR_INVALID",
                "ERROR",
                "evidence.metrics.error_ratio",
                "error ratio is missing or non-finite",
                {"raw": _json_safe(metrics.get("error_ratio"))},
            )
    elif error_ratio < 0 or error_ratio > 1:
        findings.add(
            "METRIC_MISSING_OR_INVALID",
            "ERROR",
            "evidence.metrics.error_ratio",
            "error ratio is outside [0, 1]",
            {"value": error_ratio},
        )
    if p95 is None:
        if not low_traffic:
            findings.add(
                "METRIC_MISSING_OR_INVALID",
                "ERROR",
                "evidence.metrics.p95_seconds",
                "p95 latency is missing or non-finite",
                {"raw": _json_safe(metrics.get("p95_seconds"))},
            )
    elif p95 < 0:
        findings.add(
            "METRIC_MISSING_OR_INVALID",
            "ERROR",
            "evidence.metrics.p95_seconds",
            "p95 latency is negative",
            {"value": p95},
        )

    if "up" not in metrics:
        findings.add(
            "TARGET_UP_MISSING",
            "ERROR",
            "evidence.metrics.up",
            "target up/scrape evidence is required for every release evaluation",
        )
    elif up_metric is None:
        findings.add(
            "METRIC_MISSING_OR_INVALID",
            "ERROR",
            "evidence.metrics.up",
            "target up value is non-finite or invalid",
            {"raw": _json_safe(metrics.get("up"))},
        )
    elif up_metric < 1:
        findings.add(
            "TARGET_UP_NOT_READY",
            "REVIEW",
            "evidence.metrics.up",
            "Prometheus reports the target scrape as down",
            {"up": up_metric},
        )

    presence = metrics.get("series_presence")
    for source in ("up", "memory", "requests_total", "latency_bucket"):
        if not isinstance(presence, Mapping) or presence.get(source) is not True:
            findings.add(
                "LOW_TRAFFIC_SOURCE_MISSING" if low_traffic else "METRIC_SOURCE_MISSING",
                "ERROR",
                f"evidence.metrics.series_presence.{source}",
                "raw source series must exist for every release evaluation",
                {"source": source},
            )

    if "alerts" not in metrics:
        findings.add(
            "ALERTS_MISSING",
            "ERROR",
            "evidence.metrics.alerts",
            "firing alert evidence is missing",
        )
        relevant_alerts: list[dict[str, Any]] = []
    else:
        relevant_alerts = _relevant_firing_alerts(
            metrics.get("alerts"), str(config["namespace"]), str(config["deployment"])
        )

    def check_timestamp(key: str, embedded: float | None) -> float | None:
        nonlocal min_timestamp
        timestamp = _source_timestamp(evidence, metrics, key, embedded)
        if timestamp is None:
            findings.add(
                "METRIC_TIMESTAMP_MISSING",
                "ERROR",
                f"evidence.metrics.source_timestamps.{key}",
                "metric has no real source timestamp",
            )
            return None
        min_timestamp = timestamp if min_timestamp is None else min(min_timestamp, timestamp)
        if now - timestamp > ttl:
            findings.add(
                "METRIC_STALE",
                "ERROR",
                f"evidence.metrics.source_timestamps.{key}",
                "metric sample is older than the configured TTL",
                {"age_seconds": now - timestamp, "ttl_seconds": ttl},
            )
        if timestamp - now > CLOCK_SKEW_TOLERANCE_SECONDS:
            findings.add(
                "METRIC_TIMESTAMP_FUTURE",
                "ERROR",
                f"evidence.metrics.source_timestamps.{key}",
                "metric timestamp is in the future",
                {"delta_seconds": timestamp - now},
            )
        return timestamp

    for key, value, embedded_ts, _field_name in required_metrics:
        if value is None:
            continue
        check_timestamp(key, embedded_ts)

    # Evaluation time in a PromQL response is not source freshness.  For low
    # traffic, p95 is undefined but still requires a fresh raw histogram source.
    if low_traffic and p95 is None:
        check_timestamp("p95_seconds", p95_ts)

    if low_traffic:
        findings.add(
            "LOW_TRAFFIC",
            "REVIEW",
            "evidence.metrics.request_rate",
            "traffic is too low to treat observed zero errors or latency as healthy",
            {
                "request_rate": request_rate,
                "threshold_rps": thresholds["low_traffic_rps"],
                "error_ratio": error_ratio,
                "p95_seconds": p95,
            },
        )
    if error_ratio is not None and error_ratio > thresholds["max_error_ratio"]:
        findings.add(
            "HIGH_ERROR_RATIO",
            "REVIEW",
            "evidence.metrics.error_ratio",
            "the 5m error ratio exceeds the review threshold",
            {"error_ratio": error_ratio, "threshold": thresholds["max_error_ratio"]},
        )
    if p95 is not None and p95 > thresholds["max_p95_seconds"]:
        findings.add(
            "HIGH_P95_LATENCY",
            "REVIEW",
            "evidence.metrics.p95_seconds",
            "p95 latency exceeds the review threshold",
            {"p95_seconds": p95, "threshold": thresholds["max_p95_seconds"]},
        )
    if relevant_alerts:
        findings.add(
            "FIRING_ALERTS",
            "REVIEW",
            "evidence.metrics.alerts",
            "one or more relevant alerts are firing",
            {"alerts": relevant_alerts[:10], "count": len(relevant_alerts)},
        )

    if memory is not None:
        _check_memory(metrics, new_deployment, config, findings)
    audit.update(
        {
            "memory_working_set_bytes": memory,
            "request_rate": request_rate,
            "error_ratio": error_ratio,
            "p95_seconds": p95,
            "up": up_metric,
            "low_traffic": low_traffic,
            "firing_alerts": len(relevant_alerts),
            "source_timestamps": {
                key: _source_timestamp(evidence, metrics, key, embedded)
                for key, embedded in (
                    ("memory_working_set_bytes", memory_ts),
                    ("request_rate", request_ts),
                    ("error_ratio", error_ts),
                    ("p95_seconds", p95_ts),
                    ("up", up_ts),
                )
            },
        }
    )
    return audit, min_timestamp


def _check_tree_context(context: Mapping[str, Any], findings: _Findings) -> None:
    if context.get("argo_source_changed") is True:
        findings.add(
            "ARGOCD_SOURCE_CHANGED",
            "BLOCK",
            "context.argo_source_changed",
            "the Argo CD source repository/path/revision changed",
        )
    paths = context.get("tree_changes")
    if paths is None:
        paths = context.get("changed_paths")
    if isinstance(paths, str):
        paths = [paths]
    if not isinstance(paths, list):
        return
    argo_seen: set[str] = set()
    for raw in paths[:500]:
        path = str(raw).replace("\\", "/").lower()
        if path.startswith("gitops/argocd/") or path.endswith(("/application.yaml", "/project.yaml")):
            if path not in argo_seen:
                argo_seen.add(path)
                findings.add(
                    "ARGOCD_MANIFEST_CHANGE",
                    "REVIEW",
                    "context.tree_changes",
                    "an Argo CD source/application/project file changed",
                    {"path": str(raw)},
                )
        elif path.startswith("charts/demo/templates/") or path == "charts/demo/chart.yaml":
            findings.add(
                "TEMPLATE_FILE_CHANGE",
                "REVIEW",
                "context.tree_changes",
                "the Helm chart template changed and requires review even when current renders match",
                {"path": str(raw)},
            )


def _check_ai(
    ai_result: Any,
    config: Mapping[str, Any],
    findings: _Findings,
) -> dict[str, Any]:
    audit: dict[str, Any] = {"status": None}
    required = bool(config.get("ai_required", True))
    if ai_result is None:
        if required:
            findings.add(
                "AI_REQUIRED_UNAVAILABLE",
                "ERROR",
                "ai_result",
                "DeepSeek review is required but no result was supplied",
            )
            audit["status"] = "missing"
        else:
            audit["status"] = "disabled"
        return audit
    if not isinstance(ai_result, Mapping):
        findings.add(
            "AI_INVALID_RESULT",
            "ERROR",
            "ai_result",
            "AI result must be a mapping",
        )
        audit["status"] = "invalid"
        return audit
    status = ai_result.get("status")
    audit["status"] = status
    audit["model"] = _json_safe(ai_result.get("model")) if isinstance(ai_result.get("model"), str) else None
    if status == "error":
        findings.add(
            "AI_UNAVAILABLE",
            "ERROR",
            "ai_result.error",
            "DeepSeek review failed closed",
            {"error": str(ai_result.get("error", "unknown error"))[:1000]},
        )
        return audit
    if status != "ok":
        findings.add(
            "AI_INVALID_RESULT",
            "ERROR",
            "ai_result.status",
            "AI result has an invalid status",
            {"status": status},
        )
        return audit
    summary = ai_result.get("summary")
    risks = ai_result.get("additional_risks")
    citations = ai_result.get("citations")
    if not isinstance(summary, str) or not summary.strip():
        findings.add(
            "AI_INVALID_RESULT",
            "ERROR",
            "ai_result.summary",
            "AI result has no summary",
        )
    if not isinstance(risks, list):
        findings.add(
            "AI_INVALID_RESULT",
            "ERROR",
            "ai_result.additional_risks",
            "AI additional_risks must be a list",
        )
        risks = []
    if not isinstance(citations, list):
        findings.add(
            "AI_INVALID_RESULT",
            "ERROR",
            "ai_result.citations",
            "AI citations must be a list",
        )
        citations = []
    else:
        valid_citations: list[Mapping[str, Any]] = []
        for index, citation in enumerate(citations[:20]):
            if (
                not isinstance(citation, Mapping)
                or not isinstance(citation.get("case_id"), str)
                or not citation.get("case_id")
                or not isinstance(citation.get("quote"), str)
                or not citation.get("quote").strip()
            ):
                findings.add(
                    "AI_INVALID_RESULT",
                    "ERROR",
                    f"ai_result.citations[{index}]",
                    "AI citation must contain case_id and quote",
                )
                continue
            valid_citations.append(citation)
        citations = valid_citations
    normalized_risks: list[dict[str, Any]] = []
    for index, risk in enumerate(risks[:20]):
        if isinstance(risk, str):
            normalized_risks.append({"title": risk[:300], "detail": ""})
            continue
        if not isinstance(risk, Mapping):
            findings.add(
                "AI_INVALID_RESULT",
                "ERROR",
                f"ai_result.additional_risks[{index}]",
                "AI risk entry must be a string or mapping",
            )
            continue
        title = risk.get("title") or risk.get("risk") or risk.get("message")
        detail = risk.get("detail") or risk.get("why") or ""
        if not isinstance(title, str) or not title.strip():
            findings.add(
                "AI_INVALID_RESULT",
                "ERROR",
                f"ai_result.additional_risks[{index}]",
                "AI risk entry has no title",
            )
            continue
        normalized_risks.append({"title": title[:500], "detail": str(detail)[:1000]})
    if normalized_risks:
        findings.add(
            "AI_ADDITIONAL_RISK",
            "REVIEW",
            "ai_result.additional_risks",
            "the model identified additional risk; it can only raise the decision to REVIEW",
            {"risks": normalized_risks[:10], "count": len(normalized_risks)},
        )
    audit["additional_risks"] = len(normalized_risks)
    audit["citations"] = len(citations)
    return audit


def _sanitize_context(context: Mapping[str, Any]) -> dict[str, Any]:
    def sanitize(value: Any, depth: int = 0) -> Any:
        if depth > 8:
            return "<depth-limit>"
        if isinstance(value, Mapping):
            result: dict[str, Any] = {}
            for key, child in list(value.items())[:200]:
                key_text = str(key)
                if any(part in key_text.lower() for part in SENSITIVE_PATH_PARTS):
                    result[key_text] = "<redacted>"
                else:
                    result[key_text] = sanitize(child, depth + 1)
            return result
        if isinstance(value, (list, tuple)):
            return [sanitize(item, depth + 1) for item in value[:200]]
        if isinstance(value, str):
            return value if len(value) <= 2000 else value[:1997] + "..."
        return _json_safe(value)

    return sanitize(context)


# ---------------------------------------------------------------------------
# Public API


def evaluate(
    old: list[dict],
    new: list[dict],
    evidence: dict,
    config: dict,
    context: dict,
    ai_result: dict | None = None,
) -> dict:
    """Evaluate a release using rendered resources and real evidence."""

    if not isinstance(old, list) or not isinstance(new, list):
        raise ValueError("old and new must be lists of rendered resources")
    if not isinstance(evidence, dict):
        raise ValueError("evidence must be a mapping")
    if not isinstance(config, dict):
        raise ValueError("config must be a mapping")
    if not isinstance(context, dict):
        raise ValueError("context must be a mapping")
    if ai_result is not None and not isinstance(ai_result, dict):
        raise ValueError("ai_result must be a mapping or None")

    old_resources = _flatten_resources(old)
    new_resources = _flatten_resources(new)

    namespace = str(config.get("namespace", DEFAULT_NAMESPACE))
    deployment_name = str(config.get("deployment", DEFAULT_DEPLOYMENT))
    if not re.fullmatch(r"[a-z0-9]([-a-z0-9]*[a-z0-9])?", namespace):
        raise ValueError("invalid namespace")
    if not re.fullmatch(r"[a-z0-9]([-a-z0-9]*[a-z0-9])?", deployment_name):
        raise ValueError("invalid deployment name")
    allowed_repo = str(config.get("allowed_image_repository", DEFAULT_ALLOWED_IMAGE_REPOSITORY))
    if not allowed_repo or any(char.isspace() for char in allowed_repo):
        raise ValueError("invalid allowed_image_repository")

    config = dict(config)
    config["namespace"] = namespace
    config["deployment"] = deployment_name
    config["allowed_image_repository"] = allowed_repo
    config["require_digest"] = bool(config.get("require_digest", True))

    ttl_raw = config.get("evidence_ttl_seconds", DEFAULT_EVIDENCE_TTL_SECONDS)
    if isinstance(ttl_raw, bool) or not isinstance(ttl_raw, (int, float)) or not math.isfinite(float(ttl_raw)):
        raise ValueError("invalid evidence_ttl_seconds")
    ttl = int(ttl_raw)
    if ttl <= 0:
        raise ValueError("evidence_ttl_seconds must be positive")

    now_value = context.get("evaluated_at", context.get("now"))
    now = _timestamp(now_value) if now_value is not None else time.time()
    if now is None:
        raise ValueError("context.evaluated_at must be a Unix timestamp")
    now_int = int(now)

    old_index = _index_resources(old_resources, config)
    new_index = _index_resources(new_resources, config)
    findings = _Findings()

    _check_resource_scope(new_resources, new_index, config, findings)
    old_deployment = _target_resource(old_index, "Deployment", namespace, deployment_name)
    new_deployment = _target_resource(new_index, "Deployment", namespace, deployment_name)
    deployment_ok = _check_deployment(old_deployment, new_deployment, config, findings)
    _check_scheduling(new_deployment, evidence, findings)
    if deployment_ok:
        _check_resource_reduction(old_deployment, new_deployment, findings)
        capacity_audit = _check_capacity(evidence, old_deployment, new_deployment, findings)
    else:
        capacity_audit = {}

    changes, pod_template_changed, changes_truncated = _changes_between(old_index, new_index)
    _check_tree_context(context, findings)
    metrics_audit, min_timestamp = _check_metrics(evidence, config, new_deployment, findings, now, ttl)
    ai_audit = _check_ai(ai_result, config, findings)

    # A service removal is a release-breaking change even if it is not a hard
    # safety violation.  This is deliberately REVIEW, not an availability claim.
    target_service = _target_resource(new_index, "Service", namespace, deployment_name)
    old_service = _target_resource(old_index, "Service", namespace, deployment_name)
    if old_service is not None and target_service is None:
        findings.add(
            "SERVICE_REMOVED",
            "REVIEW",
            f"Service/{namespace}/{deployment_name}",
            "the demo Service would be removed",
        )
    if new_deployment is not None and target_service is None:
        findings.add(
            "SERVICE_MISSING",
            "REVIEW",
            f"Service/{namespace}/{deployment_name}",
            "the rendered release has no demo Service",
        )

    if changes_truncated:
        findings.add(
            "CHANGES_TRUNCATED",
            "REVIEW",
            "changes",
            "the rendered field diff was truncated; manual review is required",
            {"max_changes": 2000},
        )

    decision = findings.decision()
    findings_list = findings.sorted()
    expires_base = now
    if min_timestamp is not None:
        expires_base = min(now, min_timestamp)
    expires_at = int(expires_base + ttl)

    internal_context: dict[str, Any] = {
        "namespace": namespace,
        "deployment": deployment_name,
        "old_resource_count": len(old_resources),
        "new_resource_count": len(new_resources),
        "pod_template_changed": pod_template_changed,
        "ai_required": bool(config.get("ai_required", True)),
        "ai_status": ai_audit.get("status"),
        "evidence_collected_at": _timestamp(evidence.get("collected_at")),
        "evidence_ttl_seconds": ttl,
    }
    context_out = _sanitize_context(context)
    context_out.update(internal_context)

    audit = {
        "schema_version": SCHEMA_VERSION,
        "rule_version": RULE_VERSION,
        "evaluated_at": now_int,
        "checks": [
            {
                "rule_id": item["rule_id"],
                "severity": item["severity"],
                "field": item["field"],
                "message": item["message"],
            }
            for item in findings_list
        ],
        "metrics": metrics_audit,
        "capacity": _json_safe(capacity_audit),
        "ai": ai_audit,
        "changes_count": len(changes),
        "pod_template_changed": pod_template_changed,
        "render_digest": digest_resources(new_resources),
        "old_render_digest": digest_resources(old_resources),
    }
    result = {
        "decision": decision,
        "findings": findings_list,
        "changes": changes,
        "context": context_out,
        "render_digest": digest_resources(new_resources),
        "old_render_digest": digest_resources(old_resources),
        "evaluated_at": now_int,
        "expires_at": expires_at,
        "rule_version": RULE_VERSION,
        "audit": audit,
    }
    # Assert JSON-serializable and non-NaN before returning.
    json.dumps(result, allow_nan=False, ensure_ascii=False)
    return result
