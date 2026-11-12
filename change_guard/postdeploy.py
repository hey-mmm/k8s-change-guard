"""Read-only post-deployment verification.

The verifier answers one question: did the exact release that the guard
approved actually become the running release?  It checks:

* Argo CD sync revision, sync status and health;
* the Deployment's actual image, generation/replica status;
* running Pods' readiness and image/imageID digest (with the documented
  multi-arch caveat);
* the demo HTTP ``/version`` provenance value and readiness endpoint;
* ready Service endpoints;
* a Prometheus observation window with positive traffic, bounded error ratio
  and p95 latency, and no relevant firing alert.

It never mutates the cluster, never reads Secrets, never uses ``exec``/``logs``,
and never rolls back automatically.  A failure produces a *revert pull request
recommendation* only.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import urlsplit, urlunsplit

import requests

from . import evidence as evidence_module
from . import github as github_module

SCHEMA_VERSION = 1
DEFAULT_TIMEOUT_SECONDS = 300
DEFAULT_POLL_SECONDS = 5
DEFAULT_OBSERVATION_SECONDS = 60
DEFAULT_EVIDENCE_TTL_SECONDS = 300
DEFAULT_MAX_ERROR_RATIO = 0.05
DEFAULT_MAX_P95_SECONDS = 0.5
DEFAULT_MIN_REQUEST_RATE = 0.1
MAX_HTTP_BYTES = 128 * 1024
MAX_KUBECTL_BYTES = 16 * 1024 * 1024
MAX_CHECKS = 200
_SHA_RE = re.compile(r"[0-9a-f]{40,64}")
_DNS_LABEL_RE = re.compile(r"[a-z0-9]([-a-z0-9]*[a-z0-9])?")
_IMAGE_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
_SAFE_LABEL_RE = re.compile(r"[A-Za-z0-9_.-]{1,63}")
# Label *keys* may carry a DNS prefix (for example
# ``app.kubernetes.io/name``), which the value-only character class rejected.
_LABEL_KEY_RE = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,61}[A-Za-z0-9])?"
    r"(?:/[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,61}[A-Za-z0-9])?)?"
)
_FORBIDDEN_KUBECTL_WORDS = frozenset(
    {
        "apply",
        "attach",
        "auth",
        "autoscale",
        "certificate",
        "cluster-info",
        "completion",
        "config",
        "cordon",
        "cp",
        "create",
        "debug",
        "delete",
        "drain",
        "edit",
        "exec",
        "expose",
        "label",
        "logs",
        "patch",
        "port-forward",
        "proxy",
        "replace",
        "rollout",
        "run",
        "scale",
        "set",
        "taint",
        "uncordon",
        "wait",
    }
)

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_ERROR = 2


class PostDeployError(RuntimeError):
    def __init__(self, message: str, *, code: str = "postdeploy_error"):
        super().__init__(github_module.sanitize_text(message, limit=1000))
        self.code = code


class PostDeploySetupError(PostDeployError):
    """Invalid configuration or a missing trusted tool."""


# ---------------------------------------------------------------------------
# Generic helpers


def _now(clock: Callable[[], float]) -> int:
    value = clock()
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
        raise PostDeploySetupError("clock returned an invalid time")
    return int(value)


def _finite(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        number = float(value)
        return number if math.isfinite(number) else None
    return None


def _safe(value: Any, limit: int = 1000) -> str:
    return github_module.sanitize_text(value, limit=limit)


def _redact(value: Any, *, depth: int = 0, key: str = "") -> Any:
    if depth > 12:
        return "<depth-limit>"
    lowered = key.lower()
    if any(
        part in lowered
        for part in (
            "token",
            "secret",
            "password",
            "passwd",
            "authorization",
            "credential",
            "private_key",
            "privatekey",
            "api_key",
            "apikey",
            "kubeconfig",
            "cookie",
            "stringdata",
        )
    ):
        return "<redacted>"
    if isinstance(value, Mapping):
        return {str(k): _redact(v, depth=depth + 1, key=str(k)) for k, v in list(value.items())[:500]}
    if isinstance(value, (list, tuple)):
        return [_redact(item, depth=depth + 1, key=key) for item in value[:200]]
    if isinstance(value, str):
        return _safe(value, limit=4000)
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if value is None or isinstance(value, (bool, int)):
        return value
    return _safe(value, limit=1000)


def _label(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _DNS_LABEL_RE.fullmatch(value) or len(value) > 63:
        raise PostDeploySetupError(f"{field} is not a valid Kubernetes DNS label")
    return value


def _bounded_number(
    config: Mapping[str, Any],
    key: str,
    default: float,
    minimum: float,
    maximum: float,
    *,
    integer: bool = False,
) -> float | int:
    raw = config.get(key, default)
    if isinstance(raw, bool) or not isinstance(raw, (int, float)) or not math.isfinite(float(raw)):
        raise PostDeploySetupError(f"{key} must be a finite number")
    value = float(raw)
    if not minimum <= value <= maximum:
        raise PostDeploySetupError(f"{key} must be between {minimum} and {maximum}")
    return int(value) if integer else value


def _http_base_url(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PostDeploySetupError(f"{field} is required")
    parsed = urlsplit(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise PostDeploySetupError(f"{field} must be an http(s) URL")
    if parsed.username is not None or parsed.password is not None:
        raise PostDeploySetupError(f"{field} must not contain credentials")
    if parsed.query or parsed.fragment:
        raise PostDeploySetupError(f"{field} must not contain a query or fragment")
    path = parsed.path.rstrip("/")
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def _validate_expected_image(image: Any, config: Mapping[str, Any]) -> str:
    if not isinstance(image, str) or not image.strip() or any(ch.isspace() for ch in image):
        raise PostDeploySetupError("expected image is empty or malformed")
    text = image.strip()
    repository = text.split("@", 1)[0]
    if repository.rstrip().endswith(":"):
        raise PostDeploySetupError("expected image has no tag/digest")
    if ":" in repository.rsplit("/", 1)[-1]:
        repository = repository.rsplit(":", 1)[0]
    allowed = config.get("allowed_image_repository")
    if isinstance(allowed, str) and allowed and repository != allowed:
        raise PostDeploySetupError("expected image repository is not allowlisted")
    if "@" in text:
        digest = text.rsplit("@", 1)[1]
        if not _IMAGE_DIGEST_RE.fullmatch(digest):
            raise PostDeploySetupError("expected image digest must be sha256:<64 lowercase hex>")
    elif config.get("require_digest", True):
        raise PostDeploySetupError("expected image must be pinned by sha256 digest")
    return text


def validate_config(config: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(config, Mapping):
        raise PostDeploySetupError("config must be a mapping")
    value = dict(config)
    for key in ("namespace", "deployment"):
        value[key] = _label(value.get(key, "demo"), key)
    value["argocd_namespace"] = _label(value.get("argocd_namespace", "argocd"), "argocd_namespace")
    value["argo_application"] = _label(value.get("argo_application", value["deployment"]), "argo_application")
    value["demo_url"] = _http_base_url(value.get("demo_url"), "demo_url")
    value["version_path"] = str(value.get("version_path", "/version"))
    value["ready_path"] = str(value.get("ready_path", "/ready"))
    for path_name in ("version_path", "ready_path"):
        path = value[path_name]
        if not path.startswith("/") or "://" in path or ".." in path.split("/") or any(ch.isspace() for ch in path):
            raise PostDeploySetupError(f"{path_name} must be a clean absolute path")
    value["container_name"] = value.get("container_name")
    if value["container_name"] is not None:
        if not isinstance(value["container_name"], str) or not _SAFE_LABEL_RE.fullmatch(value["container_name"]):
            raise PostDeploySetupError("container_name is invalid")
    selector = value.get(
        "pod_label_selector",
        f"app.kubernetes.io/name={value['deployment']},app.kubernetes.io/instance={value['deployment']}",
    )
    if not isinstance(selector, str) or not selector or len(selector) > 1024:
        raise PostDeploySetupError("pod_label_selector is invalid")
    for part in selector.split(","):
        if "=" not in part:
            raise PostDeploySetupError("pod_label_selector must contain key=value pairs")
        key, label_value = part.split("=", 1)
        if (
            not _LABEL_KEY_RE.fullmatch(key)
            or len(key) > 253
            or not _SAFE_LABEL_RE.fullmatch(label_value)
        ):
            raise PostDeploySetupError("pod_label_selector contains an invalid label")
    value["pod_label_selector"] = selector
    value["postdeploy_timeout_seconds"] = _bounded_number(
        value, "postdeploy_timeout_seconds", DEFAULT_TIMEOUT_SECONDS, 1, 7200, integer=True
    )
    value["postdeploy_poll_seconds"] = _bounded_number(
        value, "postdeploy_poll_seconds", DEFAULT_POLL_SECONDS, 1, 60, integer=True
    )
    value["observation_seconds"] = _bounded_number(
        value, "observation_seconds", DEFAULT_OBSERVATION_SECONDS, 0, 3600, integer=True
    )
    value["max_error_ratio"] = _bounded_number(value, "max_error_ratio", DEFAULT_MAX_ERROR_RATIO, 0, 1)
    value["max_p95_seconds"] = _bounded_number(value, "max_p95_seconds", DEFAULT_MAX_P95_SECONDS, 0, 60)
    value["min_request_rate"] = _bounded_number(value, "min_request_rate", DEFAULT_MIN_REQUEST_RATE, 0, 1_000_000)
    value["evidence_ttl_seconds"] = _bounded_number(
        value, "evidence_ttl_seconds", DEFAULT_EVIDENCE_TTL_SECONDS, 1, 86400, integer=True
    )
    value["require_digest"] = bool(value.get("require_digest", True))
    value["require_pod_image_id"] = bool(value.get("require_pod_image_id", True))
    value["strict_image_id_digest"] = bool(value.get("strict_image_id_digest", False))
    value["use_proxy_env"] = bool(value.get("use_proxy_env", True))
    value["kubectl"] = str(value.get("kubectl", "/usr/bin/kubectl"))
    value["kubeconfig"] = str(value.get("kubeconfig", ""))
    if value["kubeconfig"] and "\x00" in value["kubeconfig"]:
        raise PostDeploySetupError("kubeconfig path is invalid")
    return value


# ---------------------------------------------------------------------------
# Read-only kubectl


def _assert_read_only_kubectl_args(args: Sequence[str]) -> None:
    lowered = [str(arg).lower() for arg in args]
    if len(lowered) >= 2 and lowered[0] == "-n":
        verb_index = 2
    else:
        verb_index = 0
    if len(lowered) <= verb_index or lowered[verb_index] != "get":
        raise PostDeploySetupError("postdeploy only permits fixed kubectl get commands")
    for arg in lowered:
        if arg in _FORBIDDEN_KUBECTL_WORDS:
            raise PostDeploySetupError(f"kubectl verb/resource {arg!r} is not permitted")
        if arg in {"secret", "secrets", "pods/log", "pods/exec", "deployments/scale"}:
            raise PostDeploySetupError(f"kubectl resource {arg!r} is not permitted")
        if "pods/log" in arg or "pods/exec" in arg:
            raise PostDeploySetupError(f"kubectl subresource {arg!r} is not permitted")
        if arg.startswith("--raw") or arg.startswith("--server") or arg.startswith("--token"):
            raise PostDeploySetupError(f"kubectl option {arg!r} is not permitted")
    if "json" not in lowered:
        raise PostDeploySetupError("kubectl command must request JSON output")


def _kubectl_command(config: Mapping[str, Any], args: Sequence[str]) -> list[str]:
    _assert_read_only_kubectl_args(args)
    command = [str(config.get("kubectl", "/usr/bin/kubectl"))]
    kubeconfig = str(config.get("kubeconfig", ""))
    if kubeconfig:
        command.append(f"--kubeconfig={kubeconfig}")
    command.append(
        f"--request-timeout={int(config.get('postdeploy_timeout_seconds', DEFAULT_TIMEOUT_SECONDS))}s"
    )
    command.extend(str(arg) for arg in args)
    return command


def _default_kubectl_runner(config: Mapping[str, Any], args: Sequence[str], timeout: int) -> Any:
    command = _kubectl_command(config, args)
    executable = command[0]
    if not executable or ("/" in executable and not Path(executable).is_file()):
        raise PostDeploySetupError("kubectl executable is missing")
    with tempfile.TemporaryDirectory(prefix="change-guard-postdeploy-") as temporary:
        home = Path(temporary)
        env = {
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME": str(home),
            "XDG_CACHE_HOME": str(home / "cache"),
            "XDG_CONFIG_HOME": str(home / "config"),
            "LANG": "C",
            "LC_ALL": "C",
        }
        kubeconfig = str(config.get("kubeconfig", ""))
        if kubeconfig:
            env["KUBECONFIG"] = kubeconfig
        try:
            completed = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=False,
                env=env,
            )
        except subprocess.TimeoutExpired:
            raise PostDeployError("kubectl timed out", code="kubectl_timeout") from None
        except OSError as exc:
            raise PostDeploySetupError(f"kubectl could not start: {exc}") from None
        stdout = completed.stdout or b""
        stderr = completed.stderr or b""
        if len(stdout) > MAX_KUBECTL_BYTES or len(stderr) > MAX_KUBECTL_BYTES:
            raise PostDeployError("kubectl output exceeded the size limit", code="kubectl_output_too_large")
        if completed.returncode != 0:
            detail = _safe(stderr.decode("utf-8", errors="replace"), limit=500)
            raise PostDeployError(
                f"kubectl get failed with exit {completed.returncode}: {detail}",
                code="kubectl_failed",
            )
        try:
            text = stdout.decode("utf-8")
        except UnicodeDecodeError:
            raise PostDeployError("kubectl returned non-UTF-8 output", code="kubectl_invalid") from None
        try:
            return json.loads(text)
        except ValueError as exc:
            raise PostDeployError(f"kubectl returned invalid JSON: {exc}", code="kubectl_invalid") from None


# ---------------------------------------------------------------------------
# HTTP


def _default_http_get(config: Mapping[str, Any], path: str, timeout: int) -> tuple[int, bytes]:
    base = _http_base_url(config.get("demo_url"), "demo_url")
    if not isinstance(path, str) or not path.startswith("/") or ".." in path.split("/") or "://" in path:
        raise PostDeploySetupError("HTTP path is invalid")
    session = requests.Session()
    session.trust_env = bool(config.get("use_proxy_env", True))
    try:
        response = session.get(
            base + path,
            timeout=(3, timeout),
            headers={"Accept": "application/json", "User-Agent": "change-guard-postdeploy/1"},
            allow_redirects=False,
            stream=True,
            verify=True,
        )
        try:
            content_length = response.headers.get("Content-Length")
            if content_length is not None:
                try:
                    if int(content_length) > MAX_HTTP_BYTES:
                        raise PostDeployError("HTTP response exceeded the size limit", code="http_too_large")
                except ValueError:
                    pass
            chunks: list[bytes] = []
            total = 0
            for chunk in response.iter_content(chunk_size=16 * 1024):
                if not chunk:
                    continue
                total += len(chunk)
                if total > MAX_HTTP_BYTES:
                    raise PostDeployError("HTTP response exceeded the size limit", code="http_too_large")
                chunks.append(chunk)
            return int(response.status_code), b"".join(chunks)
        finally:
            try:
                response.close()
            except Exception:
                pass
    except requests.RequestException as exc:
        raise PostDeployError(f"HTTP request failed: {type(exc).__name__}", code="http_error") from None
    finally:
        session.close()


def _json_body(raw: bytes) -> Any:
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise PostDeployError("HTTP response is not valid JSON", code="http_invalid_json") from None


# ---------------------------------------------------------------------------
# Checks


def _check_result(name: str, status: str, detail: str, evidence: Mapping[str, Any] | None = None) -> dict[str, Any]:
    return {
        "name": name,
        "status": status,
        "detail": _safe(detail, limit=1000),
        "evidence": _redact(dict(evidence or {})),
    }


def _get_argo(config: Mapping[str, Any], kubectl_runner: Callable[..., Any]) -> Any:
    args = [
        "-n",
        str(config["argocd_namespace"]),
        "get",
        "application",
        str(config["argo_application"]),
        "-o",
        "json",
    ]
    return kubectl_runner(args, int(config["postdeploy_timeout_seconds"]))


def _check_argo(config: Mapping[str, Any], expected_sha: str, kubectl_runner: Callable[..., Any]) -> dict[str, Any]:
    app = _get_argo(config, kubectl_runner)
    if not isinstance(app, Mapping):
        return _check_result("argo", "fail", "Argo Application response is not an object")
    metadata = app.get("metadata") if isinstance(app.get("metadata"), Mapping) else {}
    if metadata.get("deletionTimestamp"):
        return _check_result("argo", "fail", "Argo Application is being deleted")
    status = app.get("status") if isinstance(app.get("status"), Mapping) else {}
    sync = status.get("sync") if isinstance(status.get("sync"), Mapping) else {}
    health = status.get("health") if isinstance(status.get("health"), Mapping) else {}
    revision = sync.get("revision")
    sync_status = sync.get("status")
    health_status = health.get("status")
    operation = status.get("operationState") if isinstance(status.get("operationState"), Mapping) else {}
    phase = operation.get("phase")
    evidence = {
        "application": config["argo_application"],
        "revision": revision,
        "sync_status": sync_status,
        "health_status": health_status,
        "operation_phase": phase,
    }
    problems: list[str] = []
    if revision != expected_sha:
        problems.append(f"Argo sync revision {str(revision)[:12]!r} != expected {expected_sha[:12]!r}")
    if sync_status != "Synced":
        problems.append(f"Argo sync status is {sync_status!r}, not 'Synced'")
    if health_status != "Healthy":
        problems.append(f"Argo health status is {health_status!r}, not 'Healthy'")
    if phase is not None and phase not in {"Succeeded", "Running"}:
        problems.append(f"Argo operation phase is {phase!r}")
    if problems:
        return _check_result("argo", "fail", "; ".join(problems), evidence)
    return _check_result("argo", "pass", "Argo is Synced/Healthy at the expected revision", evidence)


def _deployment_containers(deployment: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    spec = deployment.get("spec") if isinstance(deployment.get("spec"), Mapping) else {}
    template = spec.get("template") if isinstance(spec.get("template"), Mapping) else {}
    pod_spec = template.get("spec") if isinstance(template.get("spec"), Mapping) else {}
    containers = pod_spec.get("containers") if isinstance(pod_spec.get("containers"), list) else []
    return [item for item in containers if isinstance(item, Mapping)]


def _target_container(
    containers: Sequence[Mapping[str, Any]],
    config: Mapping[str, Any],
    expected_image: str,
) -> Mapping[str, Any] | None:
    name = config.get("container_name")
    if isinstance(name, str):
        for container in containers:
            if container.get("name") == name:
                return container
        return None
    if len(containers) == 1:
        return containers[0]
    matching = [container for container in containers if container.get("image") == expected_image]
    return matching[0] if len(matching) == 1 else None


def _check_deployment(
    config: Mapping[str, Any],
    expected_sha: str,
    expected_image: str,
    kubectl_runner: Callable[..., Any],
) -> dict[str, Any]:
    args = ["-n", str(config["namespace"]), "get", "deployment", str(config["deployment"]), "-o", "json"]
    deployment = kubectl_runner(args, int(config["postdeploy_timeout_seconds"]))
    if not isinstance(deployment, Mapping):
        return _check_result("deployment", "fail", "Deployment response is not an object")
    metadata = deployment.get("metadata") if isinstance(deployment.get("metadata"), Mapping) else {}
    spec = deployment.get("spec") if isinstance(deployment.get("spec"), Mapping) else {}
    status = deployment.get("status") if isinstance(deployment.get("status"), Mapping) else {}
    containers = _deployment_containers(deployment)
    target = _target_container(containers, config, expected_image)
    actual_images = [str(item.get("image", "")) for item in containers]
    replicas = spec.get("replicas", 1)
    if isinstance(replicas, bool) or not isinstance(replicas, int) or replicas < 1:
        return _check_result("deployment", "fail", "Deployment replicas is invalid")
    generation = metadata.get("generation")
    observed = status.get("observedGeneration")
    updated = status.get("updatedReplicas", 0)
    ready = status.get("readyReplicas", 0)
    available = status.get("availableReplicas", 0)
    evidence = {
        "name": metadata.get("name"),
        "namespace": metadata.get("namespace"),
        "generation": generation,
        "observed_generation": observed,
        "replicas": replicas,
        "updated_replicas": updated,
        "ready_replicas": ready,
        "available_replicas": available,
        "images": actual_images[:20],
        "target_container": target.get("name") if isinstance(target, Mapping) else None,
    }
    problems: list[str] = []
    if target is None:
        problems.append("expected container/image was not found in the Deployment")
    elif target.get("image") != expected_image:
        problems.append("Deployment target container image does not equal the expected digest")
    if isinstance(generation, int) and isinstance(observed, int) and observed < generation:
        problems.append("Deployment observedGeneration has not caught up")
    for label, value in (("updated", updated), ("ready", ready), ("available", available)):
        if isinstance(value, bool) or not isinstance(value, int) or value < replicas:
            problems.append(f"Deployment {label}Replicas is below desired replicas")
    if problems:
        return _check_result("deployment", "fail", "; ".join(problems), evidence)
    return _check_result("deployment", "pass", "Deployment image and replica status match", evidence)


def _parse_image_id(value: Any) -> tuple[str | None, str | None]:
    if not isinstance(value, str) or not value.strip():
        return None, None
    text = value.strip()
    for prefix in ("docker-pullable://", "docker://", "containerd://", "cri-o://"):
        if text.startswith(prefix):
            text = text[len(prefix) :]
            break
    repository: str | None = None
    digest: str | None = None
    if "@" in text:
        repository, digest = text.rsplit("@", 1)
    elif ":" in text and "sha256:" in text:
        repository = text.split("sha256:", 1)[0].rstrip("@")
        digest = "sha256:" + text.split("sha256:", 1)[1]
    if digest is not None:
        match = _IMAGE_DIGEST_RE.search(digest)
        digest = match.group(0) if match else None
    repository = repository.strip() if repository else None
    if repository and repository.endswith(":"):
        repository = None
    return repository or None, digest


def _check_pods(
    config: Mapping[str, Any],
    expected_image: str,
    kubectl_runner: Callable[..., Any],
) -> dict[str, Any]:
    args = [
        "-n",
        str(config["namespace"]),
        "get",
        "pods",
        "-l",
        str(config["pod_label_selector"]),
        "-o",
        "json",
    ]
    payload = kubectl_runner(args, int(config["postdeploy_timeout_seconds"]))
    if not isinstance(payload, Mapping):
        return _check_result("pods", "fail", "Pod response is not an object")
    items = payload.get("items") if isinstance(payload.get("items"), list) else []
    if not items:
        return _check_result("pods", "fail", "no running Pod matched the deployment selector")
    expected_repository = expected_image.split("@", 1)[0]
    expected_digest = expected_image.rsplit("@", 1)[1] if "@" in expected_image else None
    pod_summaries: list[dict[str, Any]] = []
    problems: list[str] = []
    digest_caveats: list[str] = []
    for pod in items[:200]:
        if not isinstance(pod, Mapping):
            continue
        metadata = pod.get("metadata") if isinstance(pod.get("metadata"), Mapping) else {}
        status = pod.get("status") if isinstance(pod.get("status"), Mapping) else {}
        if metadata.get("deletionTimestamp"):
            problems.append(f"Pod {metadata.get('name')} is terminating")
            continue
        if status.get("phase") != "Running":
            problems.append(f"Pod {metadata.get('name')} phase is {status.get('phase')!r}")
        conditions = status.get("conditions") if isinstance(status.get("conditions"), list) else []
        ready = any(
            isinstance(condition, Mapping)
            and condition.get("type") == "Ready"
            and str(condition.get("status", "")).lower() == "true"
            for condition in conditions
        )
        if not ready:
            problems.append(f"Pod {metadata.get('name')} is not Ready")
        container_statuses = status.get("containerStatuses") if isinstance(status.get("containerStatuses"), list) else []
        target_ready = False
        target_image_ok = False
        for container_status in container_statuses:
            if not isinstance(container_status, Mapping):
                continue
            name = container_status.get("name")
            image = container_status.get("image")
            if not container_status.get("ready"):
                problems.append(f"Pod {metadata.get('name')} container {name} is not ready")
            if name == config.get("container_name") or (
                config.get("container_name") is None and image == expected_image
            ):
                target_ready = bool(container_status.get("ready"))
                target_image_ok = image == expected_image
                repository, digest = _parse_image_id(container_status.get("imageID"))
                if config.get("require_pod_image_id", True) and digest is None:
                    problems.append(f"Pod {metadata.get('name')} has no verifiable imageID digest")
                elif digest is not None:
                    if repository is not None and repository != expected_repository:
                        problems.append(f"Pod {metadata.get('name')} imageID repository differs from expected")
                    if expected_digest is not None and digest != expected_digest:
                        caveat = (
                            f"Pod {metadata.get('name')} imageID digest {digest[:19]}... differs from "
                            "the manifest digest; this is expected for some multi-arch/config image IDs"
                        )
                        digest_caveats.append(caveat)
                        if config.get("strict_image_id_digest", False):
                            problems.append(caveat)
                pod_summaries.append(
                    {
                        "name": metadata.get("name"),
                        "node": pod.get("spec", {}).get("nodeName") if isinstance(pod.get("spec"), Mapping) else None,
                        "ready": ready,
                        "container": name,
                        "image": image,
                        "image_id": container_status.get("imageID"),
                        "image_id_digest": digest,
                    }
                )
        if config.get("container_name") is None and not target_image_ok:
            problems.append(f"Pod {metadata.get('name')} does not run the expected image")
        if config.get("container_name") is not None and not target_ready:
            problems.append(f"Pod {metadata.get('name')} target container is not ready")
    evidence = {
        "pod_count": len(items),
        "pods": pod_summaries[:100],
        "digest_caveats": digest_caveats[:20],
    }
    if problems:
        return _check_result("pods", "fail", "; ".join(problems[:10]), evidence)
    return _check_result("pods", "pass", "running Pods are ready and run the expected image", evidence)


def _check_endpoints(config: Mapping[str, Any], kubectl_runner: Callable[..., Any]) -> dict[str, Any]:
    args = ["-n", str(config["namespace"]), "get", "endpoints", str(config["deployment"]), "-o", "json"]
    endpoints = kubectl_runner(args, int(config["postdeploy_timeout_seconds"]))
    if not isinstance(endpoints, Mapping):
        return _check_result("endpoints", "fail", "Endpoints response is not an object")
    subsets = endpoints.get("subsets") if isinstance(endpoints.get("subsets"), list) else []
    ready_addresses: list[str] = []
    not_ready: list[str] = []
    for subset in subsets:
        if not isinstance(subset, Mapping):
            continue
        for address in subset.get("addresses", []) if isinstance(subset.get("addresses"), list) else []:
            if isinstance(address, Mapping) and isinstance(address.get("ip"), str):
                ready_addresses.append(address["ip"])
        for address in subset.get("notReadyAddresses", []) if isinstance(subset.get("notReadyAddresses"), list) else []:
            if isinstance(address, Mapping) and isinstance(address.get("ip"), str):
                not_ready.append(address["ip"])
    evidence = {
        "ready_addresses": len(ready_addresses),
        "not_ready_addresses": len(not_ready),
        "addresses": ready_addresses[:20],
    }
    if not ready_addresses:
        return _check_result("endpoints", "fail", "Service has no ready endpoint addresses", evidence)
    return _check_result("endpoints", "pass", "Service has ready endpoint addresses", evidence)


def _check_http(config: Mapping[str, Any], expected_sha: str, http_get: Callable[..., Any]) -> dict[str, Any]:
    timeout = int(config["postdeploy_timeout_seconds"])
    status, raw = http_get(config["version_path"], timeout)
    if status != 200:
        return _check_result("http_version", "fail", f"GET {config['version_path']} returned HTTP {status}")
    body = _json_body(raw)
    if not isinstance(body, Mapping):
        return _check_result("http_version", "fail", "version response is not a JSON object")
    git_sha = body.get("gitSha", body.get("git_sha"))
    evidence = {
        "status": status,
        "gitSha": git_sha if isinstance(git_sha, str) else None,
        "version": _safe(body.get("version", ""), limit=100),
    }
    if not isinstance(git_sha, str) or git_sha.lower() != expected_sha.lower():
        return _check_result(
            "http_version",
            "fail",
            "HTTP /version gitSha does not equal the desired release commit",
            evidence,
        )
    ready_status, _ready_raw = http_get(config["ready_path"], timeout)
    if ready_status != 200:
        return _check_result(
            "http_ready",
            "fail",
            f"GET {config['ready_path']} returned HTTP {ready_status}",
            {"status": ready_status},
        )
    return _check_result(
        "http_version",
        "pass",
        "HTTP /version provenance and readiness endpoints are healthy",
        evidence,
    )


def _check_metrics(
    config: Mapping[str, Any],
    metrics_provider: Callable[[dict], dict],
    *,
    observation_seconds: int,
) -> dict[str, Any]:
    evidence = metrics_provider(dict(config))
    if not isinstance(evidence, Mapping):
        return _check_result("metrics", "fail", "metrics provider returned an invalid result")
    metrics = evidence.get("metrics") if isinstance(evidence.get("metrics"), Mapping) else {}
    errors = [str(item) for item in (evidence.get("errors") or []) if isinstance(item, (str, int, float))]
    relevant_errors = errors
    request_rate = _finite(metrics.get("request_rate"))
    error_ratio = _finite(metrics.get("error_ratio"))
    p95 = _finite(metrics.get("p95_seconds"))
    alerts = metrics.get("alerts") if isinstance(metrics.get("alerts"), list) else []
    firing: list[dict[str, Any]] = []
    for alert in alerts:
        if not isinstance(alert, Mapping):
            continue
        state = str(alert.get("state", "")).lower()
        if state not in {"firing", "active"}:
            continue
        labels = alert.get("labels") if isinstance(alert.get("labels"), Mapping) else {}
        relevant = labels.get("namespace") == config["namespace"] or labels.get("deployment") == config["deployment"]
        if relevant:
            firing.append({"name": alert.get("name"), "state": state, "labels": dict(labels)})
    observation = {
        "window_seconds": observation_seconds,
        "request_rate": request_rate,
        "error_ratio": error_ratio,
        "p95_seconds": p95,
        "firing_alerts": firing[:20],
        "source_errors": relevant_errors[:20],
        "collected_at": evidence.get("collected_at"),
    }
    problems: list[str] = []
    if relevant_errors:
        problems.append("; ".join(relevant_errors[:3]))
    if request_rate is None or request_rate < float(config["min_request_rate"]):
        problems.append("positive request traffic was not observed")
    if error_ratio is None:
        problems.append("error ratio could not be measured")
    elif error_ratio > float(config["max_error_ratio"]):
        problems.append("error ratio exceeds the configured maximum")
    if p95 is None:
        problems.append("p95 latency could not be measured")
    elif p95 > float(config["max_p95_seconds"]):
        problems.append("p95 latency exceeds the configured maximum")
    if firing:
        problems.append("relevant Prometheus alerts are firing")
    if problems:
        return _check_result("metrics", "fail", "; ".join(problems[:6]), observation)
    return _check_result("metrics", "pass", "observation window shows positive traffic within SLO bounds", observation)


# ---------------------------------------------------------------------------
# Public verification API


def _failure_result(
    *,
    expected_sha: str,
    expected_app_sha: str,
    expected_image: str,
    checks: Sequence[Mapping[str, Any]],
    started_at: int,
    finished_at: int,
) -> dict[str, Any]:
    failing = [dict(item) for item in checks if item.get("status") != "pass"]
    reason_parts = [f"{item.get('name')}: {item.get('detail')}" for item in failing[:8]]
    reason = "; ".join(reason_parts) or "post-deployment verification failed"
    return {
        "schema_version": SCHEMA_VERSION,
        "verifier": "change-guard-postdeploy",
        "status": "failed",
        "expected_sha": expected_sha,
        "expected_app_sha": expected_app_sha,
        "expected_image": expected_image,
        "checks": list(checks),
        "recommendation": {
            "action": "open_revert_pr",
            "reason": _safe(reason, limit=2000),
            "failing_checks": [item.get("name") for item in failing],
            "note": (
                "This verifier is read-only. Open a revert pull request for the offending change; "
                "it does not and must not roll back or mutate the cluster automatically."
            ),
        },
        "started_at": started_at,
        "finished_at": finished_at,
    }


def verify_deployment(
    config: Mapping[str, Any],
    expected_sha: str,
    expected_image: str | None = None,
    *,
    report: Mapping[str, Any] | None = None,
    expected_app_sha: str | None = None,
    kubectl_runner: Callable[[Sequence[str], int], Any] | None = None,
    http_get: Callable[[str, int], tuple[int, bytes]] | None = None,
    metrics_provider: Callable[[dict], dict] | None = None,
    clock: Callable[[], float] | None = None,
    sleep: Callable[[float], None] | None = None,
) -> dict[str, Any]:
    """Verify the running release and return a JSON-serializable report."""

    clock = clock or time.time
    sleep = sleep or time.sleep
    started_at = _now(clock)
    try:
        cfg = validate_config(config)
        if not isinstance(expected_sha, str) or not _SHA_RE.fullmatch(expected_sha):
            raise PostDeploySetupError("expected_sha must be a hexadecimal Git commit id")
        app_sha = expected_sha if expected_app_sha is None else expected_app_sha
        if not isinstance(app_sha, str) or not _SHA_RE.fullmatch(app_sha):
            raise PostDeploySetupError("expected_app_sha must be a hexadecimal image source commit id")
        if expected_image is None and report is not None:
            expected_image = expected_image_from_report(report, cfg)
        if expected_image is None:
            raise PostDeploySetupError("expected_image is required")
        image = _validate_expected_image(expected_image, cfg)
        runner = kubectl_runner or (
            lambda args, timeout: _default_kubectl_runner(cfg, args, timeout)
        )
        getter = http_get or (lambda path, timeout: _default_http_get(cfg, path, timeout))
        provider = metrics_provider or evidence_module.collect
    except Exception as exc:
        return {
            "schema_version": SCHEMA_VERSION,
            "verifier": "change-guard-postdeploy",
            "status": "error",
            "error": _safe(exc, limit=1000),
            "started_at": started_at,
        }

    checks: list[dict[str, Any]] = []
    deadline = float(started_at) + int(cfg["postdeploy_timeout_seconds"])
    max_attempts = max(1, min(1000, int(cfg["postdeploy_timeout_seconds"]) + 2))
    attempts = 0

    def run_check(name: str, function: Callable[[], dict[str, Any]]) -> dict[str, Any]:
        try:
            return function()
        except Exception as exc:
            return _check_result(name, "fail", _safe(exc, limit=1000))

    def core_checks() -> list[dict[str, Any]]:
        return [
            run_check("argo", lambda: _check_argo(cfg, expected_sha, runner)),
            run_check(
                "deployment",
                lambda: _check_deployment(cfg, expected_sha, image, runner),
            ),
            run_check("pods", lambda: _check_pods(cfg, image, runner)),
            run_check("endpoints", lambda: _check_endpoints(cfg, runner)),
            run_check("http", lambda: _check_http(cfg, app_sha, getter)),
        ]

    while attempts < max_attempts:
        attempts += 1
        checks = core_checks()
        if all(item.get("status") == "pass" for item in checks):
            break
        if float(_now(clock)) >= deadline:
            break
        remaining = max(1.0, deadline - float(_now(clock)))
        sleep(min(float(cfg["postdeploy_poll_seconds"]), remaining))

    if not all(item.get("status") == "pass" for item in checks):
        finished_at = _now(clock)
        return _failure_result(
            expected_sha=expected_sha,
            expected_app_sha=app_sha,
            expected_image=image,
            checks=checks,
            started_at=started_at,
            finished_at=finished_at,
        )

    observation_seconds = int(cfg["observation_seconds"])
    if observation_seconds > 0:
        sleep(float(observation_seconds))
    metric_attempts = 0
    metric_check: dict[str, Any] = _check_result("metrics", "fail", "metrics were not observed")
    while metric_attempts < max_attempts:
        metric_attempts += 1
        metric_check = run_check(
            "metrics",
            lambda: _check_metrics(cfg, provider, observation_seconds=observation_seconds),
        )
        if metric_check.get("status") == "pass":
            break
        if float(_now(clock)) >= deadline:
            break
        remaining = max(1.0, deadline - float(_now(clock)))
        sleep(min(float(cfg["postdeploy_poll_seconds"]), remaining))
    checks.append(metric_check)
    finished_at = _now(clock)
    if metric_check.get("status") != "pass":
        return _failure_result(
            expected_sha=expected_sha,
            expected_app_sha=app_sha,
            expected_image=image,
            checks=checks,
            started_at=started_at,
            finished_at=finished_at,
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "verifier": "change-guard-postdeploy",
        "status": "ok",
        "expected_sha": expected_sha,
        "expected_app_sha": app_sha,
        "expected_image": image,
        "checks": checks,
        "observation": metric_check.get("evidence"),
        "recommendation": None,
        "started_at": started_at,
        "finished_at": finished_at,
    }


def expected_image_from_report(report: Mapping[str, Any], config: Mapping[str, Any]) -> str:
    if not isinstance(report, Mapping):
        raise PostDeploySetupError("report must be a mapping")
    images = report.get("deployment_images")
    if not isinstance(images, list) or not images:
        raise PostDeploySetupError("report has no deployment images")
    container_name = config.get("container_name")
    candidates: list[str] = []
    for item in images:
        if not isinstance(item, Mapping):
            continue
        if item.get("init"):
            continue
        if container_name is not None and item.get("container") != container_name:
            continue
        image = item.get("image")
        if isinstance(image, str) and image not in candidates:
            candidates.append(image)
    if len(candidates) == 1:
        return candidates[0]
    if not candidates:
        raise PostDeploySetupError("report has no matching non-init container image")
    raise PostDeploySetupError("report has multiple deployment images; pass --expected-image explicitly")


# ---------------------------------------------------------------------------
# CLI


def _write_json(path: str | None, payload: Mapping[str, Any]) -> None:
    encoded = json.dumps(payload, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    if path is None:
        sys.stdout.write(encoded)
        return
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".tmp", dir=str(destination.parent))
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _load_yaml(path: str) -> dict[str, Any]:
    import yaml

    try:
        raw = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise PostDeploySetupError(f"cannot read config: {exc}") from None
    try:
        value = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise PostDeploySetupError(f"config is invalid YAML: {exc}") from None
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise PostDeploySetupError("config must be a mapping")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="change-guard-postdeploy",
        description="Read-only post-deployment verification for the change guard",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    verify_parser = subparsers.add_parser("verify", help="verify Argo, Deployment, Pods, HTTP and metrics")
    verify_parser.add_argument("--config", required=True, help="YAML configuration")
    verify_parser.add_argument("--expected-sha", required=True, help="exact Git commit that Argo should sync")
    verify_parser.add_argument("--expected-app-sha", help="image source commit exposed by /version; defaults to --expected-sha")
    verify_parser.add_argument("--expected-image", help="exact repository@sha256 digest")
    verify_parser.add_argument("--report", help="change-guard evaluation report JSON (for the expected image)")
    verify_parser.add_argument("--output", help="write JSON atomically instead of stdout")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        config = _load_yaml(args.config)
        report = None
        if args.report:
            try:
                report = json.loads(Path(args.report).read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                raise PostDeploySetupError(f"cannot read report: {exc}") from None
            if not isinstance(report, dict):
                raise PostDeploySetupError("report must be a JSON object")
        result = verify_deployment(
            config,
            args.expected_sha,
            args.expected_image,
            report=report,
            expected_app_sha=args.expected_app_sha,
        )
        _write_json(args.output, result)
        if result.get("status") == "ok":
            return EXIT_OK
        if result.get("status") == "failed":
            return EXIT_FAILED
        return EXIT_ERROR
    except Exception as exc:
        result = {
            "schema_version": SCHEMA_VERSION,
            "verifier": "change-guard-postdeploy",
            "status": "error",
            "error": _safe(exc, limit=1000),
        }
        try:
            _write_json(getattr(args, "output", None), result)
        except Exception:
            sys.stderr.write(json.dumps(result, ensure_ascii=False) + "\n")
        return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
