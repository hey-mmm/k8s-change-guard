"""Render the tiny, fixed Helm surface used by the demo workload.

Security properties
-------------------
* Production rendering is Linux-only and always uses bubblewrap.  There is no
  "run helm directly" fallback.
* Only ``charts/demo`` and ``gitops/demo/values.yaml`` are copied into a fresh
  temporary directory.  Symlinks, extra chart roots (including ``charts/``
  dependencies), oversized files, and non-data values are rejected.
* The sandbox has no network, no host home, no service credentials, no Helm
  plugins, no dependency update, no post-renderer, and bounded time, memory,
  file size, document count, and output size.
* Candidate files are data only.  We never execute a candidate Shell/Python
  script and never invoke a candidate-provided binary.

For fixture-only use on Windows (or in local tests) :func:`load_rendered_manifests`
and an explicit ``allow_pre_rendered`` configuration are supported.  That path
can never be enabled on Linux unless ``fixture_mode`` is explicitly set.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterable, Sequence

import yaml

CHART_REL_PATH = "charts/demo"
VALUES_REL_PATH = "gitops/demo/values.yaml"
HELM_TARGET = "/guard-helm"

DEFAULT_TIMEOUT_SECONDS = 60
DEFAULT_OUTPUT_LIMIT_BYTES = 4 * 1024 * 1024
DEFAULT_MEMORY_LIMIT_BYTES = 2 * 1024 * 1024 * 1024
DEFAULT_TMPFS_BYTES = 64 * 1024 * 1024
MAX_INPUT_FILE_BYTES = 2 * 1024 * 1024
MAX_INPUT_TOTAL_BYTES = 12 * 1024 * 1024
MAX_INPUT_FILES = 256
MAX_MANIFEST_DOCUMENTS = 512
MAX_STRUCTURE_DEPTH = 100
MAX_STRUCTURE_NODES = 200_000

_ALLOWED_CHART_ROOT_ENTRIES = {
    "Chart.yaml",
    "values.yaml",
    "values.schema.json",
    ".helmignore",
    "templates",
}


class RenderError(RuntimeError):
    """A fail-closed renderer failure with a stable machine-readable code."""

    def __init__(self, message: str, *, code: str = "render_error", details: dict[str, Any] | None = None):
        super().__init__(message)
        self.code = code
        self.details = details or {}

    def as_dict(self) -> dict[str, Any]:
        return {"code": self.code, "message": str(self), "details": self.details}


class _UniqueKeySafeLoader(yaml.SafeLoader):
    """Safe YAML loader that refuses ambiguous duplicate mapping keys."""

    def construct_mapping(self, node: yaml.nodes.MappingNode, deep: bool = False):  # type: ignore[override]
        if not isinstance(node, yaml.MappingNode):
            raise yaml.constructor.ConstructorError(
                None, None, "expected a mapping node", node.start_mark
            )
        seen: set[Any] = set()
        for key_node, _value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                duplicate = key in seen
            except TypeError as exc:
                raise yaml.constructor.ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    "found an unhashable key",
                    key_node.start_mark,
                ) from exc
            if duplicate:
                raise yaml.constructor.ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    f"found duplicate key {key!r}",
                    key_node.start_mark,
                )
            seen.add(key)
        return super().construct_mapping(node, deep=deep)


def _is_linux() -> bool:
    return sys.platform.startswith("linux")


def _bounded_int(config: dict[str, Any], key: str, default: int, minimum: int, maximum: int) -> int:
    raw = config.get(key, default)
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise RenderError(f"{key} must be an integer", code="invalid_render_config")
    if raw < minimum or raw > maximum:
        raise RenderError(
            f"{key} must be between {minimum} and {maximum}",
            code="invalid_render_config",
        )
    return raw


def _validate_config(config: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(config, dict):
        raise RenderError("renderer config must be a mapping", code="invalid_render_config")
    chart_rel = str(config.get("chart_rel_path", CHART_REL_PATH))
    values_rel = str(config.get("values_rel_path", VALUES_REL_PATH))
    if chart_rel != CHART_REL_PATH or values_rel != VALUES_REL_PATH:
        raise RenderError(
            "the renderer only accepts charts/demo and gitops/demo/values.yaml",
            code="path_not_permitted",
        )
    namespace = str(config.get("namespace", "demo"))
    release = str(config.get("release_name", "demo"))
    _validate_dns_label(namespace, "namespace")
    _validate_dns_label(release, "release_name")
    kube_version = str(config.get("kube_version", "1.37.2"))
    if not _valid_kube_version(kube_version):
        raise RenderError("invalid kube_version", code="invalid_render_config")
    return {
        "chart_rel": chart_rel,
        "values_rel": values_rel,
        "namespace": namespace,
        "release": release,
        "kube_version": kube_version,
        "helm": str(config.get("helm", "/usr/local/bin/helm")),
        "bwrap": str(config.get("bwrap", "/usr/bin/bwrap")),
        "timeout": _bounded_int(config, "render_timeout_seconds", DEFAULT_TIMEOUT_SECONDS, 1, 600),
        "output_limit": _bounded_int(
            config, "render_output_limit_bytes", DEFAULT_OUTPUT_LIMIT_BYTES, 1024, 64 * 1024 * 1024
        ),
        "memory_limit": _bounded_int(
            config,
            "sandbox_memory_bytes",
            DEFAULT_MEMORY_LIMIT_BYTES,
            64 * 1024 * 1024,
            8 * 1024 * 1024 * 1024,
        ),
        "tmpfs_bytes": _bounded_int(
            config, "sandbox_tmpfs_bytes", DEFAULT_TMPFS_BYTES, 1024 * 1024, 1024 * 1024 * 1024
        ),
    }


def _valid_kube_version(value: str) -> bool:
    import re

    return bool(re.fullmatch(r"(0|[1-9]\d*)\.(0|[1-9]\d*)(\.(0|[1-9]\d*))?", value))


def _validate_dns_label(value: str, field: str) -> None:
    import re

    if not re.fullmatch(r"[a-z0-9]([-a-z0-9]*[a-z0-9])?", value) or len(value) > 63:
        raise RenderError(f"{field} is not a valid DNS label", code="invalid_render_config")


def _assert_no_symlink(path: Path, *, label: str) -> None:
    try:
        if path.is_symlink():
            raise RenderError(f"{label} must not be a symlink", code="symlink_not_permitted")
    except OSError as exc:  # pragma: no cover - platform dependent
        raise RenderError(f"cannot inspect {label}: {exc}", code="path_unreadable") from exc


def _assert_chain_without_symlinks(root: Path, target: Path, *, label: str) -> None:
    try:
        relative = target.relative_to(root)
    except ValueError as exc:
        raise RenderError(f"{label} escapes the candidate tree", code="path_not_permitted") from exc
    current = root
    _assert_no_symlink(current, label=f"{label} root")
    for part in relative.parts:
        current = current / part
        _assert_no_symlink(current, label=label)


def _read_regular_file(path: Path, *, limit: int, label: str) -> bytes:
    _assert_no_symlink(path, label=label)
    if not path.is_file():
        raise RenderError(f"{label} is not a regular file", code="path_not_permitted")
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise RenderError(f"cannot stat {label}: {exc}", code="path_unreadable") from exc
    if size > limit:
        raise RenderError(
            f"{label} exceeds {limit} bytes",
            code="input_too_large",
            details={"size": size, "limit": limit},
        )
    try:
        return path.read_bytes()
    except OSError as exc:
        raise RenderError(f"cannot read {label}: {exc}", code="path_unreadable") from exc


def _validate_structure(value: Any, *, source: str) -> None:
    """Reject recursive, non-JSON, or unreasonably deep YAML structures."""

    seen: set[int] = set()
    node_count = 0

    def walk(item: Any, depth: int) -> None:
        nonlocal node_count
        node_count += 1
        if node_count > MAX_STRUCTURE_NODES:
            raise RenderError(f"{source} contains too many YAML nodes", code="manifest_too_complex")
        if depth > MAX_STRUCTURE_DEPTH:
            raise RenderError(f"{source} YAML nesting is too deep", code="manifest_too_complex")
        if item is None or isinstance(item, (str, bool, int)):
            return
        if isinstance(item, float):
            if not math.isfinite(item):
                raise RenderError(f"{source} contains a non-finite number", code="invalid_manifest")
            return
        if isinstance(item, bytes):
            raise RenderError(f"{source} contains binary data", code="invalid_manifest")
        if isinstance(item, (list, dict)):
            identity = id(item)
            if identity in seen:
                raise RenderError(f"{source} contains a recursive YAML alias", code="manifest_too_complex")
            seen.add(identity)
            if isinstance(item, list):
                for child in item:
                    walk(child, depth + 1)
            else:
                for key, child in item.items():
                    if not isinstance(key, (str, int, float, bool)) and key is not None:
                        raise RenderError(
                            f"{source} contains a non-scalar mapping key", code="invalid_manifest"
                        )
                    walk(key, depth + 1)
                    walk(child, depth + 1)
            seen.remove(identity)
            return
        raise RenderError(
            f"{source} contains unsupported value type {type(item).__name__}",
            code="invalid_manifest",
        )

    walk(value, 0)


def _load_yaml_documents(text: str, *, source: str, max_documents: int = MAX_MANIFEST_DOCUMENTS) -> list[Any]:
    if len(text.encode("utf-8")) > DEFAULT_OUTPUT_LIMIT_BYTES * 4:
        raise RenderError(f"{source} is too large", code="output_too_large")
    documents: list[Any] = []
    try:
        for document in yaml.load_all(text, Loader=_UniqueKeySafeLoader):
            if document is None:
                continue
            documents.append(document)
            if len(documents) > max_documents:
                raise RenderError(
                    f"{source} contains more than {max_documents} YAML documents",
                    code="too_many_documents",
                )
    except RenderError:
        raise
    except yaml.YAMLError as exc:
        raise RenderError(f"invalid YAML in {source}: {exc}", code="invalid_yaml") from exc
    _validate_structure(documents, source=source)
    return documents


def _looks_like_kubernetes_object(obj: Any) -> bool:
    return (
        isinstance(obj, dict)
        and isinstance(obj.get("apiVersion"), str)
        and bool(obj.get("apiVersion"))
        and isinstance(obj.get("kind"), str)
        and bool(obj.get("kind"))
    )


def _flatten_manifests(documents: Iterable[Any], *, source: str) -> list[dict[str, Any]]:
    resources: list[dict[str, Any]] = []

    def add(obj: Any) -> None:
        if not _looks_like_kubernetes_object(obj):
            raise RenderError(
                f"{source} contains a document that is not a Kubernetes object",
                code="invalid_manifest",
            )
        kind = obj["kind"]
        if kind == "List":
            items = obj.get("items")
            if not isinstance(items, list):
                raise RenderError(f"{source} contains a List without items", code="invalid_manifest")
            for item in items:
                add(item)
            return
        metadata = obj.get("metadata")
        if not isinstance(metadata, dict) or not isinstance(metadata.get("name"), str) or not metadata.get("name"):
            raise RenderError(
                f"{source} contains a {kind} without metadata.name",
                code="invalid_manifest",
            )
        resources.append(obj)

    for document in documents:
        add(document)
    if len(resources) > MAX_MANIFEST_DOCUMENTS:
        raise RenderError(f"{source} renders too many objects", code="too_many_documents")
    return resources


def load_rendered_manifests(
    paths: str | os.PathLike[str] | Sequence[str | os.PathLike[str]],
    config: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Load bounded, validated, already-rendered YAML fixtures.

    This never executes anything.  It exists for Windows/local CLI use and for
    deterministic tests; production rendering always goes through bubblewrap.
    """

    config = config or {}
    output_limit = _bounded_int(
        config, "render_output_limit_bytes", DEFAULT_OUTPUT_LIMIT_BYTES, 1024, 64 * 1024 * 1024
    )
    if isinstance(paths, (str, os.PathLike)):
        candidates: list[str | os.PathLike[str]] = [paths]
    else:
        candidates = list(paths)
    if not candidates:
        raise RenderError("no rendered manifest supplied", code="invalid_input")
    if len(candidates) > MAX_INPUT_FILES:
        raise RenderError("too many rendered manifests", code="input_too_large")

    documents: list[Any] = []
    total = 0
    for index, candidate in enumerate(candidates):
        path = Path(candidate)
        if path.is_dir():
            raise RenderError("rendered input must be a file, not a directory", code="path_not_permitted")
        raw = _read_regular_file(
            path, limit=min(MAX_INPUT_FILE_BYTES, output_limit), label=f"rendered manifest {index}"
        )
        total += len(raw)
        if total > min(MAX_INPUT_TOTAL_BYTES, output_limit):
            raise RenderError("rendered manifests exceed the size limit", code="input_too_large")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RenderError("rendered manifest is not UTF-8", code="invalid_manifest") from exc
        documents.extend(_load_yaml_documents(text, source=f"rendered manifest {index}"))
    return _flatten_manifests(documents, source="rendered manifests")


def _copy_file_checked(source: Path, destination: Path, *, remaining: int, label: str) -> int:
    _assert_no_symlink(source, label=label)
    if not source.is_file():
        raise RenderError(f"{label} is not a regular file", code="path_not_permitted")
    size = source.stat().st_size
    if size > MAX_INPUT_FILE_BYTES:
        raise RenderError(f"{label} is too large", code="input_too_large", details={"size": size})
    if size > remaining:
        raise RenderError(f"{label} exceeds the total input limit", code="input_too_large")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    return size


def _copy_permitted_tree(root: Path, workdir: Path, config: dict[str, Any]) -> tuple[Path, Path]:
    chart_root = root / config["chart_rel"]
    values_path = root / config["values_rel"]
    _assert_chain_without_symlinks(root, chart_root, label="chart path")
    _assert_chain_without_symlinks(root, values_path, label="values path")
    if not chart_root.is_dir():
        raise RenderError(f"{config['chart_rel']} does not exist", code="chart_missing")
    if not values_path.is_file():
        raise RenderError(f"{config['values_rel']} does not exist", code="values_missing")

    chart_destination = workdir / "chart"
    chart_destination.mkdir(parents=True, exist_ok=True)
    values_destination = workdir / "values.yaml"

    total = _copy_file_checked(
        values_path,
        values_destination,
        remaining=MAX_INPUT_TOTAL_BYTES,
        label=config["values_rel"],
    )
    values_raw = values_destination.read_bytes()
    try:
        values_text = values_raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RenderError("values file is not UTF-8", code="invalid_values") from exc
    try:
        values_document = yaml.load(values_text, Loader=_UniqueKeySafeLoader)
    except yaml.YAMLError as exc:
        raise RenderError(f"invalid values YAML: {exc}", code="invalid_values") from exc
    _validate_structure(values_document, source="values")
    if values_document is None:
        values_document = {}
    if not isinstance(values_document, dict):
        raise RenderError("values file must contain a mapping", code="invalid_values")

    files = 0
    for entry in sorted(chart_root.iterdir(), key=lambda item: item.name):
        name = entry.name
        if name not in _ALLOWED_CHART_ROOT_ENTRIES:
            raise RenderError(
                f"chart entry {name!r} is not permitted (dependencies/files/crds are rejected)",
                code="unsupported_chart_entry",
            )
        if name == "templates":
            _assert_no_symlink(entry, label="templates directory")
            if not entry.is_dir():
                raise RenderError("templates must be a directory", code="invalid_chart")
            for directory, dirnames, filenames in os.walk(entry, followlinks=False):
                directory_path = Path(directory)
                _assert_no_symlink(directory_path, label="templates directory")
                for dirname in list(dirnames):
                    child = directory_path / dirname
                    _assert_no_symlink(child, label="templates directory")
                for filename in sorted(filenames):
                    files += 1
                    if files > MAX_INPUT_FILES:
                        raise RenderError("chart has too many files", code="input_too_large")
                    source_file = directory_path / filename
                    relative = source_file.relative_to(chart_root)
                    destination = chart_destination / relative
                    copied = _copy_file_checked(
                        source_file,
                        destination,
                        remaining=MAX_INPUT_TOTAL_BYTES - total,
                        label=f"chart file {relative.as_posix()}",
                    )
                    total += copied
                    if total > MAX_INPUT_TOTAL_BYTES:
                        raise RenderError("chart input exceeds the total size limit", code="input_too_large")
        else:
            files += 1
            if files > MAX_INPUT_FILES:
                raise RenderError("chart has too many files", code="input_too_large")
            copied = _copy_file_checked(
                entry,
                chart_destination / name,
                remaining=MAX_INPUT_TOTAL_BYTES - total,
                label=f"chart file {name}",
            )
            total += copied
            if total > MAX_INPUT_TOTAL_BYTES:
                raise RenderError("chart input exceeds the total size limit", code="input_too_large")

    if not (chart_destination / "Chart.yaml").is_file():
        raise RenderError("chart is missing Chart.yaml", code="invalid_chart")
    if not (chart_destination / "templates").is_dir():
        raise RenderError("chart is missing templates/", code="invalid_chart")
    # Argo renders with cluster API capabilities and release metadata that can
    # differ from this offline process. Restrict this small lab chart to stable
    # templates rather than accepting a second, divergent deployment program.
    forbidden = re.compile(
        r"\b(lookup|tpl|now|randAlphaNum|randAlpha|randAscii|randNumeric|randBytes|"
        r"uuidv4|genCA|genSelfSignedCert|genSignedCert|encryptAES|derivePassword|"
        r"getHostByName)\b|\.Capabilities\b|\.Release\.(Revision|IsInstall|IsUpgrade)\b"
    )
    for candidate in chart_destination.rglob('*'):
        if candidate.is_file():
            text = candidate.read_text(encoding='utf-8')
            if forbidden.search(text):
                raise RenderError('chart uses dynamic or environment-dependent templates', code='dynamic_template_forbidden')
    chart_meta = yaml.load((chart_destination / 'Chart.yaml').read_text(encoding='utf-8'), Loader=_UniqueKeySafeLoader)
    if not isinstance(chart_meta, dict) or chart_meta.get('dependencies'):
        raise RenderError('chart dependencies are not permitted', code='unsupported_chart_entry')
    return chart_destination, values_destination


def _require_sandbox(config: dict[str, Any]) -> None:
    if not _is_linux():
        raise RenderError(
            "production rendering requires Linux bubblewrap; use load_rendered_manifests for fixtures",
            code="bwrap_required",
        )
    bwrap = Path(config["bwrap"])
    if not bwrap.is_file() or not os.access(bwrap, os.X_OK):
        raise RenderError(
            "bubblewrap is required and must be executable; no unsandboxed fallback exists",
            code="bwrap_missing",
        )
    helm = Path(config["helm"])
    if not helm.is_file() or not os.access(helm, os.X_OK):
        raise RenderError("helm executable is missing", code="helm_missing")


def _build_bwrap_command(config: dict[str, Any], workdir: Path) -> list[str]:
    helm = str(Path(config["helm"]).resolve())
    bwrap = str(Path(config["bwrap"]))
    command = [
        bwrap,
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        "--clearenv",
        "--cap-drop",
        "ALL",
        "--ro-bind-try",
        "/usr",
        "/usr",
        "--ro-bind-try",
        "/bin",
        "/bin",
        "--ro-bind-try",
        "/sbin",
        "/sbin",
        "--ro-bind-try",
        "/lib",
        "/lib",
        "--ro-bind-try",
        "/lib64",
        "/lib64",
        "--dir",
        "/etc",
        "--ro-bind-try",
        "/etc/ld.so.cache",
        "/etc/ld.so.cache",
        "--tmpfs",
        "/tmp",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--bind",
        str(workdir),
        "/work",
        "--chdir",
        "/work",
        "--setenv",
        "HOME",
        "/tmp",
        "--setenv",
        "PATH",
        "/usr/local/bin:/usr/bin:/bin",
        "--setenv",
        "HELM_CACHE_HOME",
        "/tmp/helm-cache",
        "--setenv",
        "HELM_CONFIG_HOME",
        "/tmp/helm-config",
        "--setenv",
        "HELM_DATA_HOME",
        "/tmp/helm-data",
        "--setenv",
        "HELM_PLUGINS",
        "/tmp/no-helm-plugins",
        "--setenv",
        "HELM_REGISTRY_CONFIG",
        "/tmp/empty-registry.json",
        "--setenv",
        "HELM_REPOSITORY_CONFIG",
        "/tmp/empty-repositories.yaml",
        "--setenv",
        "HELM_REPOSITORY_CACHE",
        "/tmp/helm-cache",
        "--setenv",
        "KUBECONFIG",
        "/tmp/empty-kubeconfig",
        "--setenv",
        "HELM_DEBUG",
        "0",
        "--",
        HELM_TARGET,
        "template",
        config["release"],
        "/work/chart",
        "--namespace",
        config["namespace"],
        "--values",
        "/work/values.yaml",
        "--kube-version",
        config["kube_version"],
    ]
    if helm != HELM_TARGET:
        # The trusted host helm binary is mounted at a fixed path, so a candidate
        # tree cannot influence which executable runs.
        command[command.index("--dir") : command.index("--dir")] = [
            "--ro-bind",
            helm,
            HELM_TARGET,
        ]
    return command


def _preexec_limits(memory_limit: int, output_limit: int, timeout: int):  # pragma: no cover - OS specific
    def apply() -> None:
        try:
            import resource
        except ImportError:
            return
        limits = [
            (resource.RLIMIT_AS, memory_limit),
            (resource.RLIMIT_FSIZE, output_limit),
            (resource.RLIMIT_CPU, max(2, int(timeout) + 5)),
            (resource.RLIMIT_NOFILE, 128),
        ]
        if hasattr(resource, "RLIMIT_NPROC"):
            limits.append((resource.RLIMIT_NPROC, 128))
        for which, value in limits:
            try:
                resource.setrlimit(which, (value, value))
            except (ValueError, OSError):
                # Some kernels refuse lowering a hard limit.  Time/output bounds
                # are still enforced by the supervisor.
                continue

    return apply


def _execute(
    command: list[str],
    *,
    cwd: Path,
    timeout: int,
    output_limit: int,
    memory_limit: int,
) -> tuple[str, str]:
    """Run a command with bounded stdout/stderr and no inherited environment."""

    env = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": str(cwd / "empty-home"),
        "LANG": "C",
        "LC_ALL": "C",
    }
    (cwd / "empty-home").mkdir(exist_ok=True)
    with tempfile.TemporaryFile(dir=cwd) as out_file, tempfile.TemporaryFile(dir=cwd) as err_file:
        process: subprocess.Popen[bytes] | None = None
        try:
            process = subprocess.Popen(
                command,
                cwd=str(cwd),
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=out_file,
                stderr=err_file,
                close_fds=True,
                start_new_session=True,
                preexec_fn=_preexec_limits(memory_limit, output_limit, timeout)
                if os.name == "posix"
                else None,
            )
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired as exc:
                if process.poll() is None:
                    try:
                        if os.name == "posix":
                            os.killpg(process.pid, 9)
                        else:  # pragma: no cover - production is Linux
                            process.kill()
                    except ProcessLookupError:
                        pass
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:  # pragma: no cover
                        pass
                raise RenderError(
                    "helm render timed out inside bubblewrap", code="render_timeout"
                ) from exc
        except RenderError:
            raise
        except OSError as exc:
            raise RenderError(f"failed to start sandboxed helm: {exc}", code="sandbox_start_failed") from exc

        out_file.seek(0, os.SEEK_END)
        err_file.seek(0, os.SEEK_END)
        out_size = out_file.tell()
        err_size = err_file.tell()
        if out_size > output_limit or err_size > output_limit:
            raise RenderError(
                "sandboxed helm output exceeded the size limit",
                code="output_too_large",
                details={"stdout_bytes": out_size, "stderr_bytes": err_size, "limit": output_limit},
            )
        out_file.seek(0)
        err_file.seek(0)
        stdout = out_file.read(out_size).decode("utf-8", errors="replace")
        stderr = err_file.read(err_size).decode("utf-8", errors="replace")
        if process.returncode != 0:
            summary = " ".join(stderr.strip().splitlines()[-3:])[:1500]
            raise RenderError(
                f"sandboxed helm failed with exit {process.returncode}: {summary}",
                code="helm_failed",
            )
        return stdout, stderr


def _fixture_paths(tree: Path, config: dict[str, Any]) -> list[Path] | None:
    mode = config.get("renderer_mode")
    requested = (
        config.get("allow_pre_rendered") is True
        or mode in {"prebuilt", "fixture", "rendered"}
        or config.get("pre_rendered") not in (None, False)
    )
    if not requested:
        return None
    if _is_linux() and not config.get("fixture_mode"):
        raise RenderError(
            "pre-rendered inputs are fixture-only and disabled on Linux production hosts",
            code="pre_rendered_forbidden",
        )
    supplied = config.get("pre_rendered")
    if supplied is True or supplied is None:
        return [tree]
    if isinstance(supplied, (str, os.PathLike)):
        return [Path(supplied)]
    if isinstance(supplied, (list, tuple)) and all(isinstance(item, (str, os.PathLike)) for item in supplied):
        return [Path(item) for item in supplied]
    raise RenderError("pre_rendered must be a path or list of paths", code="invalid_render_config")


def render_tree(tree: str | os.PathLike[str], config: dict[str, Any]) -> list[dict[str, Any]]:
    """Render ``charts/demo`` from *tree* with ``gitops/demo/values.yaml``.

    The result is a list of Kubernetes objects.  On production Linux the call
    always executes inside bubblewrap; failures are raised, never silently
    replaced by unsandboxed Helm.
    """

    if not isinstance(config, dict):
        raise RenderError("renderer config must be a mapping", code="invalid_render_config")
    root = Path(tree)
    fixture_paths = _fixture_paths(root, config)
    if fixture_paths is not None:
        return load_rendered_manifests(fixture_paths, config)

    settings = _validate_config(config)
    _require_sandbox(settings)
    original_root = root
    _assert_no_symlink(original_root, label="candidate tree")
    try:
        root = original_root.resolve(strict=True)
    except OSError as exc:
        raise RenderError(f"candidate tree does not exist: {exc}", code="tree_missing") from exc
    _assert_no_symlink(root, label="candidate tree")
    if not root.is_dir():
        raise RenderError("candidate tree must be a directory", code="tree_missing")

    with tempfile.TemporaryDirectory(prefix="change-guard-render-") as temp:
        workdir = Path(temp) / "work"
        workdir.mkdir(mode=0o700)
        _copy_permitted_tree(root, workdir, settings)
        command = _build_bwrap_command(settings, workdir)
        stdout, _stderr = _execute(
            command,
            cwd=workdir,
            timeout=settings["timeout"],
            output_limit=settings["output_limit"],
            memory_limit=settings["memory_limit"],
        )
        if len(stdout.encode("utf-8")) > settings["output_limit"]:
            raise RenderError(
                "helm output exceeded the configured size limit",
                code="output_too_large",
            )
    documents = _load_yaml_documents(stdout, source="helm output")
    resources = _flatten_manifests(documents, source="helm output")
    for obj in resources:
        annotations = obj.get('metadata', {}).get('annotations', {}) or {}
        if any(key in annotations for key in ('helm.sh/hook', 'argocd.argoproj.io/hook')):
            raise RenderError('Helm/Argo hooks are forbidden in the protected demo chart', code='hooks_forbidden')
    return resources


def render_or_load_fixture(path: str | os.PathLike[str], config: dict[str, Any]) -> list[dict[str, Any]]:
    """Convenience alias used by local CLI/tests for already-rendered files."""

    return load_rendered_manifests(path, config)


def digest_manifests(resources: Sequence[dict[str, Any]]) -> str:
    """Stable digest of a rendered resource list (order independent)."""

    def canonical(value: Any) -> str:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)

    ordered = sorted(resources, key=lambda item: canonical(item))
    return hashlib.sha256(canonical(ordered).encode("utf-8")).hexdigest()
