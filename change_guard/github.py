"""Hardened GitHub access for the k8s change guard.

This module is deliberately small and boring: it only speaks to the fixed
GitHub REST API host, it never checks out or executes a pull-request branch, and
it materialises only the files the trusted renderer is allowed to read.

Security properties
-------------------
* A pull request is identified by its exact ``head.sha``.  The baseline is the
  *current* base branch tip, not the possibly stale ``base.sha`` recorded on the
  pull request.
* The candidate tree is obtained from the Git Trees/Blobs APIs.  Full archives
  are never downloaded or extracted, so there is no archive path traversal
  surface.  Symlinks, git submodules, unsafe paths, duplicate paths, truncated
  trees, and oversized files are rejected.
* Only ``charts/demo/**`` and ``gitops/demo/values.yaml`` are written into the
  renderer tree.  Argo CD / deployment manifests are read in memory for review
  context only.
* API responses are bounded, redirects are refused, retries are bounded, and
  authentication tokens are never included in exceptions or reports.
* Commit statuses are written only through the statuses endpoint.  The helper
  for ``/guard approve`` requires an exact command, the configured allowlist,
  a real-time repository write/admin permission check, and an unexpired
  evaluation bound to the same head/base.  Personal-repository ownership is
  checked from current repository metadata because the collaborator-permission
  endpoint requires Administration: read for fine-grained tokens.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import quote, urlsplit

import requests
import yaml

GITHUB_API_URL = "https://api.github.com"
DEFAULT_TIMEOUT_SECONDS = 20
DEFAULT_MAX_RESPONSE_BYTES = 8 * 1024 * 1024
DEFAULT_RETRIES = 2
MAX_RATE_LIMIT_WAIT_SECONDS = 60
MAX_PR_PAGES = 20
MAX_PR_PER_PAGE = 100
MAX_COMMENT_PAGES = 10
MAX_COMMENTS = 1000
MAX_TREE_ENTRIES = 100_000
MAX_CHANGED_PATHS = 5_000
MAX_RENDER_FILES = 256
MAX_RENDER_FILE_BYTES = 2 * 1024 * 1024
MAX_RENDER_TOTAL_BYTES = 12 * 1024 * 1024
MAX_ARGO_FILES = 64
MAX_ARGO_FILE_BYTES = 512 * 1024
MAX_ARGO_TOTAL_BYTES = 4 * 1024 * 1024
MAX_STATUS_DESCRIPTION = 140
MAX_STATUS_CONTEXT = 100
MAX_COMMENT_BYTES = 60_000
MAX_REPO_PATH_BYTES = 4_096

STATUS_STATES = frozenset({"error", "failure", "pending", "success"})
WRITE_PERMISSIONS = frozenset({"admin", "write"})
# For a personal repository (owner.type == "User") the owner always has admin
# rights and cannot be represented with a lower collaborator role.  Fine-grained
# tokens cannot call the collaborator-permission endpoint (it needs
# Administration: read), so daemon approval uses this association as the
# non-admin proof for the repository owner.
OWNER_APPROVAL_PERMISSION = "owner"
CLASSIC_STATUS_SCOPES = frozenset({"repo", "repo:status"})

APPROVAL_RE = re.compile(r"/guard approve ([A-Za-z0-9][A-Za-z0-9_-]{0,127})")
_REPO_RE = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}")
_SHA_RE = re.compile(r"[0-9a-f]{40,64}")
_LOGIN_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?")
_BRANCH_RE = re.compile(r"[A-Za-z0-9._/-]{1,255}")
_SAFE_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# Paths that can alter what is deployed even when they are not consumed by the
# trusted Helm renderer.  A change in one of these is surfaced to the caller as
# a review item instead of being silently ignored.
DEPLOYMENT_PATH_PREFIXES = (
    "charts/",
    "gitops/",
    "argocd/",
    "deploy/",
    "deployment/",
    "deployments/",
    "k8s/",
    "kubernetes/",
    "manifests/",
    "helm/",
    "environments/",
    "env/",
    "terraform/",
    ".github/workflows/",
)
RENDERER_PATHS = ("charts/demo/", "gitops/demo/values.yaml")
_SECRET_KEY_PARTS = (
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
)
_TOKEN_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----", re.DOTALL),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"\b(?:ghp|gho|ghu|ghs|github_pat|xox[baprs])[-_][A-Za-z0-9_-]{8,}"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b"),
)


class GitHubError(RuntimeError):
    """A fail-closed GitHub/API error with a sanitized message."""

    def __init__(
        self,
        message: str,
        *,
        status: int | None = None,
        code: str = "github_error",
        retryable: bool = False,
        details: Mapping[str, Any] | None = None,
    ):
        super().__init__(sanitize_text(str(message), limit=800))
        self.status = status
        self.code = code
        self.retryable = retryable
        self.details = dict(details or {})

    def as_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "status": self.status,
            "retryable": self.retryable,
            "message": str(self),
            "details": dict(self.details),
        }


class GitHubAuthError(GitHubError):
    """Credentials cannot perform the required repository operations."""


class GitHubRateLimitError(GitHubError):
    """GitHub asked us to wait longer than the configured bound."""


class TreeSecurityError(GitHubError):
    """A fetched Git tree violates the candidate-tree policy."""


class ForkNotAllowedError(GitHubError):
    """The pull request comes from an untrusted fork."""


# ---------------------------------------------------------------------------
# Generic helpers


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def sanitize_text(value: Any, *, limit: int = 2000) -> str:
    """Remove credentials-like strings and control characters from text."""

    text = str(value)
    for pattern in _TOKEN_PATTERNS:
        text = pattern.sub("<redacted>", text)
    text = _SAFE_CONTROL_RE.sub(" ", text)
    text = " ".join(text.split())
    if len(text) > limit:
        text = text[: max(0, limit - 3)] + "..."
    return text


def _header(headers: Mapping[str, Any], name: str) -> str | None:
    lowered = name.lower()
    for key, value in headers.items():
        if str(key).lower() == lowered:
            return str(value)
    return None


def _parse_retry_after(value: str | None) -> float | None:
    if not value:
        return None
    try:
        seconds = float(value)
    except ValueError:
        return None
    return seconds if math.isfinite(seconds) and seconds >= 0 else None


def _parse_github_time(value: Any) -> float | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    try:
        timestamp = parsed.timestamp()
    except (OverflowError, OSError, ValueError):
        return None
    return timestamp if math.isfinite(timestamp) else None


def iso_utc(timestamp: float | int | None) -> str:
    if not isinstance(timestamp, (int, float)) or not math.isfinite(float(timestamp)):
        return "unknown"
    return datetime.fromtimestamp(float(timestamp), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize_repo_path(path: Any) -> str:
    """Return a safe POSIX repository path or raise.

    The Git tree format always uses ``/``.  Backslashes, absolute paths, ``.``,
    ``..``, NUL/control characters, duplicate slashes, and trailing slashes are
    rejected rather than normalized, so a caller can never be confused about
    which file was read.
    """

    if not isinstance(path, str) or not path:
        raise TreeSecurityError("repository path is empty or not a string", code="path_invalid")
    if len(path.encode("utf-8", errors="ignore")) > MAX_REPO_PATH_BYTES:
        raise TreeSecurityError("repository path exceeds the size limit", code="path_invalid")
    if "\\" in path or "\x00" in path or _SAFE_CONTROL_RE.search(path):
        raise TreeSecurityError(f"repository path contains a forbidden character: {path!r}", code="path_invalid")
    if path.startswith("/") or path.endswith("/") or "//" in path:
        raise TreeSecurityError(f"repository path is not a clean relative path: {path!r}", code="path_invalid")
    parts = path.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise TreeSecurityError(f"repository path contains a traversal component: {path!r}", code="path_traversal")
    return path


def is_deployment_path(path: str) -> bool:
    lowered = path.lower()
    return any(lowered.startswith(prefix) for prefix in DEPLOYMENT_PATH_PREFIXES)


def is_renderer_path(path: str) -> bool:
    return path == "gitops/demo/values.yaml" or path.startswith(RENDERER_PATHS[0])


def is_argo_path(path: str) -> bool:
    lowered = path.lower()
    return (
        lowered.startswith("gitops/argocd/")
        or lowered.startswith("argocd/")
        or lowered.endswith(("/application.yaml", "/application.yml", "/project.yaml", "/project.yml"))
        or lowered in {"application.yaml", "application.yml", "project.yaml", "project.yml"}
    )


def parse_approval_body(body: Any) -> str | None:
    """Return the evaluation id for an exact ``/guard approve <id>`` comment."""

    if not isinstance(body, str):
        return None
    match = APPROVAL_RE.fullmatch(body.strip())
    return match.group(1) if match else None


def _validate_branch(branch: Any) -> str:
    if not isinstance(branch, str) or not _BRANCH_RE.fullmatch(branch):
        raise GitHubError("base branch name is invalid", code="invalid_branch")
    if branch.startswith("/") or branch.endswith("/") or ".." in branch.split("/"):
        raise GitHubError("base branch name contains a traversal component", code="invalid_branch")
    return branch


def _validate_sha(value: Any, label: str = "commit sha") -> str:
    if not isinstance(value, str) or not _SHA_RE.fullmatch(value):
        raise GitHubError(f"{label} is not a hexadecimal Git object id", code="invalid_sha")
    return value


def _validate_login(value: Any) -> str:
    if not isinstance(value, str) or not _LOGIN_RE.fullmatch(value):
        raise GitHubError("GitHub login is invalid", code="invalid_login")
    return value


def _sanitize_status_description(value: Any) -> str:
    text = sanitize_text(value, limit=MAX_STATUS_DESCRIPTION)
    return text or "change-guard evaluation"


def _sanitize_status_context(value: Any) -> str:
    text = sanitize_text(value, limit=MAX_STATUS_CONTEXT)
    if not re.fullmatch(r"[A-Za-z0-9._/-]{1,100}", text):
        raise GitHubError("status context contains unsupported characters", code="invalid_status_context")
    return text


# ---------------------------------------------------------------------------
# Candidate tree types


@dataclass(frozen=True)
class PullRequestInfo:
    number: int
    title: str
    author: str
    state: str
    draft: bool
    head_sha: str
    head_ref: str
    head_repo: str
    base_sha: str
    base_ref: str
    base_repo: str
    created_at: float | None = None
    updated_at: float | None = None
    raw_url: str | None = None


@dataclass(frozen=True)
class TreeEntry:
    path: str
    mode: str
    kind: str
    sha: str
    size: int


@dataclass(frozen=True)
class TreeSnapshot:
    sha: str
    tree_sha: str
    entries: Mapping[str, TreeEntry]
    renderer_files: Mapping[str, bytes]
    argo_files: Mapping[str, bytes]
    tree_digest: str
    entry_count: int
    renderer_bytes: int
    argo_bytes: int

    def materialize(self, destination: str | os.PathLike[str]) -> list[str]:
        return _materialize_files(self.renderer_files, destination)


@dataclass(frozen=True)
class ArgoAnalysis:
    argo_source_changed: bool = False
    argo_application_changed: bool = False
    argo_project_changed: bool = False
    argo_manifest_error: bool = False
    argo_changed_paths: tuple[str, ...] = ()
    applications: int = 0

    def as_context(self) -> dict[str, Any]:
        return {
            "argo_source_changed": bool(self.argo_source_changed),
            "argo_application_changed": bool(self.argo_application_changed),
            "argo_project_changed": bool(self.argo_project_changed),
            "argo_manifest_error": bool(self.argo_manifest_error),
            "argo_changed_paths": list(self.argo_changed_paths)[:200],
            "argo_application_count": self.applications,
        }


@dataclass(frozen=True)
class PullRequestCandidate:
    pull_request: PullRequestInfo
    base_sha: str
    base_snapshot: TreeSnapshot
    head_snapshot: TreeSnapshot
    changed_paths: tuple[str, ...]
    changed_count: int
    tree_diff_truncated: bool
    argo: ArgoAnalysis
    pr_base_sha: str


# ---------------------------------------------------------------------------
# Filesystem materialisation


def _materialize_files(files: Mapping[str, bytes], destination: str | os.PathLike[str]) -> list[str]:
    """Write only pre-validated renderer files below *destination*.

    Parent directories are created by us (never followed from the archive),
    each final component is opened with ``O_NOFOLLOW`` where available, and an
    existing file is never overwritten.
    """

    root = os.path.abspath(os.fspath(destination))
    if os.path.islink(root):
        raise TreeSecurityError("materialisation root must not be a symlink", code="symlink_not_permitted")
    os.makedirs(root, mode=0o700, exist_ok=True)
    if not os.path.isdir(root):
        raise TreeSecurityError("materialisation root is not a directory", code="path_not_permitted")

    written: list[str] = []
    for relative in sorted(files):
        path = normalize_repo_path(relative)
        if not is_renderer_path(path):
            raise TreeSecurityError(f"refusing to materialise non-renderer path {path!r}", code="path_not_permitted")
        target = os.path.abspath(os.path.join(root, *path.split("/")))
        root_prefix = root + os.sep
        if not (target == root or target.startswith(root_prefix)):
            raise TreeSecurityError(f"materialised path escapes its root: {path!r}", code="path_traversal")
        current = root
        for part in path.split("/")[:-1]:
            current = os.path.join(current, part)
            if os.path.islink(current):
                raise TreeSecurityError(f"materialisation parent is a symlink: {path!r}", code="symlink_not_permitted")
            if not os.path.exists(current):
                os.mkdir(current, 0o700)
            if not os.path.isdir(current):
                raise TreeSecurityError(f"materialisation parent is not a directory: {path!r}", code="path_not_permitted")
        if os.path.lexists(target):
            raise TreeSecurityError(f"refusing to overwrite existing file {path!r}", code="path_not_permitted")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(target, flags, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(files[path])
                handle.flush()
                os.fsync(handle.fileno())
        except Exception:
            try:
                os.unlink(target)
            except OSError:
                pass
            raise
        written.append(path)
    return written


def _tree_digest(entries: Mapping[str, TreeEntry]) -> str:
    payload = [
        [entry.path, entry.mode, entry.kind, entry.sha]
        for entry in sorted(entries.values(), key=lambda item: item.path)
    ]
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# HTTP transport


class GitHubClient:
    """Minimal, bounded GitHub REST client.

    ``session`` and ``sleep`` are injectable so the unit tests never touch the
    network or real time.  ``base_url`` is intentionally not configurable from
    the daemon configuration; keeping the host fixed avoids an SSRF primitive.
    """

    def __init__(
        self,
        repository: str,
        token: str,
        *,
        session: Any | None = None,
        timeout: int = DEFAULT_TIMEOUT_SECONDS,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        retries: int = DEFAULT_RETRIES,
        sleep: Any | None = None,
        base_url: str = GITHUB_API_URL,
        proxy_env: bool = True,
    ):
        if not isinstance(repository, str) or not _REPO_RE.fullmatch(repository):
            raise GitHubError("repository must be in owner/name form", code="invalid_repository")
        owner, name = repository.split("/", 1)
        if owner in {".", ".."} or name in {".", ".."}:
            raise GitHubError("repository owner/name is invalid", code="invalid_repository")
        if not isinstance(token, str) or not token or len(token) > 512 or any(ch.isspace() for ch in token):
            raise GitHubError("GitHub token is missing or malformed", code="invalid_token")
        if timeout < 1 or timeout > 120:
            raise GitHubError("GitHub timeout must be between 1 and 120 seconds", code="invalid_timeout")
        if max_response_bytes < 4096 or max_response_bytes > 64 * 1024 * 1024:
            raise GitHubError("GitHub response size limit is invalid", code="invalid_limit")
        if retries < 0 or retries > 5:
            raise GitHubError("GitHub retry count is invalid", code="invalid_retries")
        parsed = urlsplit(base_url)
        if parsed.scheme != "https" or parsed.hostname != "api.github.com" or parsed.query or parsed.fragment:
            raise GitHubError("GitHub API base URL must be https://api.github.com", code="invalid_base_url")

        self.repository = repository
        self.owner = owner
        self.repo = name
        self._token = token
        self.base_url = base_url.rstrip("/")
        self.timeout = int(timeout)
        self.max_response_bytes = int(max_response_bytes)
        self.retries = int(retries)
        self.sleep = sleep or time.sleep
        self.session = session or requests.Session()
        try:
            self.session.trust_env = bool(proxy_env)
        except Exception:
            pass
        self.last_headers: dict[str, str] = {}
        self._blob_cache: dict[str, bytes] = {}
        self.base_branch = "main"

    def __repr__(self) -> str:  # never expose the token in logs/tracebacks
        return f"GitHubClient(repository={self.repository!r})"

    # -- raw request -------------------------------------------------------

    def _read_body(self, response: Any) -> bytes:
        content_length = None
        try:
            content_length = response.headers.get("Content-Length")
        except Exception:
            pass
        if content_length is not None:
            try:
                if int(content_length) > self.max_response_bytes:
                    raise GitHubError("GitHub response exceeded the size limit", code="response_too_large")
            except (TypeError, ValueError):
                pass
        chunks: list[bytes] = []
        total = 0
        for chunk in response.iter_content(chunk_size=32 * 1024):
            if not chunk:
                continue
            total += len(chunk)
            if total > self.max_response_bytes:
                raise GitHubError("GitHub response exceeded the size limit", code="response_too_large")
            chunks.append(chunk)
        return b"".join(chunks)

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        body: Mapping[str, Any] | None = None,
        expected: Sequence[int] = (200,),
        retries: int | None = None,
    ) -> tuple[Any, dict[str, str]]:
        if not path.startswith("/") or "://" in path:
            raise GitHubError("GitHub API path is invalid", code="invalid_path")
        url = self.base_url + path
        attempts = self.retries if retries is None else int(retries)
        if attempts < 0 or attempts > 5:
            raise GitHubError("GitHub retry count is invalid", code="invalid_retries")
        headers = {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "k8s-change-guard/1",
        }
        last_error: GitHubError | None = None
        for attempt in range(attempts + 1):
            try:
                response = self.session.request(
                    method,
                    url,
                    params=dict(params or {}),
                    json=dict(body) if body is not None else None,
                    headers=headers,
                    timeout=(5, self.timeout),
                    allow_redirects=False,
                    stream=True,
                )
            except requests.RequestException as exc:
                last_error = GitHubError(
                    f"GitHub request failed: {type(exc).__name__}",
                    code="network_error",
                    retryable=True,
                )
                if attempt < attempts:
                    self.sleep(min(2 ** attempt, 8))
                    continue
                raise last_error from None
            except Exception as exc:  # pragma: no cover - defensive for custom sessions
                raise GitHubError(
                    f"GitHub transport failed: {type(exc).__name__}",
                    code="transport_error",
                ) from None

            response_headers = {str(key): str(value) for key, value in dict(getattr(response, "headers", {}) or {}).items()}
            status = int(getattr(response, "status_code", 0) or 0)
            try:
                raw = self._read_body(response) if status not in {204, 304} else b""
            except GitHubError:
                try:
                    response.close()
                except Exception:
                    pass
                raise
            finally:
                try:
                    response.close()
                except Exception:
                    pass
            self.last_headers = response_headers

            if status in expected:
                if not raw:
                    return None, response_headers
                try:
                    return json.loads(raw.decode("utf-8")), response_headers
                except (UnicodeDecodeError, ValueError):
                    raise GitHubError("GitHub returned invalid JSON", code="invalid_json") from None

            if status in {301, 302, 303, 307, 308}:
                raise GitHubError("GitHub redirects are not followed", code="redirect_refused", status=status)

            if status in {403, 429}:
                remaining = _header(response_headers, "X-RateLimit-Remaining")
                retry_after = _parse_retry_after(_header(response_headers, "Retry-After"))
                reset = _header(response_headers, "X-RateLimit-Reset")
                wait = retry_after
                if wait is None and remaining == "0" and reset:
                    try:
                        wait = max(1.0, float(reset) - time.time() + 1.0)
                    except ValueError:
                        wait = None
                rate_limited = remaining == "0" or retry_after is not None or (
                    status == 429
                )
                if rate_limited:
                    if wait is None:
                        wait = 5.0
                    if wait > MAX_RATE_LIMIT_WAIT_SECONDS:
                        raise GitHubRateLimitError(
                            "GitHub rate limit requires a wait longer than the configured bound",
                            status=status,
                            code="rate_limited",
                            details={"retry_after_seconds": round(wait, 1)},
                        )
                    last_error = GitHubRateLimitError(
                        "GitHub rate limit was reached",
                        status=status,
                        code="rate_limited",
                        retryable=True,
                        details={"retry_after_seconds": round(wait, 1)},
                    )
                    if attempt < attempts:
                        self.sleep(min(wait, MAX_RATE_LIMIT_WAIT_SECONDS))
                        continue
                    raise last_error

            if status >= 500:
                last_error = GitHubError(
                    f"GitHub API returned HTTP {status}",
                    status=status,
                    code="server_error",
                    retryable=True,
                )
                if attempt < attempts:
                    self.sleep(min(2 ** attempt, 8))
                    continue
                raise last_error

            detail = sanitize_text(raw.decode("utf-8", errors="replace"), limit=400) if raw else "no response body"
            if status == 401:
                raise GitHubAuthError("GitHub authentication failed (HTTP 401)", status=status, code="unauthorized")
            if status == 403:
                raise GitHubAuthError("GitHub authorization failed (HTTP 403)", status=status, code="forbidden")
            if status == 404:
                raise GitHubError("GitHub resource was not found (HTTP 404)", status=status, code="not_found")
            if status == 422:
                raise GitHubError(
                    f"GitHub rejected the request (HTTP 422): {detail}", status=status, code="unprocessable"
                )
            raise GitHubError(
                f"GitHub API returned HTTP {status}: {detail}", status=status, code="http_error"
            )

    def get(self, path: str, *, params: Mapping[str, Any] | None = None) -> Any:
        data, _headers = self._request("GET", path, params=params)
        return data

    def _get_with_headers(self, path: str, *, params: Mapping[str, Any] | None = None) -> tuple[Any, dict[str, str]]:
        return self._request("GET", path, params=params)

    # -- credentials -------------------------------------------------------

    def verify_credentials(self, *, probe_status_sha: str | None = None) -> dict[str, Any]:
        """Verify the token's *actual* documented repository capabilities.

        For classic OAuth tokens GitHub returns ``X-OAuth-Scopes``; status write
        requires ``repo`` (private/public), ``public_repo`` (public), or
        ``repo:status``.  Fine-grained tokens do not expose scopes, so their
        repository role is checked and status write is reported as inferred
        unless ``probe_status`` is explicitly requested.  The optional probe is
        an actual pending status write to a caller-supplied SHA; it is never
        enabled by default.
        """

        user, user_headers = self._get_with_headers("/user")
        if not isinstance(user, Mapping) or not isinstance(user.get("login"), str):
            raise GitHubAuthError("GitHub /user response is invalid", code="invalid_credentials")
        login = _validate_login(user.get("login"))

        repo, _repo_headers = self._get_with_headers(f"/repos/{self.owner}/{self.repo}")
        if not isinstance(repo, Mapping):
            raise GitHubAuthError("GitHub repository response is invalid", code="invalid_credentials")
        if str(repo.get("full_name", "")).lower() != self.repository.lower():
            raise GitHubAuthError("GitHub token resolved to a different repository", code="wrong_repository")
        permissions = repo.get("permissions") if isinstance(repo.get("permissions"), Mapping) else {}
        permission_flags = {
            key: bool(permissions.get(key))
            for key in ("admin", "maintain", "push", "triage", "pull")
            if key in permissions
        }
        is_private = bool(repo.get("private"))
        scopes_header = _header(user_headers, "X-OAuth-Scopes")
        scopes: set[str] = set()
        if scopes_header is not None:
            scopes = {item.strip() for item in scopes_header.split(",") if item.strip()}
            allowed = set(CLASSIC_STATUS_SCOPES)
            if not is_private:
                allowed.add("public_repo")
            if not scopes & allowed:
                raise GitHubAuthError(
                    "classic token lacks commit-status write scope (repo, public_repo, or repo:status)",
                    code="missing_status_scope",
                )
            status_write = "verified-by-scope"
            token_kind = "classic"
        else:
            if not (permission_flags.get("admin") or permission_flags.get("push")):
                raise GitHubAuthError(
                    "fine-grained token lacks push/admin repository permission",
                    code="missing_repo_write",
                )
            status_write = "inferred"
            token_kind = "fine-grained-or-unknown"

        # Confirm PR read access explicitly.  This is cheap and catches tokens
        # that can read repository metadata but not pull requests.
        self._request(
            "GET",
            f"/repos/{self.owner}/{self.repo}/pulls",
            params={"state": "open", "base": str(repo.get("default_branch") or "main"), "per_page": 1},
            expected=(200,),
        )
        # Confirm status *read* access.  A token that cannot list statuses will
        # not be able to manage this required context reliably.
        default_branch = str(repo.get("default_branch") or "")
        if default_branch:
            branch = self.get(f"/repos/{self.owner}/{self.repo}/git/ref/heads/{_branch_path(default_branch)}")
            if isinstance(branch, Mapping):
                branch_sha = (branch.get("object") or {}).get("sha") if isinstance(branch.get("object"), Mapping) else None
                if isinstance(branch_sha, str) and _SHA_RE.fullmatch(branch_sha):
                    self._request(
                        "GET",
                        f"/repos/{self.owner}/{self.repo}/commits/{branch_sha}/statuses",
                        expected=(200,),
                    )

        if probe_status_sha is not None:
            if not isinstance(probe_status_sha, str) or not _SHA_RE.fullmatch(probe_status_sha):
                raise GitHubAuthError("credential probe SHA is invalid", code="invalid_probe_sha")
            self.create_commit_status(
                probe_status_sha,
                "pending",
                "credential capability probe",
                "change-guard/credential-probe",
            )
            status_write = "verified-by-write"

        return {
            "status": "ok",
            "login": login,
            "repository": self.repository,
            "private": is_private,
            "token_kind": token_kind,
            "scopes": sorted(scopes),
            "permissions": permission_flags,
            "statuses_write": status_write,
            "default_branch": default_branch or None,
        }

    # -- pull requests -----------------------------------------------------

    def get_pull_request(self, number: int) -> PullRequestInfo:
        if isinstance(number, bool) or not isinstance(number, int) or number < 1:
            raise GitHubError("pull request number is invalid", code="invalid_pr")
        data = self.get(f"/repos/{self.owner}/{self.repo}/pulls/{number}")
        return _normalize_pull_request(data)

    def list_open_pull_requests(
        self,
        base_branch: str,
        *,
        per_page: int = MAX_PR_PER_PAGE,
        max_pages: int = MAX_PR_PAGES,
    ) -> list[PullRequestInfo]:
        base_branch = _validate_branch(base_branch)
        if isinstance(per_page, bool) or not isinstance(per_page, int) or not 1 <= per_page <= MAX_PR_PER_PAGE:
            raise GitHubError("pull request page size is invalid", code="invalid_pagination")
        if isinstance(max_pages, bool) or not isinstance(max_pages, int) or not 1 <= max_pages <= MAX_PR_PAGES:
            raise GitHubError("pull request page limit is invalid", code="invalid_pagination")
        results: list[PullRequestInfo] = []
        for page in range(1, max_pages + 1):
            data = self.get(
                f"/repos/{self.owner}/{self.repo}/pulls",
                params={
                    "state": "open",
                    "base": base_branch,
                    "sort": "created",
                    "direction": "asc",
                    "per_page": per_page,
                    "page": page,
                },
            )
            if not isinstance(data, list):
                raise GitHubError("GitHub pull request listing is not a list", code="invalid_response")
            if len(data) > per_page:
                raise GitHubError("GitHub returned more pull requests than requested", code="invalid_response")
            for item in data:
                info = _normalize_pull_request(item)
                if info.base_ref != base_branch or info.state != "open":
                    continue
                results.append(info)
            if len(data) < per_page:
                break
        return results

    def get_branch_head(self, branch: str) -> str:
        branch = _validate_branch(branch)
        data = self.get(f"/repos/{self.owner}/{self.repo}/git/ref/heads/{_branch_path(branch)}")
        if not isinstance(data, Mapping):
            raise GitHubError("GitHub branch response is invalid", code="invalid_response")
        object_value = data.get("object")
        sha = object_value.get("sha") if isinstance(object_value, Mapping) else None
        return _validate_sha(sha, "branch head")

    # -- trees / blobs -----------------------------------------------------

    def _commit_tree_sha(self, sha: str) -> str:
        data = self.get(f"/repos/{self.owner}/{self.repo}/git/commits/{sha}")
        tree = data.get("tree") if isinstance(data, Mapping) else None
        tree_sha = tree.get("sha") if isinstance(tree, Mapping) else None
        return _validate_sha(tree_sha, "commit tree")

    def _list_tree_entries(self, tree_sha: str) -> dict[str, TreeEntry]:
        data = self.get(
            f"/repos/{self.owner}/{self.repo}/git/trees/{tree_sha}",
            params={"recursive": "1"},
        )
        if not isinstance(data, Mapping):
            raise TreeSecurityError("Git tree response is invalid", code="invalid_tree")
        if data.get("truncated") is True:
            raise TreeSecurityError("GitHub truncated the recursive tree; refusing an incomplete candidate", code="tree_truncated")
        raw_entries = data.get("tree")
        if not isinstance(raw_entries, list):
            raise TreeSecurityError("Git tree response has no entries", code="invalid_tree")
        if len(raw_entries) > MAX_TREE_ENTRIES:
            raise TreeSecurityError("Git tree has too many entries", code="tree_too_large")
        entries: dict[str, TreeEntry] = {}
        for raw in raw_entries:
            if not isinstance(raw, Mapping):
                raise TreeSecurityError("Git tree contains a non-object entry", code="invalid_tree")
            path = normalize_repo_path(raw.get("path"))
            mode = str(raw.get("mode", ""))
            kind = str(raw.get("type", ""))
            sha = raw.get("sha")
            size = raw.get("size", 0)
            if path in entries:
                raise TreeSecurityError(f"Git tree contains duplicate path {path!r}", code="duplicate_path")
            if kind == "commit" or mode == "160000":
                raise TreeSecurityError(f"submodule is not permitted: {path!r}", code="submodule_not_permitted")
            if mode == "120000" or kind == "symlink":
                raise TreeSecurityError(f"symlink is not permitted: {path!r}", code="symlink_not_permitted")
            if kind == "tree":
                if mode not in {"040000", "40000"}:
                    raise TreeSecurityError(f"directory has an unsafe mode: {path!r}", code="invalid_mode")
                entries[path] = TreeEntry(path=path, mode=mode.zfill(6), kind="tree", sha=str(sha or ""), size=0)
                continue
            if kind != "blob":
                raise TreeSecurityError(f"unsupported Git tree entry type {kind!r} for {path!r}", code="invalid_type")
            if mode not in {"100644", "100755"}:
                raise TreeSecurityError(f"blob has an unsafe mode {mode!r}: {path!r}", code="invalid_mode")
            _validate_sha(sha, f"blob sha for {path}")
            if isinstance(size, bool) or not isinstance(size, int) or size < 0:
                raise TreeSecurityError(f"blob size is invalid for {path!r}", code="invalid_size")
            entries[path] = TreeEntry(path=path, mode=mode, kind="blob", sha=sha, size=size)
        return entries

    def _fetch_blob(self, sha: str, size: int, *, limit: int) -> bytes:
        if size > limit:
            raise TreeSecurityError(
                f"Git blob {sha[:12]} exceeds the per-file size limit",
                code="blob_too_large",
                details={"size": size, "limit": limit},
            )
        cached = self._blob_cache.get(sha)
        if cached is not None:
            return cached
        data = self.get(f"/repos/{self.owner}/{self.repo}/git/blobs/{sha}")
        if not isinstance(data, Mapping):
            raise TreeSecurityError("Git blob response is invalid", code="invalid_blob")
        if data.get("encoding") != "base64":
            raise TreeSecurityError("Git blob encoding is not base64", code="invalid_blob")
        content = data.get("content")
        if not isinstance(content, str):
            raise TreeSecurityError("Git blob has no content", code="invalid_blob")
        try:
            # GitHub wraps blob base64 at fixed line lengths. Strip only
            # transport whitespace; strict validation still rejects bad data.
            raw = base64.b64decode(''.join(content.split()), validate=True)
        except (binascii.Error, ValueError):
            raise TreeSecurityError("Git blob content is not valid base64", code="invalid_blob") from None
        if len(raw) > limit:
            raise TreeSecurityError("Git blob exceeded the per-file size limit", code="blob_too_large")
        expected_size = data.get("size")
        if isinstance(expected_size, int) and not isinstance(expected_size, bool) and expected_size != len(raw):
            raise TreeSecurityError("Git blob size does not match its response", code="invalid_blob")
        if len(raw) != size:
            raise TreeSecurityError("Git blob size does not match the tree entry", code="invalid_blob")
        git_sha = hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\x00" + raw).hexdigest()
        if git_sha != sha:
            raise TreeSecurityError("Git blob content does not match its tree object id", code="blob_corrupt")
        if len(self._blob_cache) < 4096:
            self._blob_cache[sha] = raw
        return raw

    def fetch_tree_snapshot(self, sha: str, *, include_argo: bool = True) -> TreeSnapshot:
        sha = _validate_sha(sha)
        tree_sha = self._commit_tree_sha(sha)
        entries = self._list_tree_entries(tree_sha)
        renderer_paths = [
            entry for entry in entries.values() if entry.kind == "blob" and is_renderer_path(entry.path)
        ]
        if len(renderer_paths) > MAX_RENDER_FILES:
            raise TreeSecurityError("renderer tree contains too many files", code="renderer_too_large")
        renderer_files: dict[str, bytes] = {}
        renderer_bytes = 0
        for entry in sorted(renderer_paths, key=lambda item: item.path):
            raw = self._fetch_blob(entry.sha, entry.size, limit=MAX_RENDER_FILE_BYTES)
            renderer_bytes += len(raw)
            if renderer_bytes > MAX_RENDER_TOTAL_BYTES:
                raise TreeSecurityError("renderer tree exceeds the total size limit", code="renderer_too_large")
            renderer_files[entry.path] = raw

        argo_files: dict[str, bytes] = {}
        argo_bytes = 0
        if include_argo:
            argo_paths = [
                entry
                for entry in entries.values()
                if entry.kind == "blob" and is_argo_path(entry.path)
            ]
            if len(argo_paths) > MAX_ARGO_FILES:
                raise TreeSecurityError("too many Argo/deployment manifest files", code="argo_tree_too_large")
            for entry in sorted(argo_paths, key=lambda item: item.path):
                raw = self._fetch_blob(entry.sha, entry.size, limit=MAX_ARGO_FILE_BYTES)
                argo_bytes += len(raw)
                if argo_bytes > MAX_ARGO_TOTAL_BYTES:
                    raise TreeSecurityError("Argo manifest set exceeds the total size limit", code="argo_tree_too_large")
                argo_files[entry.path] = raw

        return TreeSnapshot(
            sha=sha,
            tree_sha=tree_sha,
            entries=entries,
            renderer_files=renderer_files,
            argo_files=argo_files,
            tree_digest=_tree_digest(entries),
            entry_count=len(entries),
            renderer_bytes=renderer_bytes,
            argo_bytes=argo_bytes,
        )

    # -- candidate ---------------------------------------------------------

    def fetch_pull_request_candidate(self, number: int, *, allow_fork: bool = False) -> PullRequestCandidate:
        pr = self.get_pull_request(number)
        if pr.state != "open":
            raise GitHubError("pull request is not open", code="pr_not_open")
        if pr.base_ref != self._configured_base_branch():
            raise GitHubError("pull request does not target the configured base branch", code="wrong_base_branch")
        if pr.base_repo.lower() != self.repository.lower():
            raise GitHubError("pull request base repository is not the configured repository", code="wrong_base_repo")
        if pr.head_repo.lower() != self.repository.lower() and not allow_fork:
            raise ForkNotAllowedError(
                "fork pull requests are not evaluated by this guard",
                code="fork_not_allowed",
            )
        current_base = self.get_branch_head(pr.base_ref)
        base_snapshot = self.fetch_tree_snapshot(current_base)
        head_snapshot = self.fetch_tree_snapshot(pr.head_sha)
        changed_paths, changed_count, truncated = _diff_entries(base_snapshot.entries, head_snapshot.entries)
        argo = analyze_argo(base_snapshot, head_snapshot, changed_paths)
        return PullRequestCandidate(
            pull_request=pr,
            base_sha=current_base,
            base_snapshot=base_snapshot,
            head_snapshot=head_snapshot,
            changed_paths=tuple(changed_paths),
            changed_count=changed_count,
            tree_diff_truncated=truncated,
            argo=argo,
            pr_base_sha=pr.base_sha,
        )

    def _configured_base_branch(self) -> str:
        # Set by from_config(); default keeps the class usable in tests.
        return getattr(self, "base_branch", "main")

    # -- statuses / comments ----------------------------------------------

    def create_commit_status(
        self,
        sha: str,
        state: str,
        description: str,
        context: str,
        *,
        target_url: str | None = None,
    ) -> dict[str, Any]:
        sha = _validate_sha(sha)
        if state not in STATUS_STATES:
            raise GitHubError("commit status state is invalid", code="invalid_status_state")
        body: dict[str, Any] = {
            "state": state,
            "description": _sanitize_status_description(description),
            "context": _sanitize_status_context(context),
        }
        if target_url is not None:
            parsed = urlsplit(str(target_url))
            if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
                raise GitHubError("status target URL must be a plain HTTPS URL", code="invalid_target_url")
            body["target_url"] = str(target_url)
        data, _headers = self._request(
            "POST",
            f"/repos/{self.owner}/{self.repo}/statuses/{sha}",
            body=body,
            expected=(201,),
        )
        if not isinstance(data, Mapping):
            raise GitHubError("GitHub status response is invalid", code="invalid_response")
        return dict(data)

    def list_issue_comments(self, number: int, *, per_page: int = 100, max_pages: int = MAX_COMMENT_PAGES) -> list[dict[str, Any]]:
        if isinstance(number, bool) or not isinstance(number, int) or number < 1:
            raise GitHubError("pull request number is invalid", code="invalid_pr")
        if isinstance(per_page, bool) or not isinstance(per_page, int) or not 1 <= per_page <= 100:
            raise GitHubError("comment page size is invalid", code="invalid_pagination")
        comments: list[dict[str, Any]] = []
        for page in range(1, max_pages + 1):
            data = self.get(
                f"/repos/{self.owner}/{self.repo}/issues/{number}/comments",
                params={
                    "sort": "created",
                    "direction": "desc",
                    "per_page": per_page,
                    "page": page,
                },
            )
            if not isinstance(data, list):
                raise GitHubError("GitHub comment listing is not a list", code="invalid_response")
            if len(data) > per_page:
                raise GitHubError("GitHub returned more comments than requested", code="invalid_response")
            comments.extend(item for item in data if isinstance(item, Mapping))
            if len(comments) >= MAX_COMMENTS:
                break
            if len(data) < per_page:
                break
        return comments[:MAX_COMMENTS]

    def create_issue_comment(self, number: int, body: str) -> dict[str, Any]:
        if isinstance(number, bool) or not isinstance(number, int) or number < 1:
            raise GitHubError("pull request number is invalid", code="invalid_pr")
        if not isinstance(body, str) or not body.strip():
            raise GitHubError("comment body is empty", code="invalid_comment")
        encoded = body.encode("utf-8")
        if len(encoded) > MAX_COMMENT_BYTES:
            raise GitHubError("comment body is too large", code="comment_too_large")
        text = sanitize_text(body, limit=MAX_COMMENT_BYTES)
        if not text:
            raise GitHubError("comment body is empty after sanitization", code="invalid_comment")
        data, _headers = self._request(
            "POST",
            f"/repos/{self.owner}/{self.repo}/issues/{number}/comments",
            body={"body": text},
            expected=(201,),
        )
        if not isinstance(data, Mapping):
            raise GitHubError("GitHub comment response is invalid", code="invalid_response")
        return dict(data)

    def get_repository_identity(self) -> dict[str, str | None]:
        """Return the *current* repository owner identity.

        The configured ``owner/name`` is only a lookup key.  A rename or transfer
        can make that key resolve to a different owner, so callers must compare
        the returned ``full_name`` and owner login instead of trusting the
        request path.  The owner type distinguishes a personal repository
        (``User``) from an organization.
        """

        data = self.get(f"/repos/{self.owner}/{self.repo}")
        if not isinstance(data, Mapping):
            raise GitHubError("GitHub repository response is invalid", code="invalid_response")
        full_name = data.get("full_name")
        if not isinstance(full_name, str) or full_name.lower() != self.repository.lower():
            raise GitHubError(
                "configured repository no longer resolves to the same owner/name",
                code="repository_identity_changed",
            )
        owner = data.get("owner") if isinstance(data.get("owner"), Mapping) else {}
        owner_login = owner.get("login")
        owner_type = owner.get("type")
        if not isinstance(owner_login, str) or not owner_login:
            raise GitHubError("GitHub repository response has no owner login", code="invalid_response")
        return {
            "full_name": full_name,
            "owner_login": owner_login,
            "owner_type": str(owner_type) if isinstance(owner_type, str) else None,
            "default_branch": str(data.get("default_branch")) if isinstance(data.get("default_branch"), str) else None,
        }

    def get_user_permission(self, login: str) -> str | None:
        """Read a collaborator's repository permission.

        GitHub documents this endpoint as requiring repository Administration
        read for fine-grained tokens.  The guard's least-privilege token does
        not have that permission, so this call returns HTTP 403 for it.  Callers
        must treat that as "cannot verify via this endpoint", not as an
        approval, and use the personal-owner check from
        :meth:`get_repository_identity` where applicable.
        """

        login = _validate_login(login)
        data = self.get(f"/repos/{self.owner}/{self.repo}/collaborators/{quote(login, safe='')}/permission")
        if not isinstance(data, Mapping):
            raise GitHubError("GitHub permission response is invalid", code="invalid_response")
        permission = data.get("permission")
        if permission is None:
            permission = data.get("role_name")
        return str(permission) if isinstance(permission, str) else None


def _branch_path(branch: str) -> str:
    # Branch slashes are part of the path; quote everything else.
    return quote(branch, safe="/")


def _normalize_pull_request(data: Any) -> PullRequestInfo:
    if not isinstance(data, Mapping):
        raise GitHubError("GitHub pull request response is invalid", code="invalid_response")
    number = data.get("number")
    if isinstance(number, bool) or not isinstance(number, int) or number < 1:
        raise GitHubError("GitHub pull request has no valid number", code="invalid_response")
    head = data.get("head") if isinstance(data.get("head"), Mapping) else {}
    base = data.get("base") if isinstance(data.get("base"), Mapping) else {}
    head_repo = head.get("repo") if isinstance(head.get("repo"), Mapping) else {}
    base_repo = base.get("repo") if isinstance(base.get("repo"), Mapping) else {}
    head_sha = _validate_sha(head.get("sha"), "pull request head")
    base_sha = _validate_sha(base.get("sha"), "pull request base")
    user = data.get("user") if isinstance(data.get("user"), Mapping) else {}
    return PullRequestInfo(
        number=number,
        title=sanitize_text(data.get("title", ""), limit=300),
        author=str(user.get("login", ""))[:100],
        state=str(data.get("state", "")),
        draft=bool(data.get("draft", False)),
        head_sha=head_sha,
        head_ref=str(head.get("ref", ""))[:255],
        head_repo=str(head_repo.get("full_name", ""))[:200],
        base_sha=base_sha,
        base_ref=str(base.get("ref", ""))[:255],
        base_repo=str(base_repo.get("full_name", ""))[:200],
        created_at=_parse_github_time(data.get("created_at")),
        updated_at=_parse_github_time(data.get("updated_at")),
        raw_url=str(data.get("html_url")) if isinstance(data.get("html_url"), str) else None,
    )


def _diff_entries(
    base: Mapping[str, TreeEntry],
    head: Mapping[str, TreeEntry],
) -> tuple[list[str], int, bool]:
    paths: list[str] = []
    seen = 0
    truncated = False
    for path in sorted(set(base) | set(head)):
        old = base.get(path)
        new = head.get(path)
        if (old is not None and old.kind == "tree") or (new is not None and new.kind == "tree"):
            # Directory object ids change whenever a child changes; the child
            # paths below carry the actionable change.
            continue
        if old is not None and new is not None:
            if (old.mode, old.kind, old.sha) == (new.mode, new.kind, new.sha):
                continue
        if old is None or new is None or old.sha != new.sha or old.mode != new.mode:
            seen += 1
            if len(paths) < MAX_CHANGED_PATHS:
                paths.append(path)
            else:
                truncated = True
    # Surface security-relevant changes first so the engine's 500-path review
    # window cannot hide an Argo/template change behind a large code diff.
    def priority(path: str) -> tuple[int, str]:
        lowered = path.lower()
        if lowered.startswith("gitops/argocd/") or lowered.endswith(("/application.yaml", "/project.yaml")):
            return (0, path)
        if lowered.startswith("charts/demo/"):
            return (1, path)
        if is_deployment_path(path):
            return (2, path)
        return (3, path)

    paths.sort(key=priority)
    return paths, seen, truncated


# ---------------------------------------------------------------------------
# Argo CD analysis


def _yaml_documents(raw: bytes, label: str) -> list[Any]:
    if len(raw) > MAX_ARGO_FILE_BYTES:
        raise ValueError(f"{label} is too large")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label} is not UTF-8") from exc
    documents: list[Any] = []
    try:
        for document in yaml.safe_load_all(text):
            if document is None:
                continue
            documents.append(document)
            if len(documents) > 50:
                raise ValueError(f"{label} has too many YAML documents")
    except yaml.YAMLError as exc:
        raise ValueError(f"{label} is not valid YAML") from exc
    return documents


def _argo_identity(document: Mapping[str, Any]) -> tuple[str, str, str] | None:
    kind = document.get("kind")
    metadata = document.get("metadata") if isinstance(document.get("metadata"), Mapping) else {}
    name = metadata.get("name")
    if not isinstance(kind, str) or not isinstance(name, str) or not kind or not name:
        return None
    namespace = metadata.get("namespace")
    return kind, str(namespace or ""), name


def _argo_sources(document: Mapping[str, Any]) -> tuple[Any, ...]:
    spec = document.get("spec") if isinstance(document.get("spec"), Mapping) else {}
    sources: list[Any] = []
    if isinstance(spec.get("source"), Mapping):
        sources.append(spec.get("source"))
    if isinstance(spec.get("sources"), list):
        sources.extend(item for item in spec.get("sources") if isinstance(item, Mapping))
    normalized: list[dict[str, Any]] = []
    for source in sources[:20]:
        normalized.append(
            {
                "repoURL": str(source.get("repoURL", ""))[:1000],
                "path": str(source.get("path", ""))[:1000],
                "chart": str(source.get("chart", ""))[:300],
                "targetRevision": str(source.get("targetRevision", ""))[:300],
                "ref": str(source.get("ref", ""))[:100],
            }
        )
    return tuple(_canonical_json(item) for item in normalized)


def _argo_doc_digest(document: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(document).encode("utf-8")).hexdigest()


def analyze_argo(
    base_snapshot: TreeSnapshot,
    head_snapshot: TreeSnapshot,
    changed_paths: Sequence[str],
) -> ArgoAnalysis:
    """Compare Argo Applications/AppProjects without trusting PR-provided code."""

    changed = [path for path in changed_paths if is_argo_path(path)]
    changed_lower = [path.lower() for path in changed]
    path_says_app = any(
        path.endswith(("/application.yaml", "/application.yml"))
        or path.endswith(("/applicationset.yaml", "/applicationset.yml"))
        for path in changed_lower
    )
    path_says_project = any(
        path.endswith(("/project.yaml", "/project.yml")) for path in changed_lower
    )
    source_changed = False
    app_changed = bool(path_says_app)
    project_changed = bool(path_says_project)
    manifest_error = False
    applications = 0

    def load(snapshot: TreeSnapshot) -> dict[tuple[str, str, str], Mapping[str, Any]]:
        nonlocal manifest_error, applications
        result: dict[tuple[str, str, str], Mapping[str, Any]] = {}
        for path, raw in snapshot.argo_files.items():
            if not is_argo_path(path):
                continue
            try:
                documents = _yaml_documents(raw, path)
            except ValueError:
                manifest_error = True
                continue
            for document in documents:
                if not isinstance(document, Mapping):
                    continue
                kind = document.get("kind")
                if kind not in {"Application", "AppProject", "ApplicationSet"}:
                    continue
                identity = _argo_identity(document)
                if identity is None:
                    manifest_error = True
                    continue
                result[identity] = document
                if kind == "Application":
                    applications += 1
        return result

    base_docs = load(base_snapshot)
    head_docs = load(head_snapshot)
    for identity in set(base_docs) | set(head_docs):
        old = base_docs.get(identity)
        new = head_docs.get(identity)
        if old is None or new is None:
            if old is not None:
                if old.get("kind") == "AppProject":
                    project_changed = True
                else:
                    app_changed = True
            if new is not None:
                if new.get("kind") == "AppProject":
                    project_changed = True
                else:
                    app_changed = True
            continue
        kind = identity[0]
        if kind == "AppProject":
            if _argo_doc_digest(old) != _argo_doc_digest(new):
                project_changed = True
            continue
        if _argo_doc_digest(old) != _argo_doc_digest(new):
            app_changed = True
        if _argo_sources(old) != _argo_sources(new):
            source_changed = True

    return ArgoAnalysis(
        argo_source_changed=source_changed,
        argo_application_changed=app_changed,
        argo_project_changed=project_changed,
        argo_manifest_error=manifest_error,
        argo_changed_paths=tuple(changed[:200]),
        applications=applications,
    )


# ---------------------------------------------------------------------------
# Configuration helpers


def load_token_from_config(config: Mapping[str, Any]) -> str:
    """Read a GitHub token from a documented env var or a 0600 file.

    The token is returned to the caller only; it is never logged or embedded in
    reports.  File size and format are bounded.
    """

    env_name = config.get("github_token_env", "GITHUB_TOKEN")
    if not isinstance(env_name, str) or not re.fullmatch(r"[A-Z_][A-Z0-9_]{1,63}", env_name):
        raise GitHubError("github_token_env is invalid", code="invalid_config")
    value = os.environ.get(env_name)
    if value:
        token = value.strip()
    else:
        token_file = config.get("github_token_file")
        if not isinstance(token_file, str) or not token_file:
            raise GitHubError("GitHub token is not configured", code="missing_token")
        try:
            size = os.stat(token_file).st_size
        except OSError as exc:
            raise GitHubError(f"GitHub token file is unavailable: {exc}", code="missing_token") from None
        if size > 4096:
            raise GitHubError("GitHub token file is too large", code="missing_token")
        try:
            with open(token_file, "r", encoding="utf-8") as handle:
                token = handle.read().strip()
        except (OSError, UnicodeDecodeError) as exc:
            raise GitHubError(f"GitHub token file is unreadable: {exc}", code="missing_token") from None
    if not token or len(token) > 512 or any(ch.isspace() for ch in token):
        raise GitHubError("GitHub token is malformed", code="missing_token")
    return token


def client_from_config(config: Mapping[str, Any], **kwargs: Any) -> GitHubClient:
    if not isinstance(config, Mapping):
        raise GitHubError("config must be a mapping", code="invalid_config")
    repository = config.get("repository")
    token = load_token_from_config(config)
    base_branch = config.get("base_branch", "main")
    timeout = config.get("github_timeout_seconds", DEFAULT_TIMEOUT_SECONDS)
    max_bytes = config.get("github_max_response_bytes", DEFAULT_MAX_RESPONSE_BYTES)
    retries = config.get("github_retries", DEFAULT_RETRIES)
    proxy_env = config.get("use_proxy_env", True)
    for name, value, minimum, maximum in (
        ("github_timeout_seconds", timeout, 1, 120),
        ("github_max_response_bytes", max_bytes, 4096, 64 * 1024 * 1024),
        ("github_retries", retries, 0, 5),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
            raise GitHubError(f"{name} must be an integer between {minimum} and {maximum}", code="invalid_config")
    client = GitHubClient(
        str(repository),
        token,
        timeout=timeout,
        max_response_bytes=max_bytes,
        retries=retries,
        proxy_env=bool(proxy_env),
        **kwargs,
    )
    client.base_branch = _validate_branch(base_branch)
    return client
