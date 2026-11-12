"""Reliable GitHub gate daemon.

The daemon polls every open pull request whose base is the configured main
branch.  For every pull request, including code-only changes, it renders the
exact base and head snapshots, collects fresh read-only evidence, runs the
trusted evaluator and DeepSeek review, stores an immutable report, and publishes
the required ``change-guard/release`` commit status.

Design constraints from the implementation contract:

* Pending status is published before expensive work.
* Status success is possible only for PASS, or for REVIEW with a *currently
  valid* manual approval.  BLOCK is failure and evaluation failure is error.
* Before success is published, the head SHA and current base branch tip are
  re-read from GitHub.  A changed SHA/base, an expired report, or a revoked
  approval invalidates the old status and forces re-evaluation.
* Approval is the exact comment ``/guard approve <evaluation_id>`` from a
  configured approver who has *current* write/admin permission.  For a personal
  repository the current owner is proven from repository metadata (the
  collaborator-permission endpoint needs Administration: read, which the
  least-privilege fine-grained token intentionally lacks).  Labels,
  edited/stale comments, and old evaluations are not accepted.
* Reports are written atomically and may never be overwritten.  Reports contain
  sanitized summaries only, never tokens or raw cluster credentials.
* A failure for one pull request is isolated; remaining pull requests continue.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import logging
import math
import os
import re
import signal
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

import yaml

from . import ai as ai_module
from . import evidence as evidence_module
from . import github as github_module
from . import renderer as renderer_module
from .engine import evaluate as engine_evaluate
from .engine import RULE_VERSION

LOGGER = logging.getLogger("change_guard.daemon")

SCHEMA_VERSION = 1
MAX_REPORT_BYTES = 8 * 1024 * 1024
MAX_INDEX_BYTES = 4 * 1024 * 1024
MAX_APPROVERS = 100
MAX_POLL_SECONDS = 3600
DEFAULT_POLL_SECONDS = 30
DEFAULT_EVIDENCE_TTL_SECONDS = 300
STATUS_DETAIL_LIMIT = 140
_APPROVAL_EFFECTIVE_SKEW_SECONDS = 0  # approvals may not predate the report
_SEVERITY_RANK = {"BLOCK": 3, "ERROR": 2, "REVIEW": 1}
_REDACT_KEY_PARTS = (
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
    "kubeconfig_data",
    "cookie",
)
_APPROVAL_ID_RE = re.compile(r"ev-[0-9a-f]{16,64}")
_REPORT_NAME_RE = re.compile(r"ev-[0-9a-f]{16,64}\.json")
_SAFE_ERROR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class DaemonError(RuntimeError):
    """Fail-closed daemon configuration/state error."""


class DaemonBusyError(DaemonError):
    """Another daemon instance holds the state lock."""


# ---------------------------------------------------------------------------
# Small helpers


def _now(clock: Callable[[], float]) -> int:
    value = clock()
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
        raise DaemonError("clock returned an invalid time")
    return int(value)


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def _safe_text(value: Any, limit: int = 1000) -> str:
    text = github_module.sanitize_text(value, limit=limit)
    return _SAFE_ERROR_RE.sub(" ", text)


def _split_time(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        candidate = float(value)
    elif isinstance(value, str) and value.strip():
        try:
            candidate = float(value)
        except ValueError:
            parsed = github_module._parse_github_time(value)
            return int(parsed) if parsed is not None else None
    else:
        return None
    return int(candidate) if math.isfinite(candidate) else None


def _decision_from_findings(findings: Sequence[Mapping[str, Any]]) -> str:
    severities = {str(item.get("severity")) for item in findings if isinstance(item, Mapping)}
    if "BLOCK" in severities:
        return "BLOCK"
    if "ERROR" in severities:
        return "ERROR"
    if "REVIEW" in severities:
        return "REVIEW"
    return "PASS"


def _sanitize_value(value: Any, *, depth: int = 0, key: str = "") -> Any:
    if depth > 12:
        return "<depth-limit>"
    lowered = key.lower()
    if any(part in lowered for part in _REDACT_KEY_PARTS):
        return "<redacted>"
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for child_key, child in list(value.items())[:500]:
            text_key = str(child_key)
            result[text_key] = _sanitize_value(child, depth=depth + 1, key=text_key)
        return result
    if isinstance(value, (list, tuple)):
        return [_sanitize_value(item, depth=depth + 1, key=key) for item in value[:2000]]
    if isinstance(value, str):
        return _safe_text(value, limit=8000)
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if value is None or isinstance(value, (bool, int)):
        return value
    return _safe_text(value, limit=2000)


def _atomic_write_json(path: Path, payload: Any, *, overwrite: bool) -> bool:
    """Write JSON atomically; return True when a new file was created."""

    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        encoded = (json.dumps(payload, ensure_ascii=False, allow_nan=False, indent=2) + "\n").encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise DaemonError(f"state payload is not JSON serializable: {exc}") from exc
    if len(encoded) > MAX_REPORT_BYTES:
        raise DaemonError("state payload exceeds the report size limit")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        if overwrite:
            os.replace(temporary_name, path)
            return True
        try:
            os.link(temporary_name, path)
            return True
        except FileExistsError:
            return False
        except OSError:
            # FAT/other filesystems may not support hard links.  Fall back to an
            # exclusive create after the fully-written temporary file exists.
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                return False
            try:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(encoded)
                    handle.flush()
                    os.fsync(handle.fileno())
            except Exception:
                try:
                    os.unlink(path)
                except OSError:
                    pass
                raise
            return True
        finally:
            try:
                os.unlink(temporary_name)
            except OSError:
                pass
    except Exception:
        try:
            os.unlink(temporary_name)
        except OSError:
            pass
        raise


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _priority(decision: str) -> int:
    return {"PASS": 0, "REVIEW": 1, "ERROR": 2, "BLOCK": 3}.get(decision, 2)


# ---------------------------------------------------------------------------
# State storage


class StateStore:
    """Immutable report store plus a small mutable index."""

    def __init__(self, state_dir: str | os.PathLike[str]):
        if not isinstance(state_dir, (str, os.PathLike)):
            raise DaemonError("state_dir must be a path")
        self.root = Path(state_dir)
        self.reports_dir = self.root / "reports"
        self.approvals_dir = self.root / "approvals"
        self.index_path = self.root / "index.json"
        self.lock_path = self.root / ".daemon.lock"
        self.reports_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.approvals_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(self.reports_dir, 0o700)
            os.chmod(self.approvals_dir, 0o700)
        except OSError:
            pass

    def report_path(self, evaluation_id: str) -> Path:
        if not isinstance(evaluation_id, str) or not _APPROVAL_ID_RE.fullmatch(evaluation_id):
            raise DaemonError("evaluation id is invalid")
        return self.reports_dir / f"{evaluation_id}.json"

    def read_report(self, evaluation_id: str) -> dict[str, Any]:
        path = self.report_path(evaluation_id)
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise DaemonError(f"cannot read report: {exc}") from None
        if len(raw) > MAX_REPORT_BYTES:
            raise DaemonError("report exceeds the size limit")
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise DaemonError(f"report is invalid JSON: {exc}") from None
        if not isinstance(value, dict):
            raise DaemonError("report is not an object")
        return value

    def write_report(self, report: Mapping[str, Any]) -> tuple[Path, bool]:
        if not isinstance(report, Mapping):
            raise DaemonError("report must be a mapping")
        evaluation_id = report.get("evaluation_id")
        if not isinstance(evaluation_id, str) or not _APPROVAL_ID_RE.fullmatch(evaluation_id):
            raise DaemonError("report has an invalid evaluation id")
        path = self.report_path(evaluation_id)
        if path.exists():
            existing = self.read_report(evaluation_id)
            if _canonical_json(existing) == _canonical_json(dict(report)):
                return path, False
            raise DaemonError("immutable report id collision with different content")
        created = _atomic_write_json(path, dict(report), overwrite=False)
        if not created:
            existing = self.read_report(evaluation_id)
            if _canonical_json(existing) != _canonical_json(dict(report)):
                raise DaemonError("immutable report id collision with different content")
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return path, created

    def write_approval(self, record: Mapping[str, Any]) -> Path:
        evaluation_id = record.get("evaluation_id")
        comment_id = record.get("comment_id")
        if not isinstance(evaluation_id, str) or not _APPROVAL_ID_RE.fullmatch(evaluation_id):
            raise DaemonError("approval has an invalid evaluation id")
        if isinstance(comment_id, bool) or not isinstance(comment_id, int) or comment_id < 1:
            raise DaemonError("approval has an invalid comment id")
        path = self.approvals_dir / f"{evaluation_id}-{comment_id}.json"
        _atomic_write_json(path, dict(record), overwrite=False)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return path

    def load_index(self) -> dict[str, Any]:
        if not self.index_path.exists():
            return {"schema_version": SCHEMA_VERSION, "prs": {}}
        try:
            raw = self.index_path.read_bytes()
        except OSError as exc:
            raise DaemonError(f"cannot read state index: {exc}") from None
        if len(raw) > MAX_INDEX_BYTES:
            raise DaemonError("state index exceeds the size limit")
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise DaemonError(f"state index is invalid JSON: {exc}") from None
        if not isinstance(value, dict) or not isinstance(value.get("prs", {}), dict):
            raise DaemonError("state index has an invalid schema")
        value.setdefault("schema_version", SCHEMA_VERSION)
        value.setdefault("prs", {})
        return value

    def save_index(self, index: Mapping[str, Any]) -> None:
        _atomic_write_json(self.index_path, dict(index), overwrite=True)
        try:
            os.chmod(self.index_path, 0o600)
        except OSError:
            pass

    def acquire_lock(self):
        return _StateLock(self.lock_path)


class _StateLock:
    def __init__(self, path: Path):
        self.path = path
        self.handle: Any | None = None

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            import fcntl  # POSIX only
        except ImportError:  # pragma: no cover - Windows test host
            self.handle = None
            return self
        self.handle = open(self.path, "a+", encoding="utf-8")
        try:
            fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.handle.close()
            self.handle = None
            raise DaemonBusyError("another change-guard daemon is already running")
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.handle is not None:
            try:
                import fcntl

                fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
            except Exception:
                pass
            try:
                self.handle.close()
            except Exception:
                pass
            self.handle = None
        return False


# ---------------------------------------------------------------------------
# Configuration


def load_config(path: str | os.PathLike[str]) -> dict[str, Any]:
    try:
        raw = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise DaemonError(f"cannot read config: {exc}") from None
    try:
        value = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise DaemonError(f"config is invalid YAML: {exc}") from None
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise DaemonError("config must be a mapping")
    return value


def validate_config(config: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(config, Mapping):
        raise DaemonError("config must be a mapping")
    value = dict(config)
    repository = value.get("repository")
    if not isinstance(repository, str) or not re.fullmatch(
        r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}", repository
    ):
        raise DaemonError("repository must be in owner/name form")
    owner, name = repository.split("/", 1)
    if owner in {".", ".."} or name in {".", ".."}:
        raise DaemonError("repository is invalid")
    value["repository"] = repository
    try:
        base_branch = github_module._validate_branch(value.get("base_branch", "main"))
        status_context = github_module._sanitize_status_context(
            value.get("status_context", "change-guard/release")
        )
    except github_module.GitHubError as exc:
        raise DaemonError(str(exc)) from None
    value["base_branch"] = base_branch
    value["status_context"] = status_context
    state_dir = value.get("state_dir")
    if not isinstance(state_dir, str) or not state_dir.strip() or "\x00" in state_dir:
        raise DaemonError("state_dir must be a non-empty path")
    value["state_dir"] = os.path.abspath(state_dir)
    poll = value.get("poll_seconds", DEFAULT_POLL_SECONDS)
    if isinstance(poll, bool) or not isinstance(poll, (int, float)) or not math.isfinite(float(poll)):
        raise DaemonError("poll_seconds must be a finite number")
    if not 1 <= float(poll) <= MAX_POLL_SECONDS:
        raise DaemonError(f"poll_seconds must be between 1 and {MAX_POLL_SECONDS}")
    value["poll_seconds"] = float(poll)
    ttl = value.get("evidence_ttl_seconds", DEFAULT_EVIDENCE_TTL_SECONDS)
    if isinstance(ttl, bool) or not isinstance(ttl, int) or not 30 <= ttl <= 86400:
        raise DaemonError("evidence_ttl_seconds must be an integer between 30 and 86400")
    approvers = value.get("approvers", [])
    if approvers is None:
        approvers = []
    if not isinstance(approvers, list) or len(approvers) > MAX_APPROVERS:
        raise DaemonError("approvers must be a bounded list")
    cleaned: list[str] = []
    for approver in approvers:
        try:
            login = github_module._validate_login(approver)
        except github_module.GitHubError as exc:
            raise DaemonError(str(exc)) from None
        if login not in cleaned:
            cleaned.append(login)
    value["approvers"] = cleaned
    for key in ("namespace", "deployment"):
        item = value.get(key, "demo")
        if not isinstance(item, str) or not re.fullmatch(r"[a-z0-9]([-a-z0-9]*[a-z0-9])?", item):
            raise DaemonError(f"{key} is not a valid Kubernetes DNS label")
        value[key] = item
    allowed_repo = value.get("allowed_image_repository", "ghcr.io/hey-mmm/observability-demo")
    if not isinstance(allowed_repo, str) or not allowed_repo.strip() or any(ch.isspace() for ch in allowed_repo):
        raise DaemonError("allowed_image_repository is invalid")
    value["allowed_image_repository"] = allowed_repo.strip()
    for key in (
        "ai_required",
        "allow_fork_prs",
        "report_comment",
        "use_proxy_env",
        "require_verified_status_write",
    ):
        if key in value and not isinstance(value[key], bool):
            raise DaemonError(f"{key} must be boolean")
    value.setdefault("ai_required", True)
    value.setdefault("allow_fork_prs", False)
    value.setdefault("report_comment", False)
    value.setdefault("use_proxy_env", True)
    value.setdefault("require_verified_status_write", False)
    probe_sha = value.get("credential_probe_sha")
    if probe_sha is not None and (
        not isinstance(probe_sha, str) or not re.fullmatch(r"[0-9a-f]{40,64}", probe_sha)
    ):
        raise DaemonError("credential_probe_sha must be a hexadecimal Git SHA or null")
    target_url = value.get("status_target_url")
    if target_url is not None:
        if not isinstance(target_url, str) or not target_url.startswith("https://"):
            raise DaemonError("status_target_url must be an HTTPS URL")
    return value


# ---------------------------------------------------------------------------
# Daemon


class ChangeGuardDaemon:
    def __init__(
        self,
        config: Mapping[str, Any],
        *,
        github_client: Any | None = None,
        collector: Callable[[dict], dict] | None = None,
        analyzer: Callable[[dict, dict], dict] | None = None,
        render: Callable[[str, dict], list[dict]] | None = None,
        evaluator: Callable[..., dict] | None = None,
        store: StateStore | None = None,
        clock: Callable[[], float] | None = None,
        sleep: Callable[[float], None] | None = None,
    ):
        self.config = validate_config(config)
        self.clock = clock or time.time
        self.sleep = sleep or time.sleep
        self.github = github_client or github_module.client_from_config(self.config)
        self.collector = collector or evidence_module.collect
        self.analyzer = analyzer or ai_module.analyze
        self.render = render or renderer_module.render_tree
        self.evaluator = evaluator or engine_evaluate
        self.store = store or StateStore(self.config["state_dir"])
        self._render_config = {
            **self.config,
            "namespace": self.config["namespace"],
            "deployment": self.config["deployment"],
            "release_name": self.config.get("release_name", self.config["deployment"]),
        }

    # -- public entry point -------------------------------------------------

    def run_once(self) -> dict[str, Any]:
        now = _now(self.clock)
        try:
            index = self.store.load_index()
            with self.store.acquire_lock():
                return self._run_once_locked(index, now)
        except DaemonBusyError as exc:
            return {"status": "error", "checked_at": now, "error": str(exc), "prs": []}
        except Exception as exc:
            return {
                "status": "error",
                "checked_at": now,
                "error": _safe_text(exc, limit=800),
                "prs": [],
            }

    def _run_once_locked(self, index: dict[str, Any], now: int) -> dict[str, Any]:
        errors: list[str] = []
        pr_results: list[dict[str, Any]] = []
        credentials: dict[str, Any] | None = None

        verify = getattr(self.github, "verify_credentials", None)
        if callable(verify):
            try:
                credentials = verify(probe_status_sha=self.config.get("credential_probe_sha"))
                if not isinstance(credentials, dict):
                    raise github_module.GitHubAuthError("credential verification returned an invalid result")
                if self.config.get("require_verified_status_write") and credentials.get("statuses_write") == "inferred":
                    raise github_module.GitHubAuthError(
                        "status write permission is inferred, not verified; configure credential_probe_sha or disable require_verified_status_write"
                    )
                index["github"] = {
                    key: credentials.get(key)
                    for key in (
                        "status",
                        "login",
                        "repository",
                        "private",
                        "token_kind",
                        "scopes",
                        "permissions",
                        "statuses_write",
                        "default_branch",
                    )
                }
            except Exception as exc:
                message = f"GitHub credential verification failed: {_safe_text(exc, limit=500)}"
                LOGGER.error(message)
                index["updated_at"] = now
                self.store.save_index(index)
                return {"status": "error", "checked_at": now, "error": message, "prs": []}

        try:
            prs = self.github.list_open_pull_requests(self.config["base_branch"])
        except Exception as exc:
            message = f"cannot list open pull requests: {_safe_text(exc, limit=500)}"
            LOGGER.error(message)
            index["updated_at"] = now
            self.store.save_index(index)
            return {"status": "error", "checked_at": now, "error": message, "prs": []}

        max_prs = self.config.get("max_open_prs", 2000)
        if isinstance(max_prs, int) and not isinstance(max_prs, bool) and len(prs) > max_prs:
            message = f"open pull request count {len(prs)} exceeds configured maximum {max_prs}"
            index["updated_at"] = now
            self.store.save_index(index)
            return {"status": "error", "checked_at": now, "error": message, "prs": []}

        seen: set[str] = set()
        for pr in prs:
            seen.add(str(pr.number))
            try:
                result = self._process_pull_request(pr, index, now)
            except Exception as exc:  # one PR must never stop the others
                result = self._handle_pull_request_error(pr, exc, index, now)
            pr_results.append(result)
            if result.get("status_error"):
                errors.append(f"PR #{pr.number}: {result['status_error']}")

        # A PR that was open in the previous cycle but is no longer listed is
        # closed or merged.  Revoke a stale success/failure once.
        closed_count = 0
        for key, entry in list(index.get("prs", {}).items()):
            if key in seen or not isinstance(entry, dict):
                continue
            if entry.get("closed_revoked") is True:
                continue
            last = entry.get("last_status")
            if isinstance(last, dict) and isinstance(last.get("sha"), str):
                try:
                    self._revoke_status(
                        last["sha"],
                        "PR is closed or merged; the release evaluation is no longer valid",
                        state="error",
                    )
                    closed_count += 1
                except Exception as exc:
                    errors.append(f"PR #{key}: closed status revocation failed: {_safe_text(exc, limit=300)}")
            entry["closed_revoked"] = True
            entry["closed_at"] = now

        index["schema_version"] = SCHEMA_VERSION
        index["updated_at"] = now
        self.store.save_index(index)
        status = "error" if errors else "ok"
        return {
            "status": status,
            "checked_at": now,
            "credentials": {
                key: (index.get("github") or {}).get(key)
                for key in ("login", "token_kind", "statuses_write", "permissions")
            },
            "prs": sorted(pr_results, key=lambda item: item.get("number", 0)),
            "closed_invalidated": closed_count,
            "errors": errors[:100],
        }

    # -- one pull request ---------------------------------------------------

    def _process_pull_request(self, listed_pr: Any, index: dict[str, Any], now: int) -> dict[str, Any]:
        number = getattr(listed_pr, "number", None)
        if isinstance(number, bool) or not isinstance(number, int):
            raise DaemonError("pull request listing returned an invalid number")
        key = str(number)
        prev = index.setdefault("prs", {}).setdefault(key, {})
        prev["number"] = number

        # Two bounded attempts cover the common race where the PR head/base
        # changes between rendering and status publication.
        for attempt in range(2):
            pr = self.github.get_pull_request(number)
            if getattr(pr, "state", "") != "open":
                return self._invalidate_closed_pr(pr, prev, index, now)
            current_base = self.github.get_branch_head(self.config["base_branch"])
            prev["closed_revoked"] = False

            if getattr(pr, "draft", False):
                self._ensure_pending(pr, current_base, prev, now, reason="Draft PR; waiting for review")
                entry = self._entry_from_report(prev, pr, current_base, None, now)
                index["prs"][key] = entry
                return {
                    "number": number,
                    "decision": "REVIEW",
                    "state": "pending",
                    "draft": True,
                    "evaluation_id": None,
                    "head_sha": pr.head_sha,
                    "base_sha": current_base,
                }

            cached = self._load_valid_cached(prev, pr, current_base, now)
            if cached is not None:
                approval, approval_error = self._resolve_approval(cached, pr)
                desired = self._desired_status(cached, approval)
                published = self._publish(cached, pr, desired, approval, prev, index, now)
                if published.get("stale"):
                    self._revoke_status(
                        cached.get("head_sha", pr.head_sha),
                        "PR head/base changed or evidence expired; re-evaluating",
                    )
                    continue
                return {
                    "number": number,
                    "decision": cached.get("decision"),
                    "state": published.get("state"),
                    "evaluation_id": cached.get("evaluation_id"),
                    "reused": True,
                    "approval": published.get("approval"),
                    "approval_error": approval_error,
                    "status_error": published.get("error"),
                }

            # Expired report: revoke its old success before collecting evidence.
            last = prev.get("last_status")
            if isinstance(last, dict) and last.get("state") in {"success", "failure", "error"}:
                self._revoke_status(last.get("sha"), "Evaluation expired; re-evaluating")

            self._ensure_pending(pr, current_base, prev, now)
            try:
                report = self._evaluate(pr, current_base)
            except Exception as exc:
                return self._handle_pull_request_error(pr, exc, index, now, base_sha=current_base)

            self.store.write_report(report)
            approval, approval_error = self._resolve_approval(report, pr)
            desired = self._desired_status(report, approval)
            published = self._publish(report, pr, desired, approval, prev, index, now)
            if published.get("stale") or published.get("expired"):
                self._revoke_status(
                    report.get("head_sha", pr.head_sha),
                    "PR head/base changed; re-evaluating",
                )
                continue
            entry = self._entry_from_report(prev, pr, current_base, report, now)
            entry["last_status"] = published.get("last_status")
            entry["approval"] = published.get("approval")
            index["prs"][key] = entry
            return {
                "number": number,
                "decision": report.get("decision"),
                "state": published.get("state"),
                "evaluation_id": report.get("evaluation_id"),
                "reused": False,
                "approval": published.get("approval"),
                "approval_error": approval_error,
                "status_error": published.get("error"),
            }

        # Head/base changed twice in a row.  Leave a pending status on the most
        # recent head so the next poll starts the evaluation again.
        try:
            fresh = self.github.get_pull_request(number)
            base_now = self.github.get_branch_head(self.config["base_branch"])
            self._ensure_pending(fresh, base_now, prev, now, reason="PR changed; evaluation queued")
        except Exception as exc:
            prev["last_error"] = _safe_text(exc, limit=500)
        index["prs"][key] = prev
        return {
            "number": number,
            "decision": "REVIEW",
            "state": "pending",
            "evaluation_id": None,
            "changed_during_evaluation": True,
        }

    def _load_valid_cached(
        self,
        prev: Mapping[str, Any],
        pr: Any,
        current_base: str,
        now: int,
    ) -> dict[str, Any] | None:
        evaluation_id = prev.get("evaluation_id")
        if not isinstance(evaluation_id, str):
            return None
        if prev.get("head_sha") != pr.head_sha or prev.get("base_sha") != current_base:
            return None
        try:
            report = self.store.read_report(evaluation_id)
        except Exception:
            return None
        if report.get("head_sha") != pr.head_sha or report.get("base_sha") != current_base:
            return None
        expires_at = _split_time(report.get("expires_at"))
        if expires_at is None or expires_at <= now:
            return None
        if report.get("decision") == "ERROR":
            # Evaluation errors are retried next poll; they are not cached as a
            # stable release decision.
            return None
        if report.get("evaluation_id") != evaluation_id:
            return None
        return report

    # -- evaluation ---------------------------------------------------------

    def _evaluate(self, pr: Any, base_sha: str) -> dict[str, Any]:
        now_value = _now(self.clock)
        allow_fork = bool(self.config.get("allow_fork_prs", False))
        candidate = self.github.fetch_pull_request_candidate(pr.number, allow_fork=allow_fork)
        if candidate.base_sha != base_sha:
            # The baseline moved during fetching.  Fail this attempt closed; the
            # caller's bounded retry will use the new base.
            raise DaemonError("base branch moved while fetching the candidate")
        if candidate.pull_request.head_sha != pr.head_sha:
            raise DaemonError("pull request head changed while fetching the candidate")

        context = self._build_context(candidate)
        old_resources: list[dict[str, Any]] = []
        new_resources: list[dict[str, Any]] = []
        with tempfile.TemporaryDirectory(prefix="change-guard-tree-") as temporary:
            root = Path(temporary)
            base_dir = root / "base"
            head_dir = root / "head"
            candidate.base_snapshot.materialize(base_dir)
            candidate.head_snapshot.materialize(head_dir)
            old_resources = self.render(str(base_dir), self._render_config)
            if candidate.base_snapshot.renderer_files == candidate.head_snapshot.renderer_files:
                new_resources = old_resources
            else:
                new_resources = self.render(str(head_dir), self._render_config)
        if not isinstance(old_resources, list) or not isinstance(new_resources, list):
            raise DaemonError("renderer did not return a resource list")
        if not new_resources:
            raise DaemonError("renderer returned no resources for the candidate")

        evidence = self.collector(self.config)
        if not isinstance(evidence, dict):
            raise DaemonError("evidence collector did not return a mapping")
        collected_at = _split_time(evidence.get("collected_at"))
        if collected_at is None or collected_at <= 0:
            raise DaemonError("evidence has no valid collection timestamp")

        # A first pass without AI supplies the model with concrete diffs and
        # findings.  The final evaluation includes the validated model result.
        initial_config = dict(self.config)
        initial_config["ai_required"] = False
        initial = self.evaluator(
            old_resources,
            new_resources,
            evidence,
            initial_config,
            context,
            None,
        )
        if not isinstance(initial, dict):
            raise DaemonError("engine did not return an evaluation object")
        ai_result = self._analyze(initial, evidence, context, candidate)
        result = self.evaluator(
            old_resources,
            new_resources,
            evidence,
            self.config,
            context,
            ai_result,
        )
        if not isinstance(result, dict):
            raise DaemonError("engine did not return an evaluation object")
        result = self._escalate_result(result, context)
        images = self._deployment_images(new_resources)
        evidence_summary = self._evidence_summary(evidence)
        evidence_digest = _sha256_json(evidence_summary)
        trust = {
            "evidence_collected_at": collected_at,
            "evidence_digest": evidence_digest,
            "render_digest": result.get("render_digest"),
            "old_render_digest": result.get("old_render_digest"),
            "decision": result.get("decision"),
            "findings_digest": _sha256_json(result.get("findings", [])),
            "head_tree_sha": candidate.head_snapshot.tree_sha,
            "base_tree_sha": candidate.base_snapshot.tree_sha,
            "head_tree_digest": candidate.head_snapshot.tree_digest,
            "base_tree_digest": candidate.base_snapshot.tree_digest,
            "rule_version": result.get("rule_version", RULE_VERSION),
            "ai_status": ai_result.get("status") if isinstance(ai_result, dict) else None,
            "ai_model": ai_result.get("model") if isinstance(ai_result, dict) else None,
            "started_at": now_value,
        }
        identity = {
            "schema_version": SCHEMA_VERSION,
            "repository": self.config["repository"],
            "pr": pr.number,
            "head_sha": pr.head_sha,
            "base_sha": base_sha,
            "head_tree_sha": candidate.head_snapshot.tree_sha,
            "base_tree_sha": candidate.base_snapshot.tree_sha,
            "render_digest": result.get("render_digest"),
            "old_render_digest": result.get("old_render_digest"),
            **trust,
        }
        evaluation_id = "ev-" + hashlib.sha256(_canonical_json(identity).encode("utf-8")).hexdigest()[:24]
        ttl = int(self.config["evidence_ttl_seconds"])
        engine_expires = _split_time(result.get("expires_at")) or (collected_at + ttl)
        expires_at = min(engine_expires, collected_at + ttl, now_value + ttl)
        if expires_at <= now_value:
            expires_at = now_value + 1
        report = {
            "schema_version": SCHEMA_VERSION,
            "evaluation_id": evaluation_id,
            "repository": self.config["repository"],
            "pull_request": {
                "number": pr.number,
                "title": _safe_text(pr.title, limit=300),
                "author": _safe_text(pr.author, limit=100),
                "head_ref": _safe_text(pr.head_ref, limit=255),
                "head_repository": _safe_text(pr.head_repo, limit=200),
                "base_ref": _safe_text(pr.base_ref, limit=255),
                "pr_base_sha": candidate.pr_base_sha,
            },
            "head_sha": pr.head_sha,
            "base_sha": base_sha,
            "base_branch": self.config["base_branch"],
            "head_tree_sha": candidate.head_snapshot.tree_sha,
            "base_tree_sha": candidate.base_snapshot.tree_sha,
            "head_tree_digest": candidate.head_snapshot.tree_digest,
            "base_tree_digest": candidate.base_snapshot.tree_digest,
            "tree_entry_count": candidate.head_snapshot.entry_count,
            "changed_paths": list(candidate.changed_paths[:500]),
            "changed_count": candidate.changed_count,
            "tree_diff_truncated": candidate.tree_diff_truncated,
            "argo": candidate.argo.as_context(),
            "render_digest": result.get("render_digest"),
            "old_render_digest": result.get("old_render_digest"),
            "deployment_images": images,
            "decision": result.get("decision"),
            "evaluated_at": result.get("evaluated_at", now_value),
            "expires_at": expires_at,
            "evidence_ttl_seconds": ttl,
            "rule_version": result.get("rule_version", RULE_VERSION),
            "evidence": evidence_summary,
            "evidence_digest": evidence_digest,
            "ai": self._ai_summary(ai_result),
            "context": {
                "tree_changes": list(context.get("tree_changes", [])[:500]),
                "deployment_related_changes": list(context.get("deployment_related_changes", [])[:200]),
                "argo": candidate.argo.as_context(),
                "changed_count": candidate.changed_count,
                "tree_diff_truncated": candidate.tree_diff_truncated,
            },
            "evaluation": result,
            "created_at": now_value,
            "status_context": self.config["status_context"],
            "report_digest": None,
        }
        report = _sanitize_value(report)
        report["report_digest"] = _sha256_json({key: value for key, value in report.items() if key != "report_digest"})
        encoded = _canonical_json(report)
        if len(encoded.encode("utf-8")) > MAX_REPORT_BYTES:
            raise DaemonError("evaluation report exceeds the size limit")
        return report

    def _analyze(
        self,
        initial: Mapping[str, Any],
        evidence: Mapping[str, Any],
        context: Mapping[str, Any],
        candidate: Any,
    ) -> dict[str, Any]:
        inputs = {
            "repository": self.config["repository"],
            "pull_request": {
                "number": candidate.pull_request.number,
                "title": _safe_text(candidate.pull_request.title, limit=300),
                "author": _safe_text(candidate.pull_request.author, limit=100),
            },
            "head_sha": candidate.pull_request.head_sha,
            "base_sha": candidate.base_sha,
            "render_digest": initial.get("render_digest"),
            "decision_preview": initial.get("decision"),
            "findings_preview": list(initial.get("findings", []))[:100],
            "changes": list(initial.get("changes", []))[:200],
            "evidence": self._evidence_summary(dict(evidence)),
            "context": {
                "changed_paths": list(context.get("tree_changes", []))[:200],
                "argo": context.get("argo", {}),
            },
        }
        try:
            result = self.analyzer(inputs, dict(self.config))
        except Exception as exc:
            return {
                "status": "error",
                "model": self.config.get("deepseek_model", "deepseek-chat"),
                "summary": "",
                "additional_risks": [],
                "citations": [],
                "error": _safe_text(exc, limit=800),
            }
        if not isinstance(result, dict):
            return {
                "status": "error",
                "model": self.config.get("deepseek_model", "deepseek-chat"),
                "summary": "",
                "additional_risks": [],
                "citations": [],
                "error": "AI analyzer returned an invalid result",
            }
        return result

    def _build_context(self, candidate: Any) -> dict[str, Any]:
        changed = list(candidate.changed_paths)
        deployment_related = [path for path in changed if github_module.is_deployment_path(path)]
        argo_context = candidate.argo.as_context()
        return {
            "repository": self.config["repository"],
            "pull_request": candidate.pull_request.number,
            "head_sha": candidate.pull_request.head_sha,
            "base_sha": candidate.base_sha,
            "pr_base_sha": candidate.pr_base_sha,
            "head_ref": _safe_text(candidate.pull_request.head_ref, limit=255),
            "base_ref": self.config["base_branch"],
            "head_tree_sha": candidate.head_snapshot.tree_sha,
            "base_tree_sha": candidate.base_snapshot.tree_sha,
            "head_tree_digest": candidate.head_snapshot.tree_digest,
            "base_tree_digest": candidate.base_snapshot.tree_digest,
            "tree_entry_count": candidate.head_snapshot.entry_count,
            "changed_paths": changed[:500],
            "tree_changes": changed[:500],
            "deployment_related_changes": deployment_related[:200],
            "changed_count": candidate.changed_count,
            "tree_diff_truncated": candidate.tree_diff_truncated,
            "argo": argo_context,
            **argo_context,
        }

    def _escalate_result(self, result: dict[str, Any], context: Mapping[str, Any]) -> dict[str, Any]:
        findings = [
            dict(item)
            for item in result.get("findings", [])
            if isinstance(item, Mapping) and item.get("severity") in _SEVERITY_RANK
        ]
        existing = {(str(item.get("rule_id")), str(item.get("field"))) for item in findings}
        escalations: list[dict[str, Any]] = []

        def add(rule_id: str, severity: str, field_name: str, message: str, evidence: Mapping[str, Any]) -> None:
            key = (rule_id, field_name)
            if key in existing:
                return
            existing.add(key)
            item = {
                "rule_id": rule_id,
                "severity": severity,
                "field": field_name,
                "message": message,
                "evidence": dict(evidence),
            }
            findings.append(item)
            escalations.append(item)

        if context.get("argo_source_changed") is True:
            add(
                "ARGOCD_SOURCE_CHANGED",
                "BLOCK",
                "context.argo_source_changed",
                "Argo CD Application source repository/path/revision changed",
                {"paths": context.get("argo_changed_paths", [])[:20]},
            )
        if context.get("argo_application_changed") is True:
            add(
                "ARGOCD_APPLICATION_CHANGED",
                "REVIEW",
                "context.argo_application_changed",
                "An Argo CD Application/ApplicationSet changed and requires manual review",
                {"paths": context.get("argo_changed_paths", [])[:20]},
            )
        if context.get("argo_project_changed") is True:
            add(
                "ARGOCD_PROJECT_CHANGED",
                "REVIEW",
                "context.argo_project_changed",
                "An Argo CD AppProject changed and requires manual review",
                {"paths": context.get("argo_changed_paths", [])[:20]},
            )
        if context.get("argo_manifest_error") is True:
            add(
                "ARGOCD_MANIFEST_INVALID",
                "REVIEW",
                "context.argo_manifest_error",
                "Argo CD manifests could not be parsed; their source/project impact cannot be proven",
                {},
            )
        if context.get("tree_diff_truncated") is True:
            add(
                "TREE_DIFF_TRUNCATED",
                "REVIEW",
                "context.tree_diff_truncated",
                "the repository tree diff was truncated; manual review is required",
                {"changed_count": context.get("changed_count")},
            )
        extra_paths = [
            path
            for path in context.get("deployment_related_changes", [])
            if not path.startswith("charts/demo/")
            and path != "gitops/demo/values.yaml"
            and not (
                path.lower().startswith("gitops/argocd/")
                or path.lower().endswith(("/application.yaml", "/application.yml", "/project.yaml", "/project.yml"))
            )
        ]
        if extra_paths:
            add(
                "DEPLOYMENT_CONFIG_CHANGE",
                "REVIEW",
                "context.deployment_related_changes",
                "a deployment-related path outside the trusted rendered chart changed",
                {"paths": extra_paths[:20], "count": len(extra_paths)},
            )
        if not escalations:
            return result
        findings.sort(key=lambda item: (-_SEVERITY_RANK[str(item["severity"])], str(item["rule_id"]), str(item["field"])))
        result = dict(result)
        result["findings"] = findings
        result["decision"] = _decision_from_findings(findings)
        result["daemon_escalations"] = escalations
        audit = result.get("audit")
        if isinstance(audit, dict):
            audit = dict(audit)
            audit["checks"] = [
                {
                    "rule_id": item["rule_id"],
                    "severity": item["severity"],
                    "field": item["field"],
                    "message": item["message"],
                }
                for item in findings
            ]
            audit["daemon_escalations"] = [
                {"rule_id": item["rule_id"], "severity": item["severity"], "field": item["field"]}
                for item in escalations
            ]
            result["audit"] = audit
        return result

    def _deployment_images(self, resources: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
        images: list[dict[str, Any]] = []
        namespace = self.config["namespace"]
        name = self.config["deployment"]
        for resource in resources:
            if not isinstance(resource, Mapping) or resource.get("kind") != "Deployment":
                continue
            metadata = resource.get("metadata") if isinstance(resource.get("metadata"), Mapping) else {}
            if metadata.get("name") != name:
                continue
            if metadata.get("namespace", namespace) not in {"", namespace}:
                continue
            spec = resource.get("spec") if isinstance(resource.get("spec"), Mapping) else {}
            template = spec.get("template") if isinstance(spec.get("template"), Mapping) else {}
            pod_spec = template.get("spec") if isinstance(template.get("spec"), Mapping) else {}
            for group in ("containers", "initContainers"):
                for container in pod_spec.get(group, []) if isinstance(pod_spec.get(group), list) else []:
                    if not isinstance(container, Mapping):
                        continue
                    image = container.get("image")
                    if isinstance(image, str) and image:
                        images.append(
                            {
                                "container": str(container.get("name", ""))[:200],
                                "init": group == "initContainers",
                                "image": image[:1000],
                            }
                        )
        images.sort(key=lambda item: (item["init"], item["container"], item["image"]))
        return images

    def _evidence_summary(self, evidence: Mapping[str, Any]) -> dict[str, Any]:
        metrics = evidence.get("metrics") if isinstance(evidence.get("metrics"), Mapping) else {}
        source_timestamps = (
            metrics.get("source_timestamps") if isinstance(metrics.get("source_timestamps"), Mapping) else {}
        )
        alerts = metrics.get("alerts") if isinstance(metrics.get("alerts"), list) else []
        alert_summary: list[dict[str, Any]] = []
        for alert in alerts[:50]:
            if not isinstance(alert, Mapping):
                continue
            alert_summary.append(
                {
                    "name": _safe_text(alert.get("name", ""), limit=200),
                    "state": _safe_text(alert.get("state", ""), limit=50),
                    "labels": _sanitize_value(alert.get("labels") or {}),
                }
            )
        capacity = evidence.get("capacity") if isinstance(evidence.get("capacity"), Mapping) else {}
        deployment = evidence.get("deployment") if isinstance(evidence.get("deployment"), Mapping) else {}
        nodes = evidence.get("nodes") if isinstance(evidence.get("nodes"), list) else []
        pods = evidence.get("pods") if isinstance(evidence.get("pods"), list) else []
        raw_errors = evidence.get("errors") if isinstance(evidence.get("errors"), list) else []
        return {
            "collected_at": _split_time(evidence.get("collected_at")),
            "errors": [_safe_text(item, limit=500) for item in raw_errors[:20]],
            "metrics": {
                "memory_working_set_bytes": _finite(metrics.get("memory_working_set_bytes")),
                "request_rate": _finite(metrics.get("request_rate")),
                "error_ratio": _finite(metrics.get("error_ratio")),
                "p95_seconds": _finite(metrics.get("p95_seconds")),
                "alerts": alert_summary,
                "source_timestamps": {
                    str(key): _split_time(value) for key, value in list(source_timestamps.items())[:20]
                },
            },
            "capacity": {
                key: _finite(capacity.get(key))
                for key in (
                    "available_cpu_millicores",
                    "available_memory_bytes",
                    "allocatable_cpu_millicores",
                    "allocatable_memory_bytes",
                    "workers_ready",
                )
            },
            "deployment": {
                "name": _safe_text(deployment.get("name", ""), limit=200),
                "namespace": _safe_text(deployment.get("namespace", ""), limit=200),
                "replicas": deployment.get("replicas"),
                "ready_replicas": deployment.get("ready_replicas"),
                "images": [_safe_text(item, limit=500) for item in (deployment.get("images") or [])[:20]],
            },
            "node_count": len(nodes),
            "pod_count": len(pods),
        }

    def _ai_summary(self, ai_result: Mapping[str, Any] | None) -> dict[str, Any]:
        if not isinstance(ai_result, Mapping):
            return {"status": "missing"}
        risks = ai_result.get("additional_risks") if isinstance(ai_result.get("additional_risks"), list) else []
        citations = ai_result.get("citations") if isinstance(ai_result.get("citations"), list) else []
        return {
            "status": ai_result.get("status"),
            "model": _safe_text(ai_result.get("model", ""), limit=100),
            "summary": _safe_text(ai_result.get("summary", ""), limit=2000),
            "additional_risks": [
                {
                    "title": _safe_text(item.get("title", ""), limit=300),
                    "detail": _safe_text(item.get("detail", ""), limit=1000),
                    "severity": item.get("severity", "REVIEW"),
                }
                for item in risks[:10]
                if isinstance(item, Mapping)
            ],
            "citations": [
                {
                    "case_id": _safe_text(item.get("case_id", ""), limit=100),
                    "source": _safe_text(item.get("source", ""), limit=500),
                    "source_sha256": _safe_text(item.get("source_sha256", ""), limit=64),
                    "source_commit": _safe_text(item.get("source_commit", ""), limit=64),
                    "line_start": item.get("line_start"),
                    "line_end": item.get("line_end"),
                }
                for item in citations[:10]
                if isinstance(item, Mapping)
            ],
            "error": _safe_text(ai_result.get("error", ""), limit=800) if ai_result.get("error") else None,
        }

    # -- approval -----------------------------------------------------------

    def _approval_permission(self, login: str, association: str) -> tuple[str | None, str | None]:
        """Resolve an approver's *current* repository permission.

        The collaborator-permission endpoint requires Administration: read for
        fine-grained tokens, which the guard deliberately does not have.  On a
        personal repository the current owner is necessarily an administrator,
        and GitHub reports ``author_association=OWNER`` on that owner's issue
        comments.  We therefore verify the *current* repository identity (which
        also catches a rename/transfer to a different owner) and accept only an
        exact owner match.  Organizations, teams, and non-owner collaborators
        still require the explicit permission endpoint; a 403 there fails closed
        instead of being treated as write access.
        """

        if association == "OWNER":
            get_identity = getattr(self.github, "get_repository_identity", None)
            if callable(get_identity):
                try:
                    identity = get_identity()
                except Exception as exc:
                    return None, f"cannot verify current repository owner: {_safe_text(exc, limit=400)}"
                if not isinstance(identity, Mapping):
                    return None, "repository identity response is invalid"
                owner_login = identity.get("owner_login")
                owner_type = identity.get("owner_type")
                if (
                    isinstance(owner_login, str)
                    and owner_login.casefold() == login.casefold()
                    and owner_type == "User"
                ):
                    return github_module.OWNER_APPROVAL_PERMISSION, None
                # OWNER association on an organization (or a stale/renamed
                # owner) is not proof of current write access.  Continue with
                # the explicit permission endpoint below.
        try:
            permission = self.github.get_user_permission(login)
        except Exception as exc:
            return None, f"cannot verify current write permission for {login}: {_safe_text(exc, limit=400)}"
        if permission in github_module.WRITE_PERMISSIONS:
            return permission, None
        return None, None

    def _resolve_approval(self, report: Mapping[str, Any], pr: Any) -> tuple[dict[str, Any] | None, str | None]:
        if report.get("decision") != "REVIEW":
            return None, None
        approvers = set(self.config.get("approvers", []))
        if not approvers:
            return None, "no approvers are configured; REVIEW cannot be approved"
        evaluation_id = report.get("evaluation_id")
        evaluated_at = _split_time(report.get("evaluated_at"))
        expires_at = _split_time(report.get("expires_at"))
        if not isinstance(evaluation_id, str) or evaluated_at is None or expires_at is None:
            return None, "report timestamps are invalid"
        if report.get("head_sha") != pr.head_sha:
            return None, "report head no longer matches the pull request"
        now = _now(self.clock)
        if now >= expires_at:
            return None, "report has expired"
        try:
            comments = self.github.list_issue_comments(pr.number)
        except Exception as exc:
            return None, f"cannot read approval comments: {_safe_text(exc, limit=500)}"
        candidates: list[dict[str, Any]] = []
        for comment in comments:
            if not isinstance(comment, Mapping):
                continue
            if github_module.parse_approval_body(comment.get("body")) != evaluation_id:
                continue
            user = comment.get("user") if isinstance(comment.get("user"), Mapping) else {}
            login = user.get("login")
            if not isinstance(login, str) or login not in approvers:
                continue
            created = github_module._parse_github_time(comment.get("created_at"))
            updated = github_module._parse_github_time(comment.get("updated_at"))
            effective = max(value for value in (created, updated) if value is not None) if (created or updated) else None
            if effective is None:
                continue
            if effective < evaluated_at - _APPROVAL_EFFECTIVE_SKEW_SECONDS or effective >= expires_at:
                continue
            comment_id = comment.get("id")
            if isinstance(comment_id, bool) or not isinstance(comment_id, int) or comment_id < 1:
                continue
            association = comment.get("author_association")
            candidates.append(
                {
                    "comment_id": comment_id,
                    "login": login,
                    "association": str(association).upper() if isinstance(association, str) else "",
                    "effective_at": int(effective),
                    "created_at": int(created) if created is not None else None,
                    "updated_at": int(updated) if updated is not None else None,
                    "url": comment.get("html_url") if isinstance(comment.get("html_url"), str) else None,
                }
            )
        candidates.sort(key=lambda item: (-item["effective_at"], -item["comment_id"]))
        permission_error: str | None = None
        for candidate in candidates:
            permission, error = self._approval_permission(candidate["login"], candidate["association"])
            if permission is None:
                if error:
                    permission_error = error
                continue
            if report.get("head_sha") != pr.head_sha:
                return None, "report head changed during approval verification"
            record = {
                "evaluation_id": evaluation_id,
                "comment_id": candidate["comment_id"],
                "login": candidate["login"],
                "permission": permission,
                "approved_at": candidate["effective_at"],
                "created_at": candidate["created_at"],
                "updated_at": candidate["updated_at"],
                "checked_at": _now(self.clock),
                "head_sha": report.get("head_sha"),
                "base_sha": report.get("base_sha"),
                "expires_at": expires_at,
                "comment_url": candidate["url"],
            }
            try:
                self.store.write_approval(record)
            except Exception as exc:
                return None, f"cannot persist approval record: {_safe_text(exc, limit=400)}"
            return record, None
        return None, permission_error

    # -- status publication -------------------------------------------------

    def _desired_status(
        self,
        report: Mapping[str, Any],
        approval: Mapping[str, Any] | None,
    ) -> dict[str, str]:
        decision = str(report.get("decision", "ERROR"))
        evaluation_id = str(report.get("evaluation_id", ""))
        if decision == "PASS":
            return {
                "state": "success",
                "description": f"PASS {evaluation_id} head/base verified",
            }
        if decision == "BLOCK":
            top = next(
                (
                    item
                    for item in report.get("findings", [])
                    if isinstance(item, Mapping) and item.get("severity") == "BLOCK"
                ),
                {},
            )
            reason = f"{top.get('rule_id', 'BLOCK')}: {top.get('message', 'release blocked')}"
            return {"state": "failure", "description": f"BLOCK {reason} [{evaluation_id}]"}
        if decision == "ERROR":
            top = next(
                (
                    item
                    for item in report.get("findings", [])
                    if isinstance(item, Mapping) and item.get("severity") == "ERROR"
                ),
                {},
            )
            reason = f"{top.get('rule_id', 'ERROR')}: {top.get('message', 'evaluation failed')}"
            return {"state": "error", "description": f"ERROR {reason} [{evaluation_id}]"}
        if decision == "REVIEW":
            if approval is not None:
                return {
                    "state": "success",
                    "description": f"REVIEW approved by {approval.get('login')} [{evaluation_id}]",
                }
            return {
                "state": "pending",
                "description": f"REVIEW required - comment /guard approve {evaluation_id}",
            }
        return {"state": "error", "description": f"invalid evaluation decision [{evaluation_id}]"}

    def _publish(
        self,
        report: Mapping[str, Any],
        pr: Any,
        desired: Mapping[str, str],
        approval: Mapping[str, Any] | None,
        prev: dict[str, Any],
        index: dict[str, Any],
        now: int,
    ) -> dict[str, Any]:
        state = str(desired.get("state"))
        description = str(desired.get("description", ""))
        if state not in github_module.STATUS_STATES:
            state = "error"
            description = "invalid status state"
        if state == "success":
            fresh = self.github.get_pull_request(pr.number)
            base_now = self.github.get_branch_head(self.config["base_branch"])
            current = _now(self.clock)
            if (
                getattr(fresh, "state", "") != "open"
                or getattr(fresh, "draft", False)
                or fresh.head_sha != report.get("head_sha")
                or base_now != report.get("base_sha")
                or current >= int(report.get("expires_at") or 0)
            ):
                return {"state": "pending", "stale": True, "error": None}
            if report.get("decision") == "REVIEW":
                fresh_approval, _error = self._resolve_approval(report, fresh)
                if (
                    fresh_approval is None
                    or approval is None
                    or fresh_approval.get("comment_id") != approval.get("comment_id")
                ):
                    state = "pending"
                    description = (
                        f"REVIEW approval is no longer valid - comment /guard approve {report.get('evaluation_id')}"
                    )
                    approval = None
            # A second, immediate check narrows the race to the API call itself.
            final_pr = self.github.get_pull_request(pr.number)
            final_base = self.github.get_branch_head(self.config["base_branch"])
            if (
                getattr(final_pr, "state", "") != "open"
                or getattr(final_pr, "draft", False)
                or final_pr.head_sha != report.get("head_sha")
                or final_base != report.get("base_sha")
            ):
                return {"state": "pending", "stale": True, "error": None}

        last = prev.get("last_status") if isinstance(prev.get("last_status"), Mapping) else {}
        if (
            last.get("sha") == report.get("head_sha")
            and last.get("state") == state
            and _safe_text(last.get("description"), limit=STATUS_DETAIL_LIMIT) == _safe_text(
                description, limit=STATUS_DETAIL_LIMIT
            )
        ):
            self._write_optional_comment(report, pr, prev, index)
            return {
                "state": state,
                "last_status": dict(last),
                "approval": _approval_summary(approval),
                "skipped": True,
            }
        try:
            response = self.github.create_commit_status(
                str(report.get("head_sha")),
                state,
                description,
                self.config["status_context"],
                target_url=self.config.get("status_target_url"),
            )
        except Exception as exc:
            return {
                "state": state,
                "error": f"status publication failed: {_safe_text(exc, limit=500)}",
                "approval": _approval_summary(approval),
            }
        status_record = {
            "sha": report.get("head_sha"),
            "state": state,
            "description": _safe_text(description, limit=STATUS_DETAIL_LIMIT),
            "context": self.config["status_context"],
            "posted_at": _now(self.clock),
            "evaluation_id": report.get("evaluation_id"),
            "github_id": response.get("id") if isinstance(response, Mapping) else None,
        }
        prev["last_status"] = status_record
        self._write_optional_comment(report, pr, prev, index)
        return {
            "state": state,
            "last_status": status_record,
            "approval": _approval_summary(approval),
            "skipped": False,
        }

    def _write_optional_comment(
        self,
        report: Mapping[str, Any],
        pr: Any,
        prev: dict[str, Any],
        index: dict[str, Any],
    ) -> None:
        if not self.config.get("report_comment"):
            return
        if prev.get("comment_id"):
            return
        marker = f"<!-- change-guard:evaluation:{report.get('evaluation_id')} -->"
        findings = [
            item for item in report.get("findings", []) if isinstance(item, Mapping)
        ][:8]
        lines = [
            marker,
            f"### Change Guard `{report.get('evaluation_id')}`",
            f"Decision: **{report.get('decision')}**",
            f"Head: `{report.get('head_sha')}`  ",
            f"Base: `{report.get('base_sha')}`  ",
            f"Expires: `{github_module.iso_utc(report.get('expires_at'))}`  ",
            f"Report digest: `{report.get('report_digest')}`",
        ]
        for finding in findings:
            lines.append(
                f"- **{finding.get('severity')}** `{finding.get('rule_id')}`: {finding.get('message')}"
            )
        if report.get("decision") == "REVIEW":
            lines.append("")
            lines.append(f"Manual approval: `/guard approve {report.get('evaluation_id')}`")
        body = "\n".join(lines)
        try:
            response = self.github.create_issue_comment(pr.number, body)
            comment_id = response.get("id") if isinstance(response, Mapping) else None
            if isinstance(comment_id, int) and not isinstance(comment_id, bool):
                prev["comment_id"] = comment_id
                prev["comment_url"] = response.get("html_url") if isinstance(response.get("html_url"), str) else None
        except Exception as exc:
            prev["comment_error"] = _safe_text(exc, limit=500)
            LOGGER.warning("optional report comment failed for PR #%s: %s", getattr(pr, "number", "?"), _safe_text(exc, limit=300))

    def _ensure_pending(
        self,
        pr: Any,
        base_sha: str,
        prev: dict[str, Any],
        now: int,
        *,
        reason: str = "Evaluating release; pending evidence and policy checks",
    ) -> None:
        last = prev.get("last_status") if isinstance(prev.get("last_status"), Mapping) else {}
        if isinstance(last.get("sha"), str) and last.get("sha") != pr.head_sha:
            self._revoke_status(last.get("sha"), "Superseded by a newer head commit")
        if (
            last.get("sha") == pr.head_sha
            and last.get("state") == "pending"
            and prev.get("pending_base_sha") == base_sha
        ):
            return
        description = f"{reason} [{pr.head_sha[:7]}/{base_sha[:7]}]"
        try:
            response = self.github.create_commit_status(
                pr.head_sha,
                "pending",
                description,
                self.config["status_context"],
                target_url=self.config.get("status_target_url"),
            )
        except Exception as exc:
            prev["last_error"] = f"pending status failed: {_safe_text(exc, limit=500)}"
            raise DaemonError(prev["last_error"]) from None
        prev["pending_base_sha"] = base_sha
        prev["last_status"] = {
            "sha": pr.head_sha,
            "state": "pending",
            "description": _safe_text(description, limit=STATUS_DETAIL_LIMIT),
            "context": self.config["status_context"],
            "posted_at": now,
            "evaluation_id": None,
            "github_id": response.get("id") if isinstance(response, Mapping) else None,
        }

    def _revoke_status(self, sha: Any, reason: str, *, state: str = "pending") -> None:
        if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40,64}", sha):
            return
        description = f"Change Guard: {reason}"
        self.github.create_commit_status(
            sha,
            state,
            description,
            self.config["status_context"],
            target_url=self.config.get("status_target_url"),
        )

    # -- error handling -----------------------------------------------------

    def _handle_pull_request_error(
        self,
        pr: Any,
        exc: Exception,
        index: dict[str, Any],
        now: int,
        *,
        base_sha: str | None = None,
    ) -> dict[str, Any]:
        number = getattr(pr, "number", None)
        key = str(number)
        prev = index.setdefault("prs", {}).setdefault(key, {})
        message = _safe_text(exc, limit=800)
        prev["last_error"] = message
        try:
            if base_sha is None:
                base_sha = self.github.get_branch_head(self.config["base_branch"])
            report = self._error_report(pr, base_sha, message, now)
            self.store.write_report(report)
            prev["evaluation_id"] = report["evaluation_id"]
            prev["head_sha"] = report["head_sha"]
            prev["base_sha"] = report["base_sha"]
            prev["decision"] = "ERROR"
            prev["expires_at"] = report["expires_at"]
            status_error = None
            try:
                response = self.github.create_commit_status(
                    getattr(pr, "head_sha", None),
                    "error",
                    f"ERROR: {message}",
                    self.config["status_context"],
                    target_url=self.config.get("status_target_url"),
                )
                prev["last_status"] = {
                    "sha": getattr(pr, "head_sha", None),
                    "state": "error",
                    "description": _safe_text(f"ERROR: {message}", limit=STATUS_DETAIL_LIMIT),
                    "context": self.config["status_context"],
                    "posted_at": now,
                    "evaluation_id": report["evaluation_id"],
                    "github_id": response.get("id") if isinstance(response, Mapping) else None,
                }
            except Exception as status_exc:
                status_error = f"error status publication failed: {_safe_text(status_exc, limit=400)}"
            index["prs"][key] = prev
            return {
                "number": number,
                "decision": "ERROR",
                "state": "error" if status_error is None else "unknown",
                "evaluation_id": report["evaluation_id"],
                "status_error": status_error,
                "error": message,
            }
        except Exception as nested:
            prev["last_error"] = _safe_text(nested, limit=800)
            index["prs"][key] = prev
            return {
                "number": number,
                "decision": "ERROR",
                "state": "unknown",
                "status_error": f"failed to publish error state: {_safe_text(nested, limit=400)}",
                "error": message,
            }

    def _error_report(
        self,
        pr: Any,
        base_sha: str,
        message: str,
        now: int,
    ) -> dict[str, Any]:
        head_sha = getattr(pr, "head_sha", None)
        if not isinstance(head_sha, str) or not re.fullmatch(r"[0-9a-f]{40,64}", head_sha):
            raise DaemonError("cannot create an error report without a valid head SHA")
        identity = {
            "schema_version": SCHEMA_VERSION,
            "type": "evaluation-error",
            "repository": self.config["repository"],
            "pr": getattr(pr, "number", None),
            "head_sha": head_sha,
            "base_sha": base_sha,
            "message": message,
            "at": now,
        }
        evaluation_id = "ev-" + hashlib.sha256(_canonical_json(identity).encode("utf-8")).hexdigest()[:24]
        ttl = int(self.config["evidence_ttl_seconds"])
        report = {
            "schema_version": SCHEMA_VERSION,
            "evaluation_id": evaluation_id,
            "type": "evaluation-error",
            "repository": self.config["repository"],
            "pull_request": {
                "number": getattr(pr, "number", None),
                "title": _safe_text(getattr(pr, "title", ""), limit=300),
                "author": _safe_text(getattr(pr, "author", ""), limit=100),
            },
            "head_sha": head_sha,
            "base_sha": base_sha,
            "base_branch": self.config["base_branch"],
            "decision": "ERROR",
            "evaluated_at": now,
            "expires_at": now + ttl,
            "evidence": {"collected_at": now, "errors": [message]},
            "evidence_digest": _sha256_json({"error": message}),
            "findings": [
                {
                    "rule_id": "DAEMON_EVALUATION_ERROR",
                    "severity": "ERROR",
                    "field": "evaluation",
                    "message": message,
                    "evidence": {},
                }
            ],
            "evaluation": {
                "decision": "ERROR",
                "findings": [
                    {
                        "rule_id": "DAEMON_EVALUATION_ERROR",
                        "severity": "ERROR",
                        "field": "evaluation",
                        "message": message,
                        "evidence": {},
                    }
                ],
                "changes": [],
                "evaluated_at": now,
                "expires_at": now + ttl,
                "render_digest": None,
            },
            "ai": {"status": "error", "error": message},
            "created_at": now,
            "status_context": self.config["status_context"],
            "report_digest": None,
        }
        report = _sanitize_value(report)
        report["report_digest"] = _sha256_json({key: value for key, value in report.items() if key != "report_digest"})
        return report

    def _invalidate_closed_pr(
        self,
        pr: Any,
        prev: dict[str, Any],
        index: dict[str, Any],
        now: int,
    ) -> dict[str, Any]:
        last = prev.get("last_status") if isinstance(prev.get("last_status"), Mapping) else {}
        if prev.get("closed_revoked") is not True and isinstance(last.get("sha"), str):
            try:
                self._revoke_status(last.get("sha"), "PR is closed or merged", state="error")
            except Exception as exc:
                prev["last_error"] = f"closed status revocation failed: {_safe_text(exc, limit=500)}"
        prev["closed_revoked"] = True
        prev["closed_at"] = now
        index.setdefault("prs", {})[str(getattr(pr, "number"))] = prev
        return {
            "number": getattr(pr, "number", None),
            "decision": "ERROR",
            "state": "error",
            "closed": True,
            "error": "pull request is closed or merged",
        }

    def _entry_from_report(
        self,
        prev: dict[str, Any],
        pr: Any,
        base_sha: str,
        report: Mapping[str, Any] | None,
        now: int,
    ) -> dict[str, Any]:
        entry = dict(prev)
        entry.update(
            {
                "number": getattr(pr, "number", None),
                "head_sha": getattr(pr, "head_sha", None),
                "base_sha": base_sha,
                "updated_at": now,
                "closed_revoked": False,
            }
        )
        if report is not None:
            entry.update(
                {
                    "evaluation_id": report.get("evaluation_id"),
                    "decision": report.get("decision"),
                    "expires_at": report.get("expires_at"),
                    "render_digest": report.get("render_digest"),
                    "head_tree_sha": report.get("head_tree_sha"),
                    "base_tree_sha": report.get("base_tree_sha"),
                    "report_digest": report.get("report_digest"),
                }
            )
        return entry


def _finite(value: Any) -> float | int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        number = float(value)
        return value if math.isfinite(number) else None
    return None


def _approval_summary(approval: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(approval, Mapping):
        return None
    return {
        "login": approval.get("login"),
        "comment_id": approval.get("comment_id"),
        "approved_at": approval.get("approved_at"),
        "permission": approval.get("permission"),
        "evaluation_id": approval.get("evaluation_id"),
        "head_sha": approval.get("head_sha"),
        "base_sha": approval.get("base_sha"),
    }


# ---------------------------------------------------------------------------
# Module entry points


def run_once(
    config: Mapping[str, Any],
    *,
    github_client: Any | None = None,
    collector: Callable[[dict], dict] | None = None,
    analyzer: Callable[[dict, dict], dict] | None = None,
    render: Callable[[str, dict], list[dict]] | None = None,
    evaluator: Callable[..., dict] | None = None,
    store: StateStore | None = None,
    clock: Callable[[], float] | None = None,
    sleep: Callable[[float], None] | None = None,
) -> dict[str, Any]:
    """Run exactly one polling pass.  Operational failures are returned, not raised."""

    try:
        daemon = ChangeGuardDaemon(
            config,
            github_client=github_client,
            collector=collector,
            analyzer=analyzer,
            render=render,
            evaluator=evaluator,
            store=store,
            clock=clock,
            sleep=sleep,
        )
    except Exception as exc:
        return {"status": "error", "checked_at": int(time.time()), "error": _safe_text(exc, limit=800), "prs": []}
    return daemon.run_once()


def run_forever(
    config: Mapping[str, Any],
    *,
    stop_event: threading.Event | None = None,
    github_client: Any | None = None,
    collector: Callable[[dict], dict] | None = None,
    analyzer: Callable[[dict, dict], dict] | None = None,
    render: Callable[[str, dict], list[dict]] | None = None,
    evaluator: Callable[..., dict] | None = None,
    store: StateStore | None = None,
    clock: Callable[[], float] | None = None,
    sleep: Callable[[float], None] | None = None,
) -> None:
    """Poll until stopped.  A crash in one cycle is logged and retried."""

    try:
        daemon = ChangeGuardDaemon(
            config,
            github_client=github_client,
            collector=collector,
            analyzer=analyzer,
            render=render,
            evaluator=evaluator,
            store=store,
            clock=clock,
            sleep=sleep,
        )
    except Exception as exc:
        LOGGER.error("cannot start change-guard daemon: %s", _safe_text(exc, limit=500))
        return
    poll = float(daemon.config["poll_seconds"])
    backoff = poll
    stop = stop_event or threading.Event()
    while not stop.is_set():
        try:
            summary = daemon.run_once()
            LOGGER.info(
                "poll complete status=%s prs=%s errors=%s",
                summary.get("status"),
                len(summary.get("prs", [])),
                len(summary.get("errors", [])),
            )
            backoff = poll
        except Exception as exc:  # pragma: no cover - defensive
            LOGGER.error("poll failed: %s", _safe_text(exc, limit=500))
            backoff = min(max(poll, backoff * 2), 300.0)
        try:
            stop.wait(backoff)
        except Exception:
            if stop.is_set():
                break


def _load_yaml(path: str) -> dict[str, Any]:
    value = load_config(path)
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="change-guard-daemon",
        description="Poll GitHub pull requests and publish change-guard/release statuses",
    )
    parser.add_argument("--config", required=True, help="YAML configuration file")
    parser.add_argument("--once", action="store_true", help="run one polling pass and exit")
    parser.add_argument("--log-level", default="INFO", choices=("DEBUG", "INFO", "WARNING", "ERROR"))
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    try:
        config = _load_yaml(args.config)
    except Exception as exc:
        sys.stderr.write(json.dumps({"status": "error", "error": _safe_text(exc, limit=800)}) + "\n")
        return 2
    if args.once:
        summary = run_once(config)
        sys.stdout.write(json.dumps(summary, ensure_ascii=False, indent=2, allow_nan=False) + "\n")
        return 0 if summary.get("status") == "ok" else 1

    stop = threading.Event()

    def _handle_signal(signum, _frame):
        LOGGER.info("signal %s received; stopping after the current poll", signum)
        stop.set()

    for name in ("SIGTERM", "SIGINT"):
        signal_value = getattr(signal, name, None)
        if signal_value is not None:
            try:
                signal.signal(signal_value, _handle_signal)
            except (ValueError, OSError):
                pass
    run_forever(config, stop_event=stop)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
