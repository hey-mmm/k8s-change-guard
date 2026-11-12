"""Local and service-facing command line entry points.

This module never runs a candidate script.  ``evaluate`` consumes pre-rendered
manifests, ``render`` invokes the sandboxed renderer, ``collect`` uses read-only
fixed Kubernetes/Prometheus calls, and ``ai`` performs the validated DeepSeek
review.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Sequence

import yaml

from . import __version__
from . import ai as ai_module
from . import evidence as evidence_module
from . import renderer as renderer_module
from .engine import RULE_VERSION, evaluate


EXIT_PASS = 0
EXIT_REVIEW = 1
EXIT_BLOCK = 2
EXIT_ERROR = 3


def _load_yaml(path: str) -> dict[str, Any]:
    try:
        raw = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"cannot read {path}: {exc}") from exc
    try:
        value = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise ValueError(f"invalid YAML in {path}: {exc}") from exc
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a mapping")
    return value


def _load_json(path: str) -> Any:
    try:
        raw = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"cannot read {path}: {exc}") from exc
    try:
        return json.loads(raw)
    except ValueError as exc:
        raise ValueError(f"invalid JSON in {path}: {exc}") from exc


def _write_output(path: str | None, value: Any, *, mode: int = 0o600) -> None:
    encoded = json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    if path is None:
        sys.stdout.write(encoded)
        return
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    file_descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=str(destination.parent)
    )
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(file_descriptor, mode)
        with os.fdopen(file_descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, destination)
    except Exception:
        try:
            os.unlink(temporary_name)
        except OSError:
            pass
        raise


def _decision_exit(decision: str) -> int:
    return {
        "PASS": EXIT_PASS,
        "REVIEW": EXIT_REVIEW,
        "BLOCK": EXIT_BLOCK,
        "ERROR": EXIT_ERROR,
    }.get(decision, EXIT_ERROR)


def _cmd_evaluate(args: argparse.Namespace) -> int:
    config = _load_yaml(args.config) if args.config else {}
    context = _load_json(args.context) if args.context else {}
    evidence = _load_json(args.evidence) if args.evidence else {}
    ai_result = _load_json(args.ai_result) if args.ai_result else None
    old_resources = (
        renderer_module.load_rendered_manifests(args.old, config) if args.old else []
    )
    new_resources = renderer_module.load_rendered_manifests(args.new, config)
    result = evaluate(old_resources, new_resources, evidence, config, context, ai_result)
    _write_output(args.output, result)
    return _decision_exit(result["decision"])


def _cmd_render(args: argparse.Namespace) -> int:
    config = _load_yaml(args.config) if args.config else {}
    if args.pre_rendered:
        resources = renderer_module.load_rendered_manifests(args.pre_rendered, config)
    else:
        if not args.tree:
            raise ValueError("render requires --tree or --pre-rendered")
        resources = renderer_module.render_tree(args.tree, config)
    _write_output(args.output, resources)
    return EXIT_PASS


def _cmd_collect(args: argparse.Namespace) -> int:
    config = _load_yaml(args.config)
    result = evidence_module.collect(config)
    _write_output(args.output, result)
    return EXIT_ERROR if result.get("errors") else EXIT_PASS


def _cmd_ai(args: argparse.Namespace) -> int:
    config = _load_yaml(args.config)
    report = _load_json(args.report)
    result = ai_module.analyze(report, config)
    _write_output(args.output, result)
    return EXIT_PASS if result.get("status") == "ok" else EXIT_ERROR


def _cmd_verify_knowledge(args: argparse.Namespace) -> int:
    knowledge = ai_module.verify_knowledge(args.knowledge_dir)
    result = {
        "status": "ok",
        "schema_version": 1,
        "root": knowledge["root"],
        "source_count": len(knowledge["sources"]),
        "case_count": len(knowledge["cases"]),
        "sources": knowledge["sources"],
        "cases": [
            {
                "id": case["id"],
                "source": case["source"]["path"],
                "line_start": case["line_start"],
                "line_end": case["line_end"],
                "excerpt_sha256": case["excerpt_sha256"],
            }
            for case in knowledge["cases"]
        ],
    }
    _write_output(args.output, result)
    return EXIT_PASS


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="change-guard", description="Kubernetes release evaluation kernel")
    parser.add_argument("--version", action="version", version=f"change-guard {__version__} (rules {RULE_VERSION})")
    subparsers = parser.add_subparsers(dest="command", required=True)

    evaluate_parser = subparsers.add_parser("evaluate", help="evaluate pre-rendered manifests")
    evaluate_parser.add_argument("--old", action="append", default=[], help="old rendered YAML (repeatable)")
    evaluate_parser.add_argument("--new", action="append", required=True, help="new rendered YAML (repeatable)")
    evaluate_parser.add_argument("--evidence", help="evidence JSON")
    evaluate_parser.add_argument("--config", help="config YAML")
    evaluate_parser.add_argument("--context", help="context JSON")
    evaluate_parser.add_argument("--ai-result", help="DeepSeek result JSON")
    evaluate_parser.add_argument("--output", help="write JSON atomically instead of stdout")
    evaluate_parser.set_defaults(func=_cmd_evaluate)

    render_parser = subparsers.add_parser("render", help="render the permitted chart surface")
    render_parser.add_argument("--tree", help="candidate repository tree")
    render_parser.add_argument("--pre-rendered", action="append", default=[], help="fixture-only rendered YAML")
    render_parser.add_argument("--config", help="renderer config YAML")
    render_parser.add_argument("--output", help="write JSON atomically instead of stdout")
    render_parser.set_defaults(func=_cmd_render)

    collect_parser = subparsers.add_parser("collect", help="collect read-only cluster evidence")
    collect_parser.add_argument("--config", required=True, help="config YAML")
    collect_parser.add_argument("--output", help="write JSON atomically instead of stdout")
    collect_parser.set_defaults(func=_cmd_collect)

    ai_parser = subparsers.add_parser("ai", help="run the strict DeepSeek review")
    ai_parser.add_argument("--report", required=True, help="sanitized report JSON")
    ai_parser.add_argument("--config", required=True, help="config YAML")
    ai_parser.add_argument("--output", help="write JSON atomically instead of stdout")
    ai_parser.set_defaults(func=_cmd_ai)

    knowledge_parser = subparsers.add_parser("verify-knowledge", help="verify trusted case provenance")
    knowledge_parser.add_argument("--knowledge-dir", help="knowledge directory")
    knowledge_parser.add_argument("--output", help="write JSON atomically instead of stdout")
    knowledge_parser.set_defaults(func=_cmd_verify_knowledge)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except Exception as exc:  # fail closed; no traceback or credential dump
        sys.stderr.write(
            json.dumps(
                {"status": "error", "error": str(exc)[:800]},
                ensure_ascii=False,
            )
            + "\n"
        )
        return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
