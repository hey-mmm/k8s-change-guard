#!/usr/bin/env python3
"""Check the expiry of a TokenRequest service-account kubeconfig.

Exit codes:
    0  token remains valid for at least --min-remaining seconds
    1  token is expiring soon or already expired (rotate it)
    2  the file/token could not be checked (fail closed)

The token itself is never printed.
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
import time
from pathlib import Path
from typing import Any

import yaml


def _decode_payload(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("token is not a JWT")
    payload = parts[1]
    padding = "=" * (-len(payload) % 4)
    try:
        raw = base64.urlsafe_b64decode(payload + padding)
        value = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError(f"token payload is not valid JSON: {exc}") from None
    if not isinstance(value, dict):
        raise ValueError("token payload is not an object")
    return value


def _token_from_kubeconfig(path: Path) -> str:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"cannot read kubeconfig: {exc}") from None
    try:
        config = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise ValueError(f"kubeconfig is invalid YAML: {exc}") from None
    if not isinstance(config, dict):
        raise ValueError("kubeconfig is not a mapping")
    users = config.get("users")
    if not isinstance(users, list):
        raise ValueError("kubeconfig has no users")
    for user in users:
        if not isinstance(user, dict):
            continue
        credentials = user.get("user")
        if isinstance(credentials, dict) and isinstance(credentials.get("token"), str):
            token = credentials["token"].strip()
            if token:
                return token
    raise ValueError("kubeconfig has no user token")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check TokenRequest kubeconfig expiry")
    parser.add_argument("kubeconfig")
    parser.add_argument("--min-remaining", type=int, default=3600)
    parser.add_argument("--now", type=float, help="testing override for current Unix time")
    args = parser.parse_args(argv)
    if args.min_remaining < 0:
        print(json.dumps({"status": "error", "error": "min-remaining must be non-negative"}))
        return 2
    try:
        token = _token_from_kubeconfig(Path(args.kubeconfig))
        payload = _decode_payload(token)
        exp = payload.get("exp")
        if isinstance(exp, bool) or not isinstance(exp, (int, float)):
            raise ValueError("token has no numeric exp claim")
        now = float(args.now) if args.now is not None else time.time()
        remaining = int(exp - now)
        result = {
            "status": "valid" if remaining > args.min_remaining else "rotate",
            "expires_at": int(exp),
            "remaining_seconds": remaining,
        }
        print(json.dumps(result, ensure_ascii=False))
        return 0 if remaining > args.min_remaining else 1
    except Exception as exc:
        print(json.dumps({"status": "error", "error": str(exc)[:500]}, ensure_ascii=False))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
