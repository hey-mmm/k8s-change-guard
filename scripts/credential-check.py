#!/usr/bin/env python3
"""Verify the GitHub token's actual classic/fine-grained repository capability.

By default this is read-only.  ``--probe-sha`` performs a real pending status
write to the supplied commit SHA (context ``change-guard/credential-probe``);
use it only in an explicitly authorized deployment smoke test.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

from change_guard import github as github_module


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check GitHub credential capability")
    parser.add_argument("--config", required=True)
    parser.add_argument("--probe-sha")
    args = parser.parse_args(argv)
    try:
        config = yaml.safe_load(Path(args.config).read_text(encoding="utf-8"))
        if not isinstance(config, dict):
            raise ValueError("config must be a mapping")
        client = github_module.client_from_config(config)
        result = client.verify_credentials(probe_status_sha=args.probe_sha)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except Exception as exc:
        print(
            json.dumps(
                {"status": "error", "error": github_module.sanitize_text(exc, limit=800)},
                ensure_ascii=False,
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
