#!/usr/bin/env python3
"""Build a deterministic, minimal trusted release tarball.

Only the Python package, knowledge snapshots, requirements and example config
are included.  Tests, deployment tooling, VCS metadata and credential files are
never packaged.  Symlinks are rejected.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import tarfile
from pathlib import Path
from typing import Iterable

INCLUDE_FILES = ("pyproject.toml", "requirements.txt", "config.example.yaml")
INCLUDE_DIRS = ("change_guard", "knowledge")
EXCLUDED_PARTS = {"__pycache__", ".pytest_cache", ".mypy_cache", ".git"}


def _version(repo: Path) -> str:
    try:
        import tomllib

        with (repo / "pyproject.toml").open("rb") as handle:
            data = tomllib.load(handle)
        value = data.get("project", {}).get("version")
        if isinstance(value, str) and value:
            return value
    except Exception:
        pass
    text = (repo / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^\s*version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    return match.group(1) if match else "0.0.0"


def _iter_files(repo: Path) -> Iterable[tuple[Path, str]]:
    for name in INCLUDE_FILES:
        path = repo / name
        if path.is_file() and not path.is_symlink():
            yield path, name
    for directory_name in INCLUDE_DIRS:
        root = repo / directory_name
        if not root.is_dir() or root.is_symlink():
            continue
        for path in sorted(root.rglob("*")):
            if path.is_symlink():
                raise SystemExit(f"refusing to package symlink: {path}")
            if not path.is_file():
                continue
            if any(part in EXCLUDED_PARTS for part in path.parts):
                continue
            if path.suffix == ".pyc":
                continue
            relative = path.relative_to(repo).as_posix()
            yield path, relative


def build(repo: Path, output: Path, version: str) -> dict[str, object]:
    repo = repo.resolve()
    files = list(_iter_files(repo))
    if not files:
        raise SystemExit("nothing to package")
    files.sort(key=lambda pair: pair[1])
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode="wb", filename="", mtime=0, compresslevel=9) as gz:
        with tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for path, relative in files:
                if relative.startswith("/") or ".." in Path(relative).parts:
                    raise SystemExit(f"unsafe archive path: {relative}")
                data = path.read_bytes()
                info = tarfile.TarInfo(name=relative)
                info.size = len(data)
                info.mtime = 0
                # The trusted release contains Python modules, data, and docs
                # only.  Never infer executable bits from the build host: on
                # Windows os.access(X_OK) is true for ordinary files, which
                # would make every packaged source file executable.
                info.mode = 0o644
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                archive.addfile(info, io.BytesIO(data))
            for directory_name in INCLUDE_DIRS:
                if (repo / directory_name).is_dir():
                    info = tarfile.TarInfo(name=directory_name)
                    info.type = tarfile.DIRTYPE
                    info.mode = 0o755
                    info.mtime = 0
                    info.uid = 0
                    info.gid = 0
                    info.uname = ""
                    info.gname = ""
                    archive.addfile(info)
    payload = buffer.getvalue()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(payload)
    digest = hashlib.sha256(payload).hexdigest()
    return {
        "status": "ok",
        "version": version,
        "artifact": str(output),
        "sha256": digest,
        "bytes": len(payload),
        "files": len(files),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the trusted change-guard release tarball")
    parser.add_argument("--repo", default=str(Path(__file__).resolve().parent.parent))
    parser.add_argument("--output")
    parser.add_argument("--version")
    args = parser.parse_args(argv)
    repo = Path(args.repo).resolve()
    version = args.version or _version(repo)
    output = Path(args.output) if args.output else repo / "dist" / f"k8s-change-guard-{version}.tar.gz"
    result = build(repo, output, version)
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
