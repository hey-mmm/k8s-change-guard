"""``python -m change_guard`` entry point."""

from __future__ import annotations

from .cli import main

if __name__ == "__main__":  # pragma: no cover - exercised by subprocess tests
    raise SystemExit(main())
