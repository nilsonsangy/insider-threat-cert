"""Minimal ``.env`` loader (standard library only).

Precedence for :func:`get`: process environment, then ``.env``, then default.
An empty value counts as absent. Variables already defined are never overwritten.
"""
from __future__ import annotations

import os
from pathlib import Path

DEFAULT_PATH = Path(__file__).resolve().parents[2] / ".env"


def _parse_line(line: str) -> tuple[str, str] | None:
    line = line.strip()
    if not line or line.startswith("#") or "=" not in line:
        return None
    if line.startswith("export "):
        line = line[len("export "):].lstrip()
    key, _, value = line.partition("=")
    key = key.strip()
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1]
    return (key, value) if key else None


def load_env(path: Path | str | None = None) -> None:
    """Load KEY=VALUE pairs from ``path`` (default: ``.env`` at the project root).

    Comments and blank lines are ignored, surrounding quotes are removed, empty
    values are skipped, and variables already set to a non-empty value are kept.
    A missing file is not an error.
    """
    env_path = Path(path) if path is not None else DEFAULT_PATH
    try:
        text = env_path.read_text(encoding="utf-8")
    except OSError:
        return
    for line in text.splitlines():
        parsed = _parse_line(line)
        if parsed is None:
            continue
        key, value = parsed
        if value == "" or os.environ.get(key):
            continue
        os.environ[key] = value


def get(name: str, default: str | None = None) -> str | None:
    """Return the environment value of ``name``, or ``default`` if unset or empty."""
    value = os.environ.get(name)
    return value if value else default
