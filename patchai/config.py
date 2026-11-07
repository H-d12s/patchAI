"""Reads config.yaml once and gives the rest of the code easy access to settings and paths."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent  # the patchAI folder


@lru_cache(maxsize=1)
def get_config() -> dict[str, Any]:
    """Load config.yaml as a plain dictionary."""
    with open(ROOT / "config.yaml", encoding="utf-8") as f:
        return yaml.safe_load(f)


def path(name: str) -> Path:
    """Absolute path for an entry under `paths:` in config.yaml.

    Any path can be overridden with an environment variable, e.g. PATCHAI_INDEX=/tmp/idx
    (the tests use this so they never touch the real index).
    """
    override = os.environ.get(f"PATCHAI_{name.upper()}")
    return Path(override) if override else ROOT / get_config()["paths"][name]
