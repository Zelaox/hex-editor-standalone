"""Declarative parser profile registry loader."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict


def _lab_root() -> Path:
    from src.project import project_root
    return project_root()


def load_registry(format_plugin: str) -> Dict[str, Any]:
    path = _lab_root() / "config" / f"{format_plugin}_parser_profiles" / "registry.json"
    if not path.is_file():
        raise FileNotFoundError(f"missing parser registry: {path}")
    return json.loads(path.read_text(encoding="utf-8"))
