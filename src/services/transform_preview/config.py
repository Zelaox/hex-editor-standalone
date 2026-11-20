"""Transform preview policy loading."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from jsonschema import Draft202012Validator


def _root() -> Path:
    return Path(__file__).resolve().parents[3]


def load_transform_preview_policy(path: str | Path | None = None) -> Dict[str, Any]:
    target = Path(path).expanduser().resolve() if path else _root() / "config" / "transform_preview_policy.json"
    policy = json.loads(target.read_text(encoding="utf-8"))
    schema = json.loads((_root() / "schemas" / "transform_preview_policy.schema.json").read_text(encoding="utf-8"))
    errors = sorted(Draft202012Validator(schema).iter_errors(policy), key=lambda item: list(item.path))
    if errors:
        raise ValueError(f"transform preview policy invalid: {errors[0].message}")
    modes = {str(item["id"]) for item in policy["modes"]}
    if str(policy["default_mode"]) not in modes:
        raise ValueError("transform preview default_mode is not registered")
    return policy
