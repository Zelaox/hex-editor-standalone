"""Load hex editor checkpoint bridge policy — SSOT for brief/persist/admission caps."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Optional


def _lab_root() -> Path:
    from src.project import project_root
    return project_root()


def _default_policy_path() -> Path:
    return _lab_root() / "config" / "hex_editor_checkpoint_policy.json"


@lru_cache(maxsize=1)
def load_hex_checkpoint_policy(path: str | Path | None = None) -> Dict[str, Any]:
    target = Path(path).expanduser().resolve() if path else _default_policy_path()
    policy = json.loads(target.read_text(encoding="utf-8"))
    required = {
        "schema_version",
        "policy_id",
        "revision",
        "max_brief_bytes",
        "max_work_run_bytes",
        "max_tool_response_field_bytes",
        "externalize_fields",
        "reject_inline_fields",
        "tool_response_caps",
        "brief_budgets",
    }
    if int(policy.get("schema_version") or 0) != 1 or required - set(policy):
        raise ValueError("invalid hex editor checkpoint policy")
    return policy


def reload_hex_checkpoint_policy() -> Dict[str, Any]:
    load_hex_checkpoint_policy.cache_clear()
    return load_hex_checkpoint_policy()


def hex_editor_config() -> Dict[str, Any]:
    cfg_path = _lab_root() / "config" / "hex_editor.json"
    return json.loads(cfg_path.read_text(encoding="utf-8"))


def artifact_root_rel() -> str:
    return str(hex_editor_config().get("artifact_root") or "data/artifacts/hex_editor")
