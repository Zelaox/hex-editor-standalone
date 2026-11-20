"""Load binary dynamic analysis and execution policy from lab config — NO HARDCODE."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Mapping


def _lab_root() -> Path:
    from src.project import project_root
    return project_root()


def load_binary_dynamic_config() -> Dict[str, Any]:
    path = _lab_root() / "config" / "binary_dynamic_analysis.json"
    if not path.is_file():
        raise FileNotFoundError(f"missing binary dynamic config: {path}")
    cfg = json.loads(path.read_text(encoding="utf-8"))
    if int(cfg.get("schema_version") or 0) < 1:
        raise ValueError("binary_dynamic_analysis.json schema_version unsupported")
    return cfg


def load_execution_policy(path: str | Path | None = None) -> Dict[str, Any]:
    policy_path = Path(path).expanduser().resolve() if path else _lab_root() / "config" / "pe_execution_policy.json"
    if not policy_path.is_file():
        raise FileNotFoundError(f"missing PE execution policy: {policy_path}")
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    if int(policy.get("schema_version") or 0) < 1:
        raise ValueError("pe_execution_policy schema_version unsupported")
    return policy


def resolve_execution_policy(policy: Mapping[str, Any], *, mode: str | None = None) -> Dict[str, Any]:
    base = dict(policy.get("execution_policy") or {})
    presets = dict(policy.get("mode_presets") or {})
    selected = str(mode or base.get("mode") or "trusted")
    preset = dict(presets.get(selected) or {})
    if not preset and selected not in presets:
        raise ValueError(f"unknown execution mode preset: {selected}")
    merged = {**base, **preset, "mode": selected}
    required = ("backend_id", "max_runtime_seconds")
    missing = [key for key in required if key not in merged or merged[key] in (None, "")]
    if missing:
        raise ValueError(f"execution policy missing: {', '.join(missing)}")
    return merged


def load_parser_registry(format_plugin: str) -> Dict[str, Any]:
    name = f"{format_plugin}_parser_profiles"
    path = _lab_root() / "config" / name / "registry.json"
    if not path.is_file():
        raise FileNotFoundError(f"missing parser registry: {path}")
    return json.loads(path.read_text(encoding="utf-8"))
