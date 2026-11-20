"""Policy and registry loaders for region-routed pseudocode."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Mapping

from jsonschema import Draft202012Validator


def _hex_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _load_json(path: Path) -> Dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"missing config: {path}")
    payload = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(payload, dict):
        raise ValueError(f"config root must be object: {path}")
    return payload


def _validate(schema_name: str, payload: Mapping[str, Any]) -> None:
    schema_path = _hex_root() / "schemas" / schema_name
    if not schema_path.is_file():
        return
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    errors = sorted(Draft202012Validator(schema).iter_errors(payload), key=lambda item: list(item.path))
    if errors:
        raise ValueError(f"{schema_name}: {errors[0].message}")


def load_region_routing_policy(path: str | Path | None = None) -> Dict[str, Any]:
    target = Path(path).expanduser().resolve() if path else _hex_root() / "config" / "region_routing_policy.json"
    policy = _load_json(target)
    _validate("region_routing_policy.schema.json", policy)
    return policy


def load_merge_policy(path: str | Path | None = None, *, routing: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    routing_policy = dict(routing or load_region_routing_policy())
    rel = str(routing_policy.get("merge_policy_path") or "config/pseudocode_merge_policy.json")
    target = _hex_root() / rel
    policy = _load_json(target)
    _validate("pseudocode_merge_policy.schema.json", policy)
    return policy


def load_format_detect_registry(path: str | Path | None = None, *, routing: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    routing_policy = dict(routing or load_region_routing_policy())
    rel = str(routing_policy.get("format_detect_registry_path") or "config/format_detect_registry.json")
    return _load_json(_hex_root() / rel)


def load_decompiler_policy(path: str | Path | None = None, *, routing: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    routing_policy = dict(routing or load_region_routing_policy())
    rel = str(routing_policy.get("decompiler_policy_path") or "config/decompiler_pseudocode_policy.json")
    return _load_json(_hex_root() / rel)


def load_decompiler_registry(*, decompiler_policy: Mapping[str, Any]) -> Dict[str, Any]:
    rel = str(decompiler_policy.get("registry_path") or "config/decompiler_pseudocode_registry.json")
    return _load_json(_hex_root() / rel)


def load_rtf_parser_registry() -> Dict[str, Any]:
    lab_root = _hex_root()
    path = lab_root / "config" / "rtf_parser_profiles" / "registry.json"
    return _load_json(path)


def load_pseudocode_navigation_policy(*, ir_policy: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    from .ir import load_pseudocode_ir_policy

    ir = dict(ir_policy or load_pseudocode_ir_policy())
    rel = str(ir.get("navigation_policy_path") or "config/pseudocode_navigation_policy.json")
    target = _hex_root() / rel
    policy = _load_json(target)
    _validate("pseudocode_navigation_policy.schema.json", policy)
    return policy
