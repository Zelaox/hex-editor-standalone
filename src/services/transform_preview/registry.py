"""Registry-dispatched preview-safe transform hooks."""

from __future__ import annotations

import importlib
import json
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from jsonschema import Draft202012Validator

from src.services.transforms.base import TransformProbeContext


def _root() -> Path:
    return Path(__file__).resolve().parents[3]


def load_transform_preview_registry(path: str | Path | None = None) -> Dict[str, Any]:
    target = Path(path).expanduser().resolve() if path else _root() / "config" / "transform_preview_registry.json"
    registry = json.loads(target.read_text(encoding="utf-8"))
    schema_path = _root() / "schemas" / "transform_preview_registry.schema.json"
    if schema_path.is_file():
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        errors = sorted(Draft202012Validator(schema).iter_errors(registry), key=lambda item: list(item.path))
        if errors:
            raise ValueError(f"transform preview registry invalid: {errors[0].message}")
    return registry


def family_entry(registry: Mapping[str, Any], family_id: str) -> Optional[Dict[str, Any]]:
    for item in registry.get("families") or []:
        if str(item.get("family_id") or "") == str(family_id):
            return dict(item)
    return None


def is_preview_safe(registry: Mapping[str, Any], family_id: str) -> bool:
    entry = family_entry(registry, family_id)
    return bool(entry and entry.get("preview_safe"))


def dispatch_preview_step(
    *,
    family_id: str,
    data: bytes,
    step: Mapping[str, Any],
    source_sha: str,
    registry: Mapping[str, Any] | None = None,
) -> tuple[bytes, Dict[str, Any]]:
    cfg = dict(registry or load_transform_preview_registry())
    entry = family_entry(cfg, str(family_id))
    if entry is None or not entry.get("preview_safe"):
        raise ValueError("preview hook not registered or not preview_safe")
    hook = str(entry.get("hook") or "materialize")
    if hook == "materialize_scope":
        return data, {"operation": "materialize_scope", "length_relation": str(entry.get("length_relation") or "one_to_one")}
    module_name = str(entry.get("module") or "")
    if not module_name:
        raise ValueError("preview hook module missing")
    module = importlib.import_module(module_name)
    hook_fn = getattr(module, hook, None)
    if not callable(hook_fn):
        raise ValueError("preview hook function missing")
    scope_offset = int(step.get("offset") or 0)
    ctx = TransformProbeContext.build_preview(data, source_sha=source_sha, scope_offset=scope_offset)
    parameters = dict(step.get("parameters") or {})
    candidate = dict(parameters)
    if parameters:
        candidate.setdefault("parameters", parameters)
    if step.get("key_hex"):
        candidate.setdefault("key_hex", str(step["key_hex"]))
    output = bytes(hook_fn(ctx, candidate))
    return output, {
        "operation": hook,
        "family_id": family_id,
        "length_relation": str(entry.get("length_relation") or "one_to_one"),
        "input_length": len(data),
        "output_length": len(output),
    }
