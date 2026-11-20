"""Load and validate transform registry from Hex editor config SSOT."""

from __future__ import annotations

import importlib
import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence


class TransformRegistryError(ValueError):
    """Registry load or validation failure."""


def hex_editor_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _config_path(name: str) -> Path:
    return hex_editor_root() / "config" / name


def _load_json(path: Path, *, label: str) -> Dict[str, Any]:
    if not path.is_file():
        raise TransformRegistryError(f"missing_{label}: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise TransformRegistryError(f"invalid_{label}: root must be object")
    return payload


@lru_cache(maxsize=1)
def load_markers_config() -> List[bytes]:
    payload = _load_json(_config_path("markers.json"), label="markers")
    markers = payload.get("markers")
    if not isinstance(markers, list):
        raise TransformRegistryError("markers.json: markers must be array")
    return [str(item).encode("latin1", errors="replace") for item in markers]


@lru_cache(maxsize=1)
def load_transform_registry_raw() -> Dict[str, Any]:
    return _load_json(_config_path("transform_registry.json"), label="transform_registry")


@lru_cache(maxsize=1)
def load_crypto_defaults_raw() -> Dict[str, Any]:
    return _load_json(_config_path("crypto_defaults.json"), label="crypto_defaults")


def _resolve_ref(defaults: Mapping[str, Any], ref: str) -> Any:
    parts = str(ref or "").split(".")
    current: Any = defaults
    for part in parts:
        if not part:
            continue
        if not isinstance(current, Mapping):
            raise TransformRegistryError(f"config ref unresolved: {ref}")
        current = current.get(part)
    if current is None:
        raise TransformRegistryError(f"missing config ref: {ref}")
    return current


def merge_crypto_defaults(lab_overrides: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    """Hex editor config first, then lab fixture overrides (deep merge probe_pipeline)."""
    merged = dict(load_crypto_defaults_raw())
    if not lab_overrides:
        return merged
    for key, value in lab_overrides.items():
        if key == "probe_pipeline" and isinstance(value, Mapping):
            pipeline = dict(merged.get("probe_pipeline") or {})
            pipeline.update(dict(value))
            merged["probe_pipeline"] = pipeline
        elif key == "promotion_policy" and isinstance(value, Mapping):
            policy = dict(merged.get("promotion_policy") or {})
            policy.update(dict(value))
            merged["promotion_policy"] = policy
        elif key == "evidence_policy" and isinstance(value, Mapping):
            policy = dict(merged.get("evidence_policy") or {})
            policy.update(dict(value))
            merged["evidence_policy"] = policy
        else:
            merged[key] = value
    return merged


def validate_chain_recipes(
    registry: Mapping[str, Any],
    families_by_id: Mapping[str, Mapping[str, Any]],
) -> List[Dict[str, Any]]:
    max_depth = int(registry.get("max_chain_depth") or 3)
    validated: List[Dict[str, Any]] = []
    for recipe in registry.get("chain_recipes") or []:
        if not isinstance(recipe, dict):
            continue
        if not recipe.get("enabled"):
            continue
        recipe_id = str(recipe.get("id") or "")
        steps = list(recipe.get("steps") or [])
        depth = int(recipe.get("max_chain_depth") or max_depth)
        if depth > max_depth:
            raise TransformRegistryError(
                f"chain_recipe {recipe_id}: max_chain_depth {depth} exceeds registry cap {max_depth}"
            )
        if not steps:
            raise TransformRegistryError(f"chain_recipe {recipe_id}: empty steps")
        if len(steps) > depth:
            raise TransformRegistryError(f"chain_recipe {recipe_id}: steps exceed max_chain_depth")
        for step in steps:
            step_id = str(step)
            if step_id not in families_by_id:
                raise TransformRegistryError(f"chain_recipe {recipe_id}: unknown family {step_id}")
            if not families_by_id[step_id].get("enabled"):
                raise TransformRegistryError(f"chain_recipe {recipe_id}: disabled family {step_id}")
        validated.append(dict(recipe))
    return validated


def load_transform_registry(defaults: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    raw = load_transform_registry_raw()
    base_defaults = dict(defaults or merge_crypto_defaults())
    families: List[Dict[str, Any]] = []
    families_by_id: Dict[str, Dict[str, Any]] = {}
    for item in raw.get("families") or []:
        if not isinstance(item, dict):
            continue
        family = dict(item)
        family_id = str(family.get("id") or "")
        if not family_id:
            raise TransformRegistryError("family missing id")
        if family_id in families_by_id:
            raise TransformRegistryError(f"duplicate family id: {family_id}")
        families_by_id[family_id] = family
        families.append(family)
    chain_recipes = validate_chain_recipes(raw, families_by_id)
    enabled = [item for item in families if item.get("enabled")]
    enabled.sort(key=lambda item: int(item.get("priority") or 100))
    return {
        "schema_version": raw.get("schema_version"),
        "max_chain_depth": int(raw.get("max_chain_depth") or 3),
        "families": families,
        "families_by_id": families_by_id,
        "enabled_families": enabled,
        "chain_recipes": chain_recipes,
        "classifier": dict(raw.get("classifier") or {}),
        "defaults": base_defaults,
    }


def resolve_impl_callable(family: Mapping[str, Any], hook: str) -> Callable[..., Any]:
    impl = dict(family.get("impl") or {})
    module_path = str(impl.get("module") or "")
    func_name = str(impl.get(hook) or "")
    if not module_path or not func_name:
        raise TransformRegistryError(f"family {family.get('id')}: missing impl.{hook}")
    if "." in func_name:
        module_path, func_name = func_name.rsplit(".", 1)
    module = importlib.import_module(module_path)
    func = getattr(module, func_name, None)
    if not callable(func):
        raise TransformRegistryError(f"family {family.get('id')}: {module_path}.{func_name} not callable")
    return func


def scoring_profile(defaults: Mapping[str, Any], profile_ref: str) -> Dict[str, Any]:
    profiles = dict(defaults.get("scoring_profiles") or {})
    profile = profiles.get(str(profile_ref or "xor"))
    if not profile:
        raise TransformRegistryError(f"missing scoring profile: {profile_ref}")
    return dict(profile)


def family_cheap_gate(defaults: Mapping[str, Any], family: Mapping[str, Any]) -> Dict[str, Any]:
    gate = dict(family.get("cheap_gate") or {})
    resolved: Dict[str, Any] = {}
    for key, ref in gate.items():
        if key.endswith("_ref") and isinstance(ref, str):
            resolved[key.replace("_ref", "")] = _resolve_ref(defaults, ref)
        else:
            resolved[key] = ref
    return resolved
