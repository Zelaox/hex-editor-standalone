"""Load and validate representation / decoder config SSOT."""

from __future__ import annotations

import importlib
import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional


class RepresentationRegistryError(ValueError):
    """Representation registry load or validation failure."""


def hex_editor_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _config_path(name: str) -> Path:
    return hex_editor_root() / "config" / name


def _load_json(path: Path, *, label: str) -> Dict[str, Any]:
    if not path.is_file():
        raise RepresentationRegistryError(f"missing_{label}: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise RepresentationRegistryError(f"invalid_{label}: root must be object")
    return payload


def _resolve_ref(policy: Mapping[str, Any], ref: str) -> Any:
    parts = str(ref or "").split(".")
    current: Any = policy
    for part in parts:
        if not part:
            continue
        if not isinstance(current, Mapping):
            raise RepresentationRegistryError(f"config ref unresolved: {ref}")
        current = current.get(part)
    if current is None:
        raise RepresentationRegistryError(f"missing config ref: {ref}")
    return current


def _family_parameters(policy: Mapping[str, Any], family: Mapping[str, Any]) -> Dict[str, Any]:
    if isinstance(family.get("parameters"), dict):
        return dict(family["parameters"])
    ref = family.get("parameters_ref")
    if ref is None:
        return {}
    if not isinstance(ref, str):
        raise RepresentationRegistryError(f"family {family.get('id')}: invalid parameters_ref")
    resolved = _resolve_ref(policy, ref)
    if not isinstance(resolved, dict):
        raise RepresentationRegistryError(f"family {family.get('id')}: parameters_ref must resolve to object")
    return dict(resolved)


@lru_cache(maxsize=1)
def load_representation_policy(path: str | None = None) -> Dict[str, Any]:
    target = Path(path).expanduser().resolve() if path else _config_path("representation_policy.json")
    policy = _load_json(target, label="representation_policy")
    required = {
        "schema_version",
        "policy_id",
        "revision",
        "formats",
        "budgets",
        "integer_sweep",
        "float_sweep",
        "text_decoders",
        "interpreter",
        "plausibility",
        "stride_sweep",
    }
    if int(policy.get("schema_version") or 0) != 1 or required - set(policy):
        raise RepresentationRegistryError("invalid representation policy")
    return policy


@lru_cache(maxsize=1)
def load_representation_registry_raw() -> Dict[str, Any]:
    return _load_json(_config_path("representation_registry.json"), label="representation_registry")


@lru_cache(maxsize=1)
def load_decoder_registry_raw() -> Dict[str, Any]:
    return _load_json(_config_path("decoder_registry.json"), label="decoder_registry")


@lru_cache(maxsize=1)
def load_value_interpreter_policy_raw() -> Dict[str, Any]:
    return _load_json(_config_path("value_interpreter_policy.json"), label="value_interpreter_policy")


def reload_representation_config() -> Dict[str, Any]:
    load_representation_policy.cache_clear()
    load_representation_registry_raw.cache_clear()
    load_decoder_registry_raw.cache_clear()
    load_value_interpreter_policy_raw.cache_clear()
    return load_representation_bundle()


def load_decoder_registry(policy: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    raw = load_decoder_registry_raw()
    base_policy = dict(policy or load_representation_policy())
    families: List[Dict[str, Any]] = []
    families_by_id: Dict[str, Dict[str, Any]] = {}
    for item in raw.get("families") or []:
        if not isinstance(item, dict):
            continue
        family = dict(item)
        family_id = str(family.get("id") or "")
        if not family_id:
            raise RepresentationRegistryError("decoder family missing id")
        if family_id in families_by_id:
            raise RepresentationRegistryError(f"duplicate decoder family id: {family_id}")
        family["resolved_parameters"] = _family_parameters(base_policy, family)
        families_by_id[family_id] = family
        families.append(family)
    enabled = [item for item in families if item.get("enabled")]
    return {
        "schema_version": raw.get("schema_version"),
        "policy_id": raw.get("policy_id"),
        "families": families,
        "families_by_id": families_by_id,
        "enabled_families": enabled,
        "policy": base_policy,
    }


def load_value_interpreter_policy(policy: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    raw = load_value_interpreter_policy_raw()
    base_policy = dict(policy or load_representation_policy())
    patterns: List[Dict[str, Any]] = []
    for item in raw.get("patterns") or []:
        if not isinstance(item, dict):
            continue
        pattern = dict(item)
        pattern_id = str(pattern.get("id") or "")
        if not pattern_id:
            raise RepresentationRegistryError("interpreter pattern missing id")
        enabled_ids = set(base_policy.get("interpreter", {}).get("enabled_pattern_ids") or [])
        pattern["enabled"] = bool(pattern.get("enabled")) and pattern_id in enabled_ids
        patterns.append(pattern)
    return {"schema_version": raw.get("schema_version"), "patterns": patterns, "policy": base_policy}


def load_representation_bundle(policy_path: str | None = None) -> Dict[str, Any]:
    policy = load_representation_policy(policy_path)
    return {
        "policy": policy,
        "registry": load_representation_registry_raw(),
        "decoders": load_decoder_registry(policy),
        "interpreter": load_value_interpreter_policy(policy),
    }


def resolve_decoder_callable(family: Mapping[str, Any]) -> Callable[..., Any]:
    impl = dict(family.get("impl") or {})
    module_path = str(impl.get("module") or "")
    func_name = str(impl.get("decode") or "")
    if not module_path or not func_name:
        raise RepresentationRegistryError(f"family {family.get('id')}: missing impl.decode")
    module = importlib.import_module(module_path)
    func = getattr(module, func_name, None)
    if not callable(func):
        raise RepresentationRegistryError(f"family {family.get('id')}: {module_path}.{func_name} not callable")
    return func


def resolve_interpreter_callable(pattern: Mapping[str, Any]) -> Callable[..., Any]:
    impl = dict(pattern.get("impl") or {})
    module_path = str(impl.get("module") or "")
    func_name = str(impl.get("evaluate") or "")
    if not module_path or not func_name:
        raise RepresentationRegistryError(f"pattern {pattern.get('id')}: missing impl.evaluate")
    module = importlib.import_module(module_path)
    func = getattr(module, func_name, None)
    if not callable(func):
        raise RepresentationRegistryError(f"pattern {pattern.get('id')}: {module_path}.{func_name} not callable")
    return func


def resolve_policy_ref(policy: Mapping[str, Any], ref: str) -> Any:
    return _resolve_ref(policy, ref)
