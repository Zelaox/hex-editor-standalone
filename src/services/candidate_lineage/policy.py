"""Candidate lineage policy — artifact roots and rail registry."""

from __future__ import annotations

import importlib
import json
from pathlib import Path
from typing import Any, Callable, Dict, Mapping


def _hex_editor_root() -> Path:
    return Path(__file__).resolve().parents[3]


def load_candidate_lineage_policy(*, policy_path: str | Path | None = None) -> Dict[str, Any]:
    path = Path(policy_path).resolve() if policy_path else _hex_editor_root() / "config" / "candidate_lineage_policy.json"
    if not path.is_file():
        raise ValueError(f"candidate lineage policy missing: {path}")
    policy = json.loads(path.read_text(encoding="utf-8-sig"))
    if int(policy.get("schema_version") or 0) != 1:
        raise ValueError("unsupported candidate_lineage_policy schema_version")
    return policy


def artifact_root(*, policy: Mapping[str, Any] | None = None, override: str | Path | None = None) -> Path:
    if override is not None:
        return Path(override).resolve()
    bundle = dict(policy or load_candidate_lineage_policy())
    relative = str(bundle.get("artifact_root") or "")
    if not relative:
        raise ValueError("candidate_lineage_policy missing artifact_root")
    candidate = Path(relative)
    if candidate.is_absolute():
        return candidate.resolve()
    return (_hex_editor_root() / relative).resolve()


def rail_artifact_dir(rail: Mapping[str, Any], *, policy: Mapping[str, Any] | None = None, artifact_root_override: str | Path | None = None) -> Path:
    subdir = str(rail.get("artifact_subdir") or "")
    if not subdir:
        raise ValueError("rail missing artifact_subdir")
    return artifact_root(policy=policy, override=artifact_root_override) / subdir


def import_rail_callable(rail: Mapping[str, Any], key: str) -> Callable[..., Any]:
    module_name = str(rail.get("verify_module") if key == "verify_callable" else rail.get("verify_module") or "")
    if key == "inspect_callable":
        module_name = str(rail.get("verify_module") or "")
    callable_name = str(rail.get(key) or "")
    if not module_name or not callable_name:
        raise ValueError(f"rail {rail.get('rail_id')} missing {key}")
    module = importlib.import_module(module_name)
    target = getattr(module, callable_name, None)
    if not callable(target):
        raise ValueError(f"{module_name}.{callable_name} is not callable")
    return target


def selection_limits(*, policy: Mapping[str, Any] | None = None) -> Dict[str, int]:
    bundle = dict(policy or load_candidate_lineage_policy())
    selection = dict(bundle.get("selection") or {})
    scan_limit = int(selection.get("scan_limit") or 0)
    if scan_limit <= 0:
        raise ValueError("candidate_lineage_policy missing selection.scan_limit")
    return {"scan_limit": scan_limit}
