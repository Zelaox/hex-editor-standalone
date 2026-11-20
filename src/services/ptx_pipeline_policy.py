"""Load PTX pipeline policy and related config paths (NO HARDCODE)."""

from __future__ import annotations

import hashlib
import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Mapping


def hex_editor_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _policy_digest(policy: Mapping[str, Any]) -> str:
    payload = json.dumps(policy, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


@lru_cache(maxsize=1)
def load_ptx_pipeline_policy(path: str | None = None) -> Dict[str, Any]:
    root = hex_editor_root()
    target = Path(path).expanduser().resolve() if path else root / "config" / "ptx_pipeline_policy.json"
    if not target.is_file():
        raise FileNotFoundError(f"missing ptx pipeline policy: {target}")
    policy = _read_json(target)
    required = {
        "schema_version",
        "policy_id",
        "revision",
        "artifact_root",
        "parser_policy_file",
        "source_archive_policy_file",
        "converter_policy_file",
        "materialization",
        "rails",
    }
    missing = required - set(policy)
    if missing:
        raise ValueError(f"ptx_pipeline_policy missing keys: {sorted(missing)}")
    if int(policy["schema_version"]) != 1:
        raise ValueError("ptx_pipeline_policy schema_version unsupported")
    policy = dict(policy)
    policy["_resolved_path"] = str(target)
    policy["_digest"] = _policy_digest(policy)
    return policy


def resolve_policy_path(relative: str, *, policy: Mapping[str, Any] | None = None) -> Path:
    root = hex_editor_root()
    candidate = Path(relative)
    if candidate.is_file():
        return candidate.resolve()
    joined = root / relative
    if not joined.is_file():
        raise FileNotFoundError(f"policy-relative file not found: {relative}")
    return joined.resolve()


def pipeline_artifact_root(*, policy: Mapping[str, Any] | None = None) -> Path:
    bundle = dict(policy or load_ptx_pipeline_policy())
    relative = str(bundle["artifact_root"])
    root = hex_editor_root() / relative
    root.mkdir(parents=True, exist_ok=True)
    return root.resolve()


@lru_cache(maxsize=1)
def load_ptx_converter_policy(path: str | None = None) -> Dict[str, Any]:
    root = hex_editor_root()
    pipeline = load_ptx_pipeline_policy()
    rel = str(pipeline["converter_policy_file"])
    target = Path(path).expanduser().resolve() if path else root / rel
    if not target.is_file():
        raise FileNotFoundError(f"missing ptx converter policy: {target}")
    policy = _read_json(target)
    if int(policy.get("schema_version") or 0) != 1:
        raise ValueError("ptx_converter_policy schema_version unsupported")
    return policy


def rail_artifact_root(rail_policy_id: str, *, pipeline: Mapping[str, Any] | None = None) -> Path:
    bundle = dict(pipeline or load_ptx_pipeline_policy())
    rails = dict(bundle.get("rails") or {})
    if rail_policy_id not in rails:
        raise ValueError(f"unknown materialization rail: {rail_policy_id}")
    rail = dict(rails[rail_policy_id])
    policy_path = resolve_policy_path(str(rail["policy_file"]), policy=bundle)
    rail_policy = _read_json(policy_path)
    if "artifact_root" not in rail_policy:
        raise ValueError(f"rail policy missing artifact_root: {policy_path}")
    return (hex_editor_root() / str(rail_policy["artifact_root"])).resolve()
