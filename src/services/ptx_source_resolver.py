"""Resolve PTX input specs to SourceBinding records."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Mapping, MutableMapping, Optional

from src.services.artifact_store import file_identity
from src.services.path_utils import resolve_existing_file
from src.services.ptx_parse_policy import load_ptx_parse_policy
from src.services.ptx_pipeline_policy import (
    hex_editor_root,
    load_ptx_pipeline_policy,
    rail_artifact_root,
)
from src.services.ptx_schema_validate import validate_against_schema
from src.services.ptx_source_archive import resolve_archive_entry


def _canonical_digest(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _nested_get(document: Mapping[str, Any], dotted: str) -> Any:
    current: Any = document
    for part in dotted.split("."):
        if not isinstance(current, Mapping):
            return None
        if part not in current:
            return None
        current = current[part]
    return current


def _first_path(document: Mapping[str, Any], keys: list[str]) -> Optional[str]:
    for key in keys:
        value = _nested_get(document, key) if "." in key else document.get(key)
        if value:
            return str(value)
    return None


def _load_materialization_manifest(run_dir: Path, manifest_name: str) -> Dict[str, Any]:
    manifest_path = run_dir / manifest_name
    if not manifest_path.is_file():
        raise FileNotFoundError(f"materialization manifest not found: {manifest_path}")
    return json.loads(manifest_path.read_text(encoding="utf-8-sig"))


def resolve_ptx_source(spec: Mapping[str, Any]) -> Dict[str, Any]:
    """Resolve a spec dict to a validated SourceBinding."""
    if not isinstance(spec, Mapping):
        raise TypeError("spec must be a mapping")
    kind = str(spec.get("kind") or "").strip().lower()
    if not kind:
        raise ValueError("spec.kind is required")

    pipeline = load_ptx_pipeline_policy()
    parse_policy = load_ptx_parse_policy(
        str(hex_editor_root() / str(pipeline["parser_policy_file"]))
        if pipeline.get("parser_policy_file")
        else None
    )
    parser_revision = int(parse_policy.get("revision") or 0)
    pipeline_revision = int(pipeline.get("revision") or 0)

    bound_path: Path
    binding_kind = kind
    extra: Dict[str, Any] = {"spec_digest": _canonical_digest(dict(spec))}

    if kind == "filesystem":
        bound_path = resolve_existing_file(str(spec.get("path") or ""))

    elif kind == "archive":
        archive_id = str(spec.get("archive_id") or "").strip()
        if not archive_id:
            raise ValueError("archive spec requires archive_id")
        resolved = resolve_archive_entry(archive_id)
        bound_path = Path(resolved["archived_path"])
        extra["archive_id"] = archive_id

    elif kind == "materialization":
        rail = str(spec.get("rail") or "").strip()
        run_id = str(spec.get("run_id") or "").strip()
        if not rail or not run_id:
            raise ValueError("materialization spec requires rail and run_id")
        mat_cfg = dict(pipeline.get("materialization") or {})
        manifest_name = str(mat_cfg.get("manifest_filename") or "manifest.json")
        run_dir = rail_artifact_root(rail) / run_id
        if not run_dir.is_dir():
            raise FileNotFoundError(f"materialization run directory not found: {run_dir}")
        manifest = _load_materialization_manifest(run_dir, manifest_name)
        source_keys = list(mat_cfg.get("source_path_keys") or [])
        candidate_keys = list(mat_cfg.get("candidate_path_keys") or [])
        promotion_keys = list(mat_cfg.get("promotion_flag_keys") or [])
        use_candidate = bool(spec.get("use_candidate"))
        path_str = _first_path(manifest, candidate_keys if use_candidate else source_keys)
        if not path_str and use_candidate:
            path_str = _first_path(manifest, source_keys)
        if not path_str:
            raise ValueError("materialization manifest missing source/candidate path")
        bound_path = resolve_existing_file(path_str)
        require_promotion = bool(spec.get("require_promotion", mat_cfg.get("require_promotion_by_default", True)))
        if require_promotion:
            promoted = False
            for key in promotion_keys:
                flag = _nested_get(manifest, key) if "." in key else manifest.get(key)
                if flag is True:
                    promoted = True
                    break
            if not promoted:
                raise ValueError("materialization not promotion-eligible; set require_promotion=false to override")
        candidate_path = _first_path(manifest, candidate_keys)
        extra.update(
            {
                "materialization_rail": rail,
                "materialization_run_id": run_id,
                "candidate_path": candidate_path,
            }
        )

    else:
        raise ValueError(f"unsupported spec.kind: {kind}")

    identity = file_identity(bound_path)
    binding: Dict[str, Any] = {
        "schema_version": 1,
        "binding_kind": binding_kind,
        "bound_path": str(bound_path),
        "source_sha256": identity["sha256"],
        "source_size": identity["size"],
        "parser_policy_revision": parser_revision,
        "pipeline_policy_revision": pipeline_revision,
        **extra,
    }
    validate_against_schema("ptx_source_binding.schema.json", binding)
    return binding
