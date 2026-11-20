"""Immutable artifact workspace pointer — resolve and verify manifest integrity."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from src.services.artifact_store import file_identity
from src.services.hex_checkpoint_policy import artifact_root_rel, load_hex_checkpoint_policy


def _lab_root() -> Path:
    from src.project import project_root
    return project_root()


def _canonical_manifest_bytes(manifest: Mapping[str, Any]) -> bytes:
    return (json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str) + "\n").encode(
        "utf-8"
    )


def _validate_pointer_shape(pointer: Mapping[str, Any]) -> None:
    required = {
        "schema_version",
        "artifact_root_rel",
        "operation_id",
        "manifest_sha256",
        "snapshot_id",
        "snapshot_sha256",
        "format_plugin",
        "source_sha256",
        "workspace_schema_version",
    }
    if int(pointer.get("schema_version") or 0) != 1 or required - set(pointer):
        raise ValueError("invalid artifact pointer shape")


def build_artifact_pointer(
    finalize_result: Mapping[str, Any],
    *,
    manifest: Optional[Mapping[str, Any]] = None,
    lab_root: str | Path | None = None,
) -> Dict[str, Any]:
    """Build pointer from ArtifactStore.finalize() output."""
    root = Path(lab_root).resolve() if lab_root else _lab_root()
    artifact_dir = Path(str(finalize_result.get("artifact_directory") or "")).resolve()
    manifest_path = Path(str(finalize_result.get("manifest") or artifact_dir / "manifest.json"))
    if not manifest_path.is_file():
        raise FileNotFoundError(f"manifest missing: {manifest_path}")
    manifest_payload = dict(manifest or json.loads(manifest_path.read_text(encoding="utf-8")))
    details = dict(manifest_payload.get("details") or {})
    rel_root = artifact_root_rel()
    configured_root = (root / rel_root).resolve()
    try:
        artifact_dir.relative_to(configured_root)
    except ValueError:
        try:
            rel_root = artifact_dir.relative_to(root).as_posix()
        except ValueError:
            rel_root = artifact_root_rel()
    source_sha = str((manifest_payload.get("source_after") or {}).get("sha256") or "")
    operation_id = str(finalize_result.get("operation_id") or manifest_payload.get("operation_id") or "")
    pointer: Dict[str, Any] = {
        "schema_version": 1,
        "artifact_root_rel": rel_root,
        "operation_id": operation_id,
        "manifest_sha256": hashlib.sha256(_canonical_manifest_bytes(manifest_payload)).hexdigest(),
        "snapshot_id": str(details.get("snapshot_id") or ""),
        "snapshot_sha256": str(details.get("snapshot_sha256") or ""),
        "format_plugin": str(details.get("format_plugin") or "unknown"),
        "source_sha256": source_sha,
        "workspace_schema_version": int(details.get("workspace_schema_version") or 1),
        "node_count": int(details.get("node_count") or 0),
        "unknown_region_count": int(details.get("unknown_range_count") or details.get("unknown_region_count") or 0),
        "coverage_complete": bool(details.get("coverage_complete")),
    }
    try:
        artifact_dir.relative_to(configured_root)
    except ValueError:
        pointer["workspace_path"] = str(artifact_dir)
    return pointer


def resolve_workspace_path(pointer: Mapping[str, Any], *, lab_root: str | Path | None = None) -> Path:
    _validate_pointer_shape(pointer)
    direct = str(pointer.get("workspace_path") or "").strip()
    if direct:
        workspace = Path(direct).expanduser().resolve()
        if workspace.is_dir():
            return workspace
    root = Path(lab_root).resolve() if lab_root else _lab_root()
    rel_root = str(pointer.get("artifact_root_rel") or artifact_root_rel())
    workspace = (root / rel_root / str(pointer["operation_id"])).resolve()
    if workspace.is_dir():
        workspace.relative_to(root)
        return workspace
    nested = (root / rel_root).resolve()
    if nested.is_dir() and nested.name == str(pointer["operation_id"]) and (nested / "manifest.json").is_file():
        nested.relative_to(root)
        return nested
    raise FileNotFoundError(f"artifact workspace not found: {workspace}")


def verify_artifact_pointer(pointer: Mapping[str, Any], *, lab_root: str | Path | None = None) -> Dict[str, Any]:
    """Verify manifest + snapshot hash recorded in pointer."""
    _validate_pointer_shape(pointer)
    workspace = resolve_workspace_path(pointer, lab_root=lab_root)
    manifest_path = workspace / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest_sha = hashlib.sha256(_canonical_manifest_bytes(manifest)).hexdigest()
    if manifest_sha != str(pointer.get("manifest_sha256") or ""):
        raise ValueError("artifact pointer manifest_sha256 mismatch")
    for entry in manifest.get("files") or []:
        target = (workspace / str(entry["path"])).resolve()
        target.relative_to(workspace)
        if not target.is_file() or file_identity(target)["sha256"] != entry["sha256"]:
            raise ValueError(f"workspace integrity failure: {entry['path']}")
    snapshot_path = workspace / "graph" / "snapshot.json"
    if snapshot_path.is_file():
        snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
        canonical = (
            json.dumps(snapshot, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str) + "\n"
        ).encode("utf-8")
        snapshot_sha = hashlib.sha256(canonical).hexdigest()
        expected = str(pointer.get("snapshot_sha256") or (manifest.get("details") or {}).get("snapshot_sha256") or "")
        if expected and snapshot_sha != expected:
            raise ValueError("artifact pointer snapshot_sha256 mismatch")
    source_sha = str((manifest.get("source_after") or {}).get("sha256") or "")
    if source_sha and source_sha != str(pointer.get("source_sha256") or ""):
        raise ValueError("artifact pointer source_sha256 mismatch")
    return {
        "ok": True,
        "operation": "artifact_pointer_verify",
        "workspace": str(workspace),
        "operation_id": pointer.get("operation_id"),
        "integrity_verified": True,
        "node_count": pointer.get("node_count"),
        "unknown_region_count": pointer.get("unknown_region_count"),
        "coverage_complete": pointer.get("coverage_complete"),
    }


def pointer_from_session(session_carry: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    pointer = session_carry.get("artifact_pointer")
    return dict(pointer) if isinstance(pointer, dict) and pointer.get("operation_id") else None


def max_brief_bytes() -> int:
    return int(load_hex_checkpoint_policy().get("max_brief_bytes") or 0)
