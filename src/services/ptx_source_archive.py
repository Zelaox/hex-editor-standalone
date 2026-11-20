"""Source archive registry — config-driven paths (NO HARDCODE)."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Mapping

from src.services.ptx_pipeline_policy import hex_editor_root, load_ptx_pipeline_policy, resolve_policy_path


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


@lru_cache(maxsize=1)
def load_source_archive_policy(path: str | None = None) -> Dict[str, Any]:
    pipeline = load_ptx_pipeline_policy()
    rel = str(pipeline["source_archive_policy_file"])
    target = Path(path).expanduser().resolve() if path else resolve_policy_path(rel)
    policy = _read_json(target)
    required = {"schema_version", "archive_root", "registry_path", "manifest_filename", "reason_codes"}
    missing = required - set(policy)
    if missing:
        raise ValueError(f"source_archive_policy missing keys: {sorted(missing)}")
    if int(policy["schema_version"]) != 1:
        raise ValueError("source_archive_policy schema_version unsupported")
    return policy


def load_archive_registry(*, policy: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    archive_policy = dict(policy or load_source_archive_policy())
    registry_path = hex_editor_root() / str(archive_policy["registry_path"])
    if not registry_path.is_file():
        raise FileNotFoundError(f"archive registry missing: {registry_path}")
    registry = _read_json(registry_path)
    if int(registry.get("schema_version") or 0) != 1:
        raise ValueError("archive registry schema_version unsupported")
    return registry


def resolve_archive_entry(archive_id: str, *, policy: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    archive_policy = dict(policy or load_source_archive_policy())
    registry = load_archive_registry(policy=archive_policy)
    archives = dict(registry.get("archives") or {})
    entry = archives.get(archive_id)
    if entry is None:
        raise KeyError(f"archive_id not in registry: {archive_id}")
    manifest_path = Path(str(entry.get("manifest_path") or "")).expanduser()
    if not manifest_path.is_file():
        archive_root = hex_editor_root() / str(archive_policy["archive_root"])
        manifest_path = archive_root / archive_id / str(archive_policy["manifest_filename"])
    if not manifest_path.is_file():
        raise FileNotFoundError(f"archive manifest missing for {archive_id}: {manifest_path}")
    manifest = _read_json(manifest_path)
    archived_path = Path(str(manifest.get("archived_path") or entry.get("archived_path") or "")).expanduser()
    if not archived_path.is_file():
        raise FileNotFoundError(f"archived source missing for {archive_id}: {archived_path}")
    return {
        "archive_id": archive_id,
        "manifest": manifest,
        "archived_path": archived_path.resolve(),
        "manifest_path": manifest_path.resolve(),
    }
