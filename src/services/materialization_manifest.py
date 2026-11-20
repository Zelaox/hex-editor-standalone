"""Resolve scope materialization manifests from lab artifact_root (runtime — not pytest fixtures)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional


def _lab_root() -> Path:
    from src.project import project_root
    return project_root()


def _load_lab_hex_editor_config() -> Dict[str, Any]:
    path = _lab_root() / "config" / "hex_editor.json"
    if not path.is_file():
        raise ValueError(f"lab hex editor config missing: {path}")
    return json.loads(path.read_text(encoding="utf-8-sig"))


def artifact_root_path() -> Path:
    cfg = _load_lab_hex_editor_config()
    relative = str(cfg.get("artifact_root") or "")
    if not relative:
        raise ValueError("hex_editor.json missing artifact_root")
    return (_lab_root() / relative).resolve()


def _read_manifest(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def discover_materialization_manifests(
    *,
    source_sha256: str | None = None,
    under_subdir: str = "alternate_scope_gemma_live",
) -> List[Dict[str, Any]]:
    root = artifact_root_path() / under_subdir
    if not root.is_dir():
        return []
    manifests: List[Dict[str, Any]] = []
    for path in root.rglob("*.manifest.json"):
        if not path.is_file():
            continue
        try:
            payload = _read_manifest(path)
        except (OSError, json.JSONDecodeError):
            continue
        if str(payload.get("operation") or "") != "materialize_gemma_scope_candidate":
            continue
        if source_sha256 and str(payload.get("source_sha256") or "") != str(source_sha256):
            continue
        manifests.append({**payload, "manifest_path": str(path.resolve())})
    manifests.sort(key=lambda item: Path(str(item.get("manifest_path") or "")).stat().st_mtime, reverse=True)
    return manifests


def resolve_newest_materialization(
    *,
    source_sha256: str | None = None,
    under_subdir: str = "alternate_scope_gemma_live",
) -> Optional[Dict[str, Any]]:
    items = discover_materialization_manifests(source_sha256=source_sha256, under_subdir=under_subdir)
    return items[0] if items else None


def manifest_paths(manifest: Mapping[str, Any]) -> Dict[str, str]:
    source_path = str(manifest.get("source_path") or "")
    candidate_path = str(manifest.get("destination") or "")
    if not source_path or not candidate_path:
        raise ValueError("materialization manifest missing source_path or destination")
    return {"source_path": source_path, "candidate_path": candidate_path}
