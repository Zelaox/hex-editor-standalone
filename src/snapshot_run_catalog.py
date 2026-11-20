"""Discover hex investigation runs and work-run records for a source file."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Mapping


def _lab_root() -> Path:
    from src.project import project_root
    return project_root()


def _hex_editor_config() -> Dict[str, Any]:
    path = _lab_root() / "config" / "hex_editor.json"
    if not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def investigation_root() -> Path:
    cfg = _hex_editor_config()
    rel = str(cfg.get("investigation_root") or "data/investigations")
    root = (_lab_root() / rel).resolve()
    return root


def artifact_root() -> Path:
    cfg = _hex_editor_config()
    rel = str(cfg.get("artifact_root") or "data/artifacts/hex_editor")
    root = (_lab_root() / rel).resolve()
    root.mkdir(parents=True, exist_ok=True)
    return root


def _normalize_path(value: str) -> str:
    try:
        return str(Path(value).expanduser().resolve())
    except OSError:
        return str(value or "")


def _completed_milestones(state: Mapping[str, Any]) -> List[str]:
    return [str(item) for item in (state.get("completed_milestones") or [])]


def _hunt_summary(state: Mapping[str, Any]) -> Dict[str, Any]:
    carry = dict(state.get("session_carry") or {})
    hunt = dict(carry.get("decrypt_key_hunt") or state.get("decrypt_key_hunt") or {})
    return {
        "phase": str(hunt.get("phase") or ""),
        "probe_phase_id": str(hunt.get("probe_phase_id") or ""),
        "keys_found": bool(hunt.get("keys_found") or state.get("decrypt_keys_found")),
        "best_key_hex": str(hunt.get("best_key_hex") or carry.get("last_key_hex") or ""),
        "phases_completed": list(hunt.get("phases_completed") or []),
    }


def list_investigation_runs(source_path: str | Path) -> List[Dict[str, Any]]:
    """Return investigation workspaces newest-first for the given source file."""
    resolved = _normalize_path(str(source_path))
    root = investigation_root()
    if not root.is_dir():
        return []

    rows: List[Dict[str, Any]] = []
    for entry in root.iterdir():
        if not entry.is_dir():
            continue
        manifest_path = entry / "manifest.json"
        state_path = entry / "state.json"
        if not manifest_path.is_file():
            continue
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        manifest_source = _normalize_path(str(manifest.get("source_path") or ""))
        if manifest_source != resolved:
            continue
        state: Dict[str, Any] = {}
        if state_path.is_file():
            try:
                state = json.loads(state_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                state = {}
        hunt = _hunt_summary(state)
        rows.append(
            {
                "kind": "investigation_workspace",
                "investigation_id": str(manifest.get("investigation_id") or entry.name),
                "run_id": str(manifest.get("run_id") or state.get("run_id") or ""),
                "goal_text": str(manifest.get("goal_text") or state.get("goal_text") or ""),
                "created_at": str(manifest.get("created_at") or ""),
                "updated_at": str(manifest.get("updated_at") or ""),
                "completed_milestones": _completed_milestones(state),
                "workspace_path": str(entry.resolve()),
                **hunt,
            }
        )

    rows.sort(key=lambda item: item.get("updated_at") or item.get("created_at") or "", reverse=True)
    return rows


def list_work_runs(source_path: str | Path) -> List[Dict[str, Any]]:
    """Return persisted work-run summaries for the given source file."""
    resolved = _normalize_path(str(source_path))
    runs_dir = _lab_root() / "data" / "work_runs"
    if not runs_dir.is_dir():
        return []

    rows: List[Dict[str, Any]] = []
    for path in runs_dir.glob("*.json"):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        target = _normalize_path(str(payload.get("target_path") or payload.get("primary_path") or ""))
        carry_path = _normalize_path(str((payload.get("session_carry") or {}).get("primary_path") or ""))
        if target != resolved and carry_path != resolved:
            continue
        hunt = _hunt_summary(payload)
        rows.append(
            {
                "kind": "work_run",
                "investigation_id": str(payload.get("investigation_workspace_id") or ""),
                "run_id": str(payload.get("run_id") or path.stem),
                "goal_text": str(payload.get("goal_text") or payload.get("goal") or ""),
                "created_at": str(payload.get("created_at") or ""),
                "updated_at": str(payload.get("updated_at") or payload.get("last_updated_at") or ""),
                "completed_milestones": _completed_milestones(payload),
                "workspace_path": str(payload.get("investigation_workspace_path") or ""),
                "work_run_path": str(path.resolve()),
                **hunt,
            }
        )

    rows.sort(key=lambda item: item.get("updated_at") or item.get("created_at") or "", reverse=True)
    return rows


def list_runs_for_source(source_path: str | Path) -> List[Dict[str, Any]]:
    seen: set[str] = set()
    merged: List[Dict[str, Any]] = []
    for row in list_investigation_runs(source_path) + list_work_runs(source_path):
        key = str(row.get("run_id") or row.get("investigation_id") or row.get("workspace_path") or "")
        if key and key in seen:
            continue
        if key:
            seen.add(key)
        merged.append(row)
    merged.sort(key=lambda item: item.get("updated_at") or item.get("created_at") or "", reverse=True)
    return merged
