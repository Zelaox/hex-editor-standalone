"""Read-only loader for investigation folder evidence."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Mapping


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def load_investigation_evidence(investigation_root: str | Path) -> Dict[str, Any]:
    root = Path(investigation_root).expanduser().resolve()
    if not root.is_dir():
        raise FileNotFoundError(f"investigation root not found: {root}")
    manifest_path = root / "manifest.json"
    if not manifest_path.is_file():
        raise FileNotFoundError(f"investigation manifest missing: {manifest_path}")
    manifest = _read_json(manifest_path)
    state = _read_json(root / "state.json") if (root / "state.json").is_file() else {}
    snapshot_brief_path = root / "artifacts" / "snapshot_brief.json"
    snapshot_brief = _read_json(snapshot_brief_path) if snapshot_brief_path.is_file() else {}
    if not snapshot_brief:
        carry = dict(state.get("session_carry") or {})
        snapshot_brief = dict(carry.get("snapshot_brief") or {})
    if not snapshot_brief:
        raise ValueError("investigation has no snapshot_brief in artifacts or state.session_carry")
    source_path = str(manifest.get("source_path") or "")
    source_sha256 = str(manifest.get("source_sha256") or "")
    source_size = int(manifest.get("source_size") or 0)
    if not source_path or not source_sha256:
        raise ValueError("investigation manifest missing source_path or source_sha256")
    if source_size <= 0 and Path(source_path).is_file():
        source_size = Path(source_path).stat().st_size
    return {
        "investigation_id": str(manifest.get("investigation_id") or root.name),
        "investigation_root": str(root),
        "manifest": manifest,
        "state": state,
        "snapshot_brief": snapshot_brief,
        "source_path": source_path,
        "source_sha256": source_sha256,
        "source_size": source_size,
    }


def snapshot_brief_from_bundle(bundle: Mapping[str, Any]) -> Dict[str, Any]:
    brief = dict(bundle.get("snapshot_brief") or {})
    if not brief:
        raise ValueError("investigation evidence bundle has no snapshot_brief")
    return brief
