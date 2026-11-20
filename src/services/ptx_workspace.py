"""Deterministic export/reload of runtime session snapshots."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Mapping

from src.services.artifact_store import ArtifactStore, file_identity


def _canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str) + "\n").encode("utf-8")


def _write_json(store: ArtifactStore, relative_name: str, value: Any) -> None:
    store.write_json(relative_name, value)


def export_runtime_workspace(source_path: str | Path, snapshot: Mapping[str, Any], artifact_root: str | Path) -> Dict[str, Any]:
    source = Path(source_path).expanduser().resolve()
    if str(snapshot.get("source", {}).get("sha256") or "") != file_identity(source)["sha256"]:
        raise ValueError("snapshot source hash does not match source file")
    store = ArtifactStore(artifact_root, "ptx-unpack", source)
    try:
        source_bytes = source.read_bytes()
        nodes = list(snapshot.get("nodes") or [])
        edges = list(snapshot.get("edges") or [])
        coverage = list(snapshot.get("coverage") or [])
        diagnostics = list(snapshot.get("diagnostics") or [])
        _write_json(store, "session/snapshot.json", snapshot)
        _write_json(store, "session/nodes.json", nodes)
        _write_json(store, "session/edges.json", edges)
        _write_json(store, "maps/offsets.json", coverage)
        _write_json(store, "session/diagnostics.json", diagnostics)
        unknown = [item for item in coverage if item.get("class") == "unknown"]
        _write_json(store, "unknown/index.json", unknown)
        for index, item in enumerate(unknown):
            offset, length = int(item["offset"]), int(item["length"])
            if offset < 0 or length < 0 or offset + length > len(source_bytes):
                raise ValueError("snapshot coverage exceeds source bounds")
            store.write_bytes(f"unknown/block_{index:06d}.bin", source_bytes[offset : offset + length])
        for index, node in enumerate(nodes):
            ranges = list(node.get("source_ranges") or [])
            if not ranges:
                continue
            offset, length = int(ranges[0]["offset"]), int(ranges[0]["length"])
            if offset < 0 or length < 0 or offset + length > len(source_bytes):
                raise ValueError("node provenance exceeds source bounds")
            store.write_bytes(f"records/record_{index:06d}.bin", source_bytes[offset : offset + length])
        return store.finalize({"workspace_schema_version": 1, "snapshot_id": snapshot.get("snapshot_id"), "snapshot_sha256": hashlib.sha256(_canonical(snapshot)).hexdigest(), "node_count": len(nodes), "edge_count": len(edges), "unknown_range_count": len(unknown)})
    except Exception:
        store.abort()
        raise


def load_runtime_workspace(workspace: str | Path) -> Dict[str, Any]:
    root = Path(workspace).expanduser().resolve()
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for entry in manifest.get("files") or []:
        target = (root / str(entry["path"])).resolve()
        target.relative_to(root)
        if not target.is_file() or file_identity(target)["sha256"] != entry["sha256"]:
            raise ValueError(f"workspace integrity failure: {entry['path']}")
    snapshot_path = root / "session" / "snapshot.json"
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    expected = str((manifest.get("details") or {}).get("snapshot_sha256") or "")
    if expected and hashlib.sha256(_canonical(snapshot)).hexdigest() != expected:
        raise ValueError("snapshot canonical hash mismatch")
    return {"ok": True, "operation": "ptx_workspace_load", "workspace": str(root), "snapshot": snapshot, "integrity_verified": True}
