"""Deterministic export/reload of BinarySnapshot workspaces."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from src.services.artifact_store import ArtifactStore, file_identity


def _canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str) + "\n").encode("utf-8")


def _write_json(store: ArtifactStore, relative_name: str, value: Any) -> None:
    store.write_json(relative_name, value)


def export_binary_workspace(
    source_path: str | Path,
    snapshot: Mapping[str, Any],
    artifact_root: str | Path,
    *,
    include_representation_sweep: Optional[bool] = None,
) -> Dict[str, Any]:
    source = Path(source_path).expanduser().resolve()
    if str(snapshot.get("source", {}).get("sha256") or "") != file_identity(source)["sha256"]:
        raise ValueError("snapshot source hash does not match source file")
    plugin = str(snapshot.get("format_plugin") or "unknown")
    operation = "binary-unpack"
    store = ArtifactStore(artifact_root, operation, source)
    try:
        source_bytes = source.read_bytes()
        nodes = list(snapshot.get("nodes") or [])
        edges = list(snapshot.get("edges") or [])
        coverage = list(snapshot.get("coverage") or [])
        diagnostics = list(snapshot.get("diagnostics") or [])
        _write_json(store, "graph/snapshot.json", snapshot)
        _write_json(store, "graph/nodes.json", nodes)
        _write_json(store, "graph/edges.json", edges)
        _write_json(store, "maps/file_offsets.json", coverage)
        _write_json(store, "diagnostics/parser.json", diagnostics)
        _write_json(store, "coverage.json", snapshot.get("coverage_summary") or {})
        _write_json(store, "anchors.json", snapshot.get("anchors") or [])
        _write_json(store, "records/families.json", snapshot.get("record_families") or [])
        _write_json(store, "unknown/regions.json", snapshot.get("unknown_regions") or [])
        _write_json(store, "experiments/index.json", snapshot.get("experiments") or [])
        if plugin == "pe":
            rva_map = [
                {"offset": r.get("offset"), "length": r.get("length"), "rva": r.get("rva"), "class": r.get("class")}
                for r in coverage
            ]
            _write_json(store, "maps/rva_map.json", rva_map)
        unknown = [item for item in coverage if item.get("class") == "unknown" or str(item.get("class") or "").startswith("gap")]
        _write_json(store, "unknown/index.json", unknown)
        for index, item in enumerate(unknown):
            offset, length = int(item["offset"]), int(item["length"])
            if offset < 0 or length < 0 or offset + length > len(source_bytes):
                raise ValueError("snapshot coverage exceeds source bounds")
            region_id = next((str(region.get("region_id")) for region in snapshot.get("unknown_regions") or [] if int((region.get("span") or {}).get("offset", -1)) == offset and int((region.get("span") or {}).get("length", -1)) == length), f"block-{index:06d}")
            store.write_bytes(f"unknown/{region_id}.bin", source_bytes[offset : offset + length])
        for index, node in enumerate(nodes):
            ranges = list(node.get("source_ranges") or [])
            if not ranges:
                continue
            offset, length = int(ranges[0]["offset"]), int(ranges[0]["length"])
            if offset < 0 or length <= 0 or offset + length > len(source_bytes):
                continue
            store.write_bytes(f"records/record_{index:06d}.bin", source_bytes[offset : offset + length])
        from src.services.representation_workspace import sweep_unknown_regions_in_workspace

        sweep_result = sweep_unknown_regions_in_workspace(
            store.staging,
            source_bytes=source_bytes,
            include_representation_sweep=include_representation_sweep,
        )
        finalized = store.finalize(
            {
                "workspace_schema_version": 2,
                "format_plugin": plugin,
                "snapshot_id": snapshot.get("snapshot_id"),
                "snapshot_sha256": hashlib.sha256(_canonical(snapshot)).hexdigest(),
                "node_count": len(nodes),
                "edge_count": len(edges),
                "unknown_range_count": len(unknown),
                "coverage_complete": bool((snapshot.get("coverage_summary") or {}).get("coverage_complete")),
            }
        )
        from src.services.artifact_pointer import build_artifact_pointer

        finalized["representation_sweep"] = sweep_result
        finalized["artifact_pointer"] = build_artifact_pointer(finalized)
        return finalized
    except Exception:
        store.abort()
        raise


def load_binary_workspace(workspace: str | Path) -> Dict[str, Any]:
    root = Path(workspace).expanduser().resolve()
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for entry in manifest.get("files") or []:
        target = (root / str(entry["path"])).resolve()
        target.relative_to(root)
        if not target.is_file() or file_identity(target)["sha256"] != entry["sha256"]:
            raise ValueError(f"workspace integrity failure: {entry['path']}")
    snapshot_path = root / "graph" / "snapshot.json"
    if not snapshot_path.is_file():
        snapshot_path = root / "session" / "snapshot.json"
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    expected = str((manifest.get("details") or {}).get("snapshot_sha256") or "")
    if expected and hashlib.sha256(_canonical(snapshot)).hexdigest() != expected:
        raise ValueError("snapshot canonical hash mismatch")
    return {"ok": True, "operation": "binary_workspace_load", "workspace": str(root), "snapshot": snapshot, "integrity_verified": True}
