"""Three-level diff for BinarySnapshot graphs."""

from __future__ import annotations

from typing import Any, Dict, Mapping

from src.services.binary_compatibility import assess_snapshot_compatibility


def _by_id(items: list[Mapping[str, Any]]) -> Dict[str, Mapping[str, Any]]:
    return {str(item.get("id")): item for item in items}


def diff_binary_snapshots(left: Mapping[str, Any], right: Mapping[str, Any]) -> Dict[str, Any]:
    compatibility = assess_snapshot_compatibility(left, right)
    base = {
        "schema_version": 2,
        "operation": "binary_snapshot_diff",
        "left_snapshot_id": left.get("snapshot_id"),
        "right_snapshot_id": right.get("snapshot_id"),
        "left_format_plugin": left.get("format_plugin"),
        "right_format_plugin": right.get("format_plugin"),
        "compatibility": compatibility,
        "waterfall": {
            "comparison_status": compatibility["classification"],
            "automatic_diff_allowed": compatibility["automatic_diff_allowed"],
            "left_snapshot_id": left.get("snapshot_id"),
            "right_snapshot_id": right.get("snapshot_id"),
            "alignment": compatibility.get("alignment") or [],
        },
    }
    if not compatibility["automatic_diff_allowed"]:
        skipped = {"performed": False, "reason": "structural_compatibility_gate"}
        return {**base, "status": "incompatible", "raw": dict(skipped), "parsed": dict(skipped), "runtime": dict(skipped)}
    left_nodes, right_nodes = _by_id(list(left.get("nodes") or [])), _by_id(list(right.get("nodes") or []))
    left_edges, right_edges = _by_id(list(left.get("edges") or [])), _by_id(list(right.get("edges") or []))
    changed_nodes = sorted(key for key in left_nodes.keys() & right_nodes.keys() if left_nodes[key] != right_nodes[key])
    raw_changed = str(left.get("source", {}).get("sha256")) != str(right.get("source", {}).get("sha256"))
    return {
        **base,
        "status": "compared",
        "raw": {
            "performed": True,
            "mode": "direct" if compatibility["classification"] == "exact" else "aligned_segments",
            "alignment": compatibility["alignment"],
            "source_changed": raw_changed,
            "left_sha256": left.get("source", {}).get("sha256"),
            "right_sha256": right.get("source", {}).get("sha256"),
        },
        "parsed": {
            "performed": True,
            "added_node_ids": sorted(right_nodes.keys() - left_nodes.keys()),
            "removed_node_ids": sorted(left_nodes.keys() - right_nodes.keys()),
            "changed_node_ids": changed_nodes,
            "match_strategy": "stable_provenance_id",
        },
        "runtime": {
            "performed": True,
            "added_edge_ids": sorted(right_edges.keys() - left_edges.keys()),
            "removed_edge_ids": sorted(left_edges.keys() - right_edges.keys()),
            "signals_changed": left.get("signals") != right.get("signals"),
            "match_strategy": "stable_provenance_id",
        },
    }
