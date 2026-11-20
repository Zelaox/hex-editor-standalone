"""Merge static PE graph with runtime execution observations."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping


def merge_static_runtime(static_snapshot: Mapping[str, Any], runtime_snapshot: Mapping[str, Any]) -> Dict[str, Any]:
    static_nodes = {str(n.get("id")): n for n in static_snapshot.get("nodes") or []}
    crosslinks: List[Dict[str, Any]] = []
    merged_nodes: List[Dict[str, Any]] = []
    for node in runtime_snapshot.get("nodes") or []:
        merged_nodes.append({**node, "evidence_class": "runtime_observed"})
        static_id = (node.get("attributes") or {}).get("static_node_id")
        if static_id and static_id in static_nodes:
            crosslinks.append(
                {
                    "static_node_id": static_id,
                    "runtime_node_id": node.get("id"),
                    "static_kind": static_nodes[static_id].get("kind"),
                    "runtime_kind": node.get("kind"),
                    "merge_strategy": "explicit_static_node_id",
                    "confidence": 0.9,
                }
            )
    for edge in runtime_snapshot.get("edges") or []:
        crosslinks.append(
            {
                "static_node_id": edge.get("target_id"),
                "runtime_node_id": edge.get("source_id"),
                "merge_strategy": "runtime_edge",
                "confidence": edge.get("confidence"),
            }
        )
    return {
        "schema_version": 1,
        "static_snapshot_id": static_snapshot.get("snapshot_id"),
        "runtime_snapshot_id": runtime_snapshot.get("runtime_snapshot_id"),
        "crosslinks": crosslinks,
        "merged_runtime_nodes": merged_nodes,
        "static_node_count": len(static_nodes),
        "runtime_node_count": len(runtime_snapshot.get("nodes") or []),
    }
