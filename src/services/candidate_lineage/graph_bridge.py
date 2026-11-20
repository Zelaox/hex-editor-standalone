"""Bridge candidate selection to Binary Semantic Graph queries."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

from src.services.unresolved_inference import query_binary_semantic_graph


def _unresolved_node(packet: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    for node in packet.get("nodes") or []:
        if str(node.get("rail") or "") == "unresolved_inference" and node.get("verified"):
            return dict(node)
    return None


def graph_path_from_lineage(packet: Mapping[str, Any]) -> Optional[Path]:
    node = _unresolved_node(packet)
    if node is None:
        return None
    graph_path = str((node.get("artifacts") or {}).get("semantic_graph") or "")
    if not graph_path or not Path(graph_path).is_file():
        return None
    return Path(graph_path).resolve()


def _first_unresolved_offset(packet: Mapping[str, Any]) -> Optional[int]:
    node = _unresolved_node(packet)
    if node is None:
        return None
    inspected = dict(node.get("inspected") or {})
    for segment in (inspected.get("coverage") or {}).get("segments") or []:
        if str(segment.get("class") or "") == "unresolved":
            return int(segment.get("offset") or 0)
    graph_path = graph_path_from_lineage(packet)
    if graph_path is None:
        return None
    graph = json.loads(graph_path.read_text(encoding="utf-8-sig"))
    indexed = list((graph.get("indexes") or {}).get("by_offset") or [])
    if not indexed:
        return None
    return int(indexed[0].get("offset") or 0)


def candidate_graph_impact(
    *,
    lineage_packet: Mapping[str, Any],
    candidate_id: str = "",
    maximum_depth: int = 1,
    maximum_results: int = 4096,
) -> Dict[str, Any]:
    graph_path = graph_path_from_lineage(lineage_packet)
    if graph_path is None:
        return {"operation": "candidate_graph_impact", "ok": False, "error": "verified semantic graph unavailable"}
    offset = _first_unresolved_offset(lineage_packet)
    if offset is None:
        return {"operation": "candidate_graph_impact", "ok": False, "error": "no unresolved offset anchor in lineage packet"}
    nodes_result = query_binary_semantic_graph(
        graph_path,
        "nodes_at_offset",
        offset=offset,
        maximum_results=max(1, int(maximum_results)),
    )
    node_ids = [str(item.get("node_id") or "") for item in nodes_result.get("results") or [] if item.get("node_id")]
    if not node_ids:
        return {
            "operation": "candidate_graph_impact",
            "ok": True,
            "graph_id": nodes_result.get("graph_id"),
            "candidate_id": candidate_id,
            "anchor_offset": offset,
            "nodes_at_offset": [],
            "impact": [],
        }
    impact: List[Dict[str, Any]] = []
    for node_id in node_ids[: min(8, len(node_ids))]:
        neighbors = query_binary_semantic_graph(
            graph_path,
            "neighbors",
            node_id=node_id,
            maximum_depth=max(1, int(maximum_depth)),
            maximum_results=max(1, int(maximum_results)),
        )
        impact.append({"node_id": node_id, "neighbors": neighbors})
    return {
        "operation": "candidate_graph_impact",
        "ok": True,
        "graph_id": nodes_result.get("graph_id"),
        "candidate_id": candidate_id,
        "anchor_offset": offset,
        "nodes_at_offset": nodes_result.get("results") or [],
        "impact": impact,
    }


def _node_by_rail(packet: Mapping[str, Any], rail_id: str) -> Optional[Dict[str, Any]]:
    for node in packet.get("nodes") or []:
        if str(node.get("rail") or "") == rail_id:
            return dict(node)
    return None


def full_decode_from_lineage(packet: Mapping[str, Any]) -> Dict[str, Any]:
    node = _node_by_rail(packet, "full_decode")
    if node is None:
        return {}
    inspected = dict(node.get("inspected") or {})
    if inspected:
        return inspected
    return {
        "operation": "full_decode_run_inspect",
        "run_id": node.get("run_id"),
        "verified": node.get("verified"),
        "status": node.get("status"),
    }


def unresolved_inference_from_lineage(packet: Mapping[str, Any]) -> Dict[str, Any]:
    node = _unresolved_node(packet)
    if node is None:
        return {}
    inspected = dict(node.get("inspected") or {})
    artifacts = dict(node.get("artifacts") or {})
    if not inspected.get("artifacts"):
        inspected["artifacts"] = artifacts
    for key in ("verified", "status", "run_id"):
        if key not in inspected and node.get(key) is not None:
            inspected[key] = node.get(key)
    if inspected.get("graph_nodes"):
        return inspected
    graph_path = graph_path_from_lineage(packet)
    if graph_path is None:
        return inspected
    graph = json.loads(graph_path.read_text(encoding="utf-8-sig"))
    inspected["graph_nodes"] = graph.get("nodes") or []
    inspected["graph_edges"] = graph.get("edges") or []
    inspected["graph_summary"] = {
        "graph_id": graph.get("graph_id"),
        "node_count": len(graph.get("nodes") or []),
        "edge_count": len(graph.get("edges") or []),
        "validation": graph.get("validation") or {},
    }
    return inspected
