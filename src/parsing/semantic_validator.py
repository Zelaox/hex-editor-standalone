"""Semantic validation gates for BinarySnapshot graphs — blocks corrupt promotion."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping


def _node_kinds(snapshot: Mapping[str, Any]) -> set[str]:
    return {str(node.get("kind") or "") for node in snapshot.get("nodes") or []}


def validate_pe_snapshot(snapshot: Mapping[str, Any]) -> Dict[str, Any]:
    signals = dict(snapshot.get("signals") or {})
    nodes = list(snapshot.get("nodes") or [])
    issues: List[str] = []
    kinds = _node_kinds(snapshot)
    if not nodes:
        issues.append("empty_graph")
    if "pe_image" not in kinds and nodes:
        issues.append("missing_pe_image_root")
    if signals.get("entry_resolved") is False:
        issues.append("entry_unresolved")
    if float(signals.get("coverage_ratio") or 0.0) <= 0.0 and nodes:
        issues.append("zero_coverage_with_nodes")
    return {
        "ok": not issues,
        "format_plugin": "pe",
        "issues": issues,
        "promotion_blocked": bool(issues),
        "node_kinds": sorted(kinds),
    }


def validate_binary_snapshot(snapshot: Mapping[str, Any]) -> Dict[str, Any]:
    plugin = str(snapshot.get("format_plugin") or "")
    if plugin == "pe":
        return validate_pe_snapshot(snapshot)
    return {
        "ok": False,
        "format_plugin": plugin,
        "issues": ["unsupported_format_plugin"],
        "promotion_blocked": True,
        "node_kinds": sorted(_node_kinds(snapshot)),
    }
