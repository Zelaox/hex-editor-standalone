"""Minimal Binary Inspector view model — static + runtime PE views."""

from __future__ import annotations

from typing import Any, Dict, Mapping


def inspector_view_model(snapshot: Mapping[str, Any], *, runtime_snapshot: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    plugin = str(snapshot.get("format_plugin") or "unknown")
    static_tabs = ["Overview", "Coverage", "Unknown", "Diagnostics", "Relationships", "Record families", "Experiments"]
    if plugin == "ptx":
        static_tabs.extend(["Tracks", "Clips", "Timeline", "Resources"])
    elif plugin == "pe":
        static_tabs.extend(["Headers", "Sections", "Imports", "Exports", "Entry/disasm", "Overlay"])
    runtime_tabs = []
    if runtime_snapshot:
        runtime_tabs = ["Loaded modules", "Executed regions", "File I/O", "Registry", "Threads", "Runtime events"]
    return {
        "format_plugin": plugin,
        "snapshot_id": snapshot.get("snapshot_id"),
        "static_tabs": static_tabs,
        "runtime_tabs": runtime_tabs,
        "node_count": len(snapshot.get("nodes") or []),
        "has_runtime": bool(runtime_snapshot),
        "coverage_summary": dict(snapshot.get("coverage_summary") or {}),
        "unknown_region_count": len(snapshot.get("unknown_regions") or []),
        "anchor_count": len(snapshot.get("anchors") or []),
        "record_family_count": len(snapshot.get("record_families") or []),
    }
