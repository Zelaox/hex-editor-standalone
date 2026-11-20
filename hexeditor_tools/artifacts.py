"""Summarize huge hex tool responses before LLM/Gemma admission."""

from __future__ import annotations

from src.project import project_root

import json
import sys
from pathlib import Path
from typing import Any, Dict, Mapping, Optional


def _lab_root() -> Path:
    from src.project import project_root
    return project_root()


def _hex_editor_path() -> Path:
    return _lab_root()


def _load_checkpoint_policy() -> Dict[str, Any]:
    hex_root = _hex_editor_path()
    if str(hex_root) not in sys.path:
        sys.path.insert(0, str(hex_root))
    from src.services.hex_checkpoint_policy import load_hex_checkpoint_policy

    return load_hex_checkpoint_policy()


def _json_size(value: Any) -> int:
    try:
        return len(json.dumps(value, ensure_ascii=False, default=str).encode("utf-8"))
    except (TypeError, ValueError):
        return 0


def _build_pointer_summary(result: Mapping[str, Any]) -> Dict[str, Any]:
    hex_root = _hex_editor_path()
    if str(hex_root) not in sys.path:
        sys.path.insert(0, str(hex_root))
    from src.services.artifact_pointer import build_artifact_pointer

    pointer = result.get("artifact_pointer")
    if not isinstance(pointer, dict):
        pointer = build_artifact_pointer(result)
    return dict(pointer)


def _build_snapshot_summary(result: Mapping[str, Any]) -> Dict[str, Any]:
    snapshot = dict(result.get("snapshot") or {})
    summary = dict(snapshot.get("coverage_summary") or {})
    return {
        "ok": bool(result.get("ok", True)),
        "operation": result.get("operation"),
        "snapshot_id": snapshot.get("snapshot_id"),
        "format_plugin": snapshot.get("format_plugin"),
        "node_count": len(snapshot.get("nodes") or []),
        "edge_count": len(snapshot.get("edges") or []),
        "coverage_range_count": len(snapshot.get("coverage") or []),
        "unknown_region_count": len(snapshot.get("unknown_regions") or []),
        "coverage_summary": summary,
        "diagnostics_count": len(snapshot.get("diagnostics") or []),
    }


def admit_tool_response(
    tool_name: str,
    result: Mapping[str, Any],
    *,
    llm_route: bool = True,
    policy: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Apply checkpoint admission caps — pointer/summary only on LLM route."""
    if not llm_route:
        return dict(result)
    pol = dict(policy or _load_checkpoint_policy())
    caps = dict(pol.get("tool_response_caps") or {})
    mode = str(caps.get(str(tool_name)) or "")
    if not mode:
        max_field = int(pol.get("max_tool_response_field_bytes") or 0)
        if max_field > 0 and _json_size(result) <= max_field:
            return dict(result)
        mode = "summary_only"

    out = dict(result)
    if mode == "pointer_only":
        pointer = _build_pointer_summary(result)
        for heavy in ("snapshot", "nodes", "edges", "coverage", "unknown_regions", "files"):
            out.pop(heavy, None)
        out["artifact_pointer"] = pointer
        out["admission_mode"] = mode
        return out

    if mode == "summary_only":
        if tool_name == "binary_unpack_workspace":
            pointer = _build_pointer_summary(result)
            out = {
                "ok": bool(result.get("ok", True)),
                "operation": result.get("operation"),
                "operation_id": result.get("operation_id"),
                "artifact_directory": result.get("artifact_directory"),
                "artifact_pointer": pointer,
                "admission_mode": mode,
            }
            return out
        summary = _build_snapshot_summary(result)
        pointer = result.get("artifact_pointer")
        if isinstance(pointer, dict):
            summary["artifact_pointer"] = dict(pointer)
        for heavy in ("snapshot", "nodes", "edges", "coverage", "unknown_regions"):
            out.pop(heavy, None)
        out.update(summary)
        out["admission_mode"] = mode
        return out

    return dict(result)


def compile_brief_for_pointer(
    pointer: Mapping[str, Any],
    *,
    inspect_cursor: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    hex_root = _hex_editor_path()
    if str(hex_root) not in sys.path:
        sys.path.insert(0, str(hex_root))
    from src.services.snapshot_brief_compiler import compile_snapshot_brief

    return compile_snapshot_brief(pointer, inspect_cursor=inspect_cursor)
