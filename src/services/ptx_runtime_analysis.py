"""Immutable, provenance-first runtime analysis — backward-compatible re-exports."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Mapping

from src.plugins.ptx.runtime_analysis import analyze_ptx_path, build_ptx_snapshot
from src.runtime.byte_source import ByteSource
from src.runtime.snapshot import GraphEdge, GraphNode, SourceRange
from src.services.binary_runtime import binary_waterfall_payload


class SessionSnapshot:
    """Legacy wrapper around dict snapshot from BinarySnapshot."""

    def __init__(self, payload: Mapping[str, Any]):
        self._payload = dict(payload)

    def to_dict(self) -> Dict[str, Any]:
        return dict(self._payload)


# Legacy type aliases
SessionNode = GraphNode
SessionEdge = GraphEdge


def analyze_runtime_source(
    source: ByteSource,
    *,
    policy: Mapping[str, Any] | None = None,
    registry_revision: str = "generic-discovery-v1",
) -> SessionSnapshot:
    snap = build_ptx_snapshot(source, policy=policy)
    payload = snap.to_dict()
    if registry_revision:
        payload["registry_revision"] = registry_revision
    return SessionSnapshot(payload)


def analyze_ptx_runtime(path: str | Path, *, policy: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    result = analyze_ptx_path(path, policy=policy)
    return {"ok": True, "operation": "ptx_runtime_analyze", "snapshot": result["snapshot"]}


__all__ = [
    "ByteSource",
    "SourceRange",
    "SessionNode",
    "SessionEdge",
    "SessionSnapshot",
    "analyze_runtime_source",
    "analyze_ptx_runtime",
    "binary_waterfall_payload",
]
