"""BinarySnapshot — unified immutable runtime graph contract."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Mapping, Tuple


SCHEMA_VERSION = 1


@dataclass(frozen=True)
class SourceRange:
    offset: int
    length: int
    rva: int | None = None

    def __post_init__(self) -> None:
        if self.offset < 0 or self.length < 0:
            raise ValueError("source ranges must be non-negative")


def stable_node_id(kind: str, source_sha256: str, offset: int, length: int, *, rva: int | None = None) -> str:
    raw = f"{kind}:{source_sha256}:{offset}:{length}:{rva}".encode("utf-8")
    return f"{kind}-{hashlib.sha256(raw).hexdigest()[:20]}"


@dataclass(frozen=True)
class GraphNode:
    id: str
    kind: str
    label: str
    source_ranges: Tuple[SourceRange, ...]
    confidence: float
    parser_rule: str
    evidence_class: str = "static"
    attributes: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class GraphEdge:
    id: str
    kind: str
    source_id: str
    target_id: str
    confidence: float
    evidence: Tuple[str, ...]


@dataclass(frozen=True)
class BinarySnapshot:
    schema_version: int
    snapshot_id: str
    format_plugin: str
    source: Mapping[str, Any]
    registry_revision: str
    registry_digest: str
    nodes: Tuple[GraphNode, ...]
    edges: Tuple[GraphEdge, ...]
    coverage: Tuple[Mapping[str, Any], ...]
    diagnostics: Tuple[Mapping[str, Any], ...]
    signals: Mapping[str, Any]
    runtime_execution_id: str = ""
    anchors: Tuple[Mapping[str, Any], ...] = ()
    unknown_regions: Tuple[Mapping[str, Any], ...] = ()
    record_families: Tuple[Mapping[str, Any], ...] = ()
    coverage_summary: Mapping[str, Any] = field(default_factory=dict)
    analysis_passes: Tuple[Mapping[str, Any], ...] = ()
    experiments: Tuple[Mapping[str, Any], ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return json.loads(json.dumps(asdict(self), sort_keys=True, default=str))

    @classmethod
    def compute_snapshot_id(cls, *, source_sha256: str, format_plugin: str, registry_revision: str, payload: Mapping[str, Any]) -> str:
        canonical = json.dumps(
            {"source_sha256": source_sha256, "format_plugin": format_plugin, "registry_revision": registry_revision, **dict(payload)},
            sort_keys=True,
            default=str,
        ).encode("utf-8")
        return f"snapshot-{hashlib.sha256(canonical).hexdigest()}"
