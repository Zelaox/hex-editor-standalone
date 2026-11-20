"""PTX runtime graph builder — generic discovery + optional static ptx_analyze enrichment."""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List, Mapping

from src.runtime.byte_source import ByteSource
from src.runtime.config import load_binary_dynamic_config, load_parser_registry
from src.runtime.snapshot import SCHEMA_VERSION, BinarySnapshot, GraphEdge, GraphNode, SourceRange, stable_node_id


def _registry_digest(registry: Mapping[str, Any]) -> str:
    return hashlib.sha256(json.dumps(registry, sort_keys=True).encode("utf-8")).hexdigest()[:16]


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for value in data:
        counts[value] += 1
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in counts if count)


def _string_nodes(data: bytes, source_sha: str, policy: Mapping[str, Any]) -> List[GraphNode]:
    minimum = max(2, int(policy.get("minimum_string_length", 4)))
    maximum = max(minimum, int(policy.get("maximum_string_length", 512)))
    max_records = max(1, int(policy.get("max_records", 10000)))
    pattern = re.compile(rb"[\x20-\x7e]{" + str(minimum).encode("ascii") + rb"," + str(maximum).encode("ascii") + rb"}")
    nodes: List[GraphNode] = []
    for match in pattern.finditer(data):
        raw = match.group(0)
        label = raw.decode("utf-8", errors="replace")
        node_id = stable_node_id("string", source_sha, match.start(), len(raw))
        nodes.append(
            GraphNode(
                node_id,
                "string",
                label,
                (SourceRange(match.start(), len(raw)),),
                1.0,
                "generic.ascii_string",
                attributes={"encoding": "ascii"},
            )
        )
        if len(nodes) >= max_records:
            break
    return nodes


def _enrich_from_ptx_analyze(path: Path, nodes: List[GraphNode], source_sha: str) -> tuple[List[GraphEdge], Dict[str, Any]]:
    edges: List[GraphEdge] = []
    identity: Dict[str, Any] = {}
    try:
        from src.services.ptx_analysis import analyze_ptx

        analysis = analyze_ptx(path)
        if not analysis.get("ok"):
            return edges, identity
        session_id = stable_node_id("session", source_sha, 0, 0)
        session_node = GraphNode(
            session_id,
            "session",
            path.name,
            (SourceRange(0, min(int(analysis["source"]["size"]), 256)),),
            0.7,
            "ptx_analyze.session_root",
            attributes={"operation": "ptx_analyze"},
        )
        nodes.append(session_node)
        for finding in analysis.get("findings") or []:
            kind = str(finding.get("label") or finding.get("kind") or "finding")
            if kind == "header" and isinstance(finding.get("value"), Mapping):
                header = dict(finding["value"])
                identity["format_variant"] = header.get("layout")
                identity["format_version"] = header.get("version")
            fid = stable_node_id(kind, source_sha, 0, 0)
            child = GraphNode(fid, kind, kind, (SourceRange(0, 0),), 0.6, "ptx_analyze.finding", attributes={"value": finding.get("value")})
            nodes.append(child)
            eid = stable_node_id("edge", source_sha, 0, len(session_id) + len(fid))
            edges.append(GraphEdge(eid, "contains", session_id, fid, 0.6, ("ptx_analyze",)))
    except Exception:
        pass
    return edges, identity


def build_ptx_snapshot(source: ByteSource, *, policy: Mapping[str, Any] | None = None) -> BinarySnapshot:
    from src.services.ptx_full_coverage import build_anchors, build_record_families, build_unknown_regions, coverage_summary, load_full_coverage_policy, partition_coverage

    cfg = dict(policy or load_binary_dynamic_config())
    registry = load_parser_registry("ptx")
    registry_revision = str(registry.get("revision") or cfg.get("registry_revision") or "generic-discovery-v1")
    data = source.bytes()
    source_sha = str(source.identity["sha256"])
    nodes = _string_nodes(data, source_sha, cfg)
    full_policy = load_full_coverage_policy()
    edges: List[GraphEdge] = []
    format_identity: Dict[str, Any] = {}
    path = source.identity.get("path")
    if path:
        edges, format_identity = _enrich_from_ptx_analyze(Path(str(path)), nodes, source_sha)
    node_dicts = [asdict(node) for node in nodes]
    anchors = build_anchors(node_dicts, len(data), full_policy)
    coverage = partition_coverage(len(data), ({"offset": source_range.offset, "length": source_range.length, "class": "verified" if node.kind == "string" else "inferred", "node_ids": [node.id]} for node in nodes for source_range in node.source_ranges), full_policy)
    unknown_regions = build_unknown_regions(data, coverage, anchors, full_policy)
    record_families = build_record_families(anchors, full_policy)
    summary = coverage_summary(len(data), coverage)
    covered_bytes = sum(int(item["length"]) for item in coverage if item["class"] != "unknown")
    printable = sum(1 for value in data if 32 <= value <= 126 or value in (9, 10, 13))
    signals = {
        "profile_id": str(registry.get("default_profile_id") or ""),
        **format_identity,
        "file_size": len(data),
        "node_count": len(nodes),
        "edge_count": len(edges),
        "coverage_ratio": covered_bytes / len(data) if data else 0.0,
        "printable_ratio": printable / len(data) if data else 0.0,
        "entropy": _entropy(data),
        "graph_consistent": True,
        "timeline_consistent": True,
        "full_coverage": summary["coverage_complete"],
        "unknown_region_count": len(unknown_regions),
        "anchor_count": len(anchors),
        "record_family_count": len(record_families),
    }
    digest = _registry_digest(registry)
    snapshot_id = BinarySnapshot.compute_snapshot_id(
        source_sha256=source_sha,
        format_plugin="ptx",
        registry_revision=registry_revision,
        payload={"nodes": [asdict(n) for n in nodes], "coverage": coverage, "anchors": anchors, "unknown_regions": unknown_regions, "record_families": record_families, "coverage_summary": summary, "full_coverage_policy_revision": full_policy["revision"]},
    )
    diagnostics: List[Dict[str, Any]] = []
    if not nodes:
        diagnostics.append({"code": "no_semantic_records", "severity": "info", "message": "No configured semantic records discovered."})
    return BinarySnapshot(
        SCHEMA_VERSION,
        snapshot_id,
        "ptx",
        dict(source.identity),
        registry_revision,
        digest,
        tuple(nodes),
        tuple(edges),
        tuple(coverage),
        tuple(diagnostics),
        signals,
        "",
        tuple(anchors),
        tuple(unknown_regions),
        tuple(record_families),
        summary,
        ({"pass_id": "ptx-full-coverage", "policy_id": full_policy["policy_id"], "policy_revision": full_policy["revision"]},),
    )


def analyze_ptx_path(path: str | Path, *, policy: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    from src.runtime.format_router import detect_format_plugin

    cfg = dict(policy or load_binary_dynamic_config())
    resolved = Path(path).expanduser().resolve()
    if detect_format_plugin(resolved, cfg=cfg) != "ptx":
        raise ValueError("PTX plugin requires PTX-shaped binary")
    max_bytes = int(cfg.get("max_source_bytes", 268435456))
    source = ByteSource.from_path(resolved, max_bytes=max_bytes)
    snapshot = build_ptx_snapshot(source, policy=cfg)
    return {"ok": True, "operation": "binary_snapshot_parse", "format_plugin": "ptx", "snapshot": snapshot.to_dict()}
