"""Unified binary snapshot entry point."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Mapping

from src.runtime.config import load_binary_dynamic_config
from src.runtime.format_router import detect_format_plugin


def analyze_binary_snapshot(path: str | Path, *, policy: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    cfg = dict(policy or load_binary_dynamic_config())
    plugin = detect_format_plugin(path, cfg=cfg)
    if plugin == "pe":
        from src.plugins.pe.runtime_analysis import analyze_pe_path

        result = analyze_pe_path(path, policy=cfg)
    else:
        raise ValueError(f"unsupported format plugin: {plugin}")
    from src.parsing.semantic_validator import validate_binary_snapshot

    validation = validate_binary_snapshot(result["snapshot"])
    return {**result, "validation": validation}


def binary_waterfall_payload(snapshot: Mapping[str, Any]) -> Dict[str, Any]:
    from src.services.binary_compatibility import load_binary_diff_policy

    policy = load_binary_diff_policy()
    source_sha256 = (snapshot.get("source") or {}).get("sha256")
    learning_db_hints: Dict[str, Any] = {}
    if source_sha256:
        try:
            from src.services.learning_db import lookup_parser_coverage

            row = lookup_parser_coverage(str(source_sha256))
            if row:
                learning_db_hints = {
                    "metrics_source": str(row.get("metrics_source") or "learning_db_sources"),
                    "plaintext_run_count": row.get("plaintext_run_count"),
                    "unknown_bytes": row.get("unknown_bytes"),
                    "coverage_complete": row.get("coverage_complete"),
                }
        except Exception:
            learning_db_hints = {}
    return {
        "schema_version": 1,
        "snapshot_id": snapshot.get("snapshot_id"),
        "format_plugin": snapshot.get("format_plugin"),
        "source_sha256": source_sha256,
        "ranges": list(snapshot.get("coverage") or []),
        "coverage_summary": dict(snapshot.get("coverage_summary") or {}),
        "learning_db_hints": learning_db_hints,
        "anchors": list(snapshot.get("anchors") or []),
        "unknown_regions": list(snapshot.get("unknown_regions") or []),
        "record_families": list(snapshot.get("record_families") or []),
        "confidence_classes": ["verified", "inferred", "candidate", "unknown", "padding", "transformed"],
        "selection_contract": {"fields": ["snapshot_id", "offset", "length", "node_ids", "rva"]},
        "comparison_contract": {
            "policy_id": policy.get("policy_id"),
            "policy_revision": policy.get("revision"),
            "classifications": ["exact", "structural", "incompatible"],
            "incompatible_behavior": "block_automatic_diff",
        },
    }