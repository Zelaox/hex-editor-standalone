"""Compile schema-valid PTX session graphs from parse artifacts."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Mapping, Optional

from src.services.ptx_parse_policy import load_ptx_parse_policy
from src.services.ptx_parse_result import verified_timecodes
from src.services.ptx_pipeline_policy import load_ptx_pipeline_policy
from src.services.ptx_schema_validate import validate_against_schema


def _digest(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _section_rows(sections: List[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for index, section in enumerate(sections):
        if not isinstance(section, Mapping):
            continue
        rows.append(
            {
                "index": index,
                "offset": section.get("offset"),
                "size": section.get("size"),
                "type": section.get("type"),
                "type_name": section.get("type_name"),
                "status": "mechanical_parser",
            }
        )
    return rows


def compile_session_graph(
    *,
    binding: Mapping[str, Any],
    parse_result: Mapping[str, Any],
    sections_manifest: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    if not parse_result.get("ok"):
        raise ValueError("cannot compile session graph from failed parse")
    pipeline = load_ptx_pipeline_policy()
    parse_policy = load_ptx_parse_policy()
    source = dict(parse_result.get("source") or {})
    header = dict(parse_result.get("header") or {})
    sections = list(parse_result.get("sections") or [])
    timecodes = list(parse_result.get("timecodes") or [])
    metadata = dict(parse_result.get("metadata") or {})

    verified: Dict[str, Any] = {
        "source_sha256": source.get("sha256"),
        "source_size": source.get("size"),
        "layout": header.get("layout"),
        "body_encrypted": header.get("body_encrypted"),
        "session_strings": list(header.get("session_strings") or []),
        "sections": _section_rows(sections),
        "timecodes": verified_timecodes(timecodes),
    }
    hypotheses: Dict[str, Any] = {
        "metadata": metadata,
        "parser_labels": {
            "encryption_type": header.get("encryption_type"),
            "magic": header.get("magic"),
        },
    }
    if sections_manifest:
        hypotheses["section_extract"] = {
            "operation_id": sections_manifest.get("operation_id"),
            "extracted_section_count": (sections_manifest.get("details") or {}).get("extracted_section_count"),
        }

    snapshot_seed = {
        "binding_digest": binding.get("spec_digest"),
        "source_sha256": source.get("sha256"),
        "parse_digest": _digest(parse_result),
    }
    graph: Dict[str, Any] = {
        "schema_version": 1,
        "snapshot_id": f"ptx-session-{_digest(snapshot_seed)[:32]}",
        "format_plugin": "ptx",
        "source": {
            "sha256": str(source.get("sha256") or ""),
            "size": int(source.get("size") or 0),
            "path": str(source.get("path") or binding.get("bound_path") or ""),
        },
        "registry_revision": str(parse_policy.get("revision") or pipeline.get("revision") or ""),
        "registry_digest": _digest(parse_policy),
        "nodes": [],
        "edges": [],
        "coverage": [],
        "diagnostics": list(parse_result.get("consistency_checks") or []),
        "signals": {
            "binding_kind": binding.get("binding_kind"),
            "parser_policy_revision": binding.get("parser_policy_revision"),
            "pipeline_policy_revision": binding.get("pipeline_policy_revision"),
        },
        "verified_facts": verified,
        "hypotheses": hypotheses,
        "warnings": list(parse_result.get("warnings") or []),
    }
    validate_against_schema("ptx_session_graph.schema.json", graph)
    return graph
