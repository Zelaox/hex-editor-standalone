"""Normalize analyze_ptx output into PtxParseResult documents."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

from src.services.ptx_analysis import analyze_ptx
from src.services.ptx_evidence import build_consistency_checks
from src.services.ptx_schema_validate import validate_against_schema


def _finding_payload(analysis: Mapping[str, Any], kind: str) -> Any:
    for item in analysis.get("findings") or []:
        if isinstance(item, Mapping) and item.get("kind") == kind:
            return item.get("payload")
    return None


def build_parse_result(path: str | Path, *, analysis: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    resolved = Path(path).expanduser().resolve()
    raw = dict(analysis or analyze_ptx(resolved))
    header = dict(_finding_payload(raw, "header") or {})
    sections = list(_finding_payload(raw, "sections") or [])
    timecodes = list(_finding_payload(raw, "timecodes") or [])
    metadata = dict(_finding_payload(raw, "metadata") or {})
    source = dict(raw.get("source") or {})
    file_size = int(source.get("size") or resolved.stat().st_size)
    consistency = build_consistency_checks(
        file_size=file_size,
        header=header,
        sections=sections,
        timecodes=timecodes,
    )
    result: Dict[str, Any] = {
        "schema_version": 1,
        "ok": bool(raw.get("ok")),
        "source": {
            "sha256": str(source.get("sha256") or ""),
            "size": file_size,
            "path": str(source.get("path") or str(resolved)),
        },
        "header": header,
        "sections": sections,
        "timecodes": timecodes,
        "metadata": metadata,
        "consistency_checks": consistency,
        "warnings": list(raw.get("warnings") or []),
    }
    if raw.get("error"):
        result["error"] = str(raw["error"])
    if raw.get("evidence"):
        result["evidence"] = raw["evidence"]
    validate_against_schema("ptx_parse_result.schema.json", result)
    return result


def verified_timecodes(timecodes: List[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    verified: List[Dict[str, Any]] = []
    for item in timecodes:
        if not isinstance(item, Mapping):
            continue
        offset = item.get("offset")
        value = item.get("value")
        if offset is None or not value:
            continue
        verified.append(
            {
                "offset": int(offset),
                "value": str(value),
                "type": str(item.get("type") or "unknown"),
                "reference_point": bool(item.get("reference_point")),
                "confidence": "heuristic_parser",
            }
        )
    return verified
