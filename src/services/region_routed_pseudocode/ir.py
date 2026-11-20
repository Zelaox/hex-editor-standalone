"""Pseudocode IR document and source map generation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Mapping, MutableMapping, Optional, Sequence, Tuple

from jsonschema import Draft202012Validator

from .region_map import RegionSpan


def _hex_root() -> Path:
    return Path(__file__).resolve().parents[3]


def load_pseudocode_ir_policy(path: str | Path | None = None) -> Dict[str, Any]:
    target = Path(path).expanduser().resolve() if path else _hex_root() / "config" / "pseudocode_ir_policy.json"
    payload = json.loads(target.read_text(encoding="utf-8-sig"))
    schema_path = _hex_root() / "schemas" / "pseudocode_ir_policy.schema.json"
    if schema_path.is_file():
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        errors = sorted(Draft202012Validator(schema).iter_errors(payload), key=lambda item: list(item.path))
        if errors:
            raise ValueError(f"pseudocode_ir_policy invalid: {errors[0].message}")
    return payload


def build_ir_document(
    region_map_document: Mapping[str, Any],
    regions: Sequence[RegionSpan],
    *,
    region_bodies: Sequence[Mapping[str, Any]],
) -> Dict[str, Any]:
    ir_regions: List[Dict[str, Any]] = []
    code_functions: List[Dict[str, Any]] = []
    data_records: List[Dict[str, Any]] = []
    unknown_clusters: List[Dict[str, Any]] = []
    source_map: List[Dict[str, Any]] = []

    for index, (region, body) in enumerate(zip(regions, region_bodies)):
        ir_id = f"region-{index}-0x{region.offset:X}"
        entry: Dict[str, Any] = {
            "ir_id": ir_id,
            "producer_id": region.producer_id,
            "region_class": region.region_class,
            "format_plugin": region.format_plugin,
            "source_ranges": [{"offset": region.offset, "length": region.length}],
            "truth_state": "verified" if (region.meta or {}).get("ledger_protected") else "observed",
            "evidence_refs": list((region.meta or {}).get("ledger_refs") or []),
            "learning_db_refs": [
                {"proof_span_id": ref.get("proof_span_id")}
                for ref in (region.meta or {}).get("ledger_refs") or []
                if ref.get("proof_span_id")
            ],
            "line_start": int(body.get("line_start") or 0),
            "line_end": int(body.get("line_end") or 0),
        }
        ir_regions.append(entry)
        source_map.append(
            {
                "ir_id": ir_id,
                "line_start": entry["line_start"],
                "line_end": entry["line_end"],
                "file_offset": int(region.offset),
                "offset": int(region.offset),
                "length": int(region.length),
                "producer_id": region.producer_id,
            }
        )
        for sub in body.get("sub_entries") or []:
            source_map.append(dict(sub))

        if region.region_class == "executable_code":
            code_functions.append({"ir_id": ir_id, "entry_offset": region.offset, "section": (region.meta or {}).get("pe_section")})
        elif region.region_class == "structured_data":
            data_records.append({"ir_id": ir_id, "format_plugin": region.format_plugin})
        else:
            unknown_clusters.append({"ir_id": ir_id, "offset": region.offset, "length": region.length})

    return {
        "schema_version": 1,
        "kind": "pseudocode_ir_document",
        "source": dict(region_map_document.get("source") or {}),
        "region_map_digest": region_map_document.get("digest"),
        "document": {
            "regions": ir_regions,
            "code": {"functions": code_functions},
            "data": {"records": data_records},
            "unknown": {"clusters": unknown_clusters},
        },
        "source_map": source_map,
    }


def append_byte_markers(
    lines: List[str],
    source_map: Sequence[Mapping[str, Any]],
    *,
    marker_prefix: str,
    file_size: int = 0,
) -> List[str]:
    if not marker_prefix:
        return lines
    marked = list(lines)
    best_by_line: Dict[int, Mapping[str, Any]] = {}
    for entry in source_map:
        line_start = int(entry.get("line_start") or 0)
        file_offset = int(entry.get("file_offset") if entry.get("file_offset") is not None else entry.get("offset") or 0)
        if file_size > 0 and file_offset >= file_size:
            continue
        length = max(1, int(entry.get("length") or 1))
        previous = best_by_line.get(line_start)
        if previous is None or length < max(1, int(previous.get("length") or 1)):
            best_by_line[line_start] = entry
    for line_start, entry in best_by_line.items():
        file_offset = int(entry.get("file_offset") if entry.get("file_offset") is not None else entry.get("offset") or 0)
        if 0 <= line_start < len(marked):
            marker = f"/* {marker_prefix}0x{file_offset:X} ir={entry.get('ir_id')} */"
            if marker_prefix not in marked[line_start]:
                marked[line_start] = f"{marker} {marked[line_start]}"
    return marked
