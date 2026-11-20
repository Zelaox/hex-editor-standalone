"""RVA to file-offset mapping helpers."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Tuple


def rva_to_file_offset(rva: int, sections: List[Mapping[str, Any]]) -> Tuple[int, str] | None:
    for section in sections:
        va = int(section.get("virtual_address") or 0)
        vsize = int(section.get("virtual_size") or 0)
        raw_ptr = int(section.get("raw_pointer") or 0)
        raw_size = int(section.get("raw_size") or 0)
        if va <= rva < va + max(vsize, raw_size):
            delta = rva - va
            if delta < 0 or delta >= raw_size:
                return None
            return raw_ptr + delta, str(section.get("name") or "")
    return None


def section_coverage(sections: List[Mapping[str, Any]], *, file_size: int) -> List[Dict[str, Any]]:
    coverage: List[Dict[str, Any]] = []
    for section in sections:
        raw_ptr = int(section.get("raw_pointer") or 0)
        raw_size = int(section.get("raw_size") or 0)
        if raw_ptr < 0 or raw_size <= 0 or raw_ptr + raw_size > file_size:
            continue
        coverage.append(
            {
                "offset": raw_ptr,
                "length": raw_size,
                "class": f"section.{section.get('name') or 'unknown'}",
                "rva": int(section.get("virtual_address") or 0),
                "node_ids": [],
            }
        )
    return sorted(coverage, key=lambda item: int(item["offset"]))
