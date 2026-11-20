"""Normalize and validate pseudocode source map entries."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Mapping, MutableMapping, Sequence

from .address_resolve import resolve_coordinate_to_file_offset


def entry_file_offset(entry: Mapping[str, Any]) -> int:
    if "file_offset" in entry:
        return int(entry["file_offset"])
    if "offset" in entry:
        return int(entry["offset"])
    raise ValueError("source_map entry missing file_offset")


def normalize_source_map_entry(entry: Mapping[str, Any], *, file_size: int) -> Dict[str, Any]:
    normalized = dict(entry)
    file_offset = entry_file_offset(entry)
    if file_size > 0 and file_offset >= file_size:
        raise ValueError(f"source_map file_offset out of range: 0x{file_offset:X} >= {file_size}")
    normalized["file_offset"] = file_offset
    normalized["offset"] = file_offset
    length = int(normalized.get("length") or 1)
    if length < 1:
        length = 1
    normalized["length"] = length
    return normalized


def normalize_source_map(source_map: Sequence[Mapping[str, Any]], *, file_size: int) -> List[Dict[str, Any]]:
    return [normalize_source_map_entry(item, file_size=file_size) for item in source_map]


def policy_block_source_entries(
    body_lines: Sequence[str],
    *,
    region_offset: int,
    producer_id: str,
    line_start: int,
    file_size: int,
    source_path: Path,
    navigation_policy: Mapping[str, Any],
) -> List[Dict[str, Any]]:
    """Build fine-grained source entries from policy-described rendered blocks."""
    entries: List[Dict[str, Any]] = []
    rules = list(navigation_policy.get("semantic_block_mappings") or [])
    for rule in rules:
        if not isinstance(rule, Mapping):
            continue
        start_pattern = re.compile(str(rule.get("start_pattern") or ""))
        end_pattern = re.compile(str(rule.get("end_pattern") or ""))
        anchor_pattern = re.compile(str(rule.get("anchor_pattern") or ""))
        identity_group = int(rule.get("identity_group") or 1)
        offset_group = int(rule.get("file_offset_group") or 1)
        length_group = rule.get("length_group")
        end_ordinal = int(rule.get("end_match_ordinal") or 1)
        coordinate_space = str(rule.get("coordinate_space") or "")
        rule_id = str(rule.get("id") or "semantic-block")
        if not start_pattern.pattern or not end_pattern.pattern or not anchor_pattern.pattern:
            continue

        for block_start, start_line_text in enumerate(body_lines):
            start_match = start_pattern.search(start_line_text)
            if start_match is None:
                continue
            block_end = None
            end_matches = 0
            for candidate in range(block_start + 1, len(body_lines)):
                if end_pattern.search(body_lines[candidate]):
                    end_matches += 1
                    if end_matches == end_ordinal:
                        block_end = candidate
                        break
            if block_end is None:
                continue

            anchor_match = None
            for candidate in range(block_start, block_end + 1):
                anchor_match = anchor_pattern.search(body_lines[candidate])
                if anchor_match is not None:
                    break
            if anchor_match is None:
                continue
            raw_value = int(anchor_match.group(offset_group), 16)
            resolved = resolve_coordinate_to_file_offset(
                raw_value,
                coordinate_space=coordinate_space,
                file_size=file_size,
                source_path=source_path,
                navigation_policy=navigation_policy,
            )
            if resolved is None:
                continue
            length = resolved[1]
            if length_group is not None:
                length = max(1, int(anchor_match.group(int(length_group))))
            identity = start_match.group(identity_group)
            file_offset = int(resolved[0])
            entries.append(
                {
                    "ir_id": f"{int(region_offset):X}-{rule_id}-{identity}",
                    "line_start": int(line_start) + block_start,
                    "line_end": int(line_start) + block_end,
                    "file_offset": file_offset,
                    "offset": file_offset,
                    "length": max(1, int(length)),
                    "producer_id": str(producer_id),
                    "coordinate_hint": coordinate_space,
                }
            )
    return entries


def prioritize_source_map_entries(
    source_map: Sequence[Mapping[str, Any]],
    *,
    max_entries: int,
) -> List[Dict[str, Any]]:
    if max_entries <= 0 or len(source_map) <= max_entries:
        return list(source_map)
    indexed = list(enumerate(source_map))

    def sort_key(item: tuple[int, Mapping[str, Any]]) -> tuple[int, int, int]:
        _index, entry = item
        length = max(1, int(entry.get("length") or 1))
        line_start = int(entry.get("line_start") or 0)
        insn = 0 if "-insn-" in str(entry.get("ir_id") or "") else 1
        return (length, insn, line_start)

    indexed.sort(key=sort_key)
    keep = sorted(index for index, _entry in indexed[:max_entries])
    return [dict(source_map[index]) for index in keep]
