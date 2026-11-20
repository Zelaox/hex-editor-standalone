"""Line ↔ byte navigation using pseudocode source maps."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Mapping, MutableMapping, Optional, Sequence, Tuple

from .address_resolve import resolve_coordinate_to_file_offset
from .source_map_build import entry_file_offset, normalize_source_map_entry


def _span_key(file_offset: int, length: int) -> Tuple[int, int]:
    return (int(file_offset), int(length))


def offset_for_line(source_map: Sequence[Mapping[str, Any]], line_number: int) -> Optional[int]:
    from .policies import load_pseudocode_navigation_policy

    result = ranges_for_line_interval(
        source_map,
        line_number,
        line_number,
        navigation_policy=load_pseudocode_navigation_policy(),
    )
    if result is None:
        return None
    return int(result["anchor_file_offset"])


def line_for_offset(source_map: Sequence[Mapping[str, Any]], offset: int) -> Optional[int]:
    candidate: Optional[Dict[str, Any]] = None
    for entry in source_map:
        base = entry_file_offset(entry)
        length = int(entry.get("length") or 0)
        if base <= offset < base + max(1, length):
            span_len = max(1, length)
            if candidate is None or span_len < max(1, int(candidate.get("length") or 0)):
                candidate = dict(entry)
        elif base <= offset and (candidate is None or base > entry_file_offset(candidate)):
            candidate = dict(entry)
    return int(candidate.get("line_start") or 0) if candidate else None


def parse_line_for_file_span(
    line: str,
    *,
    navigation_policy: Mapping[str, Any],
    file_size: int = 0,
    source_path: Path | None = None,
    preferred_column: int | None = None,
) -> Optional[Dict[str, Any]]:
    from pathlib import Path as PathType

    path_obj = source_path if source_path is None or isinstance(source_path, PathType) else PathType(str(source_path))
    parsers = list(navigation_policy.get("fallback_line_parsers") or [])
    matched_parsers: List[Tuple[Mapping[str, Any], re.Match[str]]] = []
    for spec in parsers:
        if not isinstance(spec, Mapping):
            continue
        pattern = str(spec.get("pattern") or "")
        if not pattern:
            continue
        match = re.search(pattern, line)
        if not match:
            continue
        matched_parsers.append((spec, match))

    if preferred_column is not None:
        column = max(0, int(preferred_column))
        matched_parsers.sort(
            key=lambda item: 0 if item[1].start() <= column < item[1].end() else 1
        )

    for spec, match in matched_parsers:
        group = int(spec.get("file_offset_group") or 1)
        raw_offset = int(match.group(group), 16)
        length = 1
        length_group = spec.get("length_group")
        if length_group is not None:
            length = int(match.group(int(length_group)))
        coordinate_space = str(spec.get("coordinate_space") or "").strip()
        resolved = resolve_coordinate_to_file_offset(
            raw_offset,
            coordinate_space=coordinate_space,
            file_size=file_size,
            source_path=path_obj,
            navigation_policy=navigation_policy,
        )
        if resolved is None:
            continue
        return {
            "file_offset": resolved[0],
            "length": max(1, length, resolved[1]),
            "source_coordinate_space": coordinate_space,
            "source_coordinate_value": raw_offset,
        }
    return None


def _innermost_entry_for_line(source_map: Sequence[Mapping[str, Any]], line_number: int) -> Optional[Dict[str, Any]]:
    best: Optional[Dict[str, Any]] = None
    best_span: Optional[int] = None
    for entry in source_map:
        start = int(entry.get("line_start") or 0)
        end = int(entry.get("line_end") or start)
        if start <= line_number <= end:
            span = max(1, int(entry.get("length") or 1))
            best_insn = "-insn-" in str((best or {}).get("ir_id") or "")
            entry_insn = "-insn-" in str(entry.get("ir_id") or "")
            if (
                best is None
                or span < int(best_span or span)
                or (span == int(best_span or span) and entry_insn and not best_insn)
            ):
                best = dict(entry)
                best_span = span
    return best


def _resolve_line(source_map: Sequence[Mapping[str, Any]], line_number: int) -> Optional[Dict[str, Any]]:
    entry = _innermost_entry_for_line(source_map, line_number)
    if entry is None:
        return None
    return {
        "file_offset": entry_file_offset(entry),
        "length": max(1, int(entry.get("length") or 1)),
        "source_coordinate_space": "file_offset",
        "source_coordinate_value": entry_file_offset(entry),
    }


def _merge_ranges(
    ranges: List[Dict[str, int]],
    *,
    merge_adjacent: bool,
) -> List[Dict[str, int]]:
    if not ranges:
        return []
    ordered = sorted(ranges, key=lambda item: (item["file_offset"], item["length"]))
    deduped: List[Dict[str, int]] = []
    for item in ordered:
        if deduped and deduped[-1]["file_offset"] == item["file_offset"]:
            deduped[-1]["length"] = max(deduped[-1]["length"], item["length"])
            continue
        deduped.append(dict(item))
    if not merge_adjacent or len(deduped) < 2:
        return deduped
    merged: List[Dict[str, int]] = [deduped[0]]
    for item in deduped[1:]:
        prev = merged[-1]
        if prev["file_offset"] + prev["length"] == item["file_offset"]:
            prev["length"] = prev["length"] + item["length"]
        else:
            merged.append(dict(item))
    return merged


def _anchor_from_policy(
    ranges: Sequence[Mapping[str, int]],
    *,
    selection_start_line: int,
    selection_end_line: int,
    navigation_policy: Mapping[str, Any],
    source_map: Sequence[Mapping[str, Any]],
) -> int:
    cfg = dict(navigation_policy.get("pseudocode_to_hex") or {})
    mode = str(cfg.get("selection_anchor") or "start_line")
    if not ranges:
        raise ValueError("no ranges to anchor")
    if mode == "min_file_offset":
        return min(int(item["file_offset"]) for item in ranges)
    if mode == "first_range":
        return int(ranges[0]["file_offset"])
    entry = _innermost_entry_for_line(source_map, selection_start_line)
    if entry is not None:
        return entry_file_offset(entry)
    return int(ranges[0]["file_offset"])


def _validate_span(
    span: Mapping[str, int],
    *,
    file_size: int,
    source_path: Path | None,
    navigation_policy: Mapping[str, Any],
) -> Optional[Dict[str, Any]]:
    resolved = resolve_coordinate_to_file_offset(
        int(span["file_offset"]),
        coordinate_space="file_offset",
        file_size=file_size,
        source_path=source_path,
        navigation_policy=navigation_policy,
    )
    if resolved is None:
        return None
    file_offset, default_len = resolved
    length = max(1, int(span.get("length") or default_len))
    if file_size > 0 and file_offset + length > file_size:
        length = max(1, file_size - file_offset)
    validated = dict(span)
    validated.update({"file_offset": file_offset, "length": length})
    return validated


def ranges_for_line_interval(
    source_map: Sequence[Mapping[str, Any]],
    start_line: int,
    end_line: int,
    *,
    navigation_policy: Mapping[str, Any] | None,
    line_texts: Sequence[str] | None = None,
    file_size: int = 0,
    source_path: Path | None = None,
    selection_start_column: int | None = None,
) -> Optional[Dict[str, Any]]:
    if start_line < 0 or end_line < start_line:
        return None
    policy = dict(navigation_policy or {})
    merge_adjacent = bool((policy.get("pseudocode_to_hex") or {}).get("merge_adjacent_ranges"))
    collected: List[Dict[str, int]] = []
    anchor_line_span: Optional[Dict[str, int]] = None
    parser_first = str(policy.get("line_parser_precedence") or "") == "before_source_map"
    for line_number in range(start_line, end_line + 1):
        span = None
        if parser_first and line_texts is not None and 0 <= line_number < len(line_texts) and policy:
            span = parse_line_for_file_span(
                line_texts[line_number],
                navigation_policy=policy,
                file_size=file_size,
                source_path=source_path,
                preferred_column=selection_start_column if line_number == start_line else None,
            )
        if span is None:
            span = _resolve_line(source_map, line_number)
        if span is None and not parser_first and line_texts is not None and 0 <= line_number < len(line_texts) and policy:
            span = parse_line_for_file_span(
                line_texts[line_number],
                navigation_policy=policy,
                file_size=file_size,
                source_path=source_path,
                preferred_column=selection_start_column if line_number == start_line else None,
            )
        if span is None:
            continue
        if policy:
            span = _validate_span(span, file_size=file_size, source_path=source_path, navigation_policy=policy)
        if span is not None:
            if line_number == start_line and anchor_line_span is None:
                anchor_line_span = dict(span)
            collected.append({"file_offset": int(span["file_offset"]), "length": int(span["length"])})
    merged = _merge_ranges(collected, merge_adjacent=merge_adjacent)
    if not merged:
        return None
    anchor_cfg = dict(policy.get("pseudocode_to_hex") or {})
    if str(anchor_cfg.get("selection_anchor") or "") == "start_line" and anchor_line_span is not None:
        anchor = int(anchor_line_span["file_offset"])
    else:
        anchor = _anchor_from_policy(
            merged,
            selection_start_line=start_line,
            selection_end_line=end_line,
            navigation_policy=policy,
            source_map=source_map,
        )
    result: Dict[str, Any] = {"ranges": merged, "anchor_file_offset": anchor}
    if anchor_line_span is not None:
        source_space = str(anchor_line_span.get("source_coordinate_space") or "")
        source_value = anchor_line_span.get("source_coordinate_value")
        if source_space and source_value is not None:
            result["anchor_source_coordinate"] = {
                "coordinate_space": source_space,
                "value": int(source_value),
            }
    return result


def ranges_for_selection(
    source_map: Sequence[Mapping[str, Any]],
    *,
    start_line: int,
    end_line: int,
    navigation_policy: Mapping[str, Any],
    line_texts: Sequence[str] | None = None,
    file_size: int = 0,
    source_path: Path | None = None,
    selection_start_column: int | None = None,
) -> Optional[Dict[str, Any]]:
    return ranges_for_line_interval(
        source_map,
        start_line,
        end_line,
        navigation_policy=navigation_policy,
        line_texts=line_texts,
        file_size=file_size,
        source_path=source_path,
        selection_start_column=selection_start_column,
    )


def generation_tokens_from_bundle(bundle: Mapping[str, Any]) -> Dict[str, Optional[str]]:
    document = dict(bundle.get("region_map_document") or {})
    source = dict(document.get("source") or {})
    return {
        "source_path": str(source.get("path") or "") or None,
        "source_sha256": str(source.get("sha256") or "") or None,
        "region_map_digest": str(document.get("digest") or "") or None,
    }


def navigation_generation_matches(
    stored: Mapping[str, Any],
    current: Mapping[str, Any],
    *,
    navigation_policy: Mapping[str, Any],
) -> bool:
    guard = dict(navigation_policy.get("generation_guard") or {})
    if bool(guard.get("require_matching_source_path", False)):
        stored_path = str(stored.get("source_path") or "").strip()
        current_path = str(current.get("source_path") or "").strip()
        if not stored_path or not current_path:
            return False
        try:
            stored_identity = Path(stored_path).expanduser().resolve().as_posix().casefold()
            current_identity = Path(current_path).expanduser().resolve().as_posix().casefold()
        except OSError:
            return False
        if stored_identity != current_identity:
            return False
    if bool(guard.get("require_matching_digest", True)):
        if stored.get("region_map_digest") != current.get("region_map_digest"):
            return False
    if bool(guard.get("require_matching_source_sha256", True)):
        if stored.get("source_sha256") != current.get("source_sha256"):
            return False
    return True
