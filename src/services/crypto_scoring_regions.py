"""Compile body-only scoring windows excluding cleartext regions from fixture."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Sequence


def _region_overlaps(window_start: int, window_end: int, exclude_start: int, exclude_end: int) -> bool:
    return window_start < exclude_end and window_end > exclude_start


def excluded_regions_for_case(case: Optional[Mapping[str, Any]], *, file_size: int) -> List[Dict[str, Any]]:
    regions: List[Dict[str, Any]] = []
    if not case:
        return regions
    decrypt = dict(case.get("decrypt") or {})
    for item in decrypt.get("excluded_scoring_regions") or []:
        if not isinstance(item, dict):
            continue
        start = int(item.get("start_offset") or item.get("start") or 0)
        end = int(item.get("end_offset") or item.get("end") or 0)
        if end > start:
            regions.append({"start": start, "end": min(end, file_size), "reason": str(item.get("reason") or "")})
    derive = str(decrypt.get("derive_from_layout") or "")
    if derive == "session_text_header":
        exclude_end = int(decrypt.get("session_cleartext_end_offset") or 1024)
        transform_start = int(decrypt.get("xor_start_offset") or 16)
        regions.append(
            {
                "start": transform_start,
                "end": min(exclude_end, file_size),
                "reason": "session_text_header_cleartext",
            }
        )
    return regions


def compile_scoring_windows(
    probe_windows: Sequence[Mapping[str, Any]],
    excluded_regions: Sequence[Mapping[str, Any]],
    *,
    file_size: int,
) -> List[Dict[str, Any]]:
    compiled: List[Dict[str, Any]] = []
    for window in probe_windows:
        start = max(0, int(window.get("offset") or 0))
        length = max(64, int(window.get("length") or 4096))
        end = min(file_size, start + length)
        if start >= file_size:
            continue
        excluded_only = all(
            _region_overlaps(start, end, int(region.get("start") or 0), int(region.get("end") or 0))
            for region in excluded_regions
        ) if excluded_regions else False
        if excluded_only:
            continue
        compiled.append(
            {
                "name": str(window.get("name") or hex(start)),
                "offset": start,
                "length": end - start,
                "excluded_cleartext_only": False,
            }
        )
    return compiled


def anchors_for_case(case: Optional[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    if not case:
        return []
    anchors: List[Dict[str, Any]] = []
    for item in case.get("timecode_anchors") or []:
        if not isinstance(item, dict):
            continue
        offset = int(item.get("offset") or 0)
        needle = str(item.get("byte_substring") or item.get("needle") or "").encode("latin1", errors="ignore")
        if offset and needle:
            anchors.append(
                {
                    "offset": offset,
                    "needle": needle,
                    "label": str(item.get("label") or item.get("byte_substring") or ""),
                }
            )
    decrypt = dict(case.get("decrypt") or {})
    for item in decrypt.get("validation_anchors") or []:
        if isinstance(item, dict) and item.get("offset") and item.get("needle"):
            anchors.append(dict(item))
    anchor_case_id = str(decrypt.get("anchor_source_case_id") or "")
    if anchor_case_id and not anchors:
        from src.services.crypto_calibration import load_crypto_calibration

        for sibling in load_crypto_calibration().get("cases") or []:
            if str(sibling.get("id") or "") == anchor_case_id:
                return anchors_for_case(sibling)
    return anchors
