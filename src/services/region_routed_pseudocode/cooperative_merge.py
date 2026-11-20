"""Merge audits — detect generic whole-file takeover and precedence violations."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Sequence

from .region_map import RegionSpan


def _is_whole_file_span(region: RegionSpan, file_size: int) -> bool:
    if file_size <= 0:
        return False
    return int(region.offset) == 0 and int(region.length) >= file_size


def audit_region_map(
    regions: Sequence[RegionSpan],
    *,
    file_size: int,
    format_plugin: str,
    merge_policy: Mapping[str, Any],
) -> List[Dict[str, Any]]:
    violations: List[Dict[str, Any]] = []
    if file_size <= 0:
        return violations

    high_priority_classes = {"executable_code", "structured_data"}
    has_high_priority = any(r.region_class in high_priority_classes for r in regions)
    forbidden = list(merge_policy.get("generic_whole_file_forbidden_when") or [])

    for rule in forbidden:
        if not isinstance(rule, Mapping):
            continue
        plugin = str(rule.get("format_plugin") or "")
        if plugin and plugin != format_plugin:
            continue
        requires_any = {str(item) for item in (rule.get("requires_region_class_any") or [])}
        if requires_any and not any(r.region_class in requires_any for r in regions):
            continue
        for region in regions:
            if region.producer_id != "unknown" and region.region_class != "unknown_data":
                continue
            if not _is_whole_file_span(region, file_size):
                continue
            violations.append(
                {
                    "code": "generic_whole_file_takeover",
                    "format_plugin": format_plugin,
                    "region": region.to_dict(),
                    "message": "Generic unknown producer owns the entire file while higher-priority regions were expected.",
                }
            )

    if len(regions) == 1 and has_high_priority is False and format_plugin == "pe":
        only = regions[0]
        if _is_whole_file_span(only, file_size) and only.region_class == "unknown_data":
            violations.append(
                {
                    "code": "pe_collapsed_to_whole_unknown",
                    "format_plugin": format_plugin,
                    "region": only.to_dict(),
                    "message": "PE file mapped to a single whole-file unknown region; pe_sections routing failed.",
                }
            )

    exec_regions = [r for r in regions if r.region_class == "executable_code"]
    if format_plugin == "pe" and not exec_regions and file_size > 0:
        meta = dict((regions[0].meta if regions else {}) or {})
        if meta.get("strategy") != "pe_sections_error":
            violations.append(
                {
                    "code": "pe_missing_executable_region",
                    "format_plugin": format_plugin,
                    "message": "No executable_code region present for PE file.",
                }
            )

    return violations


def format_plugin_from_regions(regions: Sequence[RegionSpan]) -> str:
    for region in regions:
        if str(region.format_plugin or "") not in {"", "unknown"}:
            return str(region.format_plugin)
    return "unknown"
