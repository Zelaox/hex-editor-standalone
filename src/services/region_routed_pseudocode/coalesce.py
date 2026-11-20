"""Coalesce raw regions to prevent producer thrashing."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Sequence, Tuple

from .region_map import RegionSpan


def _compatible(producer_a: str, producer_b: str, merge_policy: Mapping[str, Any]) -> bool:
    if producer_a == producer_b:
        return True
    groups = merge_policy.get("coalescence", {}).get("compatible_producer_groups") or []
    for group in groups:
        names = {str(item) for item in group}
        if producer_a in names and producer_b in names:
            return True
    return False


def coalesce_regions(
    regions: Sequence[RegionSpan],
    *,
    merge_policy: Mapping[str, Any],
    file_size: int,
) -> Tuple[List[RegionSpan], Dict[str, Any]]:
    cfg = dict(merge_policy.get("coalescence") or {})
    if not bool(cfg.get("enabled")):
        return list(regions), {"coalesced": False, "steps": []}

    max_raw = int(cfg.get("max_raw_regions_after_classify") or 0)
    if max_raw > 0 and len(regions) > max_raw:
        raise ValueError(f"region_map_truncated: raw regions {len(regions)} exceed max_raw_regions_after_classify")

    min_emit = int(cfg.get("min_emit_span_bytes") or 0)
    same_producer = bool(cfg.get("coalesce_adjacent_same_producer"))
    compatible = bool(cfg.get("coalesce_adjacent_compatible_producer"))
    audit_steps: List[Dict[str, Any]] = []

    ordered = sorted(regions, key=lambda item: (item.offset, item.length))
    merged: List[RegionSpan] = []
    for region in ordered:
        if not merged:
            merged.append(region)
            continue
        prev = merged[-1]
        if (prev.meta or {}).get("ledger_blocks_merge") or (region.meta or {}).get("ledger_blocks_merge"):
            merged.append(region)
            continue
        if prev.region_class == "executable_code" or region.region_class == "executable_code":
            if prev.producer_id != region.producer_id or prev.region_class != region.region_class:
                merged.append(region)
                continue
        adjacent = prev.offset + prev.length == region.offset
        can_merge = adjacent and (
            (same_producer and prev.producer_id == region.producer_id and prev.region_class == region.region_class)
            or (compatible and _compatible(prev.producer_id, region.producer_id, merge_policy) and prev.region_class == region.region_class)
        )
        if can_merge or (adjacent and min_emit > 0 and (prev.length < min_emit or region.length < min_emit)):
            combined = RegionSpan(
                offset=prev.offset,
                length=prev.length + region.length,
                region_class=prev.region_class if prev.region_class == region.region_class else region.region_class,
                producer_id=prev.producer_id if prev.producer_id == region.producer_id else str(cfg.get("micro_gap_fill_producer_id") or prev.producer_id),
                format_plugin=prev.format_plugin or region.format_plugin,
                confidence=max(prev.confidence, region.confidence),
                meta={"coalesced_from": [prev.to_dict(), region.to_dict()]},
            )
            merged[-1] = combined
            audit_steps.append({"action": "merge_adjacent", "offset": combined.offset, "length": combined.length})
            continue
        merged.append(region)

    max_switches = int(cfg.get("max_producer_switches_per_document") or 0)
    if max_switches > 0:
        switches = 0
        last_producer = None
        for region in merged:
            if last_producer is not None and region.producer_id != last_producer:
                switches += 1
            last_producer = region.producer_id
        if switches > max_switches:
            raise ValueError(f"producer_switch_cap_exceeded: {switches} > {max_switches}")

    max_view = int(cfg.get("max_regions_in_pseudocode_view") or 0)
    if max_view > 0 and len(merged) > max_view:
        head = merged[: max_view - 1]
        tail = merged[max_view - 1 :]
        if tail:
            start = tail[0].offset
            end = max(item.offset + item.length for item in tail)
            summary = RegionSpan(
                offset=start,
                length=max(0, end - start),
                region_class="unknown_data",
                producer_id=str(cfg.get("micro_gap_fill_producer_id") or "unknown"),
                format_plugin=tail[0].format_plugin,
                confidence=min(item.confidence for item in tail),
                meta={"collapsed_region_count": len(tail), "strategy": "view_budget"},
            )
            merged = head + [summary]
            audit_steps.append({"action": "collapse_for_view_budget", "collapsed": len(tail)})

    _assert_full_coverage(merged, file_size=file_size)
    return merged, {"coalesced": True, "steps": audit_steps}


def _assert_full_coverage(regions: Sequence[RegionSpan], *, file_size: int) -> None:
    if file_size <= 0:
        return
    cursor = 0
    for region in sorted(regions, key=lambda item: item.offset):
        if region.offset > cursor:
            raise ValueError(f"coalescence left uncovered gap at {cursor}")
        cursor = max(cursor, region.offset + region.length)
    if cursor < file_size:
        raise ValueError(f"coalescence left trailing uncovered bytes from {cursor} to {file_size}")
