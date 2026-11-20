"""Delegate unknown/text-heavy regions to the legacy semantic pseudocode fallback."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Mapping

from .region_map import RegionSpan


def _routing_uses_semantic_fallback(routing: Mapping[str, Any]) -> bool:
    unknown_cfg = dict(routing.get("unknown_producer") or {})
    return str(unknown_cfg.get("strategy") or "") == "semantic_fallback"


def _whole_file_region(region: RegionSpan, file_size: int) -> bool:
    return file_size > 0 and int(region.offset) == 0 and int(region.length) >= file_size


def render_semantic_fallback_for_region(
    path: Path,
    data: bytes,
    region: RegionSpan,
    *,
    routing: Mapping[str, Any],
    merge_policy: Mapping[str, Any] | None = None,
) -> List[str] | None:
    if not _routing_uses_semantic_fallback(routing):
        return None
    if str(region.region_class or "") == "executable_code":
        return None
    file_size = len(data)
    if (region.meta or {}).get("strategy") == "gap_fill":
        gap_cfg = dict((merge_policy or {}).get("gap_unknown_producer") or {})
        if str(gap_cfg.get("strategy") or "") == "bytes_only":
            return None
    if merge_policy is not None and _whole_file_region(region, file_size):
        forbidden = list(merge_policy.get("generic_whole_file_forbidden_when") or [])
        for rule in forbidden:
            if not isinstance(rule, Mapping):
                continue
            plugin = str(rule.get("format_plugin") or "")
            if plugin and plugin != str(region.format_plugin or ""):
                continue
            return None
    unknown_modes = dict((merge_policy or {}).get("producer_modes") or {}).get("unknown") or {}
    if str(unknown_modes.get("semantic_fallback") or "") == "scoped_only" and _whole_file_region(region, file_size):
        if str(region.format_plugin or "") == "pe":
            return None
    unknown_cfg = dict(routing.get("unknown_producer") or {})
    rel = str(unknown_cfg.get("semantic_policy_path") or "config/semantic_pseudocode_policy.json")
    policy_path = Path(rel)
    if not policy_path.is_absolute():
        policy_path = Path(__file__).resolve().parents[3] / rel

    from src.services.semantic_pseudocode import (
        load_semantic_pseudocode_policy,
        render_semantic_fallback_for_byte_range,
    )

    policy = load_semantic_pseudocode_policy(policy_path)
    lines = render_semantic_fallback_for_byte_range(
        path,
        offset=int(region.offset),
        length=int(region.length),
        policy=policy,
    )
    header = f"/* unknown_data semantic_fallback @ 0x{region.offset:X}[{region.length}] plugin={region.format_plugin} */"
    return [header] + lines
