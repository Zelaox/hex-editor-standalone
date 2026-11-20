"""Mechanical byte-level diff spans for source/candidate pair overlays."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Sequence


def _cap_spans(spans: Sequence[Dict[str, Any]], policy: Mapping[str, Any]) -> List[Dict[str, Any]]:
    max_spans = int((policy.get("load_budgets") or {}).get("max_forensic_overlay_spans") or 0)
    if max_spans <= 0 or len(spans) <= max_spans:
        return list(spans)
    priority = list((policy.get("hex_overlays") or {}).get("overlay_priority") or [])

    def sort_key(item: Mapping[str, Any]) -> tuple:
        role = str(item.get("role") or "")
        role_rank = priority.index(role) if role in priority else len(priority)
        return (role_rank, -int(item.get("length") or 0), int(item.get("offset") or 0))

    ranked = sorted(spans, key=sort_key)
    return ranked[:max_spans]


def build_pair_diff_spans(
    source: bytes,
    candidate: bytes,
    *,
    policy: Mapping[str, Any],
) -> List[Dict[str, Any]]:
    if len(source) != len(candidate):
        raise ValueError("source and candidate must have equal length for pair diff overlays")
    if not source:
        return []

    priority = list((policy.get("hex_overlays") or {}).get("overlay_priority") or [])
    spans: List[Dict[str, Any]] = []
    index = 0
    total = len(source)
    while index < total:
        unchanged = source[index] == candidate[index]
        end = index + 1
        while end < total and (source[end] == candidate[end]) == unchanged:
            end += 1
        role = "preserve" if unchanged else "candidate_body"
        token = "binary_waterfall.preserve" if unchanged else "binary_waterfall.candidate_body"
        spans.append(
            {
                "offset": index,
                "length": end - index,
                "theme_token": token,
                "role": role,
                "source_id": "pair_diff",
                "priority": priority.index(role) if role in priority else len(priority),
            }
        )
        index = end

    return _cap_spans(spans, policy)


def count_changed_bytes(source: bytes, candidate: bytes) -> int:
    if len(source) != len(candidate):
        raise ValueError("source and candidate must have equal length")
    return sum(1 for left, right in zip(source, candidate) if left != right)
