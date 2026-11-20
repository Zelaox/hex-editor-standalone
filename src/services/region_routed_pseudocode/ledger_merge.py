"""Apply learning DB proof spans to region maps (ledger-protected spans)."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Sequence

from .region_map import RegionSpan


def _overlaps(a_start: int, a_len: int, b_start: int, b_len: int) -> bool:
    a_end = a_start + a_len
    b_end = b_start + b_len
    return not (a_end <= b_start or b_end <= a_start)


def load_proof_spans_for_source(source_sha256: str, *, limit: int, enabled: bool) -> List[Dict[str, Any]]:
    if not enabled or not source_sha256:
        return []
    try:
        from src.services.learning_db.core import query_learning_db

        result = query_learning_db(
            "proof_spans",
            filters={"source_sha256": source_sha256},
            order_by="indexed_at",
            limit=limit,
        )
        return list(result.get("rows") or [])
    except Exception:
        return []


def apply_ledger_to_regions(
    regions: Sequence[RegionSpan],
    proof_rows: Sequence[Mapping[str, Any]],
    *,
    merge_policy: Mapping[str, Any],
) -> List[RegionSpan]:
    if not proof_rows:
        return list(regions)
    overlap_cfg = dict(merge_policy.get("overlap_resolution") or {})
    ledger_blocks = bool(overlap_cfg.get("ledger_blocks_merge", True))
    adjusted: List[RegionSpan] = []
    for region in regions:
        protected_refs: List[Dict[str, Any]] = []
        for row in proof_rows:
            span_offset = int(row.get("span_offset") or 0)
            span_length = int(row.get("span_length") or 0)
            if not _overlaps(region.offset, region.length, span_offset, span_length):
                continue
            protected_refs.append(
                {
                    "proof_span_id": row.get("proof_span_id"),
                    "coverage_class": row.get("coverage_class"),
                    "truth_state": row.get("truth_state"),
                    "span_offset": span_offset,
                    "span_length": span_length,
                }
            )
        meta = dict(region.meta or {})
        if protected_refs:
            meta["ledger_protected"] = True
            meta["ledger_refs"] = protected_refs
            meta["ledger_blocks_merge"] = ledger_blocks
        adjusted.append(
            RegionSpan(
                offset=region.offset,
                length=region.length,
                region_class=region.region_class,
                producer_id=region.producer_id,
                format_plugin=region.format_plugin,
                confidence=region.confidence,
                meta=meta,
            )
        )
    return adjusted
