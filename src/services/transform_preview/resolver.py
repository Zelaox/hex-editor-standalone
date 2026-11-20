"""Resolve evidence-backed preview descriptors for a source range."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

from src.services.transform_preview.contracts import PartitionResult, PreviewDescriptor, PreviewSpan


def _cid(prefix: str, payload: Mapping[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return f"{prefix}-{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"


def _overlap(a_start: int, a_len: int, b_start: int, b_len: int) -> bool:
    a_end, b_end = a_start + a_len, b_start + b_len
    return a_start < b_end and b_start < a_end


def _clip_span(offset: int, length: int, *, range_offset: int, range_length: int) -> Optional[tuple[int, int]]:
    start = max(offset, range_offset)
    end = min(offset + length, range_offset + range_length)
    if start >= end:
        return None
    return start, end - start


def _load_proof_artifacts(inspected: Mapping[str, Any], run_root: Path) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    artifacts = dict(inspected.get("artifacts") or {})
    candidate_file = Path(str(artifacts.get("candidate") or ""))
    candidate_root = candidate_file.parent if candidate_file.is_file() else run_root
    proof_path = candidate_root / "proof_spans.json"
    inverse_path = candidate_root / "inverse.json"
    if not proof_path.is_file():
        proof_path = Path(str(artifacts.get("proof_spans") or ""))
    if not inverse_path.is_file():
        inverse_path = Path(str(artifacts.get("inverse") or ""))
    proof_spans = json.loads(proof_path.read_text(encoding="utf-8")) if proof_path.is_file() else []
    inverse = json.loads(inverse_path.read_text(encoding="utf-8")) if inverse_path.is_file() else []
    return list(proof_spans), list(inverse)


def descriptors_from_full_decode(
    inspected: Mapping[str, Any],
    *,
    source_sha256: str,
    parent_sha256: str,
    range_offset: int,
    range_length: int,
    inverse_by_offset: Mapping[int, Mapping[str, Any]],
) -> PartitionResult:
    run_root = Path(str(inspected.get("run_root") or ""))
    proof_spans, inverse = _load_proof_artifacts(inspected, run_root)
    inverse_map = {int(item["offset"]): item for item in inverse}
    descriptors: List[PreviewDescriptor] = []
    preview_spans: List[PreviewSpan] = []
    conflicts: List[Dict[str, Any]] = []
    covered: List[tuple[int, int]] = []

    for proof in proof_spans:
        offset, length = int(proof["offset"]), int(proof["length"])
        clipped = _clip_span(offset, length, range_offset=range_offset, range_length=range_length)
        if clipped is None:
            continue
        local_offset, local_length = clipped
        overlap_hits = [item for item in covered if _overlap(local_offset, local_length, item[0], item[1])]
        if overlap_hits:
            conflicts.append(
                {
                    "kind": "overlapping_proof_span",
                    "offset": local_offset,
                    "length": local_length,
                    "scope_id": proof.get("scope_id"),
                    "conflict_with": overlap_hits,
                }
            )
            continue
        covered.append((local_offset, local_length))
        inverse_entry = inverse_map.get(offset) or inverse_by_offset.get(offset) or {}
        step_id = str(inverse_entry.get("inverse_id") or proof.get("scope_id") or "")
        descriptor: PreviewDescriptor = {
            "schema_version": 1,
            "descriptor_id": str(proof.get("scope_id") or _cid("preview-descriptor", proof)),
            "source_sha256": source_sha256,
            "parent_sha256": parent_sha256,
            "offset": local_offset,
            "length": local_length,
            "scope_id": str(proof.get("scope_id") or ""),
            "proof_id": str(proof.get("proof_id") or ""),
            "provider_id": str(proof.get("provider_id") or ""),
            "truth_state": "verified",
            "mapping_kind": "block",
            "steps": [
                {
                    "step_id": step_id,
                    "family_id": str(proof.get("provider_id") or "materialization"),
                    "operation": "materialize_scope",
                    "offset": local_offset,
                    "length": local_length,
                }
            ],
        }
        descriptors.append(descriptor)
        preview_spans.append(
            {
                "offset": local_offset,
                "length": local_length,
                "presentation_class": "preview_plaintext",
                "descriptor_id": descriptor["descriptor_id"],
                "truth_state": "verified",
            }
        )

    gaps: List[PreviewSpan] = []
    cursor = range_offset
    range_end = range_offset + range_length
    for start, length in sorted(covered):
        if start > cursor:
            gaps.append(
                {
                    "offset": cursor,
                    "length": start - cursor,
                    "presentation_class": "raw_plaintext",
                    "truth_state": "source",
                }
            )
        cursor = max(cursor, start + length)
    if cursor < range_end:
        gaps.append(
            {
                "offset": cursor,
                "length": range_end - cursor,
                "presentation_class": "raw_plaintext",
                "truth_state": "source",
            }
        )

    ordered_spans = sorted(preview_spans + gaps, key=lambda item: (int(item["offset"]), str(item.get("presentation_class") or "")))

    return {"spans": ordered_spans, "descriptors": descriptors, "conflicts": conflicts, "gaps": gaps}


def partition_range(
    *,
    inspected: Mapping[str, Any],
    source_sha256: str,
    parent_sha256: str,
    range_offset: int,
    range_length: int,
    scope_sources: Sequence[str],
) -> PartitionResult:
    if "full_decode_proof_spans" not in scope_sources:
        return {"spans": [], "descriptors": [], "conflicts": [], "gaps": []}
    _, inverse = _load_proof_artifacts(inspected, Path(str(inspected.get("run_root") or "")))
    inverse_by_offset = {int(item["offset"]): item for item in inverse}
    return descriptors_from_full_decode(
        inspected,
        source_sha256=source_sha256,
        parent_sha256=parent_sha256,
        range_offset=range_offset,
        range_length=range_length,
        inverse_by_offset=inverse_by_offset,
    )
