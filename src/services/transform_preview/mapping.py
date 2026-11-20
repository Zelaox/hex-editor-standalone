"""Source/output mapping composition for transform preview."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Sequence

from src.services.transform_preview.contracts import PreviewDescriptor, PreviewMapping, PreviewSpan


def mappings_for_spans(
    *,
    spans: Sequence[PreviewSpan],
    range_offset: int,
    range_length: int,
) -> List[PreviewMapping]:
    mappings: List[PreviewMapping] = []
    output_cursor = 0
    for span in spans:
        offset = int(span["offset"])
        length = int(span["length"])
        local_start = offset - range_offset
        presentation = str(span.get("presentation_class") or "raw_plaintext")
        if presentation == "preview_plaintext":
            kind = "block"
            exact = False
        else:
            kind = "one_to_one"
            exact = True
        mappings.append(
            {
                "kind": kind,
                "source_offset": offset,
                "source_length": length,
                "output_offset": output_cursor,
                "output_length": length,
                "step_id": str(span.get("descriptor_id") or ""),
                "presentation_class": presentation,
                "exact": exact,
            }
        )
        output_cursor += length
    if output_cursor != range_length:
        mappings.append(
            {
                "kind": "unmapped",
                "source_offset": range_offset + output_cursor,
                "source_length": max(0, range_length - output_cursor),
                "output_offset": output_cursor,
                "output_length": max(0, range_length - output_cursor),
                "presentation_class": "unresolved",
                "exact": False,
            }
        )
    return mappings


def compose_chain_mappings(
    span_mappings: Sequence[PreviewMapping],
    chain_mappings: Sequence[Mapping[str, Any]],
) -> List[PreviewMapping]:
    combined = list(span_mappings)
    for item in chain_mappings:
        combined.append(dict(item))
    return combined


def reject_unmapped_length_change(
    *,
    source_length: int,
    output_length: int,
    chain_mappings: Sequence[Mapping[str, Any]],
) -> bool:
    if source_length == output_length:
        return True
    return any(str(item.get("kind") or "") == "block" for item in chain_mappings)


def aggregate_mapping(
    mappings: Sequence[PreviewMapping],
    *,
    range_offset: int,
    output_length: int,
) -> Dict[str, Any]:
    if not mappings:
        return {
            "kind": "one_to_one",
            "source_offset": range_offset,
            "source_length": output_length,
            "output_offset": 0,
            "output_length": output_length,
            "segments": [],
        }
    return {
        "kind": "composite",
        "source_offset": range_offset,
        "source_length": output_length,
        "output_offset": 0,
        "output_length": output_length,
        "segments": list(mappings),
    }
