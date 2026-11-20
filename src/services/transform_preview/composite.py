"""Composite span assembly for transform preview."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Sequence, Tuple

from src.services.transform_preview.contracts import PreviewSpan


def _decode_piece(data: bytes, encodings: Sequence[str]) -> str | None:
    for encoding in encodings:
        try:
            return data.decode(str(encoding), errors="strict")
        except (LookupError, UnicodeDecodeError):
            continue
    return None


def _label_for_span(span: Mapping[str, Any], policy: Mapping[str, Any]) -> str:
    labels = dict(policy.get("truth_labels") or {})
    presentation = str(span.get("presentation_class") or "unresolved")
    return str(labels.get(presentation) or presentation)


def assemble_composite_text(
    *,
    raw: bytes,
    output: bytes,
    spans: Sequence[PreviewSpan],
    conflicts: Sequence[Mapping[str, Any]],
    policy: Mapping[str, Any],
    range_offset: int,
) -> Tuple[str, List[Dict[str, Any]], List[Dict[str, Any]]]:
    encodings = list(map(str, policy.get("text_encodings") or []))
    label_format = str(policy.get("span_label_format") or "[{label}] {text}")
    rows: List[Dict[str, Any]] = []
    parts: List[str] = []
    ordered = sorted(list(spans or []), key=lambda item: (int(item["offset"]), str(item.get("presentation_class") or "")))

    for span in ordered:
        offset = int(span["offset"])
        length = int(span["length"])
        local_start = offset - range_offset
        local_end = local_start + length
        if local_start < 0 or local_end > len(raw):
            continue
        presentation = str(span.get("presentation_class") or "unresolved")
        label = _label_for_span(span, policy)
        if presentation in {"preview_plaintext", "materialized_plaintext"}:
            piece = output[local_start:local_end]
        elif presentation in {"raw_plaintext", "semantic_field"}:
            piece = raw[local_start:local_end]
        else:
            piece = output[local_start:local_end] if local_end <= len(output) else raw[local_start:local_end]

        decoded = _decode_piece(piece, encodings) if presentation.endswith("_plaintext") or presentation == "semantic_field" else None
        if decoded is not None:
            text = decoded
        elif presentation == "unresolved":
            text = str(policy["unresolved_placeholder"]).format(offset_hex=f"0x{offset:X}", length=length)
        elif presentation == "conflict":
            text = str(policy.get("conflict_placeholder") or policy["unresolved_placeholder"]).format(
                offset_hex=f"0x{offset:X}",
                length=length,
            )
        else:
            text = str(policy["binary_placeholder"]).format(
                offset_hex=f"0x{offset:X}",
                length=length,
                classification=presentation,
            )
        rendered = label_format.format(label=label, text=text)
        parts.append(rendered)
        rows.append(
            {
                "offset": offset,
                "length": length,
                "presentation_class": presentation,
                "truth_label": label,
                "text": text,
                "rendered": rendered,
                "descriptor_id": span.get("descriptor_id"),
            }
        )

    for conflict in conflicts or []:
        offset = int(conflict.get("offset") or range_offset)
        length = int(conflict.get("length") or 0)
        label = _label_for_span({"presentation_class": "conflict"}, policy)
        text = str(policy.get("conflict_placeholder") or policy["unresolved_placeholder"]).format(
            offset_hex=f"0x{offset:X}",
            length=length,
        )
        rendered = label_format.format(label=label, text=text)
        parts.append(rendered)
        rows.append(
            {
                "offset": offset,
                "length": length,
                "presentation_class": "conflict",
                "truth_label": label,
                "text": text,
                "rendered": rendered,
                "conflict_kind": conflict.get("kind"),
            }
        )

    if not parts:
        decoded = _decode_piece(output, encodings)
        if decoded is not None:
            return decoded, rows, [{"kind": "full_range", "exact": True}]
        return str(policy["binary_placeholder"]).format(
            offset_hex=f"0x{range_offset:X}",
            length=len(output),
            classification="binary",
        ), rows, [{"kind": "full_range", "exact": False}]

    coverage_rows = _coverage_accounting(range_offset=range_offset, range_length=len(raw), rows=rows)
    return "\n".join(parts), rows, coverage_rows


def _coverage_accounting(
    *,
    range_offset: int,
    range_length: int,
    rows: Sequence[Mapping[str, Any]],
) -> List[Dict[str, Any]]:
    covered: List[tuple[int, int]] = []
    for row in rows:
        if str(row.get("presentation_class") or "") == "conflict":
            continue
        covered.append((int(row["offset"]), int(row["length"])))
    covered.sort()
    gaps: List[Dict[str, Any]] = []
    cursor = range_offset
    end = range_offset + range_length
    for start, length in covered:
        if start > cursor:
            gaps.append({"offset": cursor, "length": start - cursor, "kind": "uncovered_gap"})
        cursor = max(cursor, start + length)
    if cursor < end:
        gaps.append({"offset": cursor, "length": end - cursor, "kind": "uncovered_gap"})
    return gaps
