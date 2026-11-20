"""Hex overlay spans for transform preview scopes and conflicts."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Sequence


def build_transform_preview_overlay_spans(
    preview: Mapping[str, Any],
    *,
    ui_policy: Mapping[str, Any],
) -> List[Dict[str, Any]]:
    from src.services.ui_policy import hex_overlay_enabled, load_budget

    if not hex_overlay_enabled(ui_policy, "show_transform_preview_scopes"):
        return []
    priority = list((ui_policy.get("hex_overlays") or {}).get("overlay_priority") or [])
    theme = dict(ui_policy.get("theme_tokens") or {})
    spans: List[Dict[str, Any]] = []

    def add_span(offset: int, length: int, role: str, token: str, source_id: str = "") -> None:
        if length <= 0:
            return
        spans.append(
            {
                "offset": int(offset),
                "length": int(length),
                "theme_token": token,
                "role": role,
                "source_id": source_id,
                "priority": priority.index(role) if role in priority else len(priority),
            }
        )

    for span in preview.get("composite_spans") or []:
        presentation = str(span.get("presentation_class") or "")
        if presentation == "preview_plaintext":
            token = str(theme.get("transform_preview.scope") or "binary_waterfall.transform_preview_supported")
            add_span(int(span["offset"]), int(span["length"]), "transform_preview_scope", token, str(span.get("descriptor_id") or ""))
        elif presentation == "raw_plaintext":
            token = str(theme.get("transform_preview.raw_gap") or "binary_waterfall.preserve")
            add_span(int(span["offset"]), int(span["length"]), "transform_preview_raw", token)

    for conflict in preview.get("conflicts") or []:
        token = str(theme.get("transform_preview.conflict") or "binary_waterfall.unresolved")
        add_span(int(conflict.get("offset") or 0), int(conflict.get("length") or 0), "transform_preview_conflict", token, str(conflict.get("kind") or ""))

    spans.sort(key=lambda item: (-int(item.get("priority") or 0), int(item.get("offset") or 0)))
    max_spans = load_budget(ui_policy, "max_forensic_overlay_spans")
    if max_spans > 0 and len(spans) > max_spans:
        spans = spans[:max_spans]
    return spans
