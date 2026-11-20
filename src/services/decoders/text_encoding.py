"""Text encoding decoder hooks for the representation layer."""

from __future__ import annotations

from typing import Any, Dict, Mapping

from src.services.text_encoding import analyze_bytes


def decode_text_candidate(
    data: bytes,
    *,
    policy: Mapping[str, Any],
    family: Mapping[str, Any],
    offset: int = 0,
) -> Dict[str, Any]:
    parameters = dict(family.get("resolved_parameters") or family.get("parameters") or {})
    encoding = str(parameters.get("encoding") or "")
    if not encoding:
        raise ValueError(f"decoder {family.get('id')}: encoding parameter required")
    text_cfg = dict(policy.get("text_decoders") or {})
    errors = str(text_cfg.get("errors_mode") or "replace")
    max_preview = int(dict(policy.get("budgets") or {})["max_preview_chars"])
    result = analyze_bytes(data, encoding=encoding, errors=errors, offset=offset)
    preview = str(result.get("decoded_text") or "")[:max_preview]
    escaped = "".join(ch if ch.isprintable() and ch not in "\x00\r\n" else "." for ch in preview)
    return {
        "decoder_id": str(family.get("id") or ""),
        "kind": "text",
        "encoding": encoding,
        "valid": result.get("decode_error") is None or errors != "strict",
        "preview": preview,
        "escaped": escaped,
        "replacement_count": int(result.get("replacement_count") or 0),
        "bom_detected": result.get("bom_detected"),
        "error_detail": result.get("decode_error"),
    }
