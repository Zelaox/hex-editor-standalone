"""Shared cheap-probe helpers for transform families."""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

from src.services.transform_scoring import score_window
from src.services.transforms.base import TransformProbeContext, read_window


def score_transform_windows(
    ctx: TransformProbeContext,
    *,
    transform_fn: Callable[[bytes], bytes],
    profile_name: str,
    name: str,
    algorithm: str,
    key_hex: str,
    provenance: str,
    key_length: int = 1,
    parameters: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    window_scores: List[Dict[str, Any]] = []
    total = 0
    for window in ctx.body_windows:
        cipher, start = read_window(ctx.raw, int(window.get("offset") or 0), int(window.get("length") or 4096))
        if not cipher:
            continue
        transformed = transform_fn(cipher)
        scored = score_window(
            cipher,
            transformed,
            region_name=str(window.get("name") or hex(start)),
            profile_name=profile_name,
            defaults=ctx.defaults,
        )
        window_scores.append(
            {
                **scored,
                "offset": start,
                "length": len(cipher),
                "excluded_cleartext_only": bool(window.get("excluded_cleartext_only")),
            }
        )
        total += int(scored.get("score") or 0)
    cheap_identity = bool(window_scores) and all(item.get("identity") for item in window_scores)
    return {
        "name": name,
        "algorithm": algorithm,
        "key_hex": key_hex,
        "key_length": key_length,
        "score": total,
        "window_scores": window_scores,
        "marker_hits": sorted({hit for item in window_scores for hit in item.get("marker_hits") or []}),
        "printable_ratio": max((float(item.get("printable_ratio") or 0) for item in window_scores), default=0.0),
        "provenance": provenance,
        "cheap_only": True,
        "cheap_identity": cheap_identity,
        "parameters": dict(parameters or {}),
        "family_id": algorithm,
    }
