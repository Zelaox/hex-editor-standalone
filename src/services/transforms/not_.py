"""Bitwise NOT transform."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping

from src.services.transforms.base import TransformProbeContext
from src.services.transforms.common import score_transform_windows


def cheap_probe(ctx: TransformProbeContext) -> List[Dict[str, Any]]:
    return [
        score_transform_windows(
            ctx,
            transform_fn=lambda data: bytes(b ^ 0xFF for b in data),
            profile_name="byte_arith",
            name="not",
            algorithm="not",
            key_hex="00",
            provenance="bitwise NOT",
        )
    ]


def materialize(ctx: TransformProbeContext, candidate: Mapping[str, Any]) -> bytes:
    body = bytes(b ^ 0xFF for b in ctx.raw[ctx.xor_start :])
    return ctx.raw[: ctx.xor_start] + body


def stage2_evidence(ctx: TransformProbeContext, candidate: Mapping[str, Any]) -> Dict[str, Any]:
    return dict(candidate)
