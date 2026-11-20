"""Nibble swap transform."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping

from src.services.transforms.base import TransformProbeContext
from src.services.transforms.common import score_transform_windows


def _nibble_swap(data: bytes) -> bytes:
    return bytes(((byte >> 4) | ((byte << 4) & 0xF0)) & 0xFF for byte in data)


def cheap_probe(ctx: TransformProbeContext) -> List[Dict[str, Any]]:
    return [
        score_transform_windows(
            ctx,
            transform_fn=_nibble_swap,
            profile_name="byte_arith",
            name="nibble_swap",
            algorithm="nibble_swap",
            key_hex="00",
            provenance="nibble swap (self-inverse)",
        )
    ]


def materialize(ctx: TransformProbeContext, candidate: Mapping[str, Any]) -> bytes:
    body = _nibble_swap(ctx.raw[ctx.xor_start :])
    return ctx.raw[: ctx.xor_start] + body


def stage2_evidence(ctx: TransformProbeContext, candidate: Mapping[str, Any]) -> Dict[str, Any]:
    return dict(candidate)
