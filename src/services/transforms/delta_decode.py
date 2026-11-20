"""Delta decode transform."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping

from src.services.transforms.base import TransformProbeContext
from src.services.transforms.common import score_transform_windows


def _delta_decode(data: bytes) -> bytes:
    if not data:
        return data
    out = bytearray(len(data))
    out[0] = data[0]
    for index in range(1, len(data)):
        out[index] = (data[index] - data[index - 1]) & 0xFF
    return bytes(out)


def cheap_probe(ctx: TransformProbeContext) -> List[Dict[str, Any]]:
    return [
        score_transform_windows(
            ctx,
            transform_fn=_delta_decode,
            profile_name="byte_arith",
            name="delta_decode",
            algorithm="delta_decode",
            key_hex="00",
            provenance="adjacent delta decode",
        )
    ]


def materialize(ctx: TransformProbeContext, candidate: Mapping[str, Any]) -> bytes:
    body = _delta_decode(ctx.raw[ctx.xor_start :])
    return ctx.raw[: ctx.xor_start] + body


def stage2_evidence(ctx: TransformProbeContext, candidate: Mapping[str, Any]) -> Dict[str, Any]:
    return dict(candidate)
