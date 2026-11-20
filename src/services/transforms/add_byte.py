"""Byte ADD transform."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping

from src.services.transforms.base import TransformProbeContext
from src.services.transforms.common import score_transform_windows


def _add_byte(data: bytes, addend: int) -> bytes:
    value = int(addend) & 0xFF
    return bytes((byte - value) & 0xFF for byte in data)


def cheap_probe(ctx: TransformProbeContext) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    step = max(1, 256 // 16)
    for addend in range(0, 256, step):
        results.append(
            score_transform_windows(
                ctx,
                transform_fn=lambda data, a=addend: _add_byte(data, a),
                profile_name="byte_arith",
                name=f"add_byte_0x{addend:02x}",
                algorithm="add_byte",
                key_hex=f"{addend:02x}",
                provenance="single-byte add inverse",
                parameters={"addend": addend},
            )
        )
    return results


def materialize(ctx: TransformProbeContext, candidate: Mapping[str, Any]) -> bytes:
    addend = int(dict(candidate.get("parameters") or {}).get("addend") or int(str(candidate.get("key_hex") or "0"), 16))
    body = _add_byte(ctx.raw[ctx.xor_start :], addend)
    return ctx.raw[: ctx.xor_start] + body


def stage2_evidence(ctx: TransformProbeContext, candidate: Mapping[str, Any]) -> Dict[str, Any]:
    return dict(candidate)
