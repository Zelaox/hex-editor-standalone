"""Byte SUB transform."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping

from src.services.transforms.base import TransformProbeContext
from src.services.transforms.common import score_transform_windows


def _sub_byte(data: bytes, subtrahend: int) -> bytes:
    value = int(subtrahend) & 0xFF
    return bytes((byte + value) & 0xFF for byte in data)


def cheap_probe(ctx: TransformProbeContext) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    step = max(1, 256 // 16)
    for subtrahend in range(0, 256, step):
        results.append(
            score_transform_windows(
                ctx,
                transform_fn=lambda data, s=subtrahend: _sub_byte(data, s),
                profile_name="byte_arith",
                name=f"sub_byte_0x{subtrahend:02x}",
                algorithm="sub_byte",
                key_hex=f"{subtrahend:02x}",
                provenance="single-byte sub inverse",
                parameters={"subtrahend": subtrahend},
            )
        )
    return results


def materialize(ctx: TransformProbeContext, candidate: Mapping[str, Any]) -> bytes:
    subtrahend = int(dict(candidate.get("parameters") or {}).get("subtrahend") or int(str(candidate.get("key_hex") or "0"), 16))
    body = _sub_byte(ctx.raw[ctx.xor_start :], subtrahend)
    return ctx.raw[: ctx.xor_start] + body


def stage2_evidence(ctx: TransformProbeContext, candidate: Mapping[str, Any]) -> Dict[str, Any]:
    return dict(candidate)
