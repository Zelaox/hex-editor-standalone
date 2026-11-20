"""Rotate-right transform."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping

from src.services.transforms.base import TransformProbeContext
from src.services.transforms.common import score_transform_windows


def _rol_byte(byte: int, bits: int) -> int:
    bits = int(bits) & 7
    if bits == 0:
        return byte
    return ((byte << bits) | (byte >> (8 - bits))) & 0xFF


def _ror_inverse(data: bytes, bits: int) -> bytes:
    return bytes(_rol_byte(byte, bits) for byte in data)


def cheap_probe(ctx: TransformProbeContext) -> List[Dict[str, Any]]:
    max_bits = 7
    family = (ctx.registry.get("families_by_id") or {}).get("ror") or {}
    max_bits = int((family.get("keyspace") or {}).get("max_bits") or max_bits)
    results: List[Dict[str, Any]] = []
    for bits in range(1, max_bits + 1):
        results.append(
            score_transform_windows(
                ctx,
                transform_fn=lambda data, b=bits: _ror_inverse(data, b),
                profile_name="byte_arith",
                name=f"ror_{bits}",
                algorithm="ror",
                key_hex=f"{bits:02x}",
                provenance=f"rotate right inverse bits={bits}",
                parameters={"bits": bits},
            )
        )
    return results


def materialize(ctx: TransformProbeContext, candidate: Mapping[str, Any]) -> bytes:
    bits = int(dict(candidate.get("parameters") or {}).get("bits") or int(str(candidate.get("key_hex") or "1"), 16))
    body = _ror_inverse(ctx.raw[ctx.xor_start :], bits)
    return ctx.raw[: ctx.xor_start] + body


def stage2_evidence(ctx: TransformProbeContext, candidate: Mapping[str, Any]) -> Dict[str, Any]:
    return dict(candidate)
