"""Bounded XOR sweep — single-byte and 2-byte repeating (L≤2)."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Sequence

from src.services.ptx_crypto_analysis import decode_sweep_cursor, materialize_xor_copy
from src.services.ptx_crypto_primitives import xor_apply
from src.services.transforms.base import TransformProbeContext
from src.services.transforms.common import score_transform_windows


def cheap_probe_batch(
    ctx: TransformProbeContext,
    *,
    cursor: int,
    batch: int,
    single_byte_limit: int,
) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    end = min(int(cursor) + max(1, int(batch)), int(ctx.pipeline.get("sweep_key_limit") or 2560))
    for sweep_index in range(int(cursor), end):
        decoded = decode_sweep_cursor(sweep_index, single_byte_limit=single_byte_limit)
        key = bytes(decoded["key"])
        results.append(
            score_transform_windows(
                ctx,
                transform_fn=lambda data, k=key: xor_apply(data, k),
                profile_name="xor",
                name=str(decoded["name"]),
                algorithm=str(decoded["algorithm"]),
                key_hex=key.hex(),
                provenance=str(decoded["provenance"]),
                key_length=len(key),
            )
        )
    return results


def cheap_probe(ctx: TransformProbeContext, *, cursor: int = 0, batch: int = 16) -> List[Dict[str, Any]]:
    single_limit = int(ctx.pipeline.get("sweep_single_byte_limit") or 256)
    return cheap_probe_batch(ctx, cursor=cursor, batch=batch, single_byte_limit=single_limit)


def materialize(ctx: TransformProbeContext, candidate: Mapping[str, Any]) -> bytes:
    key = bytes.fromhex(str(candidate.get("key_hex") or ""))
    return materialize_xor_copy(ctx.raw, key, xor_start_offset=ctx.xor_start)


def stage2_evidence(ctx: TransformProbeContext, candidate: Mapping[str, Any]) -> Dict[str, Any]:
    return dict(candidate)
