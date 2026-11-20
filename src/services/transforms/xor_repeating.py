"""Per-position XOR lane recovery for L≥3 — O(L×256) not 256^L."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Sequence

from src.services.ptx_crypto_analysis import materialize_xor_copy
from src.services.ptx_crypto_primitives import xor_apply
from src.services.transform_scoring import score_window
from src.services.transforms.base import TransformProbeContext, read_window
from src.services.transforms.common import score_transform_windows


def _infer_key_lengths(defaults: Mapping[str, Any], cipher: bytes) -> List[int]:
    inference = defaults.get("xor_period_inference")
    if not isinstance(inference, Mapping):
        raise ValueError("crypto defaults missing xor_period_inference")
    required = ("minimum_period", "maximum_period", "minimum_samples")
    if any(key not in inference for key in required) or "key_length_top_k" not in defaults:
        raise ValueError("crypto defaults missing XOR period inference bounds")
    minimum = int(inference["minimum_period"])
    maximum = int(inference["maximum_period"])
    minimum_samples = int(inference["minimum_samples"])
    if minimum <= 0 or maximum < minimum or minimum_samples <= 0:
        raise ValueError("invalid XOR period inference policy")
    ranked = []
    for period in range(minimum, min(maximum, len(cipher) - 1) + 1):
        comparisons = min(len(cipher) - period, minimum_samples)
        if comparisons < minimum_samples:
            continue
        matches = sum(1 for index in range(comparisons) if cipher[index] == cipher[index + period])
        ranked.append((matches / comparisons, period))
    ranked.sort(key=lambda item: (-item[0], item[1]))
    return [period for _, period in ranked[: int(defaults["key_length_top_k"])]]


def _recover_lane_key(cipher: bytes, lane: int, period: int, sample_bytes: int) -> tuple[int, int]:
    best_byte = 0
    best_score = -1
    indices = list(range(lane, len(cipher), period))
    if not indices:
        return 0, 0
    sample = bytes(cipher[index] for index in indices[: min(len(indices), sample_bytes)])
    for candidate in range(256):
        key_byte = bytes([candidate])
        transformed = xor_apply(sample, key_byte)
        scored = score_window(sample, transformed, region_name=f"lane_{lane}", profile_name="xor")
        printable_count = sum(1 for byte in transformed if 32 <= byte <= 126)
        total = int(scored.get("score") or 0)
        total += printable_count
        total += int(float(scored.get("printable_ratio") or 0) * 100)
        if total > best_score:
            best_score = total
            best_byte = candidate
    return best_byte, best_score


def recover_repeating_key(cipher: bytes, period: int, *, sample_bytes: int) -> tuple[bytes, List[Dict[str, Any]]]:
    key_bytes = bytearray(period)
    lane_scores: List[Dict[str, Any]] = []
    for lane in range(period):
        byte_val, lane_score = _recover_lane_key(cipher, lane, period, sample_bytes)
        key_bytes[lane] = byte_val
        lane_scores.append({"lane": lane, "byte": byte_val, "score": lane_score})
    return bytes(key_bytes), lane_scores


def apply_crib_constraints(
    key: bytes,
    *,
    cipher: bytes,
    crib_plain: bytes,
    crib_offset: int,
    start_offset: int,
) -> Optional[bytes]:
    if not crib_plain:
        return key
    period = len(key)
    if period <= 0:
        return None
    confirmed = bytearray(key)
    rel_offset = int(crib_offset) - int(start_offset)
    if rel_offset < 0 or rel_offset >= len(cipher):
        return None
    unset = 0
    for index, plain_byte in enumerate(crib_plain):
        pos = rel_offset + index
        if pos >= len(cipher):
            break
        lane = pos % period
        expected = cipher[pos] ^ plain_byte
        if confirmed[lane] != unset and confirmed[lane] != expected:
            return None
        confirmed[lane] = expected
    return bytes(confirmed)


def cheap_probe(ctx: TransformProbeContext) -> List[Dict[str, Any]]:
    if "key_length_top_k" not in ctx.defaults or "xor_lane_sample_bytes" not in ctx.defaults:
        raise ValueError("crypto defaults missing XOR inference budgets")
    body = ctx.raw[ctx.xor_start :]
    lengths = _infer_key_lengths(ctx.defaults, body)
    sample_bytes = int(ctx.defaults["xor_lane_sample_bytes"])
    if not lengths:
        return []
    results: List[Dict[str, Any]] = []
    for period in lengths:
        key, lane_scores = recover_repeating_key(body, period, sample_bytes=sample_bytes)
        candidate = score_transform_windows(
            ctx,
            transform_fn=lambda data, k=key: xor_apply(data, k),
            profile_name="xor",
            name=f"xor_infer_L{period}",
            algorithm="xor_repeating_byte",
            key_hex=key.hex(),
            provenance=f"per_lane_recovery period={period}",
            key_length=period,
            parameters={"period": period, "lane_scores": lane_scores},
        )
        cribs = list((ctx.case or {}).get("decrypt", {}).get("cribs") or [])
        for crib in cribs:
            if not isinstance(crib, dict):
                continue
            plain = crib.get("plain")
            if isinstance(plain, str):
                plain_bytes = plain.encode("latin1", errors="ignore")
            else:
                plain_bytes = bytes(plain or b"")
            offset = int(crib.get("offset") or 0)
            refined = apply_crib_constraints(
                key,
                cipher=body,
                crib_plain=plain_bytes,
                crib_offset=offset,
                start_offset=ctx.xor_start,
            )
            if refined and refined != key:
                results.append(
                    score_transform_windows(
                        ctx,
                        transform_fn=lambda data, k=refined: xor_apply(data, k),
                        profile_name="xor",
                        name=f"xor_crib_L{period}",
                        algorithm="xor_repeating_byte",
                        key_hex=refined.hex(),
                        provenance=f"crib_refined period={period}",
                        key_length=len(refined),
                        parameters={"period": period, "crib_offset": offset},
                    )
                )
        results.append(candidate)
    return results


def materialize(ctx: TransformProbeContext, candidate: Mapping[str, Any]) -> bytes:
    key = bytes.fromhex(str(candidate.get("key_hex") or ""))
    return materialize_xor_copy(ctx.raw, key, xor_start_offset=ctx.xor_start)


def stage2_evidence(ctx: TransformProbeContext, candidate: Mapping[str, Any]) -> Dict[str, Any]:
    return dict(candidate)
