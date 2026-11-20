"""AES-128-ECB transform family."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping

from src.services.crypto_primitives import aes128_ecb_decrypt, derive_aes_candidate_keys, pkcs7_unpad
from src.services.transforms.base import TransformProbeContext
from src.services.transforms.common import score_transform_windows


def _candidate_keys(ctx: TransformProbeContext) -> List[bytes]:
    return list(derive_aes_candidate_keys(ctx.raw[:64]))


def cheap_probe(ctx: TransformProbeContext) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    for index, key in enumerate(_candidate_keys(ctx)):
        def transform(data: bytes, k: bytes = key) -> bytes:
            if len(data) < 16:
                return data
            aligned = data[: len(data) - (len(data) % 16)]
            try:
                decrypted = aes128_ecb_decrypt(aligned, k[:16])
            except ValueError:
                return data
            decrypted, _ = pkcs7_unpad(decrypted)
            return decrypted

        results.append(
            score_transform_windows(
                ctx,
                transform_fn=transform,
                profile_name="aes",
                name=f"aes128_ecb_{index}",
                algorithm="aes128_ecb",
                key_hex=key.hex(),
                provenance="derived AES-128 key candidate from header prefix / SHA256 seed",
                key_length=len(key),
            )
        )
    return results


def materialize(ctx: TransformProbeContext, candidate: Mapping[str, Any]) -> bytes:
    key = bytes.fromhex(str(candidate.get("key_hex") or ""))[:16]
    body = ctx.raw[ctx.xor_start :]
    body = body[: len(body) - (len(body) % 16)]
    decrypted_body = aes128_ecb_decrypt(body, key)
    decrypted_body, _ = pkcs7_unpad(decrypted_body)
    return ctx.raw[: ctx.xor_start] + decrypted_body


def stage2_evidence(ctx: TransformProbeContext, candidate: Mapping[str, Any]) -> Dict[str, Any]:
    return dict(candidate)
