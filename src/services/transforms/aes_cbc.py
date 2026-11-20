"""AES-128-CBC transform family with registry IV derivations."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping

from src.services.crypto_primitives import aes128_cbc_decrypt, derive_aes_candidate_keys, derive_iv_from_spec, pkcs7_unpad
from src.services.transforms.base import TransformProbeContext
from src.services.transforms.common import score_transform_windows


def _iv_candidates(ctx: TransformProbeContext, family: Mapping[str, Any]) -> List[Dict[str, Any]]:
    derivations = list(family.get("iv_derivations") or [])
    if not derivations:
        derivations = [{"id": "prefix_slice", "spec": "prefix_slice:0:16"}]
    out: List[Dict[str, Any]] = []
    for item in derivations:
        spec = str(item.get("spec") or "")
        iv = derive_iv_from_spec(ctx.raw, spec)
        out.append({"iv_hex": iv.hex(), "iv_provenance": spec, "derivation_id": str(item.get("id") or "")})
    return out


def cheap_probe(ctx: TransformProbeContext, *, family: Mapping[str, Any] | None = None) -> List[Dict[str, Any]]:
    family_cfg = dict(family or (ctx.registry.get("families_by_id") or {}).get("aes128_cbc") or {})
    results: List[Dict[str, Any]] = []
    for index, key in enumerate(derive_aes_candidate_keys(ctx.raw[:64])):
        for iv_info in _iv_candidates(ctx, family_cfg):
            iv = bytes.fromhex(str(iv_info["iv_hex"]))

            def transform(data: bytes, k: bytes = key, iv_bytes: bytes = iv) -> bytes:
                if len(data) < 16:
                    return data
                aligned = data[: len(data) - (len(data) % 16)]
                try:
                    decrypted = aes128_cbc_decrypt(aligned, k[:16], iv_bytes)
                except ValueError:
                    return data
                decrypted, _ = pkcs7_unpad(decrypted)
                return decrypted

            results.append(
                score_transform_windows(
                    ctx,
                    transform_fn=transform,
                    profile_name="aes",
                    name=f"aes128_cbc_{index}_{iv_info['derivation_id']}",
                    algorithm="aes128_cbc",
                    key_hex=key.hex(),
                    provenance=f"CBC iv={iv_info['iv_provenance']}",
                    key_length=len(key),
                    parameters={
                        "iv_hex": iv_info["iv_hex"],
                        "iv_provenance": iv_info["iv_provenance"],
                        "block_alignment": 16,
                    },
                )
            )
    return results


def materialize(ctx: TransformProbeContext, candidate: Mapping[str, Any]) -> bytes:
    key = bytes.fromhex(str(candidate.get("key_hex") or ""))[:16]
    params = dict(candidate.get("parameters") or {})
    iv = bytes.fromhex(str(params.get("iv_hex") or "00" * 16))[:16]
    body = ctx.raw[ctx.xor_start :]
    body = body[: len(body) - (len(body) % 16)]
    decrypted_body = aes128_cbc_decrypt(body, key, iv)
    decrypted_body, _ = pkcs7_unpad(decrypted_body)
    tail = ctx.raw[ctx.xor_start + len(body) :]
    return ctx.raw[: ctx.xor_start] + decrypted_body + tail


def stage2_evidence(ctx: TransformProbeContext, candidate: Mapping[str, Any]) -> Dict[str, Any]:
    enriched = dict(candidate)
    params = dict(enriched.get("parameters") or {})
    params.setdefault("block_alignment", 16)
    params.setdefault("partial_tail_policy", "preserve_ciphertext_tail")
    enriched["parameters"] = params
    return enriched
