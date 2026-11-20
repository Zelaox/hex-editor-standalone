"""AES-128-CTR transform family."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping

from src.services.ptx_crypto_primitives import aes128_ctr_decrypt, derive_aes_candidate_keys, derive_iv_from_spec
from src.services.transforms.base import TransformProbeContext
from src.services.transforms.common import score_transform_windows


def _nonce_candidates(ctx: TransformProbeContext, family: Mapping[str, Any]) -> List[Dict[str, Any]]:
    derivations = list(family.get("iv_derivations") or [])
    if not derivations:
        derivations = [{"id": "prefix_nonce", "spec": "prefix_slice:0:16", "counter_start": 0}]
    out: List[Dict[str, Any]] = []
    for item in derivations:
        spec = str(item.get("spec") or "prefix_slice:0:16")
        nonce = derive_iv_from_spec(ctx.raw, spec)
        out.append(
            {
                "nonce_hex": nonce.hex(),
                "iv_provenance": spec,
                "derivation_id": str(item.get("id") or ""),
                "counter_start": int(item.get("counter_start") or 0),
            }
        )
    return out


def cheap_probe(ctx: TransformProbeContext, *, family: Mapping[str, Any] | None = None) -> List[Dict[str, Any]]:
    family_cfg = dict(family or (ctx.registry.get("families_by_id") or {}).get("aes128_ctr") or {})
    results: List[Dict[str, Any]] = []
    for index, key in enumerate(derive_aes_candidate_keys(ctx.raw[:64])):
        for nonce_info in _nonce_candidates(ctx, family_cfg):
            nonce = bytes.fromhex(str(nonce_info["nonce_hex"]))
            counter_start = int(nonce_info["counter_start"])

            def transform(data: bytes, k: bytes = key, n: bytes = nonce, cs: int = counter_start) -> bytes:
                try:
                    return aes128_ctr_decrypt(data, k[:16], n, counter_start=cs)
                except ValueError:
                    return data

            results.append(
                score_transform_windows(
                    ctx,
                    transform_fn=transform,
                    profile_name="aes",
                    name=f"aes128_ctr_{index}_{nonce_info['derivation_id']}",
                    algorithm="aes128_ctr",
                    key_hex=key.hex(),
                    provenance=f"CTR nonce={nonce_info['iv_provenance']}",
                    key_length=len(key),
                    parameters={
                        "nonce_hex": nonce_info["nonce_hex"],
                        "iv_provenance": nonce_info["iv_provenance"],
                        "counter_start": counter_start,
                    },
                )
            )
    return results


def materialize(ctx: TransformProbeContext, candidate: Mapping[str, Any]) -> bytes:
    key = bytes.fromhex(str(candidate.get("key_hex") or ""))[:16]
    params = dict(candidate.get("parameters") or {})
    nonce = bytes.fromhex(str(params.get("nonce_hex") or params.get("iv_hex") or "00" * 16))[:16]
    counter_start = int(params.get("counter_start") or 0)
    body = ctx.raw[ctx.xor_start :]
    decrypted_body = aes128_ctr_decrypt(body, key, nonce, counter_start=counter_start)
    return ctx.raw[: ctx.xor_start] + decrypted_body


def stage2_evidence(ctx: TransformProbeContext, candidate: Mapping[str, Any]) -> Dict[str, Any]:
    return dict(candidate)
