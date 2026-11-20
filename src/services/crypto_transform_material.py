"""Advanced XOR / SHA / AES scoring with mechanical promotion gate (body-only windows)."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from src.services.crypto_calibration import (
    case_by_id,
    crypto_defaults,
    known_keys_for_case,
    probe_pipeline_config,
    probe_windows_for_case,
    reference_sha256_for_case,
    resolve_crypto_case,
)
from src.services.crypto_primitives import (
    aes128_ecb_decrypt,
    aes_sbox_density,
    derive_aes_candidate_keys,
    is_identity_transform,
    pkcs7_unpad,
    printable_ratio,
    pt12_signature_key,
    sha256_digest,
    shannon_entropy,
    xor_apply,
)
from src.services.promotion_gate import build_already_at_reference_result, evaluate_promotion
from src.services.crypto_scoring_regions import (
    anchors_for_case,
    compile_scoring_windows,
    excluded_regions_for_case,
)
from src.services.transform_evidence import compile_transform_evidence
from src.services.stage2_policy import select_stage2_survivors
from src.services.transform_scoring import score_window

logger = logging.getLogger(__name__)


def _parse_key_hex(key_hex: str) -> bytes:
    cleaned = str(key_hex or "").strip().replace(" ", "")
    if not cleaned or len(cleaned) % 2:
        raise ValueError("key_hex must be even-length hex")
    return bytes.fromhex(cleaned)


def _marker_score(decrypted: bytes) -> Tuple[int, List[str]]:
    from src.services.transform_scoring import marker_score

    return marker_score(decrypted)


def _score_window(cipher: bytes, transformed: bytes, *, region_name: str) -> Dict[str, Any]:
    return score_window(cipher, transformed, region_name=region_name, profile_name="xor")


def _read_window(raw: bytes, offset: int, length: int) -> Tuple[bytes, int]:
    start = max(0, int(offset))
    end = min(len(raw), start + max(64, int(length)))
    if start >= len(raw):
        return b"", start
    return raw[start:end], start


def validate_timecode_anchors(
    raw: bytes,
    *,
    key: bytes,
    algorithm: str,
    anchors: Sequence[Mapping[str, Any]] | None = None,
) -> Dict[str, Any]:
    hits: List[Dict[str, Any]] = []
    for anchor in anchors or ():
        offset = int(anchor.get("offset") or 0)
        needle = anchor.get("needle")
        if isinstance(needle, str):
            needle = needle.encode("latin1", errors="ignore")
        needle = bytes(needle or b"")
        if not needle or offset + len(needle) > len(raw):
            continue
        window = raw[offset : offset + max(len(needle), 32)]
        if algorithm in {"xor_single_byte", "xor_repeating_byte"}:
            transformed = xor_apply(window, key)
        elif algorithm == "aes128_ecb":
            try:
                transformed = aes128_ecb_decrypt(window[:16], key[:16])
            except ValueError:
                transformed = window
        else:
            transformed = window
        ok_plain = needle in window
        ok_transform = needle in transformed
        if ok_plain or ok_transform:
            hits.append(
                {
                    "label": str(anchor.get("label") or ""),
                    "offset": hex(offset),
                    "plaintext_already": ok_plain,
                    "transform_reveals": ok_transform,
                }
            )
    return {
        "ok": len(hits) >= 1,
        "hits": hits,
        "hit_count": len(hits),
    }


def materialize_xor_copy(raw: bytes, key: bytes, *, xor_start_offset: int) -> bytes:
    start = max(0, min(int(xor_start_offset), len(raw)))
    return raw[:start] + xor_apply(raw[start:], key)


def validate_full_file_transform(
    raw: bytes,
    *,
    key: bytes,
    algorithm: str,
    xor_start_offset: int,
    reference_sha256: str = "",
    anchors: Sequence[Mapping[str, Any]] | None = None,
) -> Dict[str, Any]:
    if algorithm in {"xor_single_byte", "xor_repeating_byte"}:
        transformed = materialize_xor_copy(raw, key, xor_start_offset=xor_start_offset)
    elif algorithm == "aes128_ecb":
        body = raw[xor_start_offset:]
        body = body[: len(body) - (len(body) % 16)]
        decrypted_body = aes128_ecb_decrypt(body, key[:16])
        decrypted_body, pkcs7_ok = pkcs7_unpad(decrypted_body)
        transformed = raw[:xor_start_offset] + decrypted_body
    else:
        transformed = raw

    digest = sha256_digest(transformed)
    source_digest = sha256_digest(raw)
    identity_full = transformed == raw
    start = max(0, min(int(xor_start_offset), len(raw)))
    cipher_body = raw[start:]
    body_out = transformed[start:]
    identity_body = cipher_body == body_out

    ref = str(reference_sha256 or "").lower()
    sha_match = bool(ref and digest.lower() == ref)

    anchor_result = validate_timecode_anchors(transformed, key=key, algorithm=algorithm, anchors=anchors)
    return {
        "algorithm": algorithm,
        "sha256": digest,
        "source_sha256": source_digest,
        "sha256_match_reference": sha_match,
        "identity_full_file": identity_full,
        "identity_on_ciphertext_body": identity_body,
        "anchor_validation": anchor_result,
        "pkcs7_valid": algorithm != "aes128_ecb",
        "bytes_changed_in_body": sum(1 for left, right in zip(cipher_body, body_out) if left != right),
    }


def _build_structural_validators(
    *,
    window_scores: Sequence[Mapping[str, Any]],
    full_validation: Mapping[str, Any],
    defaults: Mapping[str, Any],
) -> List[Dict[str, Any]]:
    validators: List[Dict[str, Any]] = []
    min_entropy_drop = float(defaults.get("min_entropy_drop") or 0.35)
    min_cross = int(defaults.get("min_cross_window_agreement") or 2)

    max_drop = max((float(item.get("entropy_drop") or 0) for item in window_scores), default=0.0)
    if max_drop >= min_entropy_drop:
        validators.append({"code": "entropy_drop", "ok": True, "details": {"max_entropy_drop": max_drop}})

    anchor = dict(full_validation.get("anchor_validation") or {})
    if anchor.get("ok"):
        validators.append(
            {
                "code": "timecode_anchor_present",
                "ok": True,
                "details": {"hit_count": anchor.get("hit_count")},
            }
        )

    if full_validation.get("sha256_match_reference"):
        validators.append({"code": "sha256_reference_match", "ok": True, "details": {}})

    non_identity = [
        item for item in window_scores if not item.get("identity") and int(item.get("score") or 0) > 0
    ]
    if len(non_identity) >= min_cross:
        validators.append(
            {
                "code": "cross_window_marker_consistency",
                "ok": True,
                "details": {"agreeing_windows": len(non_identity)},
            }
        )
    return validators


def _lab_root() -> Path:
    from src.project import project_root
    return project_root()


@dataclass
class ProbeContext:
    """Cached invariant probe inputs — one disk read per probe call."""

    raw: bytes
    case: Optional[Dict[str, Any]]
    defaults: Dict[str, Any]
    pipeline: Dict[str, Any]
    xor_start: int
    reference_sha: str
    source_sha: str
    anchors: List[Dict[str, Any]]
    body_windows: List[Dict[str, Any]]
    reference_bytes: Optional[bytes] = None
    crypto_case_id: str = ""
    timings_ms: Dict[str, float] = field(default_factory=dict)

    @classmethod
    def build(
        cls,
        raw: bytes,
        *,
        case: Optional[Dict[str, Any]],
        defaults: Dict[str, Any],
        source_sha: str,
        body_windows: List[Dict[str, Any]],
    ) -> "ProbeContext":
        xor_start = int((case or {}).get("decrypt", {}).get("xor_start_offset") or defaults.get("xor_start_offset") or 16)
        return cls(
            raw=raw,
            case=case,
            defaults=defaults,
            pipeline=probe_pipeline_config(defaults),
            xor_start=xor_start,
            reference_sha=reference_sha256_for_case(case),
            source_sha=str(source_sha or sha256_digest(raw)),
            anchors=list(anchors_for_case(case)),
            body_windows=list(body_windows),
            reference_bytes=_load_reference_bytes(case),
            crypto_case_id=str((case or {}).get("id") or ""),
        )


def _load_reference_bytes(case: Optional[Mapping[str, Any]]) -> Optional[bytes]:
    if not case:
        return None
    ref_id = str((case.get("decrypt") or {}).get("reference_case_id") or "")
    if not ref_id:
        return None
    ref_case = case_by_id(ref_id)
    if not ref_case:
        return None
    rel = str(ref_case.get("path") or "")
    if not rel:
        return None
    path = (_lab_root() / rel).resolve()
    if not path.is_file():
        return None
    return path.read_bytes()


def _log_probe_progress(message: str, *, pipeline: Mapping[str, Any]) -> None:
    if not pipeline.get("log_progress"):
        return
    logger.info("ptx_probe: %s", message)
    print(f"ptx_probe: {message}", flush=True)


def _sweep_limits(pipeline: Mapping[str, Any]) -> tuple[int, int]:
    sweep_limit = max(1, int(pipeline.get("sweep_key_limit") or 256))
    single_limit = max(1, min(int(pipeline.get("sweep_single_byte_limit") or 256), sweep_limit))
    return sweep_limit, single_limit


def decode_sweep_cursor(cursor: int, *, single_byte_limit: int) -> Dict[str, Any]:
    """Map linear sweep cursor to XOR key material (single-byte then 2-byte repeating)."""
    c = max(0, int(cursor))
    if c < single_byte_limit:
        return {
            "cursor": c,
            "key": bytes([c]),
            "name": f"single_byte_0x{c:02x}",
            "algorithm": "xor_single_byte",
            "provenance": "bounded single-byte XOR sweep",
        }
    idx = c - single_byte_limit
    b0, b1 = idx // 256, idx % 256
    return {
        "cursor": c,
        "key": bytes([b0, b1]),
        "name": f"double_byte_0x{b0:02x}{b1:02x}",
        "algorithm": "xor_repeating_byte",
        "provenance": "bounded two-byte repeating XOR sweep",
    }


def _score_xor_candidate_cheap(
    ctx: ProbeContext,
    *,
    name: str,
    key: bytes,
    provenance: str,
) -> Dict[str, Any]:
    window_scores: List[Dict[str, Any]] = []
    total = 0
    for window in ctx.body_windows:
        cipher, start = _read_window(ctx.raw, int(window.get("offset") or 0), int(window.get("length") or 4096))
        if not cipher:
            continue
        transformed = xor_apply(cipher, key)
        scored = _score_window(cipher, transformed, region_name=str(window.get("name") or hex(start)))
        window_scores.append(
            {
                **scored,
                "offset": start,
                "length": len(cipher),
                "excluded_cleartext_only": bool(window.get("excluded_cleartext_only")),
            }
        )
        total += int(scored.get("score") or 0)
    cheap_identity = bool(window_scores) and all(item.get("identity") for item in window_scores)
    algorithm = "xor_single_byte" if len(key) == 1 else "xor_repeating_byte"
    return {
        "name": name,
        "algorithm": algorithm,
        "key_hex": key.hex(),
        "key_length": len(key),
        "score": total,
        "window_scores": window_scores,
        "marker_hits": sorted({hit for item in window_scores for hit in item.get("marker_hits") or []}),
        "printable_ratio": max((float(item.get("printable_ratio") or 0) for item in window_scores), default=0.0),
        "provenance": provenance,
        "cheap_only": True,
        "cheap_identity": cheap_identity,
    }


def _select_stage2_xor_survivors(
    cheap_candidates: Sequence[Mapping[str, Any]],
    *,
    pipeline: Mapping[str, Any],
    force_full: bool = False,
    defaults: Optional[Mapping[str, Any]] = None,
) -> List[int]:
    from src.services.crypto_calibration import crypto_defaults

    return select_stage2_survivors(
        cheap_candidates,
        pipeline=pipeline,
        defaults=defaults or crypto_defaults(),
        force_full=force_full,
    )


def _finalize_xor_candidate(ctx: ProbeContext, cheap: Mapping[str, Any], *, key: bytes) -> Dict[str, Any]:
    t0 = time.perf_counter()
    window_scores = list(cheap.get("window_scores") or [])
    total = int(cheap.get("score") or 0)
    skip_reference_diff = bool(cheap.get("cheap_identity")) and total <= 0
    algorithm = str(cheap.get("algorithm") or ("xor_single_byte" if len(key) == 1 else "xor_repeating_byte"))

    t_transform = time.perf_counter()
    full_validation = validate_full_file_transform(
        ctx.raw,
        key=key,
        algorithm=algorithm,
        xor_start_offset=ctx.xor_start,
        reference_sha256=ctx.reference_sha,
        anchors=ctx.anchors,
    )
    structural_validators = _build_structural_validators(
        window_scores=window_scores,
        full_validation=full_validation,
        defaults=ctx.defaults,
    )
    artifact_bytes = materialize_xor_copy(ctx.raw, key, xor_start_offset=ctx.xor_start)
    transform_ms = (time.perf_counter() - t_transform) * 1000.0

    t_evidence = time.perf_counter()
    transform_evidence = compile_transform_evidence(
        ctx.raw,
        artifact_bytes,
        case=ctx.case,
        crypto_defaults=ctx.defaults,
        algorithm=algorithm,
        key_hex=key.hex(),
        reference_bytes=ctx.reference_bytes,
        include_reference_diff=not skip_reference_diff,
    )
    evidence_ms = (time.perf_counter() - t_evidence) * 1000.0

    t_promote = time.perf_counter()
    promotion = evaluate_promotion(
        ctx.raw,
        artifact_bytes,
        transform_start=ctx.xor_start,
        reference_sha256=ctx.reference_sha,
        crypto_defaults=ctx.defaults,
        window_scores=window_scores,
        structural_validators=structural_validators,
        transform_evidence=transform_evidence,
    )
    promote_ms = (time.perf_counter() - t_promote) * 1000.0
    promoted = bool(promotion.get("promoted"))

    return {
        "name": str(cheap.get("name") or ""),
        "algorithm": "xor_single_byte",
        "key_hex": key.hex(),
        "key_length": len(key),
        "score": total,
        "window_scores": window_scores,
        "marker_hits": sorted({hit for item in window_scores for hit in item.get("marker_hits") or []}),
        "printable_ratio": max((float(item.get("printable_ratio") or 0) for item in window_scores), default=0.0),
        "timecode_anchor": full_validation["anchor_validation"],
        "full_file_validation": full_validation,
        "provenance": str(cheap.get("provenance") or ""),
        "confidence": "high" if promoted else "low",
        "promoted": promoted,
        "reject_reasons": list(promotion.get("reject_reasons") or []),
        "promotion_evidence": promotion,
        "transform_evidence": transform_evidence,
        "cheap_only": False,
        "timing_ms": {
            "transform": round(transform_ms, 2),
            "evidence": round(evidence_ms, 2),
            "promotion": round(promote_ms, 2),
            "total": round((time.perf_counter() - t0) * 1000.0, 2),
        },
        "crypto_analysis": {
            "sha256": full_validation.get("sha256"),
            "sha256_match_reference": full_validation.get("sha256_match_reference"),
            "entropy_drop_max": promotion.get("max_entropy_drop"),
            "aes_sbox_density_body": aes_sbox_density(ctx.raw[ctx.xor_start : ctx.xor_start + 4096]),
        },
    }


def evaluate_xor_candidate(
    raw: bytes,
    *,
    name: str,
    key: bytes,
    provenance: str,
    windows: Sequence[Mapping[str, Any]],
    xor_start_offset: int,
    reference_sha256: str,
    anchors: Sequence[Mapping[str, Any]],
    defaults: Mapping[str, Any],
    case: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    ctx = ProbeContext(
        raw=raw,
        case=dict(case) if case else None,
        defaults=dict(defaults),
        pipeline=probe_pipeline_config(defaults),
        xor_start=int(xor_start_offset),
        reference_sha=str(reference_sha256 or ""),
        source_sha=sha256_digest(raw),
        anchors=list(anchors),
        body_windows=[dict(item) for item in windows if isinstance(item, dict)],
        reference_bytes=_load_reference_bytes(case),
        crypto_case_id=str((case or {}).get("id") or ""),
    )
    cheap = _score_xor_candidate_cheap(
        ctx,
        name=name,
        key=key,
        provenance=provenance,
    )
    return _finalize_xor_candidate(ctx, cheap, key=key)


def _score_aes_candidate_cheap(
    ctx: ProbeContext,
    *,
    name: str,
    key: bytes,
    provenance: str,
) -> Dict[str, Any]:
    window_scores: List[Dict[str, Any]] = []
    total = 0
    for window in ctx.body_windows:
        cipher, start = _read_window(ctx.raw, int(window.get("offset") or 0), int(window.get("length") or 4096))
        if len(cipher) < 16:
            continue
        cipher = cipher[: len(cipher) - (len(cipher) % 16)]
        try:
            transformed = aes128_ecb_decrypt(cipher, key[:16])
        except ValueError:
            continue
        transformed, _ = pkcs7_unpad(transformed)
        scored = _score_window(cipher, transformed, region_name=str(window.get("name") or hex(start)))
        window_scores.append({**scored, "offset": start, "length": len(cipher)})
        total += int(scored.get("score") or 0)
    return {
        "name": name,
        "algorithm": "aes128_ecb",
        "key_hex": key.hex(),
        "key_length": len(key),
        "score": total,
        "window_scores": window_scores,
        "marker_hits": sorted({hit for item in window_scores for hit in item.get("marker_hits") or []}),
        "printable_ratio": max((float(item.get("printable_ratio") or 0) for item in window_scores), default=0.0),
        "provenance": provenance,
        "cheap_only": True,
    }


def _finalize_aes_candidate(ctx: ProbeContext, cheap: Mapping[str, Any], *, key: bytes) -> Dict[str, Any]:
    window_scores = list(cheap.get("window_scores") or [])
    total = int(cheap.get("score") or 0)
    full_validation = validate_full_file_transform(
        ctx.raw,
        key=key,
        algorithm="aes128_ecb",
        xor_start_offset=ctx.xor_start,
        reference_sha256=ctx.reference_sha,
        anchors=ctx.anchors,
    )
    structural_validators = _build_structural_validators(
        window_scores=window_scores,
        full_validation=full_validation,
        defaults=ctx.defaults,
    )
    body = ctx.raw[ctx.xor_start :]
    body = body[: len(body) - (len(body) % 16)]
    decrypted_body = aes128_ecb_decrypt(body, key[:16])
    decrypted_body, _ = pkcs7_unpad(decrypted_body)
    artifact_bytes = ctx.raw[: ctx.xor_start] + decrypted_body
    transform_evidence = compile_transform_evidence(
        ctx.raw,
        artifact_bytes,
        case=ctx.case,
        crypto_defaults=ctx.defaults,
        algorithm="aes128_ecb",
        key_hex=key.hex(),
        reference_bytes=ctx.reference_bytes,
        include_reference_diff=total > 0,
    )
    promotion = evaluate_promotion(
        ctx.raw,
        artifact_bytes,
        transform_start=ctx.xor_start,
        reference_sha256=ctx.reference_sha,
        crypto_defaults=ctx.defaults,
        window_scores=window_scores,
        structural_validators=structural_validators,
        transform_evidence=transform_evidence,
    )
    promoted = bool(promotion.get("promoted"))
    return {
        "name": str(cheap.get("name") or ""),
        "algorithm": "aes128_ecb",
        "key_hex": key.hex(),
        "key_length": len(key),
        "score": total,
        "window_scores": window_scores,
        "marker_hits": sorted({hit for item in window_scores for hit in item.get("marker_hits") or []}),
        "printable_ratio": max((float(item.get("printable_ratio") or 0) for item in window_scores), default=0.0),
        "timecode_anchor": full_validation["anchor_validation"],
        "full_file_validation": full_validation,
        "provenance": str(cheap.get("provenance") or ""),
        "confidence": "high" if promoted else "low",
        "promoted": promoted,
        "reject_reasons": list(promotion.get("reject_reasons") or []),
        "promotion_evidence": promotion,
        "transform_evidence": transform_evidence,
        "cheap_only": False,
        "crypto_analysis": {
            "sha256": full_validation.get("sha256"),
            "sha256_match_reference": full_validation.get("sha256_match_reference"),
            "entropy_drop_max": promotion.get("max_entropy_drop"),
            "aes_sbox_density_body": aes_sbox_density(ctx.raw[ctx.xor_start : ctx.xor_start + 4096]),
        },
    }


def evaluate_aes_candidate(
    raw: bytes,
    *,
    name: str,
    key: bytes,
    provenance: str,
    windows: Sequence[Mapping[str, Any]],
    xor_start_offset: int,
    reference_sha256: str,
    anchors: Sequence[Mapping[str, Any]],
    defaults: Mapping[str, Any],
    case: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    ctx = ProbeContext(
        raw=raw,
        case=dict(case) if case else None,
        defaults=dict(defaults),
        pipeline=probe_pipeline_config(defaults),
        xor_start=int(xor_start_offset),
        reference_sha=str(reference_sha256 or ""),
        source_sha=sha256_digest(raw),
        anchors=list(anchors),
        body_windows=[dict(item) for item in windows if isinstance(item, dict)],
        reference_bytes=_load_reference_bytes(case),
        crypto_case_id=str((case or {}).get("id") or ""),
    )
    cheap = _score_aes_candidate_cheap(ctx, name=name, key=key, provenance=provenance)
    return _finalize_aes_candidate(ctx, cheap, key=key)


def _evaluate_known_key_lane(ctx: ProbeContext, *, case: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    pipeline = ctx.pipeline
    xor_cheaps: List[Dict[str, Any]] = []
    aes_cheaps: List[Dict[str, Any]] = []
    for item in known_keys_for_case(case):
        algorithm = str(item.get("algorithm") or "xor_single_byte")
        try:
            key = _parse_key_hex(str(item.get("key_hex") or ""))
        except ValueError:
            continue
        if algorithm == "aes128_ecb" and len(key) != 16:
            continue
        if algorithm == "aes128_ecb":
            aes_cheaps.append(
                _score_aes_candidate_cheap(
                    ctx,
                    name=str(item.get("name") or "fixture_aes"),
                    key=key,
                    provenance=str(item.get("provenance") or "fixture"),
                )
            )
        else:
            xor_cheaps.append(
                _score_xor_candidate_cheap(
                    ctx,
                    name=str(item.get("name") or "fixture_xor"),
                    key=key,
                    provenance=str(item.get("provenance") or "fixture"),
                )
            )
    sig_key = bytes([pt12_signature_key(ctx.raw[:4])])
    xor_cheaps.append(
        _score_xor_candidate_cheap(
            ctx,
            name="pt12_signature_xor",
            key=sig_key,
            provenance="sum(\\x03\\x30\\x30\\x31) mod 256",
        )
    )
    for index, aes_key in enumerate(derive_aes_candidate_keys(ctx.raw[:64])):
        aes_cheaps.append(
            _score_aes_candidate_cheap(
                ctx,
                name=f"aes128_candidate_{index}",
                key=aes_key,
                provenance="derived AES-128 key candidate from header prefix / SHA256 seed",
            )
        )

    xor_survivors = set(_select_stage2_xor_survivors(xor_cheaps, pipeline=pipeline))
    aes_min = int(ctx.defaults.get("found_score_threshold") or pipeline.get("aes_stage2_min_score") or 8)
    aes_survivors = {
        index
        for index, cheap in enumerate(aes_cheaps)
        if int(cheap.get("score") or 0) >= aes_min
    }
    results: List[Dict[str, Any]] = []
    for index, cheap in enumerate(xor_cheaps):
        key = bytes.fromhex(str(cheap["key_hex"]))
        if index in xor_survivors:
            results.append(_finalize_xor_candidate(ctx, cheap, key=key))
        else:
            results.append(dict(cheap))
    for index, cheap in enumerate(aes_cheaps):
        key = bytes.fromhex(str(cheap["key_hex"]))
        if index in aes_survivors:
            results.append(_finalize_aes_candidate(ctx, cheap, key=key))
        else:
            results.append(dict(cheap))
    return results


def build_default_probe_windows(file_size: int) -> List[Dict[str, Any]]:
    defaults = crypto_defaults()
    windows = list(defaults.get("probe_windows") or [])
    if windows:
        return windows
    candidates = [
        {"name": "body_early", "offset": 1024, "length": 4096},
        {"name": "body_mid", "offset": 8192, "length": 4096},
    ]
    return [dict(item) for item in candidates if int(item["offset"]) < file_size]


def analyze_ptx_crypto_candidates(
    path: str | Path,
    *,
    sample_offset: int,
    sample_length: int,
    key_cursor: int,
    key_batch: int,
    include_known: bool,
    source_sha256: str = "",
    file_size: int = 0,
    probe_phase_id: str = "",
    investigation_root: str | None = None,
    window_source: str | None = None,
) -> Dict[str, Any]:
    from src.services.transform_engine import analyze_binary_transform_candidates

    return analyze_binary_transform_candidates(
        path,
        sample_offset=sample_offset,
        sample_length=sample_length,
        key_cursor=key_cursor,
        key_batch=key_batch,
        include_known=include_known,
        source_sha256=source_sha256,
        file_size=file_size,
        probe_phase_id=probe_phase_id,
        investigation_root=investigation_root,
        window_source=window_source,
    )
