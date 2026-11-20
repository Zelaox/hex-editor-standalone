"""Mechanical decrypt promotion gate — algorithm-agnostic, no key literals."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Sequence

from src.services.crypto_primitives import sha256_digest


def evaluate_promotion(
    source_bytes: bytes,
    artifact_bytes: bytes,
    *,
    transform_start: int,
    reference_sha256: str,
    crypto_defaults: Mapping[str, Any],
    window_scores: Sequence[Mapping[str, Any]],
    structural_validators: Sequence[Mapping[str, Any]],
    transform_evidence: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Return promotion verdict — identity transform never promotes."""
    source_sha = sha256_digest(source_bytes)
    artifact_sha = sha256_digest(artifact_bytes)
    start = max(0, min(int(transform_start), len(source_bytes)))
    source_body = source_bytes[start:]
    artifact_body = artifact_bytes[start:]
    changed_byte_count = sum(1 for left, right in zip(source_body, artifact_body) if left != right)

    reject_reasons: List[str] = []
    hard_reject = False
    if changed_byte_count == 0:
        reject_reasons.append("identity_transform")
        hard_reject = True
    if artifact_sha == source_sha:
        reject_reasons.append("artifact_sha_equals_source_sha")
        hard_reject = True

    evidence_verdict = dict((transform_evidence or {}).get("evidence_verdict") or {})
    if evidence_verdict.get("plaintext_regression"):
        reject_reasons.append("plaintext_metadata_regression")
        hard_reject = True
    if evidence_verdict and not evidence_verdict.get("preserve_ok", True):
        reject_reasons.append("preserve_region_mutated")
        hard_reject = True
    if evidence_verdict.get("reference_acceptable") is False:
        reject_reasons.append("reference_diff_unacceptable")

    non_identity_windows = [
        item
        for item in window_scores
        if not item.get("identity") and not item.get("excluded_cleartext_only")
    ]
    cross_window_agreement = sum(
        1 for item in non_identity_windows if int(item.get("score") or 0) > 0
    )
    min_cross = int(crypto_defaults.get("min_cross_window_agreement") or 2)

    improvements = [item for item in structural_validators if item.get("ok")]
    improvement_codes = sorted({str(item.get("code") or "") for item in improvements if item.get("code")})
    min_structural = int(crypto_defaults.get("min_structural_improvements") or 1)

    ref = str(reference_sha256 or "").lower()
    sha_match = bool(ref and artifact_sha.lower() == ref)
    if sha_match:
        improvement_codes = sorted(set(improvement_codes + ["sha256_reference_match"]))

    max_entropy_drop = max((float(item.get("entropy_drop") or 0) for item in non_identity_windows), default=0.0)
    min_entropy_drop = float(crypto_defaults.get("min_entropy_drop") or 0.35)

    if window_scores and all(item.get("excluded_cleartext_only") for item in window_scores):
        reject_reasons.append("all_windows_excluded_cleartext")
        hard_reject = True

    promotion_policy = dict(crypto_defaults.get("promotion_policy") or {})
    sha_requires_evidence = bool(promotion_policy.get("sha_match_requires_evidence_pass", True))
    evidence_required = sha_requires_evidence and sha_match
    evidence_ok = bool(evidence_verdict.get("promote_allowed")) if evidence_verdict else False

    if not sha_match:
        if cross_window_agreement < min_cross:
            reject_reasons.append("insufficient_cross_window_agreement")
        if len(improvement_codes) < min_structural:
            reject_reasons.append("insufficient_structural_validators")

    promoted = False
    promotion_reason = ""
    if hard_reject:
        promoted = False
    elif sha_match and bool(crypto_defaults.get("sha256_match_promotes", True)):
        if evidence_required and not evidence_ok:
            reject_reasons.append("sha_match_insufficient_evidence")
            promoted = False
        else:
            promoted = True
            promotion_reason = "sha256_reference_match"
    elif (
        len(improvement_codes) >= min_structural
        and cross_window_agreement >= min_cross
        and max_entropy_drop >= min_entropy_drop
        and evidence_ok
    ):
        promoted = True
        promotion_reason = "structural_and_cross_window"
    elif evidence_ok and not hard_reject:
        promoted = True
        promotion_reason = "transform_evidence_pass"

    return {
        "promoted": promoted,
        "promotion_reason": promotion_reason,
        "reject_reasons": sorted(set(reject_reasons)),
        "source_sha256": source_sha,
        "artifact_sha256": artifact_sha,
        "sha256_match_reference": sha_match,
        "changed_byte_count": changed_byte_count,
        "cross_window_agreement": cross_window_agreement,
        "structural_improvements": improvement_codes,
        "max_entropy_drop": max_entropy_drop,
        "evidence": {
            "validators": list(structural_validators),
            "window_scores": list(window_scores),
        },
        "transform_evidence": dict(transform_evidence or {}),
        "promote_allowed": promoted,
    }


def build_already_at_reference_result(
    *,
    source_bytes: bytes,
    reference_sha256: str,
    fixture_key_hex: str,
    algorithm: str,
) -> Dict[str, Any]:
    """Source already matches decrypted reference digest — no transform needed."""
    source_sha = sha256_digest(source_bytes)
    ref = str(reference_sha256 or "").lower()
    if not ref or source_sha.lower() != ref:
        return {}
    return {
        "promoted": True,
        "promotion_reason": "already_at_reference_digest",
        "reject_reasons": [],
        "source_sha256": source_sha,
        "artifact_sha256": source_sha,
        "sha256_match_reference": True,
        "changed_byte_count": 0,
        "cross_window_agreement": 0,
        "structural_improvements": ["sha256_reference_match"],
        "max_entropy_drop": 0.0,
        "evidence": {"already_decrypted": True},
        "best_key_hex": str(fixture_key_hex or ""),
        "algorithm": algorithm,
        "skip_materialize": True,
        "promote_allowed": True,
    }
