"""Wire promotion gate results into export manifests."""

from __future__ import annotations

from typing import Any, Mapping


def resolve_export_promotion(
    source_bytes: bytes,
    artifact_bytes: bytes,
    *,
    policy: Mapping[str, Any],
) -> dict[str, Any]:
    export_cfg = dict(policy.get("export_promotion") or {})
    if not bool(export_cfg.get("enabled")):
        return {
            "promoted": False,
            "promotion_eligible": False,
            "verified_decryption": False,
            "promotion_reason": "",
            "reject_reasons": ["export_promotion_disabled"],
        }
    from src.services.promotion_gate import evaluate_promotion

    crypto_defaults = dict(export_cfg.get("crypto_defaults") or {})
    verdict = evaluate_promotion(
        source_bytes,
        artifact_bytes,
        transform_start=int(export_cfg.get("transform_start") or 0),
        reference_sha256=str(export_cfg.get("reference_sha256") or ""),
        crypto_defaults=crypto_defaults,
        window_scores=list(export_cfg.get("window_scores") or []),
        structural_validators=list(export_cfg.get("structural_validators") or []),
        transform_evidence=dict(export_cfg.get("transform_evidence") or {}) or None,
    )
    promoted = bool(verdict.get("promoted"))
    return {
        "promoted": promoted,
        "promotion_eligible": promoted,
        "verified_decryption": promoted,
        "promotion_reason": str(verdict.get("promotion_reason") or ""),
        "reject_reasons": list(verdict.get("reject_reasons") or []),
        "gate_verdict": verdict,
    }
