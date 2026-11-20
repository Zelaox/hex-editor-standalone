"""Config-driven milestone verify paths for decrypt probe phases — NO HARDCODE."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional

from src.services.probe_phase_config import phase_for_milestone
from src.services.crypto_calibration import crypto_defaults


class MilestoneVerifyError(ValueError):
    pass


def load_milestone_verify_profile(
    milestone_id: str,
    defaults: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    base = dict(defaults or crypto_defaults())
    profiles = base.get("milestone_verify_profiles")
    if not isinstance(profiles, Mapping):
        return {}
    profile = profiles.get(str(milestone_id or "").strip())
    return dict(profile) if isinstance(profile, Mapping) else {}


def expected_phase_id_for_milestone(
    milestone_id: str,
    defaults: Optional[Mapping[str, Any]] = None,
) -> str:
    phase = phase_for_milestone(milestone_id, defaults)
    phase_id = str(phase.get("id") or "").strip()
    if not phase_id:
        raise MilestoneVerifyError(f"milestone {milestone_id} has no configured probe phase id")
    return phase_id


def _stage2_candidates_present(result: Mapping[str, Any]) -> bool:
    timings = dict(result.get("probe_timings_ms") or {})
    if float(timings.get("stage2_ms") or 0) > 0:
        return True
    candidates = list(result.get("candidates") or [])
    if candidates:
        return any(not bool(item.get("cheap_only", True)) for item in candidates if isinstance(item, dict))
    findings = list(result.get("findings") or [])
    for item in findings:
        if not isinstance(item, dict):
            continue
        label = str(item.get("label") or item.get("kind") or "")
        if label in {"stage2_survivors", "transform_candidates"}:
            value = item.get("value") or item.get("data") or []
            if isinstance(value, list) and value:
                return True
    return False


def _promotion_path_attempted(result: Mapping[str, Any]) -> bool:
    if bool(result.get("keys_found")):
        return True
    promotion = dict(result.get("promotion_evidence") or {})
    return bool(promotion)


def _promotion_succeeded(result: Mapping[str, Any]) -> bool:
    promotion = dict(result.get("promotion_evidence") or {})
    if not bool(result.get("keys_found")):
        return False
    if promotion.get("promoted"):
        return True
    transform_evidence = dict(result.get("transform_evidence") or promotion.get("transform_evidence") or {})
    verdict = dict(transform_evidence.get("evidence_verdict") or {})
    return bool(verdict.get("promote_allowed"))


def _extract_transform_evidence(result: Mapping[str, Any]) -> Dict[str, Any]:
    promotion = dict(result.get("promotion_evidence") or {})
    transform_evidence = dict(result.get("transform_evidence") or promotion.get("transform_evidence") or {})
    if transform_evidence:
        return transform_evidence
    for finding in result.get("findings") or []:
        if isinstance(finding, dict) and str(finding.get("label") or "") == "transform_evidence":
            return dict(finding.get("value") or finding.get("data") or {})
    return {}


def _evaluate_token(
    token: str,
    *,
    result: Mapping[str, Any],
    hunt: Mapping[str, Any],
    expected_phase_id: str,
    promotion: Mapping[str, Any],
    transform_evidence: Mapping[str, Any],
) -> bool:
    hunt_phase = str(hunt.get("phase") or "")
    phases_completed = {str(item) for item in list(hunt.get("phases_completed") or [])}

    if token == "structured_result":
        return result.get("ok") is True

    if token == "phase_completed_for_expected_phase":
        return expected_phase_id in phases_completed

    if token == "sweep_exhausted":
        if hunt_phase == "exhausted":
            return True
        if bool(result.get("phase_exhausted")):
            return True
        if result.get("next_key_cursor") is None and not bool(result.get("keys_found")):
            return True
        return False

    if token == "no_fatal_probe_error":
        if result.get("ok") is not True:
            return False
        error = str(result.get("error") or result.get("fatal") or "").strip()
        return not error

    if token == "transform_evidence_present":
        return bool(transform_evidence.get("windows"))

    if token == "promote_allowed_true":
        verdict = dict(transform_evidence.get("evidence_verdict") or {})
        return bool(verdict.get("promote_allowed")) and bool(promotion.get("promoted"))

    if token == "decrypt_candidate_promoted":
        verdict = dict(transform_evidence.get("evidence_verdict") or {})
        if not promotion.get("promoted"):
            return False
        return (
            promotion.get("promotion_reason") == "already_at_reference_digest"
            or bool(verdict.get("promote_allowed"))
        )

    if token == "artifact_sha_changed":
        reason = str(promotion.get("promotion_reason") or "")
        source_sha = str(promotion.get("source_sha256") or "")
        artifact_sha = str(promotion.get("artifact_sha256") or "")
        if reason == "already_at_reference_digest":
            return True
        return bool(source_sha and artifact_sha and source_sha != artifact_sha)

    if token == "cross_window_validation":
        if promotion.get("promoted") and int(promotion.get("cross_window_agreement") or 0) >= 1:
            return True
        if promotion.get("sha256_match_reference"):
            return True
        reason = str(promotion.get("promotion_reason") or "")
        return reason in {"sha256_reference_match", "already_at_reference_digest", "structural_and_cross_window"}

    if token == "artifact_sha_matches_reference_or_structural":
        structural = list(promotion.get("structural_improvements") or [])
        if promotion.get("sha256_match_reference") or "sha256_reference_match" in structural:
            return True
        return len(structural) >= 1 and bool(promotion.get("promoted"))

    raise MilestoneVerifyError(f"unknown verify token: {token}")


def _transform_evidence_required(profile: Mapping[str, Any], result: Mapping[str, Any]) -> bool:
    when = list(profile.get("transform_evidence_required_when") or [])
    if not when:
        return False
    checks = {
        "stage2_candidates_present": _stage2_candidates_present(result),
        "promotion_path_attempted": _promotion_path_attempted(result),
    }
    return any(checks.get(str(item)) for item in when if str(item) in checks)


def evaluate_milestone_verify(
    milestone_id: str,
    result: Mapping[str, Any],
    hunt: Mapping[str, Any],
    *,
    defaults: Optional[Mapping[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    profile = load_milestone_verify_profile(milestone_id, defaults)
    if not profile:
        return None

    expected_phase_id = expected_phase_id_for_milestone(milestone_id, defaults)
    promotion = dict(result.get("promotion_evidence") or {})
    transform_evidence = _extract_transform_evidence(result)

    if _promotion_succeeded(result) or _promotion_path_attempted(result):
        path_name = "promotion_path"
        tokens = list(profile.get("promotion_path") or [])
    else:
        path_name = "phase_complete_path"
        tokens = list(profile.get("phase_complete_path") or [])

    if not tokens:
        return None

    satisfied: List[str] = []
    failures: List[str] = []
    need_transform_evidence = _transform_evidence_required(profile, result)

    for token in tokens:
        if token == "transform_evidence_present" and not need_transform_evidence:
            continue
        try:
            if _evaluate_token(
                token,
                result=result,
                hunt=hunt,
                expected_phase_id=expected_phase_id,
                promotion=promotion,
                transform_evidence=transform_evidence,
            ):
                satisfied.append(token)
            else:
                failures.append(f"{token} missing")
        except MilestoneVerifyError as exc:
            failures.append(str(exc))

    if need_transform_evidence and path_name == "promotion_path" and "transform_evidence_present" not in tokens:
        if transform_evidence.get("windows"):
            satisfied.append("transform_evidence_present")
        else:
            failures.append("transform_evidence_present missing")

    ok = not failures
    note = path_name if ok else ""
    if ok and path_name == "phase_complete_path":
        note = "phase_complete_without_promotion"
    elif ok and path_name == "promotion_path":
        note = "promotion_gate_passed"

    return {
        "ok": ok,
        "milestone_id": milestone_id,
        "blocking_tokens": tokens,
        "satisfied_tokens": sorted(set(satisfied)),
        "failures": failures,
        "note": note,
        "verify_path": path_name,
    }
