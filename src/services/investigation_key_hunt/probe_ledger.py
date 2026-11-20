"""Append-only probe ledger, best-rejected diagnostics, and checkpoints."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Dict, Mapping, Optional


def _digest(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _artifact_path(root: Path, policy: Mapping[str, Any], key: str) -> Path:
    layout = dict(policy.get("artifact_layout") or {})
    relative = str(layout.get(key) or "")
    if not relative:
        raise ValueError(f"investigation key hunt policy missing artifact_layout.{key}")
    return root / relative


def write_derived_windows(investigation_root: str | Path, derived: Mapping[str, Any], *, policy: Mapping[str, Any]) -> Path:
    root = Path(investigation_root).resolve()
    target = _artifact_path(root, policy, "derived_windows")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(dict(derived), indent=2, sort_keys=True, ensure_ascii=False, default=str) + "\n", encoding="utf-8")
    return target


def append_probe_event(investigation_root: str | Path, event: Mapping[str, Any], *, policy: Mapping[str, Any]) -> str:
    root = Path(investigation_root).resolve()
    target = _artifact_path(root, policy, "probe_ledger")
    target.parent.mkdir(parents=True, exist_ok=True)
    event_id = str(event.get("event_id") or _digest(event))
    row = {**dict(event), "event_id": event_id}
    with target.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, sort_keys=True, ensure_ascii=False, default=str) + "\n")
    return event_id


def _promotion_gate_snapshot(candidate: Mapping[str, Any]) -> Dict[str, Any]:
    promotion = dict(candidate.get("promotion_evidence") or {})
    checks = {
        "promoted": promotion.get("promoted") is True,
        "sha256_match_reference": promotion.get("sha256_match_reference") is True,
        "cross_window_agreement": int(promotion.get("cross_window_agreement") or 0),
        "structural_improvements": list(promotion.get("structural_improvements") or []),
        "max_entropy_drop": float(promotion.get("max_entropy_drop") or 0.0),
        "changed_byte_count": int(promotion.get("changed_byte_count") or 0),
    }
    return {
        "promotion_denied": promotion.get("promoted") is not True,
        "reject_reasons": sorted(str(item) for item in promotion.get("reject_reasons") or []),
        "checks": checks,
        "promotion_reason": str(promotion.get("promotion_reason") or ""),
    }


def _is_identity_candidate(candidate: Mapping[str, Any]) -> bool:
    if candidate.get("cheap_identity"):
        return True
    promotion = dict(candidate.get("promotion_evidence") or {})
    reasons = list(candidate.get("reject_reasons") or promotion.get("reject_reasons") or [])
    if "identity_transform" in reasons:
        return True
    key_hex = str(candidate.get("key_hex") or "").lower().removeprefix("0x")
    window_scores = list(candidate.get("window_scores") or [])
    if key_hex in ("00", "") and window_scores and all(item.get("identity") for item in window_scores):
        return True
    return False


def write_best_rejected(
    investigation_root: str | Path,
    *,
    candidate: Mapping[str, Any],
    policy: Mapping[str, Any],
    probe_phase_id: str,
    policy_digest: str,
    window_names: Optional[list[str]] = None,
) -> Path:
    root = Path(investigation_root).resolve()
    target = _artifact_path(root, policy, "best_rejected")
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor = {
        "key_hex": str(candidate.get("key_hex") or ""),
        "algorithm": str(candidate.get("algorithm") or ""),
        "probe_phase_id": str(probe_phase_id or ""),
        "policy_digest": str(policy_digest or ""),
    }
    transform_evidence = dict(candidate.get("transform_evidence") or {})
    payload = {
        "schema_version": 1,
        "operation": "investigation_probe_best_rejected",
        "candidate_id": _digest(descriptor),
        "key_hex": descriptor["key_hex"],
        "algorithm": descriptor["algorithm"],
        "scores": {
            "cheap_score": int(candidate.get("score") or 0),
            "stage2_score": int(candidate.get("score") or 0),
        },
        "promotion_gate": _promotion_gate_snapshot(candidate),
        "transform_evidence_digest": _digest(transform_evidence) if transform_evidence else "",
        "policy_digest": descriptor["policy_digest"],
        "probe_phase_id": descriptor["probe_phase_id"],
        "window_names": sorted(str(item) for item in (window_names or [])),
        "provenance": str(candidate.get("provenance") or candidate.get("name") or ""),
    }
    target.write_text(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False, default=str) + "\n", encoding="utf-8")
    return target


def load_checkpoint(investigation_root: str | Path, *, policy: Mapping[str, Any]) -> Dict[str, Any]:
    root = Path(investigation_root).resolve()
    target = _artifact_path(root, policy, "checkpoint")
    if not target.is_file():
        return {}
    return json.loads(target.read_text(encoding="utf-8-sig"))


def save_checkpoint(investigation_root: str | Path, checkpoint: Mapping[str, Any], *, policy: Mapping[str, Any]) -> Path:
    root = Path(investigation_root).resolve()
    target = _artifact_path(root, policy, "checkpoint")
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = {"schema_version": 1, **dict(checkpoint)}
    target.write_text(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False, default=str) + "\n", encoding="utf-8")
    return target


def record_probe_run(
    investigation_root: str | Path,
    *,
    analysis: Mapping[str, Any],
    policy: Mapping[str, Any],
    window_resolution: Mapping[str, Any],
    elapsed_seconds: float,
    started_monotonic: float,
) -> Dict[str, Any]:
    root = Path(investigation_root).resolve()
    candidates = list(analysis.get("candidates") or [])
    best = dict(analysis.get("best") or {})
    keys_found = bool(analysis.get("keys_found"))
    ranked = sorted(candidates, key=lambda item: int(item.get("score") or 0), reverse=True)
    top = next((item for item in ranked if not _is_identity_candidate(item)), ranked[0] if ranked else {})
    if not keys_found and top and policy.get("promotion_gate_recording", {}).get("record_best_rejected"):
        write_best_rejected(
            root,
            candidate=top,
            policy=policy,
            probe_phase_id=str(analysis.get("probe_phase_id") or ""),
            policy_digest=str(window_resolution.get("policy_digest") or policy.get("policy_digest") or ""),
            window_names=[str(item.get("name") or "") for item in window_resolution.get("body_windows") or []],
        )
    event_id = append_probe_event(
        root,
        {
            "schema_version": 1,
            "operation": "investigation_probe_batch",
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "probe_phase_id": str(analysis.get("probe_phase_id") or ""),
            "key_cursor": int(analysis.get("key_cursor") or 0),
            "next_key_cursor": analysis.get("next_key_cursor"),
            "key_batch": int(analysis.get("key_batch") or 0),
            "keys_found": keys_found,
            "best_key_hex": str(best.get("key_hex") or top.get("key_hex") or ""),
            "best_score": int(best.get("score") or top.get("score") or 0),
            "candidate_count": len(candidates),
            "window_source": str(window_resolution.get("window_source") or ""),
            "derived_windows_digest": str((window_resolution.get("derived_windows") or {}).get("artifact_digest") or ""),
            "policy_digest": str(window_resolution.get("policy_digest") or policy.get("policy_digest") or ""),
            "elapsed_seconds": round(float(elapsed_seconds), 3),
        },
        policy=policy,
    )
    checkpoint = {
        "probe_phase_id": str(analysis.get("probe_phase_id") or ""),
        "key_cursor": analysis.get("next_key_cursor") if analysis.get("next_key_cursor") is not None else int(analysis.get("key_cursor") or 0),
        "phase_exhausted": bool(analysis.get("phase_exhausted")),
        "keys_found": keys_found,
        "last_event_id": event_id,
        "budgets_consumed_seconds": round(float(elapsed_seconds), 3),
        "updated_monotonic": time.monotonic() - started_monotonic,
        "policy_digest": str(policy.get("policy_digest") or ""),
    }
    save_checkpoint(root, checkpoint, policy=policy)
    return {"event_id": event_id, "checkpoint": checkpoint}
