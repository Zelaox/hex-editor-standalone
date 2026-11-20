"""Resolve probe windows for transform analysis from investigation or case SSOT."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional

from src.services.crypto_calibration import probe_windows_for_case, resolve_crypto_case
from src.services.crypto_transform_material import build_default_probe_windows
from src.services.crypto_scoring_regions import compile_scoring_windows, excluded_regions_for_case

from .coverage_window_deriver import derive_coverage_windows
from .evidence_loader import load_investigation_evidence
from .policy import load_investigation_key_hunt_policy
from .probe_ledger import write_derived_windows


def resolve_investigation_probe_windows(
    *,
    source_path: str,
    source_sha256: str = "",
    file_size: int = 0,
    investigation_root: str | None = None,
    window_source: str | None = None,
    policy: Mapping[str, Any] | None = None,
    case: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    active_policy = dict(policy or load_investigation_key_hunt_policy())
    modes = set(active_policy.get("window_source_modes") or [])
    mode = str(window_source or active_policy.get("default_window_source") or "")
    if mode not in modes:
        raise ValueError(f"blocked_by_policy: unknown window_source {mode!r}")
    resolved_case = dict(case) if case else resolve_crypto_case(source_path, sha256=source_sha256, file_size=file_size)
    if mode == "case_static":
        probe_windows = probe_windows_for_case(resolved_case) or build_default_probe_windows(file_size)
        derived = None
    else:
        if not investigation_root:
            raise ValueError("blocked_by_policy: investigation_derived window_source requires investigation_root")
        bundle = load_investigation_evidence(investigation_root)
        derived = derive_coverage_windows(bundle, policy=active_policy, case=resolved_case, file_size=file_size)
        probe_windows = [dict(item) for item in derived.get("windows") or []]
        if active_policy.get("promotion_gate_recording", {}).get("record_derived_windows"):
            write_derived_windows(investigation_root, derived, policy=active_policy)
    excluded = excluded_regions_for_case(resolved_case, file_size=file_size)
    body_windows = compile_scoring_windows(probe_windows, excluded, file_size=file_size)
    if not body_windows:
        raise ValueError("blocked_by_policy: all derived probe windows excluded by cleartext regions")
    return {
        "window_source": mode,
        "probe_windows": probe_windows,
        "body_windows": body_windows,
        "derived_windows": derived,
        "excluded_regions": excluded,
        "policy_digest": str(active_policy.get("policy_digest") or ""),
    }
