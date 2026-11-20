"""Registry-driven binary transform search engine."""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

from src.services.behavior_classifier import classify_binary
from src.services.crypto_transform_material import (
    _build_structural_validators,
    _evaluate_known_key_lane,
    _finalize_aes_candidate,
    _finalize_xor_candidate,
    _log_probe_progress,
    _parse_key_hex,
    _score_aes_candidate_cheap,
    _score_xor_candidate_cheap,
    _sweep_limits,
    build_default_probe_windows,
    decode_sweep_cursor,
)
from src.services.crypto_calibration import (
    crypto_defaults,
    known_keys_for_case,
    probe_windows_for_case,
    reference_sha256_for_case,
    resolve_crypto_case,
)
from src.services.crypto_primitives import (
    derive_aes_candidate_keys,
    pt12_signature_key,
    sha256_digest,
)
from src.services.promotion_gate import build_already_at_reference_result
from src.services.crypto_scoring_regions import anchors_for_case, compile_scoring_windows, excluded_regions_for_case
from src.services.stage2_policy import select_stage2_survivors, stage2_cap_applied
from src.services.transform_registry import load_transform_registry, resolve_impl_callable
from src.services.transform_scheduler import schedule_families
from src.services.transforms.base import TransformProbeContext
from src.services.transforms import xor_sweep

logger = logging.getLogger(__name__)


def finalize_xor_registry_candidate(ctx: Any, candidate: Mapping[str, Any], family: Mapping[str, Any]) -> Dict[str, Any]:
    del family
    key_hex = str(candidate.get("key_hex") or "")
    if not key_hex:
        raise ValueError("XOR candidate missing registry-produced key material")
    return _finalize_xor_candidate(ctx, candidate, key=bytes.fromhex(key_hex))


def finalize_aes_registry_candidate(ctx: Any, candidate: Mapping[str, Any], family: Mapping[str, Any]) -> Dict[str, Any]:
    parameters = dict(family.get("finalize_parameters") or {})
    if "key_bytes" not in parameters:
        raise ValueError(f"transform family {family.get('id')} missing finalize key budget")
    key_hex = str(candidate.get("key_hex") or "")
    if not key_hex:
        raise ValueError("AES candidate missing registry-derived key material")
    key = bytes.fromhex(key_hex)
    key_bytes = int(parameters["key_bytes"])
    if len(key) < key_bytes:
        raise ValueError("AES candidate key shorter than registry requirement")
    return _finalize_aes_candidate(ctx, candidate, key=key[:key_bytes])


def finalize_passthrough_registry_candidate(ctx: Any, candidate: Mapping[str, Any], family: Mapping[str, Any]) -> Dict[str, Any]:
    del ctx, family
    return dict(candidate, cheap_only=False)


def _probe_context_from_legacy(ctx: Any) -> TransformProbeContext:
    return TransformProbeContext(
        raw=ctx.raw,
        case=ctx.case,
        defaults=ctx.defaults,
        pipeline=ctx.pipeline,
        xor_start=ctx.xor_start,
        reference_sha=ctx.reference_sha,
        source_sha=ctx.source_sha,
        anchors=ctx.anchors,
        body_windows=ctx.body_windows,
        reference_bytes=ctx.reference_bytes,
        crypto_case_id=ctx.crypto_case_id,
    )


def analyze_binary_transform_candidates(
    path: str | Path,
    *,
    sample_offset: int = 0,
    sample_length: int = 0,
    key_cursor: int = 0,
    key_batch: int = 16,
    include_known: bool = True,
    source_sha256: str = "",
    file_size: int = 0,
    include_byte_transforms: bool = False,
    include_infer_xor: bool = False,
    include_extended_crypto: bool = False,
    probe_phase_id: str = "",
    investigation_root: str | None = None,
    window_source: str | None = None,
) -> Dict[str, Any]:
    resolved = Path(path).expanduser().resolve()
    raw = resolved.read_bytes()
    case = resolve_crypto_case(resolved, sha256=source_sha256, file_size=file_size or len(raw))
    defaults = crypto_defaults()
    registry = load_transform_registry(defaults)

    phase_exec: Optional[Dict[str, Any]] = None
    active_phase_id = str(probe_phase_id or "")
    if active_phase_id:
        from src.services.probe_phase_config import phase_by_id, resolve_phase_execution

        phase = phase_by_id(active_phase_id, defaults)
        phase_exec = resolve_phase_execution(
            phase,
            defaults=defaults,
            case=case,
            session_carry={"last_key_cursor": key_cursor},
        )
        include_known = bool(phase_exec.get("include_known"))
        include_infer_xor = bool(phase_exec.get("include_infer_xor"))
        include_extended_crypto = bool(phase_exec.get("include_extended_crypto"))
        include_byte_transforms = bool(phase_exec.get("include_byte_transforms"))
        if int(phase_exec.get("sample_offset") or 0):
            sample_offset = int(phase_exec["sample_offset"])
        if int(phase_exec.get("sample_length") or 0):
            sample_length = int(phase_exec["sample_length"])
        key_cursor = int(phase_exec.get("key_cursor") or key_cursor)
        key_batch = int(phase_exec.get("key_batch") or key_batch)

    if investigation_root:
        from src.services.investigation_key_hunt import load_investigation_key_hunt_policy

        hunt_policy = load_investigation_key_hunt_policy()
        key_batch = min(int(key_batch), int(hunt_policy["budgets"]["default_key_batch"]))

    xor_start = int((case or {}).get("decrypt", {}).get("xor_start_offset") or defaults.get("xor_start_offset") or 16)
    reference_sha = reference_sha256_for_case(case)
    source_sha = str(source_sha256 or sha256_digest(raw))

    classifier = classify_binary(raw, defaults=defaults, transform_start=xor_start)

    early = build_already_at_reference_result(
        source_bytes=raw,
        reference_sha256=reference_sha,
        fixture_key_hex=str((case or {}).get("decrypt", {}).get("key_hex") or ""),
        algorithm=str((case or {}).get("decrypt", {}).get("algorithm") or "xor_single_byte"),
    )
    if early and source_sha.lower() == reference_sha.lower():
        best = {
            "name": "already_at_reference_digest",
            "algorithm": early.get("algorithm"),
            "key_hex": early.get("best_key_hex"),
            "promoted": True,
            "confidence": "high",
            "skip_materialize": True,
            "promotion_evidence": early,
            "full_file_validation": {
                "sha256": source_sha,
                "source_sha256": source_sha,
                "sha256_match_reference": True,
            },
        }
        return {
            "candidates": [best],
            "best": best,
            "keys_found": True,
            "key_cursor": 0,
            "next_key_cursor": None,
            "probe_windows": [],
            "reference_sha256": reference_sha,
            "xor_start_offset": xor_start,
            "crypto_case_id": str((case or {}).get("id") or ""),
            "promotion_evidence": early,
            "behavior_classifier": classifier,
        }

    probe_windows = probe_windows_for_case(case) or build_default_probe_windows(len(raw))
    window_resolution: Optional[Dict[str, Any]] = None
    if investigation_root:
        from src.services.investigation_key_hunt import resolve_investigation_probe_windows

        window_resolution = resolve_investigation_probe_windows(
            source_path=str(resolved),
            source_sha256=source_sha,
            file_size=len(raw),
            investigation_root=investigation_root,
            window_source=window_source,
            case=case,
        )
        probe_windows = list(window_resolution.get("probe_windows") or [])
        body_windows = list(window_resolution.get("body_windows") or [])
    else:
        excluded = excluded_regions_for_case(case, file_size=len(raw))
        body_windows = compile_scoring_windows(probe_windows, excluded, file_size=len(raw))
        if not body_windows:
            body_windows = compile_scoring_windows(build_default_probe_windows(len(raw)), excluded, file_size=len(raw))
    if sample_offset or sample_length:
        body_windows = [
            {"name": "requested_sample", "offset": sample_offset, "length": sample_length},
            *body_windows,
        ]

    ctx = TransformProbeContext.build(
        raw,
        case=case,
        defaults=defaults,
        source_sha=source_sha,
        body_windows=body_windows,
        classifier=classifier,
        registry=registry,
    )
    pipeline = ctx.pipeline
    if phase_exec:
        sweep_limit = int(phase_exec.get("sweep_key_limit") or pipeline.get("sweep_key_limit") or 2560)
    else:
        sweep_limit, _ = _sweep_limits(pipeline)
    if investigation_root:
        from src.services.investigation_key_hunt import load_investigation_key_hunt_policy

        hunt_policy = load_investigation_key_hunt_policy()
        investigation_sweep_cap = int(hunt_policy["budgets"]["max_sweep_keys_per_run"])
        sweep_limit = min(sweep_limit, investigation_sweep_cap)
    single_limit = max(1, min(int(pipeline.get("sweep_single_byte_limit") or 256), sweep_limit))
    candidates: List[Dict[str, Any]] = []
    probe_timings: Dict[str, float] = {"cheap_ms": 0.0, "stage2_ms": 0.0}

    run_xor_sweep = phase_exec is None or bool(phase_exec.get("xor_sweep"))

    if include_known and (phase_exec is None or run_xor_sweep):
        from src.services.crypto_transform_material import ProbeContext

        legacy_ctx = ProbeContext.build(raw, case=case, defaults=defaults, source_sha=source_sha, body_windows=body_windows)
        _log_probe_progress("known-key lane (cheap -> stage2 survivors)", pipeline=pipeline)
        t_known = time.perf_counter()
        candidates.extend(_evaluate_known_key_lane(legacy_ctx, case=case))
        probe_timings["known_lane_ms"] = round((time.perf_counter() - t_known) * 1000.0, 2)

    batch = max(1, min(int(key_batch), sweep_limit))
    cursor = max(0, min(int(key_cursor), max(0, sweep_limit - 1)))
    end = min(sweep_limit, cursor + batch)

    if run_xor_sweep and end > cursor and not classifier.get("skip_crypto_lanes"):
        t_cheap = time.perf_counter()
        cheap_batch = xor_sweep.cheap_probe_batch(ctx, cursor=cursor, batch=batch, single_byte_limit=single_limit)
        probe_timings["cheap_ms"] = round((time.perf_counter() - t_cheap) * 1000.0, 2)
        survivors = select_stage2_survivors(cheap_batch, pipeline=pipeline, defaults=defaults)
        cap_info = stage2_cap_applied(cheap_batch, pipeline=pipeline, defaults=defaults)
        best_cheap_score = max((int(item.get("score") or 0) for item in cheap_batch), default=0)
        _log_probe_progress(
            f"batch {cursor}-{end - 1}: cheap={len(cheap_batch)} stage2={len(survivors)} "
            f"best_score={best_cheap_score} stage2_cap_policy={cap_info.get('stage2_cap_policy')} "
            f"stage2_cap_applied={cap_info.get('stage2_cap_applied')} elapsed_cheap_ms={probe_timings['cheap_ms']}",
            pipeline=pipeline,
        )
        t_stage2 = time.perf_counter()
        from src.services.crypto_transform_material import ProbeContext

        legacy_ctx = ProbeContext.build(raw, case=case, defaults=defaults, source_sha=source_sha, body_windows=body_windows)
        finalized_by_index: Dict[int, Dict[str, Any]] = {}
        for index in survivors:
            cheap = cheap_batch[index]
            finalized_by_index[index] = _finalize_xor_candidate(
                legacy_ctx,
                cheap,
                key=bytes.fromhex(str(cheap["key_hex"])),
            )
        probe_timings["stage2_ms"] = round((time.perf_counter() - t_stage2) * 1000.0, 2)
        for index, cheap in enumerate(cheap_batch):
            if index in finalized_by_index:
                candidates.append(finalized_by_index[index])
            else:
                candidates.append(dict(cheap))

    scheduled = schedule_families(
        registry,
        classifier=classifier,
        include_byte_transforms=include_byte_transforms,
        include_infer_xor=include_infer_xor,
        include_extended_crypto=include_extended_crypto,
    )
    if include_extended_crypto or include_infer_xor or include_byte_transforms:
        for family in scheduled:
            family_id = str(family.get("id") or "")
            try:
                cheap_fn = resolve_impl_callable(family, "cheap")
                finalize_fn = resolve_impl_callable(family, "finalize")
            except Exception as exc:
                logger.warning("skip family %s: %s", family_id, exc)
                continue
            t_family = time.perf_counter()
            cheap_results = cheap_fn(ctx, family=family) if bool((family.get("impl") or {}).get("pass_family")) else cheap_fn(ctx)
            probe_timings[f"family_{family_id}_ms"] = round((time.perf_counter() - t_family) * 1000.0, 2)
            if not cheap_results:
                continue
            survivors = select_stage2_survivors(cheap_results, pipeline=pipeline, defaults=defaults)
            from src.services.crypto_transform_material import ProbeContext

            legacy_ctx = ProbeContext.build(raw, case=case, defaults=defaults, source_sha=source_sha, body_windows=body_windows)
            for index in survivors:
                cheap = cheap_results[index]
                candidates.append(finalize_fn(legacy_ctx, cheap, family))

    phase_exhausted = bool(phase_exec and phase_exec.get("single_shot"))
    if phase_exec and run_xor_sweep:
        phase_exhausted = end >= sweep_limit
    elif not phase_exec:
        phase_exhausted = end >= sweep_limit
    next_cursor = None if phase_exhausted or end >= sweep_limit else end

    promoted = [item for item in candidates if item.get("promoted")]
    promoted.sort(key=lambda item: (-int(item.get("score") or 0), str(item.get("key_hex") or "")))
    best = promoted[0] if promoted else None
    keys_found = bool(best)
    promotion_evidence = dict((best or {}).get("promotion_evidence") or {})
    transform_evidence = dict((best or {}).get("transform_evidence") or promotion_evidence.get("transform_evidence") or {})

    result = {
        "candidates": candidates,
        "best": best,
        "keys_found": keys_found,
        "key_cursor": cursor,
        "key_batch": batch,
        "sweep_key_limit": sweep_limit,
        "sweep_single_byte_limit": single_limit,
        "next_key_cursor": next_cursor if not phase_exhausted else None,
        "probe_phase_id": active_phase_id,
        "phase_exhausted": phase_exhausted,
        "probe_windows": body_windows,
        "reference_sha256": reference_sha,
        "xor_start_offset": xor_start,
        "crypto_case_id": str((case or {}).get("id") or ""),
        "promotion_evidence": promotion_evidence,
        "transform_evidence": transform_evidence,
        "behavior_classifier": classifier,
    }
    if window_resolution:
        result["window_source"] = window_resolution.get("window_source")
        result["derived_windows_digest"] = (window_resolution.get("derived_windows") or {}).get("artifact_digest")
        result["window_policy_digest"] = window_resolution.get("policy_digest")
    if pipeline.get("include_timing"):
        result["probe_timings_ms"] = probe_timings
    return result
