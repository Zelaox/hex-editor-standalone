"""Config-driven decrypt probe phases — NO HARDCODE milestone key lanes."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Sequence

from src.services.crypto_calibration import crypto_defaults, probe_pipeline_config, probe_windows_for_case
from src.services.transform_registry import merge_crypto_defaults


class ProbePhaseConfigError(ValueError):
    pass


def _resolve_ref(defaults: Mapping[str, Any], ref: str) -> Any:
    parts = str(ref or "").split(".")
    current: Any = defaults
    for part in parts:
        if not part:
            continue
        if not isinstance(current, Mapping):
            raise ProbePhaseConfigError(f"unresolved config ref: {ref}")
        current = current.get(part)
    if current is None:
        raise ProbePhaseConfigError(f"missing config ref: {ref}")
    return current


def load_probe_phases(defaults: Optional[Mapping[str, Any]] = None) -> List[Dict[str, Any]]:
    base = dict(defaults or crypto_defaults())
    phases = base.get("probe_phases")
    if not isinstance(phases, list) or not phases:
        raise ProbePhaseConfigError("missing probe_phases in crypto config SSOT")
    out: List[Dict[str, Any]] = []
    for item in phases:
        if not isinstance(item, dict):
            continue
        phase = dict(item)
        if not str(phase.get("id") or ""):
            raise ProbePhaseConfigError("probe phase missing id")
        out.append(phase)
    if not out:
        raise ProbePhaseConfigError("probe_phases empty")
    return out


def phase_for_milestone(milestone_id: str, defaults: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    needle = str(milestone_id or "").strip()
    for phase in load_probe_phases(defaults):
        milestones = [str(item) for item in phase.get("milestones") or []]
        if needle in milestones:
            return dict(phase)
    raise ProbePhaseConfigError(f"no probe phase configured for milestone {needle}")


def phase_by_id(phase_id: str, defaults: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    needle = str(phase_id or "").strip()
    for phase in load_probe_phases(defaults):
        if str(phase.get("id") or "") == needle:
            return dict(phase)
    raise ProbePhaseConfigError(f"unknown probe phase id: {needle}")


def _default_sample_length(defaults: Mapping[str, Any], case: Optional[Mapping[str, Any]]) -> int:
    windows = probe_windows_for_case(case) or list(defaults.get("probe_windows") or [])
    if windows and isinstance(windows[0], dict):
        return int(windows[0].get("length") or 4096)
    pipeline = probe_pipeline_config(defaults)
    return int(pipeline.get("default_sample_length") or 4096)


def _window_from_ref(
    engine: Mapping[str, Any],
    *,
    defaults: Mapping[str, Any],
    case: Optional[Mapping[str, Any]],
) -> Dict[str, int]:
    window_ref = str(engine.get("sample_window_ref") or "")
    if window_ref == "case.decrypt.m8_probe_window" and case:
        m8 = dict((case.get("decrypt") or {}).get("m8_probe_window") or {})
        if m8:
            return {
                "sample_offset": int(m8.get("offset") or 8192),
                "sample_length": int(m8.get("length") or 4096),
            }

    default_ref = str(engine.get("default_window_ref") or "")
    if default_ref == "crypto_defaults.xor_start_offset":
        return {
            "sample_offset": int(defaults.get("xor_start_offset") or 0),
            "sample_length": _default_sample_length(defaults, case),
        }

    if not window_ref and not default_ref:
        return {
            "sample_offset": int(defaults.get("xor_start_offset") or 0),
            "sample_length": _default_sample_length(defaults, case),
        }

    windows = probe_windows_for_case(case) or list(defaults.get("probe_windows") or [])
    if window_ref == "probe_windows.body_mid" and len(windows) > 1 and isinstance(windows[1], dict):
        win = windows[1]
        return {
            "sample_offset": int(win.get("offset") or 8192),
            "sample_length": int(win.get("length") or 4096),
        }
    if len(windows) > 1 and isinstance(windows[1], dict):
        win = windows[1]
        return {
            "sample_offset": int(win.get("offset") or 8192),
            "sample_length": int(win.get("length") or 4096),
        }
    return {
        "sample_offset": int(defaults.get("xor_start_offset") or 0),
        "sample_length": _default_sample_length(defaults, case),
    }


def resolve_phase_execution(
    phase: Mapping[str, Any],
    *,
    defaults: Optional[Mapping[str, Any]] = None,
    case: Optional[Mapping[str, Any]] = None,
    session_carry: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    base = dict(defaults or crypto_defaults())
    pipeline = probe_pipeline_config(base)
    engine = dict(phase.get("engine") or {})
    window = _window_from_ref(engine, defaults=base, case=case)

    sweep_limit = int(pipeline.get("sweep_key_limit") or 25600)
    if engine.get("sweep_limit_ref"):
        sweep_limit = int(_resolve_ref(base, str(engine["sweep_limit_ref"])))
    batch = int(pipeline.get("exhaustive_key_batch") or sweep_limit)
    if engine.get("batch_ref"):
        batch = int(_resolve_ref(base, str(engine["batch_ref"])))
    batch = max(1, min(batch, sweep_limit))

    cursor = int((session_carry or {}).get("last_key_cursor") or 0)
    if not bool(engine.get("uses_cursor", True)):
        cursor = 0

    return {
        "probe_phase_id": str(phase.get("id") or ""),
        "include_known": bool(engine.get("include_known", False)),
        "include_infer_xor": bool(engine.get("include_infer_xor", False)),
        "include_extended_crypto": bool(engine.get("include_extended_crypto", False)),
        "include_byte_transforms": bool(engine.get("include_byte_transforms", False)),
        "xor_sweep": bool(engine.get("xor_sweep", False)),
        "sample_offset": int(window["sample_offset"]),
        "sample_length": int(window["sample_length"]),
        "key_cursor": cursor,
        "key_batch": batch,
        "sweep_key_limit": sweep_limit,
        "single_shot": bool(engine.get("single_shot", False)),
    }


def resolve_active_probe_execution(
    milestone_id: str,
    *,
    target_path: str = "",
    session_carry: Optional[Mapping[str, Any]] = None,
    hunt: Optional[Mapping[str, Any]] = None,
    case: Optional[Mapping[str, Any]] = None,
    defaults: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Single authority for probe tool params — milestone runner and next_action."""
    base = dict(defaults or crypto_defaults())
    if case is None and target_path:
        from src.services.crypto_calibration import resolve_crypto_case

        case = resolve_crypto_case(target_path)

    carry = dict(session_carry or {})
    hunt_state = dict(hunt or carry.get("decrypt_key_hunt") or {})
    phases_completed = [str(item) for item in list(hunt_state.get("phases_completed") or [])]
    milestone_phase = phase_for_milestone(milestone_id, base)
    milestone_phase_id = str(milestone_phase.get("id") or "")

    if milestone_phase_id not in phases_completed:
        phase = milestone_phase
    else:
        active_phase_id = str(hunt_state.get("probe_phase_id") or "")
        if not active_phase_id:
            active_phase_id = str(next_probe_phase(phases_completed, base) or milestone_phase_id)
        phase = phase_by_id(active_phase_id, base)

    cursor_carry = dict(carry)
    if hunt_state:
        cursor_carry["last_key_cursor"] = int(hunt_state.get("last_key_cursor") or carry.get("last_key_cursor") or 0)

    resolved = resolve_phase_execution(phase, defaults=base, case=case, session_carry=cursor_carry)
    resolved["milestone_id"] = str(milestone_id)
    return resolved


def milestone_probe_params(
    milestone_id: str,
    *,
    target_path: str = "",
    session_carry: Optional[Mapping[str, Any]] = None,
    case: Optional[Mapping[str, Any]] = None,
    defaults: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    base = dict(defaults or crypto_defaults())
    if case is None and target_path:
        from src.services.crypto_calibration import resolve_crypto_case

        case = resolve_crypto_case(target_path)
    phase = phase_for_milestone(milestone_id, base)
    resolved = resolve_phase_execution(phase, defaults=base, case=case, session_carry=session_carry)
    resolved["milestone_id"] = str(milestone_id)
    return resolved


def resolve_probe_next_action_params(
    *,
    target_path: str,
    session_carry: Optional[Mapping[str, Any]] = None,
    completed: Optional[Sequence[str]] = None,
    defaults: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    done = {str(item) for item in list(completed or [])}
    for milestone_id in ("M7", "M8", "M9"):
        if milestone_id not in done:
            return resolve_active_probe_execution(
                milestone_id,
                target_path=target_path,
                session_carry=session_carry,
                defaults=defaults,
            )
    return resolve_active_probe_execution(
        "M9",
        target_path=target_path,
        session_carry=session_carry,
        defaults=defaults,
    )


def initial_probe_phase(defaults: Optional[Mapping[str, Any]] = None) -> str:
    phases = load_probe_phases(defaults)
    return str(phases[0].get("id") or "")


def next_probe_phase(
    phases_completed: List[str],
    defaults: Optional[Mapping[str, Any]] = None,
) -> Optional[str]:
    done = {str(item) for item in phases_completed}
    for phase in load_probe_phases(defaults):
        phase_id = str(phase.get("id") or "")
        if phase_id and phase_id not in done:
            return phase_id
    return None
