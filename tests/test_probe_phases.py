"""Probe phase config tests."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

HEX_ROOT = Path(__file__).resolve().parents[1]
if str(HEX_ROOT) not in sys.path:
    sys.path.insert(0, str(HEX_ROOT))


def test_probe_phases_load_for_milestones():
    from src.services.probe_phase_config import load_probe_phases, phase_for_milestone

    phases = load_probe_phases()
    assert len(phases) >= 3
    m7 = phase_for_milestone("M7")
    m8 = phase_for_milestone("M8")
    m9 = phase_for_milestone("M9")
    assert m7["id"] == "xor_l2_sweep"
    assert m8["id"] == "xor_repeating_infer"
    assert m9["id"] == "extended_crypto_byte"
    assert m7["id"] != m8["id"] != m9["id"]


def test_sweep_limit_x10_in_config():
    from src.services.ptx_crypto_config import crypto_defaults

    pipeline = crypto_defaults().get("probe_pipeline") or {}
    assert int(pipeline.get("sweep_key_limit") or 0) == 25600
    assert int(pipeline.get("exhaustive_key_batch") or 0) == 25600
    assert int(pipeline.get("xor_l2_sweep_limit") or 0) == 2560


def test_m8_phase_runs_infer_not_sweep():
    from src.services.probe_phase_config import milestone_probe_params

    params = milestone_probe_params("M8", case={"decrypt": {"m8_probe_window": {"offset": 8192, "length": 4096}}})
    assert params["probe_phase_id"] == "xor_repeating_infer"
    assert params["include_infer_xor"] is True
    assert params.get("xor_sweep") is not True
    assert int(params.get("sample_offset") or 0) == 8192


def test_m7_xor_l2_sweep_window_uses_xor_start_offset():
    from src.services.probe_phase_config import milestone_probe_params

    params = milestone_probe_params("M7", case={"decrypt": {"m8_probe_window": {"offset": 8192, "length": 4096}}})
    assert params["probe_phase_id"] == "xor_l2_sweep"
    assert int(params.get("sample_offset") or 0) == 16


def test_resolve_active_probe_execution_uses_hunt_phase():
    from src.services.probe_phase_config import resolve_active_probe_execution

    params = resolve_active_probe_execution(
        "M7",
        case={"decrypt": {"m8_probe_window": {"offset": 8192, "length": 4096}}},
        hunt={
            "probe_phase_id": "xor_l2_sweep",
            "phases_completed": [],
            "last_key_cursor": 128,
        },
    )
    assert params["probe_phase_id"] == "xor_l2_sweep"
    assert int(params.get("sample_offset") or 0) == 16
    assert int(params.get("key_cursor") or 0) == 128


def test_m7_passes_phase_complete_with_stage2_but_no_transform_evidence():
    from src.services.probe_milestone_verify import evaluate_milestone_verify

    verify = evaluate_milestone_verify(
        "M7",
        {
            "ok": True,
            "operation": "ptx_probe_decrypt_keys",
            "keys_found": False,
            "phase_exhausted": True,
            "next_key_cursor": None,
            "probe_timings_ms": {"stage2_ms": 42.0},
        },
        {
            "phase": "probe",
            "probe_phase_id": "xor_repeating_infer",
            "phases_completed": ["xor_l2_sweep"],
        },
    )
    assert verify is not None
    assert verify["ok"] is True
    assert verify.get("verify_path") == "phase_complete_path"


def test_resolve_active_probe_execution_keeps_milestone_phase_until_complete():
    from src.services.probe_phase_config import resolve_active_probe_execution

    params = resolve_active_probe_execution(
        "M7",
        case={"decrypt": {"m8_probe_window": {"offset": 8192, "length": 4096}}},
        hunt={
            "probe_phase_id": "xor_repeating_infer",
            "phases_completed": [],
            "last_key_cursor": 0,
        },
    )
    assert params["probe_phase_id"] == "xor_l2_sweep"
    assert int(params.get("sample_offset") or 0) == 16


def test_resolve_active_probe_execution_after_m7_phase_advances():
    from src.services.probe_phase_config import resolve_active_probe_execution

    params = resolve_active_probe_execution(
        "M7",
        case={"decrypt": {"m8_probe_window": {"offset": 8192, "length": 4096}}},
        hunt={
            "probe_phase_id": "xor_repeating_infer",
            "phases_completed": ["xor_l2_sweep"],
            "last_key_cursor": 0,
        },
    )
    assert params["probe_phase_id"] == "xor_repeating_infer"
    assert int(params.get("sample_offset") or 0) == 8192
