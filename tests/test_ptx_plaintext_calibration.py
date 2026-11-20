from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.services.ptx_plaintext_calibration import (
    load_calibration_manifest,
    resolve_calibration_bundle_path,
    scan_ptx_plaintext_signals,
    write_expectations,
)


ROOT = Path(__file__).resolve().parents[1]
BUNDLE_ID = "materialized_candidate_plaintext_v1"
EXPECTATIONS_PATH = ROOT / "data" / "artifacts" / "hex_editor" / "calibration" / "ptx_plaintext_expectations.json"


def _bundle():
    manifest = load_calibration_manifest()
    match = next((item for item in manifest["bundles"] if item["bundle_id"] == BUNDLE_ID), None)
    return match


def test_calibration_manifest_is_pytest_only():
    manifest = load_calibration_manifest()
    assert manifest.get("pytest_only") is True
    assert isinstance(manifest.get("bundles"), list)


@pytest.mark.skipif(_bundle() is None or not resolve_calibration_bundle_path(_bundle()).is_file(), reason="optional private calibration fixture not supplied")
def test_scan_meets_recorded_minimums():
    bundle = _bundle()
    source = resolve_calibration_bundle_path(bundle)
    scan = scan_ptx_plaintext_signals(source)
    assert scan["minimums"]["printable_run_count"] > 0
    assert scan["minimums"]["timecode_hit_count"] >= 0

    if not EXPECTATIONS_PATH.is_file():
        write_expectations(scan, EXPECTATIONS_PATH)

    expectations = json.loads(EXPECTATIONS_PATH.read_text(encoding="utf-8"))
    minimums = dict(expectations.get("minimums") or {})
    for key, recorded in minimums.items():
        assert int(scan["minimums"][key]) >= int(recorded), f"{key} regressed: {scan['minimums'][key]} < {recorded}"


@pytest.mark.skipif(_bundle() is None or not resolve_calibration_bundle_path(_bundle()).is_file(), reason="optional private calibration fixture not supplied")
def test_ptx_timecode_count_matches_handler():
    source = resolve_calibration_bundle_path(_bundle())
    scan = scan_ptx_plaintext_signals(source)
    assert scan["ptx_timecode_count"] == scan["minimums"]["ptx_timecode_count"]
