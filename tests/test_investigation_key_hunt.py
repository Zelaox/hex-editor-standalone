"""Tests for evidence-driven investigation key hunt windows and ledger."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

INVESTIGATION = ROOT / "tests" / "fixtures" / "private" / "investigation"


@pytest.fixture
def investigation_copy(tmp_path):
    if not INVESTIGATION.is_dir():
        pytest.skip("AC240 investigation folder unavailable")
    target = tmp_path / "investigation"
    target.mkdir()
    for name in ("manifest.json", "state.json"):
        (target / name).write_text((INVESTIGATION / name).read_text(encoding="utf-8"), encoding="utf-8")
    (target / "artifacts").mkdir()
    (target / "artifacts" / "snapshot_brief.json").write_text(
        (INVESTIGATION / "artifacts" / "snapshot_brief.json").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    return target


def test_derived_windows_exclude_header_and_include_body_cipher(investigation_copy):
    from src.services.investigation_key_hunt import derive_coverage_windows, load_investigation_evidence, load_investigation_key_hunt_policy
    from src.services.ptx_crypto_config import resolve_crypto_case

    bundle = load_investigation_evidence(investigation_copy)
    policy = load_investigation_key_hunt_policy()
    case = resolve_crypto_case(bundle["source_path"], sha256=bundle["source_sha256"], file_size=bundle["source_size"])
    derived = derive_coverage_windows(bundle, policy=policy, case=case, file_size=bundle["source_size"])
    offsets = {int(item["offset"]) for item in derived["windows"]}
    assert 256 not in offsets
    assert any(offset >= 1024 for offset in offsets)


def test_bounded_investigation_probe_writes_ledger_and_best_rejected(investigation_copy):
    from src.services.investigation_key_hunt import load_investigation_evidence, load_investigation_key_hunt_policy
    from src.services.ptx_key_discovery import probe_ptx_decrypt_keys

    bundle = load_investigation_evidence(investigation_copy)
    source = Path(bundle["source_path"])
    if not source.is_file():
        pytest.skip("AC240 source file unavailable")
    policy = load_investigation_key_hunt_policy()
    result = probe_ptx_decrypt_keys(
        source,
        exhaustive=False,
        include_known=True,
        probe_phase_id="xor_l2_sweep",
        investigation_root=str(investigation_copy),
        materialize_confirmed=False,
    )
    assert result["ok"] is True
    layout = policy["artifact_layout"]
    ledger_path = investigation_copy / layout["probe_ledger"]
    checkpoint_path = investigation_copy / layout["checkpoint"]
    best_rejected_path = investigation_copy / layout["best_rejected"]
    derived_path = investigation_copy / layout["derived_windows"]
    assert ledger_path.is_file()
    assert checkpoint_path.is_file()
    assert derived_path.is_file()
    if not result.get("keys_found"):
        assert best_rejected_path.is_file()
        rejected = json.loads(best_rejected_path.read_text(encoding="utf-8"))
        assert rejected["operation"] == "investigation_probe_best_rejected"
        assert "promotion_gate" in rejected
        gate = rejected["promotion_gate"]
        assert gate.get("promotion_denied") is True or "reject_reasons" in gate or "checks" in gate
        assert rejected.get("key_hex", "").lower() not in ("00", "0x00")


def test_no_hardcoded_investigation_key_hunt_sources():
    forbidden = ("ac240.ptx", "943d8d8b", "0x94", "if offset ==")
    for relative in (
        "src/services/investigation_key_hunt/coverage_window_deriver.py",
        "src/services/investigation_key_hunt/probe_windows.py",
        "src/services/investigation_key_hunt/probe_ledger.py",
    ):
        source = (ROOT / relative).read_text(encoding="utf-8")
        assert not any(token in source for token in forbidden)
