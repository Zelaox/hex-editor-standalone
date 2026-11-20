"""Live investigation closure and full-decode multi-turn tests."""

from __future__ import annotations

import random
from pathlib import Path

import pytest

from src.services.full_decode.core import _read

ROOT = Path(__file__).resolve().parents[1]
CLOSURE_POLICY = ROOT / "config" / "full_decode_closure_policy.json"
REGISTRY = ROOT / "config" / "full_decode_registry.json"
LIVE_POLICY = ROOT / "config" / "live_investigation_policy.json"


def _pair(tmp_path: Path, positions=(137, 509, 1301), relation=0xD3, *, extra_parent_diff: tuple[int, int] | None = None):
    rng = random.Random(771)
    decoded = bytearray(rng.randrange(128, 256) for _ in range(2048))
    text = b"portable repeated ascii record"
    for offset in positions:
        decoded[offset - 1] = 0
        decoded[offset:offset + len(text)] = text
        decoded[offset + len(text)] = 0
    parent = bytearray(decoded)
    for offset in positions:
        for index in range(offset, offset + len(text)):
            parent[index] ^= relation
    if extra_parent_diff is not None:
        start, end = extra_parent_diff
        for index in range(start, end):
            parent[index] ^= rng.randrange(1, 256)
    source, base = tmp_path / "decoded.bin", tmp_path / "parent.bin"
    source.write_bytes(decoded)
    base.write_bytes(parent)
    return source, base


def test_full_decode_model_packet_includes_pending_measurements(tmp_path):
    from src.services.full_decode import build_full_decode_model_packet, run_full_decode_e2e

    source, parent = _pair(tmp_path, extra_parent_diff=(1800, 1850))
    run = run_full_decode_e2e(source, parent, output_root=tmp_path / "runs", policy_path=CLOSURE_POLICY, registry_path=REGISTRY)
    run_path = Path(run["run_root"]) / "run.json"
    packet = build_full_decode_model_packet(run_path, policy_path=CLOSURE_POLICY, registry_path=REGISTRY)
    pending = [item for item in packet["measurements"] if item["status"] == "pending"]
    assert pending
    assert any(item["measurement_id"] == "run-local-transform-proof" for item in pending)


def test_execute_registered_measurement_recomposes_run(tmp_path):
    from src.services.full_decode import (
        apply_full_decode_advisory_action,
        build_full_decode_model_packet,
        inspect_full_decode_run,
        run_full_decode_e2e,
        verify_full_decode_run,
    )

    source, parent = _pair(tmp_path, extra_parent_diff=(1800, 1850))
    run = run_full_decode_e2e(source, parent, output_root=tmp_path / "runs", policy_path=CLOSURE_POLICY, registry_path=REGISTRY)
    run_path = Path(run["run_root"]) / "run.json"
    assert run["status"] == "partial_unresolved"
    before = inspect_full_decode_run(run_path)
    packet = build_full_decode_model_packet(run_path, policy_path=CLOSURE_POLICY, registry_path=REGISTRY)
    action = {"action": "request_registered_measurement", "measurement_ids": ["run-local-transform-proof"], "reason": "execute deferred provider"}
    result = apply_full_decode_advisory_action(run_path, action, policy_path=CLOSURE_POLICY, registry_path=REGISTRY)
    assert result["executed_new_work"] is True
    updated = inspect_full_decode_run(run_path)
    assert verify_full_decode_run(run_path)["ok"] is True
    assert updated["status"] == "partial_unresolved"
    assert len(updated["providers"]) >= len(before["providers"])
    assert any(item["provider_id"] == "local-transform-proof" for item in updated["providers"])
    assert Path(_read(run_path)["artifacts"]["executed_measurements"]).is_file()


def test_validate_rejects_non_pending_measurement(tmp_path):
    from src.services.full_decode import build_full_decode_model_packet, run_full_decode_e2e, validate_full_decode_model_action

    source, parent = _pair(tmp_path, extra_parent_diff=(1800, 1850))
    run = run_full_decode_e2e(source, parent, output_root=tmp_path / "runs", policy_path=CLOSURE_POLICY, registry_path=REGISTRY)
    run_path = Path(run["run_root"]) / "run.json"
    packet = build_full_decode_model_packet(run_path, policy_path=CLOSURE_POLICY, registry_path=REGISTRY)
    with pytest.raises(ValueError, match="not pending"):
        validate_full_decode_model_action(
            {"action": "request_registered_measurement", "measurement_ids": ["run-record-family-proof"], "reason": "already active"},
            packet,
            policy_path=CLOSURE_POLICY,
            registry_path=REGISTRY,
        )


def test_live_investigation_mechanical_closure_executes_deferred_provider(tmp_path):
    from src.services.live_investigation import run_live_investigation_e2e

    source, parent = _pair(tmp_path, extra_parent_diff=(1800, 1850))
    summary = run_live_investigation_e2e(source, parent, output_root=tmp_path / "investigation", policy_path=LIVE_POLICY)
    assert summary["verified"] is True
    assert summary["final_status"] == "partial_unresolved"
    assert summary["turn_count"] >= 2
    assert any(turn.get("executed_new_work") for turn in summary["turns"] if turn.get("phase") == "advisory_closure")


def test_terminal_resume_is_read_only(tmp_path):
    from src.services.full_decode import resume_full_decode_run, run_full_decode_e2e

    source, parent = _pair(tmp_path)
    run = run_full_decode_e2e(source, parent, output_root=tmp_path / "runs")
    assert run["status"] == "completed"
    resumed = resume_full_decode_run(Path(run["run_root"]))
    assert resumed["executed_new_work"] is False
    assert resumed["reason"] == "terminal_completed"


def test_advisory_generation_falls_back_when_runtime_rejects_grammar():
    from src.services.live_investigation.core import _generate_advisory

    class Client:
        def __init__(self):
            self.calls = []

        def generate(self, prompt, **kwargs):
            self.calls.append(kwargs)
            if "grammar" in kwargs:
                raise RuntimeError("Failed to initialize samplers: failed to parse grammar")
            return {"content": '{"selected_candidate_number":1,"reason":"verified"}'}

    client = Client()
    response = _generate_advisory(
        client,
        "choose",
        boundary={"maximum_tokens": 32, "temperature": 0.0},
        grammar="root ::= \"x\"",
    )

    assert "selected_candidate_number" in response["content"]
    assert "grammar" in client.calls[0]
    assert "grammar" not in client.calls[1]
