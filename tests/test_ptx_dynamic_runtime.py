from __future__ import annotations

import json
from pathlib import Path

from src.services.ptx_dynamic_key_hunt import compile_hypothesis, run_dynamic_key_hunt
from src.services.ptx_runtime_analysis import ByteSource, analyze_runtime_source, binary_waterfall_payload
from src.services.ptx_session_diff import diff_snapshots
from src.services.ptx_workspace import export_runtime_workspace, load_runtime_workspace


def _policy(size: int) -> dict:
    return {
        "schema_version": 1,
        "registry_revision": "test-registry",
        "capability": "bounded_binary_hypothesis",
        "budgets": {"max_source_bytes": 100000, "max_candidates": 8, "max_seconds": 5, "max_preview_bytes": 16, "max_attempts_in_packet": 4},
        "transform_registry": {"xor_single_byte": {"key_length_min": 1, "key_length_max": 1, "requires_key_hex": True, "executor": {"module": "src.services.key_hunt_executors", "function": "apply_xor_descriptor"}}},
        "parser_policy": {"minimum_string_length": 4, "maximum_string_length": 128, "max_records": 100},
        "promotion_gate": {"minimum_coverage_gain": 0.1, "minimum_printable_gain": 0.1, "minimum_cross_window_agreement": 2},
        "seed_hypotheses": [{"claim": "bounded fixture transform", "source_ranges": [{"offset": 0, "length": size // 2}, {"offset": size // 2, "length": size - size // 2}], "transform_family_id": "xor_single_byte", "constraints": {"key_hex": "ff"}, "expected_observations": ["coverage improves"], "falsifiers": ["coverage does not improve"], "evidence_refs": [], "proposal_confidence": 0.5}],
    }


def test_snapshot_is_deterministic_and_preserves_unknown_ranges():
    source = ByteSource.from_bytes(b"\x00\x01Track One\x00\xff")
    first = analyze_runtime_source(source).to_dict()
    second = analyze_runtime_source(source).to_dict()
    assert first == second
    assert first["nodes"][0]["label"] == "Track One"
    assert any(item["class"] == "unknown" for item in first["coverage"])
    waterfall = binary_waterfall_payload(first)
    assert waterfall["snapshot_id"] == first["snapshot_id"]


def test_workspace_round_trip_and_three_level_diff(tmp_path: Path):
    source_path = tmp_path / "session.ptx"
    source_path.write_bytes(b"Header Track One End")
    left = analyze_runtime_source(ByteSource.from_path(source_path)).to_dict()
    exported = export_runtime_workspace(source_path, left, tmp_path / "artifacts")
    loaded = load_runtime_workspace(exported["artifact_directory"])
    assert loaded["snapshot"] == left
    right = analyze_runtime_source(ByteSource.from_bytes(b"Header Track Two End")).to_dict()
    diff = diff_snapshots(left, right)
    assert diff["raw"]["source_changed"] is True
    assert diff["parsed"]["match_strategy"] == "stable_provenance_id"


def test_key_hunt_model_is_advisory_and_mechanics_verify(tmp_path: Path):
    clear = b"TrackName ClipName Timeline Metadata"
    encrypted = bytes(value ^ 0xFF for value in clear)
    source_path = tmp_path / "encrypted.ptx"
    source_path.write_bytes(encrypted)
    checkpoint = tmp_path / "hunt.json"
    result = run_dynamic_key_hunt(source_path, _policy(len(encrypted)), checkpoint_path=checkpoint)
    assert result["status"] == "promoted"
    assert result["keys_found"] is True
    assert result["materialized"] is False
    assert result["verified_candidate"]["origin"] == "policy_seed"
    assert json.loads(checkpoint.read_text(encoding="utf-8"))["source_sha256"] == result["source_sha256"]


def test_hypothesis_compiler_rejects_unknown_and_out_of_bounds():
    policy = _policy(10)
    base = {"source_ranges": [{"offset": 0, "length": 10}], "constraints": {"key_hex": "ff"}}
    try:
        compile_hypothesis({**base, "transform_family_id": "free_python"}, policy, 10)
        assert False, "unknown family must be rejected"
    except ValueError:
        pass
    try:
        compile_hypothesis({**base, "source_ranges": [{"offset": 9, "length": 2}], "transform_family_id": "xor_single_byte"}, policy, 10)
        assert False, "out-of-range descriptor must be rejected"
    except ValueError:
        pass


def test_model_direct_key_material_is_rejected_before_execution(tmp_path: Path):
    source_path = tmp_path / "model-key.ptx"
    source_path.write_bytes(b"bounded source bytes")
    policy = _policy(source_path.stat().st_size)
    policy["seed_hypotheses"] = []

    def provider(packet, capability):
        del packet, capability
        return [{"transform_family_id": "xor_single_byte", "source_ranges": [{"offset": 0, "length": source_path.stat().st_size}], "constraints": {"key_hex": "ff"}}]

    result = run_dynamic_key_hunt(source_path, policy, hypothesis_provider=provider)
    rejection = next(item for item in result["attempts"] if item.get("reason") == "model_direct_key_material_forbidden")
    assert rejection["status"] == "rejected_before_execution"
    assert result["keys_found"] is False
