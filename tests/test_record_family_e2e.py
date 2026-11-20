"""End-to-end and no-hardcode tests for record-family proof."""

from __future__ import annotations

import json
import random
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _policy(tmp_path: Path) -> Path:
    policy = json.loads((ROOT / "config" / "record_family_policy.json").read_text(encoding="utf-8"))
    policy["artifact_root"] = str(tmp_path / "runs")
    policy["finding_ledger"]["root"] = str(tmp_path / "ledger")
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(policy), encoding="utf-8")
    return path


def _pair(tmp_path: Path, *, positions=(173, 701, 1299), relation=0xA7):
    rng = random.Random(9182)
    source = bytearray(rng.randrange(128, 256) for _ in range(2048))
    value = b"structural repeated payload"
    prefix, suffix = b"\x01\x02\x03", b"\x00\x04"
    for position in positions:
        source[position - len(prefix):position] = prefix
        source[position:position + len(value)] = value
        source[position + len(value):position + len(value) + len(suffix)] = suffix
    parent = bytearray(source)
    for position in positions:
        for index in range(position, position + len(value)):
            parent[index] ^= relation
    source_path, parent_path = tmp_path / "materialized.bin", tmp_path / "parent.bin"
    source_path.write_bytes(source); parent_path.write_bytes(parent)
    return source_path, parent_path, value, positions


def test_full_record_family_run_proves_holdout_materializes_and_reverts(tmp_path):
    from src.services.record_family import inspect_record_family_run, run_record_family_e2e, verify_record_family_run

    source, parent, value, positions = _pair(tmp_path)
    run = run_record_family_e2e(source, parent, output_root=tmp_path / "runs", ledger_root=tmp_path / "ledger", policy_path=_policy(tmp_path))

    assert run["status"] == "goal_satisfied"
    run_path = Path(run["run_root"]) / "run.json"
    assert verify_record_family_run(run_path)["ok"] is True
    inspected = inspect_record_family_run(run_path)
    assert inspected["verified"] is True
    matching = [item for item in inspected["families"] if item["normalized_layout"]["seed_length"] == len(value)]
    assert matching
    proof = next(item for item in inspected["proofs"] if item["family_id"] == matching[0]["family_id"])
    assert proof["state"] == "holdout_passed"
    assert len(proof["holdout_occurrence_ids"]) == 1
    assert inspected["frontier"]
    candidate = Path(inspected["frontier"][0]["artifact_path"]).read_bytes()
    for position in positions:
        assert candidate[position:position + len(value)] == value
    inverse = json.loads((Path(run["run_root"]) / "candidates" / inspected["frontier"][0]["candidate_id"] / "inverse.json").read_text(encoding="utf-8"))
    restored = bytearray(candidate)
    for item in reversed(inverse):
        restored[item["offset"]:item["offset"] + item["length"]] = bytes.fromhex(item["bytes_hex"])
    assert bytes(restored) == parent.read_bytes()


def test_finding_ledger_deduplicates_across_identical_runs(tmp_path):
    from src.services.record_family import run_record_family_e2e

    source, parent, _, _ = _pair(tmp_path)
    policy = _policy(tmp_path)
    first = run_record_family_e2e(source, parent, output_root=tmp_path / "runs", ledger_root=tmp_path / "ledger", policy_path=policy)
    checkpoint_before = json.loads((tmp_path / "ledger" / "checkpoints" / "latest.json").read_text(encoding="utf-8"))
    second = run_record_family_e2e(source, parent, output_root=tmp_path / "runs", ledger_root=tmp_path / "ledger", policy_path=policy)
    checkpoint_after = json.loads((tmp_path / "ledger" / "checkpoints" / "latest.json").read_text(encoding="utf-8"))
    assert first["run_id"] == second["run_id"]
    assert checkpoint_before["record_count"] == checkpoint_after["record_count"]


def test_identity_parent_produces_proof_without_fake_candidate(tmp_path):
    from src.services.record_family import run_record_family_e2e

    source, _, _, _ = _pair(tmp_path)
    run = run_record_family_e2e(source, source, output_root=tmp_path / "runs", ledger_root=tmp_path / "ledger", policy_path=_policy(tmp_path))
    assert run["status"] == "family_proof_satisfied"
    assert run["candidate_ids"] == []
    assert run["proof_ids"]


def test_model_boundary_rejects_authority_fields(tmp_path):
    from src.services.record_family import build_record_family_model_packet, run_record_family_e2e, validate_record_family_model_action

    source, parent, _, _ = _pair(tmp_path)
    policy = _policy(tmp_path)
    run = run_record_family_e2e(source, parent, output_root=tmp_path / "runs", ledger_root=tmp_path / "ledger", policy_path=policy)
    packet = build_record_family_model_packet(Path(run["run_root"]) / "run.json")
    target = packet["families"][0]["family_id"]
    assert validate_record_family_model_action({"action": "rank_existing_family", "target_id": target, "reason": "mechanical evidence"}, packet, policy_path=policy)
    with pytest.raises(ValueError, match="authority"):
        validate_record_family_model_action({"action": "rank_existing_family", "target_id": target, "reason": "guess", "offset": 9}, packet, policy_path=policy)


def test_runtime_contains_no_case_specific_facts():
    paths = [ROOT / "src" / "services" / "record_family" / "core.py", ROOT / "config" / "record_family_policy.json", ROOT / "config" / "record_family_registry.json"]
    text = "\n".join(path.read_text(encoding="utf-8").casefold() for path in paths)
    forbidden = ("blue cat", "patchwork", "1candidate", "chillax", "nectar", "0x7aed", "0x7b18", "0x7b47")
    assert not any(value in text for value in forbidden)


def test_transform_lane_consistency_is_scoped_per_family():
    from src.services.record_family.core import measure_transform_lane_consistency

    parent = bytes((0x10, 0x20, 0x30, 0x40))
    source = bytes((0x11, 0x21, 0x32, 0x42))
    scopes = [
        {"offset": 0, "length": 2, "family_id": "left"},
        {"offset": 2, "length": 2, "family_id": "right"},
    ]

    result = measure_transform_lane_consistency(source, parent, scopes)

    assert result["supported"] is True
    assert result["lane_count"] == 2
    assert result["families"]["left"]["lanes"] == [0x01]
    assert result["families"]["right"]["lanes"] == [0x02]


def test_variant_context_passes_masked_invariant_holdout(tmp_path):
    from src.services.record_family.core import build_family_proofs, load_record_family_bundle

    policy_path = _policy(tmp_path)
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    policy["boundary"]["holdout_boundary_strategy_preference"] = ["masked-invariant-context", "shared-context"]
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    bundle = load_record_family_bundle(policy_path)
    rng = random.Random(4417)
    source = bytearray(rng.randrange(128, 256) for _ in range(4096))
    value = b"variant framing payload"
    positions = (512, 1024, 1536)
    for index, position in enumerate(positions):
        source[position - 1] = 0x01
        source[position - 2] = 0x20 + index
        source[position:position + len(value)] = value
    seed = {
        "seed_id": "test-seed",
        "length": len(value),
        "decoded_digest": __import__("hashlib").sha256(value).hexdigest(),
        "occurrences": [{"offset": position, "length": len(value)} for position in positions],
    }
    families, proofs, _ = build_family_proofs(bytes(source), [seed], bundle=bundle)
    assert families
    proof = proofs[0]
    assert proof["boundary"]["strategy_id"] == "masked-invariant-context"
    assert proof["state"] == "holdout_passed"


def test_shared_context_fails_when_only_distant_bytes_match(tmp_path):
    from src.services.record_family.core import infer_shared_context_boundaries, load_record_family_bundle

    bundle = load_record_family_bundle(_policy(tmp_path))
    data = bytearray(b"." * 32)
    value = b"VALUE"
    data[5:10] = value
    data[15:20] = value
    data[4] = ord("a")
    data[14] = ord("b")
    seed = {"length": len(value)}
    training = [{"offset": 5, "length": len(value)}, {"offset": 15, "length": len(value)}]
    shared = infer_shared_context_boundaries(bytes(data), seed, training, bundle=bundle)
    assert shared["measured_shared_left_bytes"] == 0
    assert shared["supported"] is False


def test_one_sided_framing_is_policy_controlled(tmp_path):
    from src.services.record_family.core import infer_masked_invariant_boundaries, infer_shared_context_boundaries, load_record_family_bundle

    policy_path = _policy(tmp_path)
    bundle = load_record_family_bundle(policy_path)
    data = b"AxxVALUEqBxxVALUErCxxVALUEs"
    seed = {"length": 5}
    training = [{"offset": 3, "length": 5}, {"offset": 12, "length": 5}]
    masked = infer_masked_invariant_boundaries(data, seed, training, bundle=bundle)
    assert masked["measured_invariant_prefix_count"] >= 1
    assert masked["supported"] is True

    hypothesis = infer_shared_context_boundaries(data, seed, training, bundle=bundle)
    assert hypothesis["left_bytes"] == bundle["policy"]["boundary"]["minimum_shared_prefix_bytes"]
    assert hypothesis["right_bytes"] == 0

    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    policy["boundary"]["minimum_shared_suffix_bytes"] = 1
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    strict = infer_shared_context_boundaries(data, seed, training, bundle=load_record_family_bundle(policy_path))
    assert strict["supported"] is False


def test_mcp_record_family_tools_are_registered():
    import sys
    lab_root = ROOT
    if str(lab_root) not in sys.path:
        sys.path.insert(0, str(lab_root))
    from hexeditor_tools.catalog import _definitions

    definitions = _definitions()
    assert definitions["binary_record_family_run"]["effect"] == "reversible_mutation"
    assert definitions["binary_record_family_inspect"]["effect"] == "evidence_read"
    assert definitions["binary_record_family_verify"]["effect"] == "evidence_read"


def test_record_family_overlay_spans_and_discovery(tmp_path):
    from src.gui_evidence_presenter import build_record_family_overlay_spans
    from src.services.record_family import discover_record_family_run_for_source, inspect_record_family_run, run_record_family_e2e
    from src.services.ui_policy import load_ui_policy

    source, parent, _, _ = _pair(tmp_path)
    policy_path = _policy(tmp_path)
    run = run_record_family_e2e(source, parent, output_root=tmp_path / "runs", ledger_root=tmp_path / "ledger", policy_path=policy_path)
    run_path = Path(run["run_root"]) / "run.json"
    discovered = discover_record_family_run_for_source(source, policy_path=policy_path)
    assert discovered == str(run_path.resolve())
    assert discover_record_family_run_for_source(parent, policy_path=policy_path) == str(run_path.resolve())
    inspected = inspect_record_family_run(run_path)
    ui_policy = load_ui_policy()
    ui_policy = {**ui_policy, "feature_flags": {**ui_policy.get("feature_flags", {}), "hex_forensic_overlays": True}}
    ui_policy = {**ui_policy, "hex_overlays": {**ui_policy.get("hex_overlays", {}), "show_record_family_training": True, "show_record_family_holdout": True}}
    spans = build_record_family_overlay_spans(inspected, policy=ui_policy)
    assert spans
    roles = {item["role"] for item in spans}
    assert "record_family_training" in roles
    assert "record_family_holdout" in roles
    ui_policy_off = dict(ui_policy)
    overlays = dict(ui_policy_off.get("hex_overlays") or {})
    overlays["show_record_family_training"] = False
    overlays["show_record_family_holdout"] = False
    ui_policy_off["hex_overlays"] = overlays
    assert build_record_family_overlay_spans(inspected, policy=ui_policy_off) == []


def test_mcp_record_family_run_requires_confirmation():
    import sys
    lab_root = ROOT
    if str(lab_root) not in sys.path:
        sys.path.insert(0, str(lab_root))
    from hexeditor_tools import api as hex_editor_tools

    with pytest.raises(ValueError, match="confirmed=true"):
        hex_editor_tools.binary_record_family_run("source", "parent", "output")
