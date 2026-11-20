"""Multi-turn semantic scope search, integrity and no-hardcode coverage."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _policy(tmp_path: Path) -> Path:
    value = json.loads((ROOT / "config" / "iterative_scope_policy.json").read_text(encoding="utf-8"))
    value["budgets"].update({"maximum_turns": 3, "maximum_candidates_per_turn": 12, "maximum_total_candidates": 24})
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def test_e2e_recovers_lost_semantic_signal_and_keeps_gained_text(tmp_path):
    from src.services.iterative_scope import inspect_iterative_run, run_iterative_scope_search, verify_iterative_run

    source = tmp_path / "source.bin"
    alternative = tmp_path / "alternative.bin"
    before = bytearray(bytes(range(256)) * 4)
    time_value = b"01:02:03:04"
    gained = b"new readable session metadata"
    before[700:700 + len(time_value)] = time_value
    after = bytearray(before)
    after[80:80 + len(gained)] = gained
    after[700:700 + len(time_value)] = bytes(value ^ 0x6D for value in time_value)
    source.write_bytes(before)
    alternative.write_bytes(after)

    run = run_iterative_scope_search(source, alternative, output_root=tmp_path / "runs", policy_path=_policy(tmp_path))
    assert run["status"] == "goal_satisfied"
    assert verify_iterative_run(Path(run["run_root"]) / "run.json")["ok"] is True
    inspected = inspect_iterative_run(Path(run["run_root"]) / "run.json")
    assert inspected["verified"] is True
    assert any(item["class"] == "semantic_lost" for item in inspected["waterfall_overlay"]["ranges"])
    frontier = json.loads(Path(run["artifacts"]["frontier"]).read_text(encoding="utf-8"))
    hybrids = [item for item in frontier if item["candidate_id"] not in {"source", "alternative"}]
    assert hybrids
    assert any(item["metrics"]["timecode_count"] >= 1 and item["metrics"]["text_bytes"] > 12 for item in hybrids)
    assert all(json.loads((Path(run["run_root"]) / "candidates" / item["candidate_id"] / "manifest.json").read_text(encoding="utf-8"))["verified_decryption"] is False for item in hybrids)


def test_runtime_values_change_descriptors_without_policy_edits(tmp_path):
    from src.services.iterative_scope import run_iterative_scope_search

    policy = _policy(tmp_path)
    source = tmp_path / "source.bin"
    source.write_bytes(b"prefix 01:02:03:04" + bytes(range(128)))
    alternatives = []
    for index, location in enumerate((24, 48)):
        data = bytearray(source.read_bytes() + b" " * 80)
        data[7:18] = b"xxxxxxxxxxx"
        data[location:location + 9] = b"plaintext"
        path = tmp_path / f"alternative-{index}.bin"
        path.write_bytes(data[: len(source.read_bytes())])
        alternatives.append(path)
    left = run_iterative_scope_search(source, alternatives[0], output_root=tmp_path / "left", policy_path=policy)
    right = run_iterative_scope_search(source, alternatives[1], output_root=tmp_path / "right", policy_path=policy)
    assert left["run_id"] != right["run_id"]
    left_descriptors = list((Path(left["run_root"]) / "turns").glob("*/hypothesis_descriptors.json"))
    right_descriptors = list((Path(right["run_root"]) / "turns").glob("*/hypothesis_descriptors.json"))
    assert left_descriptors and right_descriptors
    assert left_descriptors[0].read_text(encoding="utf-8") != right_descriptors[0].read_text(encoding="utf-8")


def test_no_case_literals_in_iterative_runtime_or_defaults():
    paths = [
        ROOT / "src" / "services" / "iterative_scope" / "core.py",
        ROOT / "config" / "iterative_scope_policy.json",
        ROOT / "config" / "iterative_scope_registry.json",
    ]
    text = "\n".join(path.read_text(encoding="utf-8").lower() for path in paths)
    forbidden = ("ac240", "0x94", "540812", "556029", "if offset ==")
    assert not any(token in text for token in forbidden)


def test_model_is_advisory_and_cannot_invent_candidate_or_authority(tmp_path):
    import pytest
    from src.services.iterative_scope import validate_iterative_model_action

    packet = {"candidates": [{"candidate_id": "mechanical-candidate"}, {"candidate_id": "frontier-but-ineligible"}], "advisory_eligible_candidate_ids": ["mechanical-candidate"]}
    accepted = validate_iterative_model_action({"action": "rank_frontier_candidate", "candidate_id": "mechanical-candidate", "reason": "best measured frontier"}, packet, policy_path=_policy(tmp_path))
    assert accepted["candidate_id"] == "mechanical-candidate"
    with pytest.raises(ValueError, match="outside"):
        validate_iterative_model_action({"action": "rank_frontier_candidate", "candidate_id": "invented", "reason": "guess"}, packet, policy_path=_policy(tmp_path))
    with pytest.raises(ValueError, match="ineligible"):
        validate_iterative_model_action({"action": "rank_frontier_candidate", "candidate_id": "frontier-but-ineligible", "reason": "guess"}, packet, policy_path=_policy(tmp_path))
    with pytest.raises(ValueError, match="authority"):
        validate_iterative_model_action({"action": "rank_frontier_candidate", "candidate_id": "mechanical-candidate", "reason": "guess", "verified_decryption": True}, packet, policy_path=_policy(tmp_path))


def test_overlapping_registered_detectors_count_one_semantic_span(tmp_path):
    from src.services.iterative_scope.core import _load_bundle, analyze_candidate

    analysis = analyze_candidate(b"prefix 01:02:03:04 suffix", bundle=_load_bundle(_policy(tmp_path)), include_runtime=False)
    assert analysis["metrics"]["timecode_count"] == 1


def test_external_mcp_operations_are_registered_and_enabled():
    lab_root = ROOT
    if str(lab_root) not in sys.path:
        sys.path.insert(0, str(lab_root))
    from hexeditor_tools.catalog import _definitions

    names = {"binary_iterative_scope_run", "binary_iterative_scope_inspect", "binary_iterative_scope_verify"}
    assert names.issubset(_definitions())
    config = json.loads((lab_root / "config" / "hex_editor.json").read_text(encoding="utf-8"))
    assert names.issubset(config["enabled_operations"])
