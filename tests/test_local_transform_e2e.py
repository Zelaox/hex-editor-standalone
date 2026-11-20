"""Local transform discovery, lineage, materialization and authority tests."""

from __future__ import annotations

import json
import random
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _bundle(tmp_path: Path):
    from src.services.local_transform.core import _load_bundle
    policy = json.loads((ROOT / "config" / "local_transform_policy.json").read_text(encoding="utf-8"))
    policy["scan"].update({"window_bytes": 96, "step_bytes": 16, "maximum_scan_bytes": 4096, "minimum_printable_gain": 0.2, "minimum_printable_ratio": 0.2, "minimum_structural_ratio": 0.6, "minimum_zero_ratio": 0.1})
    path = tmp_path / "policy.json"; path.write_text(json.dumps(policy), encoding="utf-8")
    return _load_bundle(path)


def _fixture(parameter: int, positions=(211, 877)):
    rng = random.Random(41)
    source = bytearray([parameter] * 1536)
    for index in range(0, len(source), 113):
        source[index] = rng.randrange(128, 256)
    plaintext = b"repeated semantic record value"
    encoded = bytes(value ^ parameter for value in plaintext)
    for offset in positions:
        source[offset:offset + len(encoded)] = encoded
    return bytes(source), plaintext, positions


def test_singleton_parent_diff_materializes_isolated_span(tmp_path):
    from src.services.local_transform.core import aggregate_record_families, discover_parent_diff_xor, materialize_record_families

    source, plaintext, positions = _fixture(0xA5)
    parent = bytearray(source)
    parent_relation = 0x29
    for offset in positions[:1]:
        for index in range(offset, offset + len(plaintext)):
            parent[index] ^= parent_relation
    bundle = _bundle(tmp_path)
    observations = discover_parent_diff_xor(source, parent=bytes(parent), family_id="parent-diff-xor", bundle=bundle)
    families = aggregate_record_families(observations, bundle=bundle)
    assert any(family.get("singleton_parent_diff") for family in families)
    result = materialize_record_families(source, bytes(parent), families, {item["observation_id"]: item for item in observations}, bundle=bundle)
    offset = positions[0]
    assert result["bytes"][offset:offset + len(plaintext)] == source[offset:offset + len(plaintext)]


def test_parent_diff_discovery_groups_by_parameter(tmp_path):
    from src.services.local_transform.core import aggregate_record_families, discover_parent_diff_xor

    source, plaintext, positions = _fixture(0xA5)
    parent = bytearray(source)
    parent_relation = 0x29
    for offset in positions:
        for index in range(offset, offset + len(plaintext)):
            parent[index] ^= parent_relation
    bundle = _bundle(tmp_path)
    observations = discover_parent_diff_xor(source, parent=bytes(parent), family_id="parent-diff-xor", bundle=bundle)
    assert observations
    families = aggregate_record_families(observations, bundle=bundle)
    assert families
    assert any(item["independent_occurrence_count"] >= 2 for item in families)


def test_discovery_and_record_family_use_runtime_evidence(tmp_path):
    from src.services.local_transform.core import aggregate_record_families, discover_xor_windows
    source, plaintext, positions = _fixture(0xEA)
    bundle = _bundle(tmp_path)
    observations = discover_xor_windows(source, family_id="xor-single-byte", bundle=bundle)
    matching = [item for item in observations if item["bounded_preview"] == plaintext.decode()]
    assert {item["offset"] for item in matching} == set(positions)
    families = aggregate_record_families(observations, bundle=bundle)
    assert any(item["independent_occurrence_count"] >= 2 and set(item["occurrence_ids"]).issuperset({match["observation_id"] for match in matching}) for item in families)


def test_lineage_composition_materializes_plaintext(tmp_path):
    from src.services.local_transform.core import aggregate_record_families, discover_xor_windows, materialize_record_families
    source, plaintext, positions = _fixture(0xB3)
    parent_relation = 0x29
    parent = bytes(value ^ parent_relation for value in source)
    bundle = _bundle(tmp_path)
    observations = discover_xor_windows(source, family_id="xor-single-byte", bundle=bundle)
    families = aggregate_record_families(observations, bundle=bundle)
    result = materialize_record_families(source, parent, families, {item["observation_id"]: item for item in observations}, bundle=bundle)
    for offset in positions:
        assert result["bytes"][offset:offset + len(plaintext)] == plaintext
    scopes = result["descriptor"]["scopes"]
    assert scopes and all(item["parent_relation_hex"] == f"{parent_relation:02x}" for item in scopes)


def test_full_artifact_run_and_integrity(tmp_path, monkeypatch):
    from src.services.local_transform import core
    source_data, _, _ = _fixture(0xD6)
    source = tmp_path / "source.bin"; parent = tmp_path / "parent.bin"
    source.write_bytes(source_data); parent.write_bytes(source_data)
    _bundle(tmp_path)
    monkeypatch.setattr(core, "_semantic_analysis", lambda data, *, bundle: {"legacy-ptx-summary": {"parser_sections": 2, "timecode_count": 3, "legacy_string_count": 4}, "runtime-snapshot-summary": {"runtime_nodes": 5, "runtime_anchors": 2, "unknown_bytes": len(data)}})
    run = core.run_local_transform_search(source, parent_path=parent, output_root=tmp_path / "runs", policy_path=tmp_path / "policy.json")
    assert run["status"] == "goal_satisfied"
    assert core.verify_local_transform_run(Path(run["run_root"]) / "run.json")["ok"]
    inspected = core.inspect_local_transform_run(Path(run["run_root"]) / "run.json")
    assert inspected["verified"] and inspected["record_families"]


def test_model_boundary_and_no_case_literals(tmp_path):
    from src.services.local_transform import validate_local_transform_model_action
    packet = {"candidates": [{"candidate_id": "mechanical"}], "advisory_eligible_candidate_ids": ["mechanical"]}
    assert validate_local_transform_model_action({"action": "rank_existing_candidate", "candidate_id": "mechanical", "reason": "supported"}, packet)
    with pytest.raises(ValueError, match="unknown"):
        validate_local_transform_model_action({"action": "rank_existing_candidate", "candidate_id": "invented", "reason": "guess"}, packet)
    with pytest.raises(ValueError, match="authority"):
        validate_local_transform_model_action({"action": "rank_existing_candidate", "candidate_id": "mechanical", "reason": "guess", "key_hex": "00"}, packet)
    paths = [ROOT / "src" / "services" / "local_transform" / "core.py", ROOT / "config" / "local_transform_policy.json", ROOT / "config" / "local_transform_registry.json"]
    text = "\n".join(path.read_text(encoding="utf-8").lower() for path in paths)
    forbidden = ("blue cat", "patchwork", "0xf7", "0x7af0", "snap48", "nectar")
    assert not any(item in text for item in forbidden)
