"""End-to-end tests for the verified parser-learning feedback rail."""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _workspace(root: Path, source_bytes: bytes, region_id: str, payload: bytes = b"ABCD") -> Path:
    from src.services.representation_sweep import sweep_region, write_representation_brief_cache

    root.mkdir(parents=True)
    source_digest = hashlib.sha256(source_bytes).hexdigest()
    (root / "manifest.json").write_text(json.dumps({"source_before": {"sha256": source_digest}, "details": {"snapshot_id": f"snapshot-{source_digest}", "format_plugin": "test-format"}}), encoding="utf-8")
    (root / "unknown").mkdir()
    (root / "unknown" / "regions.json").write_text(json.dumps([{"region_id": region_id, "span": {"offset": 0, "length": len(payload)}, "neighbor_anchor_ids": []}]), encoding="utf-8")
    write_representation_brief_cache(root, region_id, sweep_region(payload))
    return root


def _passing_facts():
    return {"deterministic_replay": True, "negative_fixture_result": True, "no_coverage_regression": True, "no_graph_regression": True}


def test_cross_file_e2e_and_gemma_boundary(tmp_path):
    from src.services.parser_learning import run_parser_learning

    first = _workspace(tmp_path / "first", b"source-one", "region-one")
    second = _workspace(tmp_path / "second", b"source-two", "region-two")
    output = tmp_path / "output"
    result = run_parser_learning([first, second], output_workspace=output, format_plugin="test-format", base_profile_id="generic", validation_results=_passing_facts())
    assert result["ok"] is True
    assert result["candidate_count"] > 0
    validations = json.loads((Path(result["artifact_root"]) / "validations" / "index.json").read_text(encoding="utf-8"))
    assert any(item["eligible"] for item in validations)
    packet = result["gemma_packet"]
    assert packet["model_role"] == "advisory_only"
    serialized = json.dumps(packet)
    assert "declaration" not in serialized
    assert "offset" not in packet["candidates"][0]


def test_duplicate_source_does_not_satisfy_cross_file_gate(tmp_path):
    from src.services.parser_learning import run_parser_learning

    first = _workspace(tmp_path / "first", b"same-source", "region-one")
    duplicate = _workspace(tmp_path / "duplicate", b"same-source", "region-two")
    result = run_parser_learning([first, duplicate], output_workspace=tmp_path / "output", format_plugin="test-format", base_profile_id="generic", validation_results=_passing_facts())
    validations = json.loads((Path(result["artifact_root"]) / "validations" / "index.json").read_text(encoding="utf-8"))
    assert validations
    assert all(item["observed_independent_source_count"] == 1 for item in validations)
    assert all(item["checks"]["independent_sources"] is False for item in validations)
    assert all(item["eligible"] is False for item in validations)


def test_policy_changes_cross_file_threshold_without_source_change(tmp_path):
    from src.services.parser_learning import load_parser_learning_bundle, validate_candidates

    bundle = load_parser_learning_bundle()
    candidate = {"candidate_id": "candidate", "independent_region_count": 3, "independent_source_count": 3, "counterexample_count": 0}
    assert validate_candidates([candidate], bundle=bundle, validation_results=_passing_facts())[0]["eligible"] is True
    changed = copy.deepcopy(bundle)
    changed["policy"]["promotion_profiles"]["learned_general"]["minimum_independent_source_count"] = 4
    assert validate_candidates([candidate], bundle=changed, validation_results=_passing_facts())[0]["eligible"] is False


def test_missing_cross_file_threshold_fails_loud(tmp_path):
    from src.services.parser_learning import load_parser_learning_bundle

    policy = json.loads((ROOT / "config" / "parser_learning_policy.json").read_text(encoding="utf-8"))
    del policy["promotion_profiles"]["learned_general"]["minimum_independent_source_count"]
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    with pytest.raises(ValueError, match="minimum_independent_source_count"):
        load_parser_learning_bundle(policy_path=policy_path)


def test_single_source_profile_is_explicit_and_stricter(tmp_path):
    from src.services.parser_learning import load_parser_learning_bundle, validate_candidates

    bundle = load_parser_learning_bundle()
    candidate = {"candidate_id": "candidate", "independent_region_count": 4, "independent_source_count": 1, "counterexample_count": 0}
    general = validate_candidates([candidate], bundle=bundle, validation_results=_passing_facts())[0]
    strict = validate_candidates([candidate], bundle=bundle, validation_results=_passing_facts(), promotion_profile_id="single_source_strict")[0]
    assert general["eligible"] is False
    assert strict["eligible"] is True


def test_transaction_stages_and_requires_confirmation_for_publish(tmp_path):
    from src.services.parser_learning import promote_profile_transaction

    registry = tmp_path / "registry.json"
    original = {"schema_version": 1, "revision": 1, "default_profile_id": "generic", "profiles": []}
    registry.write_text(json.dumps(original), encoding="utf-8")
    candidate = {"candidate_id": "candidate-id", "format_plugin": "test-format", "declaration": {"field": "derived"}, "evidence_refs": ["evidence-id"]}
    validation = {"validation_id": "validation-id", "candidate_id": "candidate-id", "eligible": True, "review_required": True}
    staged = promote_profile_transaction(candidate, validation, registry_path=registry, staging_root=tmp_path / "staging", reviewed=True)
    assert Path(staged["staging_directory"], "registry.json").is_file()
    assert json.loads(registry.read_text(encoding="utf-8")) == original
    with pytest.raises(ValueError, match="confirmed=true"):
        promote_profile_transaction(candidate, validation, registry_path=registry, staging_root=tmp_path / "staging-2", reviewed=True, publish=True)


def test_field_and_relationship_inference_are_mechanical(tmp_path):
    from src.services.parser_learning import run_parser_learning

    payload = bytes(4)
    first = _workspace(tmp_path / "first", b"relation-source-one", "region-one", payload)
    second = _workspace(tmp_path / "second", b"relation-source-two", "region-two", payload)
    result = run_parser_learning([first, second], output_workspace=tmp_path / "output", format_plugin="test-format", base_profile_id="generic", validation_results=_passing_facts())
    inferred = json.loads((Path(result["artifact_root"]) / "clusters" / "index.json").read_text(encoding="utf-8"))
    kinds = {item["rule_kind"] for item in inferred}
    assert "field_layout" in kinds
    assert "relationship" in kinds
    relationships = [item for item in inferred if item["rule_kind"] == "relationship" and item["eligibility"]["allowed"]]
    assert relationships
    assert all(item["declaration"]["resolver_id"] == "exact-region-offset" for item in relationships)


def test_mcp_parser_learning_tools_are_registered():
    lab_root = ROOT
    if str(lab_root) not in sys.path:
        sys.path.insert(0, str(lab_root))
    from hexeditor_tools.catalog import _definitions

    definitions = _definitions()
    assert definitions["binary_parser_learning_run"]["effect"] == "reversible_mutation"
    assert definitions["binary_parser_learning_inspect"]["effect"] == "evidence_read"


def test_no_hardcoded_format_facts_in_generic_parser_learning_sources():
    source = (ROOT / "src" / "services" / "parser_learning" / "core.py").read_text(encoding="utf-8")
    forbidden = ("0x1234", "ac240", "1ac240", "if format_plugin ==", "if offset ==")
    assert not any(token in source for token in forbidden)
    policy = json.loads((ROOT / "config" / "parser_learning_policy.json").read_text(encoding="utf-8"))
    assert "minimum_independent_source_count" in policy["promotion_profiles"][policy["default_promotion_profile_id"]]
    registry = json.loads((ROOT / "config" / "parser_learning_registry.json").read_text(encoding="utf-8"))
    assert all("impl" in stage for stage in registry["inference_stages"])


def test_gemma_actions_cannot_supply_parser_authority():
    from src.services.parser_learning import validate_gemma_actions

    packet = {"candidates": [{"candidate_id": "candidate-one"}]}
    safe = validate_gemma_actions([{"action": "prioritize_candidate", "candidate_id": "candidate-one"}], packet)
    assert safe["ok"] is True
    malicious = validate_gemma_actions([{"action": "prioritize_candidate", "candidate_id": "candidate-one", "offset": 4660, "promotion_allowed": True}], packet)
    assert malicious["ok"] is False
    assert "forbidden_authority_field" in malicious["rejected"][0]["reasons"]


def test_mechanical_validation_blocks_without_regression_baselines(tmp_path):
    from src.services.parser_learning import run_parser_learning

    first = _workspace(tmp_path / "first", b"source-one", "region-one")
    second = _workspace(tmp_path / "second", b"source-two", "region-two")
    result = run_parser_learning([first, second], output_workspace=tmp_path / "output", format_plugin="test-format", base_profile_id="generic")
    facts = result["validation_facts"]
    assert facts["deterministic_replay"] is True
    assert facts["negative_fixture_result"] is True
    assert facts["no_coverage_regression"] is False
    assert facts["no_graph_regression"] is False
    validations = json.loads((Path(result["artifact_root"]) / "validations" / "index.json").read_text(encoding="utf-8"))
    assert validations
    assert all(item["eligible"] is False for item in validations)
    mechanical = json.loads((Path(result["artifact_root"]) / "validations" / "mechanical" / "index.json").read_text(encoding="utf-8"))
    assert mechanical["operation"] == "parser_learning_mechanical_validation"


def test_parse_gemma_model_content_rejects_empty():
    from src.services.parser_learning import parse_gemma_model_content

    with pytest.raises(ValueError, match="empty"):
        parse_gemma_model_content("")
    assert parse_gemma_model_content('[{"action":"prioritize_candidate","candidate_id":"candidate-one"}]')[0]["candidate_id"] == "candidate-one"


def test_mcp_parser_learning_run_requires_confirmed():
    lab_root = ROOT
    if str(lab_root) not in sys.path:
        sys.path.insert(0, str(lab_root))
    from hexeditor_tools import api as hex_editor_tools

    with pytest.raises(ValueError, match="confirmed=true"):
        hex_editor_tools.binary_parser_learning_run("[]", str(ROOT / "tests"), "test-format", "generic")
