"""E2E, durability, authority-boundary and no-hardcode tests."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _source(tmp_path: Path, name: str = "fixture.ptx") -> Path:
    path = tmp_path / name
    prefix = b"PTX test header\x00metadata\x00"
    body = bytes(range(256)) * 5 + b"\x00" * 96 + b"track clip region timeline"
    path.write_bytes(prefix + body)
    return path


def _policy(tmp_path: Path, **budget_overrides) -> Path:
    policy = json.loads((ROOT / "config" / "alternate_scope_policy.json").read_text(encoding="utf-8"))
    policy["budgets"].update({"maximum_probe_windows": 6, "maximum_scope_hypotheses": 4, "maximum_descriptor_executions": 4, "maximum_parser_evaluations": 2, **budget_overrides})
    path = tmp_path / "alternate-policy.json"
    path.write_text(json.dumps(policy), encoding="utf-8")
    return path


def test_full_e2e_artifacts_gates_logs_verify_and_resume(tmp_path):
    from src.services.alternate_scope import inspect_alternate_scope_run, resume_alternate_scope_run, run_alternate_scope_proof, verify_alternate_scope_run

    source = _source(tmp_path)
    before = source.read_bytes()
    run = run_alternate_scope_proof(source, output_root=tmp_path / "runs", candidate_hex="6b", boundary_hint=341, policy_path=_policy(tmp_path))
    assert source.read_bytes() == before
    root = Path(run["run_root"])
    assert verify_alternate_scope_run(root / "run.json")["ok"] is True
    inspected = inspect_alternate_scope_run(root / "run.json")
    assert inspected["verified"] is True
    assert inspected["progress"]["phase"] == "terminal"
    assert inspected["waterfall_overlay"]["ranges"]
    assert all(item["theme_token"].startswith("binary_waterfall.") for item in inspected["waterfall_overlay"]["ranges"])
    assert resume_alternate_scope_run(root / "run.json")["new_descriptor_executions"] == 0
    assert list((root / "logs").glob("events-*.jsonl"))
    assert (root / "boundaries" / "measurements.json").is_file()
    assert (root / "scopes" / "hypotheses.json").is_file()
    assert (root / "gates" / "breakdowns.json").is_file()


def test_runtime_observations_change_outputs_without_config_edits(tmp_path):
    from src.services.alternate_scope import run_alternate_scope_proof

    source = _source(tmp_path)
    policy = _policy(tmp_path, maximum_parser_evaluations=1)
    left = run_alternate_scope_proof(source, output_root=tmp_path / "left", candidate_hex="13", boundary_hint=191, policy_path=policy)
    right = run_alternate_scope_proof(source, output_root=tmp_path / "right", candidate_hex="a2", boundary_hint=733, policy_path=policy)
    assert left["run_id"] != right["run_id"]
    left_plan = json.loads(Path(left["artifacts"]["probe_plan"]).read_text(encoding="utf-8"))
    right_plan = json.loads(Path(right["artifacts"]["probe_plan"]).read_text(encoding="utf-8"))
    assert left_plan != right_plan


def test_budget_uses_unique_ranges_and_preserve_is_invariant(tmp_path):
    from src.services.alternate_scope.core import execute_scope_descriptors
    from src.services.alternate_scope import load_alternate_scope_bundle

    bundle = load_alternate_scope_bundle(policy_path=_policy(tmp_path))
    hypothesis = {"scope_hypothesis_id": "scope", "candidate_material_ref": "observation", "strategy_id": "test", "preserve_spans": [{"offset": 0, "length": 4}], "scopes": [{"offset": 8, "length": 8, "independence_group_id": "same-window"}, {"offset": 12, "length": 8, "independence_group_id": "same-window"}]}
    result = execute_scope_descriptors(bytes(range(64)), [hypothesis], bytes.fromhex("31"), bundle=bundle)[0]
    assert result["transformed_bytes_debited"] == 12
    assert result["artifact_bytes"][:4] == bytes(range(4))
    assert len(result["window_results"]) == 1


def test_model_cannot_supply_authority_fields(tmp_path):
    from src.services.alternate_scope import validate_model_actions

    policy = _policy(tmp_path)
    packet = {"hypotheses": [{"hypothesis_id": "h1", "gate_statuses": {"header": "inconclusive", "parser": "passed"}}], "measurements": [{"measurement_id": "m1"}]}
    assert validate_model_actions([{"action": "rank_existing_hypotheses", "hypothesis_ids": ["h1"], "observed_non_passed_gate_ids": ["header"], "reason": "mechanical gates"}], packet, policy_path=policy)
    with pytest.raises(ValueError, match="authority fields"):
        validate_model_actions([{"action": "rank_existing_hypotheses", "hypothesis_ids": ["h1"], "observed_non_passed_gate_ids": ["header"], "reason": "bad", "offset": 10}], packet, policy_path=policy)
    with pytest.raises(ValueError, match="unknown evidence references"):
        validate_model_actions([{"action": "rank_existing_hypotheses", "hypothesis_ids": ["invented"], "observed_non_passed_gate_ids": [], "reason": "bad"}], packet, policy_path=policy)
    with pytest.raises(ValueError, match="gate grounding mismatch"):
        validate_model_actions([{"action": "rank_existing_hypotheses", "hypothesis_ids": ["h1"], "observed_non_passed_gate_ids": [], "reason": "bad"}], packet, policy_path=policy)
    with pytest.raises(ValueError, match="not registered"):
        validate_model_actions([{"action": "execute_transform"}], policy_path=policy)


def test_missing_policy_and_unknown_registry_hook_fail_loudly(tmp_path):
    from src.services.alternate_scope import load_alternate_scope_bundle

    policy = json.loads((ROOT / "config" / "alternate_scope_policy.json").read_text(encoding="utf-8"))
    del policy["artifact_layout"]
    policy_path = tmp_path / "bad-policy.json"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    with pytest.raises(ValueError):
        load_alternate_scope_bundle(policy_path=policy_path)


def test_event_rotation_and_digest_chain(tmp_path):
    from src.services.alternate_scope import run_alternate_scope_proof, verify_alternate_scope_run

    source = _source(tmp_path)
    policy = _policy(tmp_path, maximum_log_segment_bytes=1600, maximum_log_segments=80, maximum_parser_evaluations=1)
    run = run_alternate_scope_proof(source, output_root=tmp_path / "rotated", candidate_hex="44", boundary_hint=501, policy_path=policy)
    root = Path(run["run_root"])
    assert len(list((root / "logs").glob("events-*.jsonl"))) > 1
    verified = verify_alternate_scope_run(root / "run.json")
    assert verified["event_chain_ok"] is True


def test_integrity_tamper_blocks_resume(tmp_path):
    from src.services.alternate_scope import resume_alternate_scope_run, run_alternate_scope_proof

    run = run_alternate_scope_proof(_source(tmp_path), output_root=tmp_path / "tamper", candidate_hex="22", boundary_hint=277, policy_path=_policy(tmp_path, maximum_parser_evaluations=1))
    Path(run["artifacts"]["feedback"]).write_text("[]\n", encoding="utf-8")
    with pytest.raises(ValueError, match="failed integrity"):
        resume_alternate_scope_run(Path(run["run_root"]) / "run.json")


def test_no_case_literals_in_runtime_or_defaults():
    paths = [ROOT / "src" / "services" / "alternate_scope" / "core.py", ROOT / "config" / "alternate_scope_policy.json", ROOT / "config" / "alternate_scope_registry.json", ROOT / "scripts" / "alternate_scope_e2e.py"]
    text = "\n".join(path.read_text(encoding="utf-8").lower() for path in paths)
    forbidden = ("0x94", "ac240", "1024+", "transform-scope-e2e-20260901", "if offset ==")
    assert not any(token in text for token in forbidden)


def test_external_mcp_operations_are_registered_and_enabled():
    lab_root = ROOT
    if str(lab_root) not in sys.path:
        sys.path.insert(0, str(lab_root))
    from hexeditor_tools.catalog import _definitions

    names = {"binary_alternate_scope_run", "binary_alternate_scope_inspect", "binary_alternate_scope_verify", "binary_alternate_scope_resume"}
    assert names.issubset(_definitions())
    config = json.loads((lab_root / "config" / "hex_editor.json").read_text(encoding="utf-8"))
    assert names.issubset(config["enabled_operations"])


def test_gemma_scope_materialization_is_separate_and_preserves_protected_bytes(tmp_path, monkeypatch):
    import hashlib
    from src.services.alternate_scope import materialize as module

    source = tmp_path / "source.ptx"
    source.write_bytes(bytes(range(32)))
    observations = tmp_path / "observations.json"
    observations.write_text(json.dumps([{"observation_id": "material", "value_hex": "5a"}]), encoding="utf-8")
    hypotheses = tmp_path / "hypotheses.json"
    hypotheses.write_text(json.dumps([{"scope_hypothesis_id": "scope", "candidate_material_ref": "material", "scopes": [{"offset": 8, "length": 4}], "preserve_spans": [{"offset": 0, "length": 4}]}]), encoding="utf-8")
    run = tmp_path / "run.json"
    run.write_text(json.dumps({"run_id": "run", "source": {"sha256": hashlib.sha256(source.read_bytes()).hexdigest()}, "artifacts": {"observations": str(observations), "hypotheses": str(hypotheses)}}), encoding="utf-8")
    gemma = tmp_path / "gemma.json"
    gemma.write_text(json.dumps({"result_id": "gemma", "source_run_verified": True, "authority_valid": True, "source_run_id": "run", "accepted_actions": [{"hypothesis_ids": ["scope"], "observed_non_passed_gate_ids": ["header"]}]}), encoding="utf-8")
    monkeypatch.setattr(module, "verify_alternate_scope_run", lambda _path: {"ok": True})
    destination = tmp_path / "candidate.ptx"
    before = source.read_bytes()
    result = module.materialize_gemma_scope_candidate(source, run, gemma, destination)
    assert result["source_preserved"] is True
    assert result["verified_decryption"] is False
    assert source.read_bytes() == before
    assert destination.read_bytes()[:4] == before[:4]
    assert destination.read_bytes()[8:12] == bytes(value ^ 0x5A for value in before[8:12])
