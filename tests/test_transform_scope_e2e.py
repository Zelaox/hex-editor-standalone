"""E2E and no-hardcode tests for transform scope/gate proof."""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _source(tmp_path: Path) -> Path:
    path = tmp_path / "sample.ptx"
    path.write_bytes(b"PTX header readable\x00" + bytes(range(256)) * 8 + b"track clip timeline")
    return path


def test_scope_proof_writes_breakdown_checkpoint_and_logs(tmp_path):
    from src.services.transform_scope import resume_transform_scope_proof, run_transform_scope_proof, verify_scope_run

    source = _source(tmp_path)
    before = source.read_bytes()
    run = run_transform_scope_proof(source, output_root=tmp_path / "runs", candidate_hex="5a", boundary_hint=257)
    assert source.read_bytes() == before
    assert run["promotion_allowed"] in {True, False}
    assert verify_scope_run(Path(run["run_root"]) / "run.json")["ok"] is True
    resumed = resume_transform_scope_proof(Path(run["run_root"]) / "run.json")
    assert resumed["new_descriptor_executions"] == 0
    root = Path(run["run_root"])
    assert (root / "logs" / "events.jsonl").is_file()
    assert (root / "logs" / "rolling.log").is_file()
    assert (root / "gates" / "breakdowns.json").is_file()
    assert (root / "checkpoints" / "latest.json").is_file()
    events = [json.loads(line) for line in (root / "logs" / "events.jsonl").read_text(encoding="utf-8").splitlines()]
    assert [item["sequence"] for item in events] == list(range(len(events)))
    assert events[-1]["event_type"] == "run_terminal"


def test_case_values_change_descriptors_without_config_changes(tmp_path):
    from src.services.transform_scope import run_transform_scope_proof

    source = _source(tmp_path)
    first = run_transform_scope_proof(source, output_root=tmp_path / "one", candidate_hex="01", boundary_hint=211)
    second = run_transform_scope_proof(source, output_root=tmp_path / "two", candidate_hex="a7", boundary_hint=977)
    assert first["run_id"] != second["run_id"]
    first_observations = json.loads(Path(first["artifacts"]["observations"]).read_text(encoding="utf-8"))
    second_observations = json.loads(Path(second["artifacts"]["observations"]).read_text(encoding="utf-8"))
    assert first_observations != second_observations


def test_missing_required_policy_value_fails_loud(tmp_path):
    from src.services.transform_scope import load_scope_bundle

    policy = json.loads((ROOT / "config" / "transform_scope_policy.json").read_text(encoding="utf-8"))
    del policy["artifact_layout"]
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(policy), encoding="utf-8")
    with pytest.raises(ValueError):
        load_scope_bundle(policy_path=path)


def test_no_case_hardcode_in_scope_runtime():
    source = (ROOT / "src" / "services" / "transform_scope" / "core.py").read_text(encoding="utf-8").lower()
    forbidden = ("0x94", "ac240", "1024+", "parser-learning-bounded-e2e", "if offset ==")
    assert not any(token in source for token in forbidden)
    policy = json.loads((ROOT / "config" / "transform_scope_policy.json").read_text(encoding="utf-8"))
    registry = json.loads((ROOT / "config" / "transform_scope_registry.json").read_text(encoding="utf-8"))
    assert policy["validation_profiles"]
    assert registry["window_derivers"] and registry["gates"]
