"""Learning DB identity lookup and DB-first rail discovery."""

from __future__ import annotations

import hashlib
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _learning_db_bundle(tmp_path: Path) -> dict:
    from src.services.learning_db import load_learning_db_bundle

    policy = json.loads((ROOT / "config" / "learning_db_policy.json").read_text(encoding="utf-8"))
    registry = json.loads((ROOT / "config" / "learning_db_registry.json").read_text(encoding="utf-8"))
    hex_cfg = json.loads((ROOT / "config" / "hex_editor.json").read_text(encoding="utf-8"))
    hex_cfg["learning_db_root"] = str(tmp_path / "learning_db")
    hex_path = tmp_path / "hex_editor.json"
    hex_path.write_text(json.dumps(hex_cfg), encoding="utf-8")
    policy["storage"]["path_source"]["config_file"] = str(hex_path.resolve())
    policy["storage"]["path_source"]["config_root"] = "lab"
    policy_path = tmp_path / "learning_db_policy.json"
    registry_path = tmp_path / "learning_db_registry.json"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    registry_path.write_text(json.dumps(registry), encoding="utf-8")
    return load_learning_db_bundle(policy_path=policy_path, registry_path=registry_path)


def _synthetic_full_decode_run(tmp_path: Path):
    from src.services.full_decode import run_full_decode_e2e

    rng = random.Random(90210)
    source_data = bytearray(rng.randrange(128, 256) for _ in range(2048))
    parent_data = bytearray(source_data)
    text = b"learning-db repeated record"
    for offset in (193, 777, 1409):
        source_data[offset - 1] = parent_data[offset - 1] = 0
        source_data[offset : offset + len(text)] = text
        parent_data[offset : offset + len(text)] = bytes(value ^ 0xA7 for value in text)
        source_data[offset + len(text)] = parent_data[offset + len(text)] = 0
    for offset in (49, 503, 1801):
        source_data[offset] ^= 0x11
    source = tmp_path / "source.bin"
    parent = tmp_path / "parent.bin"
    tmp_path.mkdir(parents=True, exist_ok=True)
    source.write_bytes(source_data)
    parent.write_bytes(parent_data)
    run = run_full_decode_e2e(source, parent, output_root=tmp_path / "full-runs")
    run_path = Path(run["run_root"]) / "run.json"
    candidate_path = Path(run["run_root"]) / "candidates" / run["selected_candidate_id"] / "candidate.bin"
    return source, parent, run_path, candidate_path


def test_indexed_run_stores_numeric_unresolved_bytes(tmp_path: Path):
    from src.services.learning_db import index_rail_run, query_runs_for_source

    bundle = _learning_db_bundle(tmp_path)
    _source, _parent, run_path, _candidate = _synthetic_full_decode_run(tmp_path / "runs")
    index_rail_run(run_path, "full_decode", bundle=bundle)
    sha = hashlib.sha256(_source.read_bytes()).hexdigest()
    rows = query_runs_for_source(sha, bundle=bundle)
    assert rows["count"] >= 1
    unresolved = rows["rows"][0]["unresolved_bytes"]
    assert isinstance(unresolved, int)


def test_query_runs_for_identity_matches_candidate_output_sha(tmp_path: Path):
    from src.services.learning_db import index_rail_run, query_runs_for_identity

    bundle = _learning_db_bundle(tmp_path)
    _source, _parent, run_path, candidate_path = _synthetic_full_decode_run(tmp_path / "runs")
    index_rail_run(run_path, "full_decode", bundle=bundle)
    output_sha = hashlib.sha256(candidate_path.read_bytes()).hexdigest()
    rows = query_runs_for_identity(output_sha, rail_id="full_decode", bundle=bundle)
    assert rows["count"] >= 1
    assert rows["rows"][0]["rail_id"] == "full_decode"


def test_discover_full_decode_run_prefers_learning_db(tmp_path: Path, monkeypatch):
    from src.gui_evidence_presenter import discover_full_decode_run
    from src.services.learning_db import index_rail_run

    bundle = _learning_db_bundle(tmp_path)
    _source, _parent, run_path, candidate_path = _synthetic_full_decode_run(tmp_path / "runs")
    index_rail_run(run_path, "full_decode", bundle=bundle)
    output_sha = hashlib.sha256(candidate_path.read_bytes()).hexdigest()

    def _fail_scan(*_args, **_kwargs):
        raise AssertionError("artifact scan should not run when learning db resolves the run")

    monkeypatch.setattr(
        "src.services.candidate_lineage.discover_verified_run_for_rail",
        _fail_scan,
    )
    inspected = discover_full_decode_run(output_sha, scan_limit=8)
    assert inspected.get("verified") is True
    assert inspected.get("state_source") == "learning_db"
    assert inspected.get("run_id")


def test_format_display_scalar_normalizes_negative_zero():
    from src.services.ui_policy import format_display_scalar, load_ui_policy

    policy = load_ui_policy()
    assert format_display_scalar(-0.0, policy=policy) == "0.0"
    assert format_display_scalar(0.0, policy=policy) == "0.0"
