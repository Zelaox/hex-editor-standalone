"""End-to-end tests for the config-driven learning DB index."""

from __future__ import annotations

import hashlib
import json
import random
import sys
from pathlib import Path

import pytest

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
    return source, Path(run["run_root"]) / "run.json"


def test_learning_db_schema_and_query(tmp_path):
    from src.services.learning_db import ensure_learning_db_schema, inspect_learning_db, query_runs_for_source

    bundle = _learning_db_bundle(tmp_path)
    ensure = ensure_learning_db_schema(bundle=bundle)
    assert ensure["ok"] is True
    inspect = inspect_learning_db(bundle=bundle)
    assert inspect["table_counts"]["runs"] == 0
    source, run_path = _synthetic_full_decode_run(tmp_path / "runs")
    from src.services.learning_db import index_rail_run

    index_rail_run(run_path, "full_decode", bundle=bundle)
    sha = hashlib.sha256(source.read_bytes()).hexdigest()
    rows = query_runs_for_source(sha, bundle=bundle)
    assert rows["count"] >= 1
    assert rows["rows"][0]["rail_id"] == "full_decode"
    assert rows["rows"][0]["source_sha256"] == sha


def test_parser_learning_indexes_observations(tmp_path):
    from src.services.learning_db import index_parser_learning_run, query_learning_db
    from src.services.parser_learning import run_parser_learning

    bundle = _learning_db_bundle(tmp_path)
    first = tmp_path / "first"
    second = tmp_path / "second"
    for index, label in enumerate(("one", "two")):
        root = first if index == 0 else second
        root.mkdir(parents=True)
        source_digest = hashlib.sha256(f"source-{label}".encode("utf-8")).hexdigest()
        (root / "manifest.json").write_text(
            json.dumps({"source_before": {"sha256": source_digest}, "details": {"snapshot_id": f"snapshot-{label}", "format_plugin": "test-format"}}),
            encoding="utf-8",
        )
        (root / "unknown").mkdir()
        (root / "unknown" / "regions.json").write_text(json.dumps([{"region_id": f"region-{label}", "span": {"offset": 0, "length": 4}, "neighbor_anchor_ids": []}]), encoding="utf-8")
        from src.services.representation_sweep import sweep_region, write_representation_brief_cache

        write_representation_brief_cache(root, f"region-{label}", sweep_region(b"ABCD"))
    output = tmp_path / "output"
    result = run_parser_learning(
        [first, second],
        output_workspace=output,
        format_plugin="test-format",
        base_profile_id="generic",
        validation_results={
            "deterministic_replay": True,
            "negative_fixture_result": True,
            "no_coverage_regression": True,
            "no_graph_regression": True,
        },
    )
    index_parser_learning_run(result["artifact_root"], bundle=bundle, format_plugin="test-format")
    candidates = query_learning_db("candidates", filters={"rail_id": "parser_learning"}, bundle=bundle)
    assert candidates["count"] >= 1
    events = query_learning_db("learning_events", filters={"event_kind": "parser_learning_indexed"}, bundle=bundle)
    assert events["count"] >= 1


def test_sync_respects_disabled_policy(tmp_path):
    from src.services.learning_db import sync_learning_db

    bundle = _learning_db_bundle(tmp_path)
    bundle["policy"]["sync"]["enabled"] = False
    result = sync_learning_db(bundle=bundle)
    assert result["synced"] is False
