"""End-to-end tests for proof ledger preservation and cross-run deltas."""

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


def _proof_ledger_bundle(tmp_path: Path) -> dict:
    from src.services.proof_ledger.core import load_proof_ledger_bundle

    policy = json.loads((ROOT / "config" / "proof_ledger_policy.json").read_text(encoding="utf-8"))
    registry = json.loads((ROOT / "config" / "proof_ledger_registry.json").read_text(encoding="utf-8"))
    policy["artifact_root"] = str((tmp_path / "proof_ledger").resolve()).replace("\\", "/")
    policy_path = tmp_path / "proof_ledger_policy.json"
    registry_path = tmp_path / "proof_ledger_registry.json"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    registry_path.write_text(json.dumps(registry), encoding="utf-8")
    return load_proof_ledger_bundle(policy_path=policy_path, registry_path=registry_path)


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

    rng = random.Random(424242)
    source_data = bytearray(rng.randrange(32, 64) for _ in range(1024))
    parent_data = bytearray(source_data)
    text = b"synthetic-proof-span"
    offset = 128
    source_data[offset - 1] = parent_data[offset - 1] = 0
    source_data[offset : offset + len(text)] = text
    parent_data[offset : offset + len(text)] = bytes(value ^ 0x5A for value in text)
    source_data[offset + len(text)] = parent_data[offset + len(text)] = 0
    source = tmp_path / "source.bin"
    parent = tmp_path / "parent.bin"
    tmp_path.mkdir(parents=True, exist_ok=True)
    source.write_bytes(source_data)
    parent.write_bytes(parent_data)
    run = run_full_decode_e2e(source, parent, output_root=tmp_path / "full-runs")
    return source, parent, Path(run["run_root"]) / "run.json"


def test_proof_ledger_compile_and_query(tmp_path):
    from src.services.proof_ledger import compile_proof_ledger_from_run, load_protected_spans, query_lineage_ledger

    bundle = _proof_ledger_bundle(tmp_path)
    _, _, run_path = _synthetic_full_decode_run(tmp_path / "runs")
    result = compile_proof_ledger_from_run(run_path, "full_decode", bundle=bundle)
    assert result["ok"] is True
    lineage = query_lineage_ledger(result["lineage_key"], bundle=bundle)
    assert lineage["exists"] is True
    protected = load_protected_spans(result["lineage_key"], bundle=bundle)
    assert isinstance(protected, list)


def test_preservation_blocks_span_loss(tmp_path):
    from src.services.proof_ledger.composition import evaluate_compositions
    from src.services.proof_ledger.core import preservation_metrics

    bundle = _proof_ledger_bundle(tmp_path)
    parent = b"\x00" + b"A" * 16 + b"\x00"
    source = parent
    protected = [
        {
            "proof_span_id": "proof-span-test",
            "span": {"offset": 1, "length": 4},
            "truth_state": "proof_owned",
            "coverage_class": "verified_plaintext",
            "proven_bytes_digest": hashlib.sha256(b"AAAA").hexdigest(),
        }
    ]
    compositions = [
        {"bytes": parent, "proof_spans": [], "provider_candidate_ids": ["a"], "resolved_source_bytes": 0, "changed_bytes": 0},
        {"bytes": b"\x00" + b"B" * 16 + b"\x00", "proof_spans": [], "provider_candidate_ids": ["b"], "resolved_source_bytes": 0, "changed_bytes": 4},
    ]
    ranked = evaluate_compositions(compositions, parent, source, protected, bundle={"policy": {"reference_evaluation": {"enabled": False, "require_reference_non_regression": False}}}, ledger_bundle=bundle)
    assert ranked
    assert ranked[0]["bytes"] == parent
    metrics = preservation_metrics(parent, compositions[1]["bytes"], protected)
    assert metrics["lost_proof_owned_span_count"] == 1


def test_cross_run_delta_and_learning_db_index(tmp_path):
    from src.services.learning_db import ensure_learning_db_schema, index_proof_ledger_artifacts, query_learning_db
    from src.services.proof_ledger import compile_proof_ledger_from_run
    from src.services.proof_ledger.delta_compiler import compile_cross_run_delta

    proof_bundle = _proof_ledger_bundle(tmp_path)
    learning_bundle = _learning_db_bundle(tmp_path)
    ensure_learning_db_schema(bundle=learning_bundle)
    _, _, first_run = _synthetic_full_decode_run(tmp_path / "first")
    first_compile = compile_proof_ledger_from_run(first_run, "full_decode", bundle=proof_bundle)
    _, _, second_run = _synthetic_full_decode_run(tmp_path / "second")
    second_compile = compile_proof_ledger_from_run(second_run, "full_decode", bundle=proof_bundle)
    delta = compile_cross_run_delta(first_run, second_run, "run_to_run", bundle=proof_bundle)
    assert delta["ok"] is True
    index_proof_ledger_artifacts(second_compile, second_run, "full_decode", bundle=learning_bundle)
    rows = query_learning_db("preservation_events", filters={"lineage_key": second_compile["lineage_key"]}, bundle=learning_bundle)
    assert rows["count"] >= 1


def test_reference_filter_keeps_compositions_when_all_regress(tmp_path):
    from src.services.proof_ledger.composition import evaluate_compositions

    bundle = _proof_ledger_bundle(tmp_path)
    parent = b"\x00" + b"P" * 8 + b"\x00"
    source = parent
    reference = b"\x00" + b"R" * 8 + b"\x00"
    compositions = [
        {"bytes": b"\x00" + b"A" * 8 + b"\x00", "proof_spans": [], "provider_candidate_ids": ["a"], "resolved_source_bytes": 0, "changed_bytes": 8},
    ]
    full_decode_bundle = {
        "policy": {"reference_evaluation": {"enabled": True, "require_reference_non_regression": True}},
        "reference": {"bytes": reference},
    }
    ranked = evaluate_compositions(compositions, parent, source, [], bundle=full_decode_bundle, ledger_bundle=bundle)
    assert len(ranked) == 1


def test_delta_context_packet_bounds(tmp_path):
    from src.services.proof_ledger.delta_packet import build_delta_context_packet

    bundle = _proof_ledger_bundle(tmp_path)
    delta = {
        "delta_id": "cross-run-delta-test",
        "lineage_key": hashlib.sha256(b"lineage").hexdigest(),
        "from": {"candidate_id": "from-id"},
        "to": {"candidate_id": "to-id"},
        "summary": {"lost_proof_owned_span_count": 0, "preserved_proof_owned_span_count": 1, "unresolved_byte_delta": 0},
        "spans": {"lost_proof_owned_spans": [], "gained_proof_owned_spans": []},
    }
    packet = build_delta_context_packet(delta, bundle=bundle)
    assert packet["delta_context"]["schema_version"] == 1
    assert packet["delta_context"]["required_preservation_violations"] == []
