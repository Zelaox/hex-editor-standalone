"""Forensic bundle export and knowledge metrics (policy-driven fixtures only)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _reference_preserved_run() -> Path | None:
    base = ROOT / "data" / "artifacts" / "hex_editor" / "preserved_binary_inference_runs"
    if not base.is_dir():
        return None
    for run_json in sorted(base.rglob("run.json"), key=lambda item: item.stat().st_mtime_ns, reverse=True):
        if run_json.parent.name.startswith("preserved-inference-run-"):
            return run_json
    return None


def test_compile_structural_findings_from_reference_run_when_present():
    run_path = _reference_preserved_run()
    if run_path is None:
        pytest.skip("no preserved inference run artifacts in workspace")
    from src.services.forensic_bundle import export_preserved_forensic_bundle
    from src.services.preserved_binary_inference import verify_preserved_binary_inference_run

    if not verify_preserved_binary_inference_run(run_path).get("ok"):
        pytest.skip("reference preserved run failed verification")
    result = export_preserved_forensic_bundle(run_path)
    findings_path = Path(result["bundle_root"]) / "findings.json"
    payload = json.loads(findings_path.read_text(encoding="utf-8-sig"))
    assert payload["finding_count"] == len(payload["findings"])
    assert payload["finding_count"] >= 1
    for row in payload["findings"]:
        assert "offset" in row and "length" in row
        assert row.get("dependency_ids")


def test_knowledge_coverage_partition_equals_file_size():
    run_path = _reference_preserved_run()
    if run_path is None:
        pytest.skip("no preserved inference run artifacts in workspace")
    from src.services.forensic_knowledge_metrics import compile_knowledge_coverage_from_runs

    run = json.loads(run_path.read_text(encoding="utf-8-sig"))
    upstream_id = str(run["upstream_run_id"])
    fd_run = None
    search_root = ROOT / "data" / "artifacts" / "hex_editor"
    from src.services.full_decode import verify_full_decode_run

    for candidate in search_root.rglob("run.json"):
        try:
            upstream = json.loads(candidate.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError):
            continue
        if str(upstream.get("run_id")) != upstream_id:
            continue
        if verify_full_decode_run(candidate).get("ok"):
            fd_run = candidate
            break
    if fd_run is None:
        pytest.skip("upstream full-decode run not found for reference preserved run")
    metrics = compile_knowledge_coverage_from_runs(fd_run, run_path)
    total = (
        int(metrics["semantic_coverage_bytes"])
        + int(metrics["structural_only_bytes"])
        + int(metrics["owned_but_unlabeled_bytes"])
        + int(metrics["unowned_bytes"])
    )
    assert total == int(metrics["file_size"])


def test_synthetic_length_of_finding_compiler():
    from src.services.forensic_bundle import compile_structural_findings

    coverage = {
        "segments": [
            {"segment_id": "seg-next", "class": "verified_decoded_binary", "offset": 1, "length": 4},
        ]
    }
    spans = [{"span_id": "span-a", "offset": 0, "length": 2, "class": "preserved_binary"}]
    boundaries = [{"span_id": "span-a", "left_segment_id": None, "right_segment_id": "seg-next"}]
    representations = [{"representation_id": "rep-a", "span_id": "span-a", "offset": 0, "width": 1, "value": 4, "endian": "little", "state": "tested"}]
    dependencies = {
        "edges": [
            {
                "dependency_id": "dep-a",
                "edge_type": "length_of",
                "state": "verified",
                "source_span_id": "span-a",
                "target_segment_id": "seg-next",
                "representation_id": "rep-a",
            }
        ]
    }
    proofs = [{"span_id": "span-a", "gate_statuses": {"structural_metadata": "passed"}}]
    rows = compile_structural_findings(
        run_id="test-run",
        source_sha256="0" * 64,
        spans=spans,
        boundaries=boundaries,
        representations=representations,
        dependencies=dependencies,
        coverage=coverage,
        proofs=proofs,
    )
    assert len(rows) == 1
    assert rows[0]["offset"] == 0
    assert rows[0]["target_segment"]["length"] == 4


def test_learning_db_indexes_preserved_rail(tmp_path):
    from src.services.learning_db import discover_rail_run_via_learning_db, index_rail_run, load_learning_db_bundle

    run_path = _reference_preserved_run()
    if run_path is None:
        pytest.skip("no preserved inference run artifacts in workspace")
    bundle = load_learning_db_bundle()
    if not bundle["policy"]["sync"].get("enabled"):
        pytest.skip("learning db sync disabled")
    run = json.loads(run_path.read_text(encoding="utf-8-sig"))
    source_sha = str(run["source"]["sha256"])
    index_rail_run(run_path, "preserved_binary_inference", bundle=bundle)
    discovery = discover_rail_run_via_learning_db("preserved_binary_inference", source_sha, bundle=bundle)
    assert discovery.get("verified")
