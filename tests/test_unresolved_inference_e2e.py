"""Unresolved ownership and Binary Semantic Graph E2E tests."""

from __future__ import annotations
import json, random, sys
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]


def _upstream(tmp_path: Path):
    from src.services.full_decode import run_full_decode_e2e
    rng = random.Random(993)
    source_data = bytearray(rng.randrange(128, 256) for _ in range(2048))
    parent_data = bytearray(source_data)
    text = b"portable repeated record"
    for offset in (193, 777, 1409):
        source_data[offset - 1] = parent_data[offset - 1] = 0
        source_data[offset:offset + len(text)] = text
        parent_data[offset:offset + len(text)] = bytes(value ^ 0xA7 for value in text)
        source_data[offset + len(text)] = parent_data[offset + len(text)] = 0
    for offset in (49, 503, 1801):
        source_data[offset] ^= 0x11
    source, parent = tmp_path / "source.bin", tmp_path / "parent.bin"
    source.write_bytes(source_data); parent.write_bytes(parent_data)
    run = run_full_decode_e2e(source, parent, output_root=tmp_path / "full-runs")
    return Path(run["run_root"]) / "run.json"


def test_unresolved_e2e_is_verified_coverage_complete_and_idempotent(tmp_path):
    from src.services.unresolved_inference import inspect_unresolved_inference_run, run_unresolved_inference_e2e, verify_unresolved_inference_run
    upstream = _upstream(tmp_path)
    first = run_unresolved_inference_e2e(upstream, output_root=tmp_path / "runs")
    second = run_unresolved_inference_e2e(upstream, output_root=tmp_path / "runs")
    assert first == second
    run_path = Path(first["run_root"]) / "run.json"
    assert verify_unresolved_inference_run(run_path)["ok"]
    inspected = inspect_unresolved_inference_run(run_path)
    assert inspected["verified"] and inspected["coverage"]["coverage_complete"]
    assert inspected["graph_summary"]["validation"]["valid"]
    assert inspected["graph_summary"]["node_count"] > 0


def test_graph_offset_and_neighbor_queries_are_bounded(tmp_path):
    from src.services.unresolved_inference import query_binary_semantic_graph, run_unresolved_inference_e2e
    run = run_unresolved_inference_e2e(_upstream(tmp_path), output_root=tmp_path / "runs")
    graph_path = Path(run["artifacts"]["semantic_graph"])
    graph = json.loads(graph_path.read_text(encoding="utf-8"))
    indexed = graph["indexes"]["by_offset"]
    assert indexed
    result = query_binary_semantic_graph(graph_path, "nodes_at_offset", offset=indexed[0]["offset"], maximum_results=2)
    assert result["results"] and len(result["results"]) <= 2
    node_id = result["results"][0]["node_id"]
    neighbors = query_binary_semantic_graph(graph_path, "neighbors", node_id=node_id, maximum_depth=2, maximum_results=5)
    assert len(neighbors["results"]) <= 5


def test_dependency_requires_independent_occurrences():
    from src.services.unresolved_inference.core import compile_ownership_proofs, infer_dependencies, load_unresolved_bundle
    bundle = load_unresolved_bundle()
    spans = [{"span_id": "s1", "segment_id": "u1", "offset": 0, "length": 1}, {"span_id": "s2", "segment_id": "u2", "offset": 11, "length": 1}]
    coverage = {"segments": [{"segment_id": "u1", "offset": 0, "length": 1}, {"segment_id": "a", "offset": 1, "length": 10}, {"segment_id": "u2", "offset": 11, "length": 1}, {"segment_id": "b", "offset": 12, "length": 10}]}
    reps = [{"representation_id": "r1", "span_id": "s1", "width": 1, "endian": "little", "value": 10}, {"representation_id": "r2", "span_id": "s2", "width": 1, "endian": "little", "value": 10}]
    result = infer_dependencies(reps, spans, coverage, bundle=bundle)
    assert len(result["edges"]) == 2
    assert all(item["state"] == "verified" for item in result["edges"])
    proofs = compile_ownership_proofs(spans, result, bundle=bundle)
    assert all(item["state"] == "accepted" for item in proofs)
    assert all(item["classification"] == "preserved_binary" for item in proofs)


def test_model_is_advisory_and_cannot_inject_authority(tmp_path):
    from src.services.unresolved_inference import build_unresolved_model_packet, run_unresolved_inference_e2e, validate_unresolved_model_action
    run = run_unresolved_inference_e2e(_upstream(tmp_path), output_root=tmp_path / "runs")
    packet = build_unresolved_model_packet(Path(run["run_root"]) / "run.json")
    target = packet["clusters"][0]["cluster_id"]
    assert validate_unresolved_model_action({"action": "prioritize_existing_cluster", "target_id": target, "reason": "largest unresolved component"}, packet)
    with pytest.raises(ValueError, match="authority"):
        validate_unresolved_model_action({"action": "prioritize_existing_cluster", "target_id": target, "reason": "guess", "offset": 7}, packet)


def test_resume_is_terminal_and_read_only(tmp_path):
    from src.services.unresolved_inference import resume_unresolved_inference_run, run_unresolved_inference_e2e
    run = run_unresolved_inference_e2e(_upstream(tmp_path), output_root=tmp_path / "runs")
    result = resume_unresolved_inference_run(Path(run["run_root"]))
    assert result["executed_new_work"] is False


def test_corrupt_graph_fails_verification(tmp_path):
    from src.services.unresolved_inference import run_unresolved_inference_e2e, verify_unresolved_inference_run
    run = run_unresolved_inference_e2e(_upstream(tmp_path), output_root=tmp_path / "runs")
    graph_path = Path(run["artifacts"]["semantic_graph"])
    graph = json.loads(graph_path.read_text(encoding="utf-8")); graph["validation"]["valid"] = False
    graph_path.write_text(json.dumps(graph), encoding="utf-8")
    assert not verify_unresolved_inference_run(Path(run["run_root"]) / "run.json")["ok"]


def test_runtime_contains_no_case_facts():
    paths = list((ROOT / "src" / "services" / "unresolved_inference").glob("*.py")) + [ROOT / "config" / "unresolved_inference_policy.json", ROOT / "config" / "unresolved_inference_registry.json"]
    content = "\n".join(path.read_text(encoding="utf-8").casefold() for path in paths)
    forbidden = ("blue cat", "patchwork", "nectar", "chillax", "1candidate", "0x7aed", "0x7b18", "0x7b47")
    assert not any(item in content for item in forbidden)


def test_mcp_tools_registered_and_writes_require_confirmation():
    lab = ROOT
    if str(lab) not in sys.path: sys.path.insert(0, str(lab))
    from hexeditor_tools import api as hex_editor_tools
    from hexeditor_tools.catalog import _definitions
    definitions = _definitions()
    for name in ("binary_unresolved_inference_run", "binary_unresolved_inference_inspect", "binary_unresolved_inference_verify", "binary_unresolved_inference_resume", "binary_semantic_graph_query"):
        assert name in definitions
    with pytest.raises(ValueError, match="confirmed=true"):
        hex_editor_tools.binary_unresolved_inference_run("run", "output")
    with pytest.raises(ValueError, match="confirmed=true"):
        hex_editor_tools.binary_unresolved_inference_resume("run")
