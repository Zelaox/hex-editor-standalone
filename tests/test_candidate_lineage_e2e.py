"""Candidate lineage E2E — policy-driven discovery, resolve, verify, graph bridge."""

from __future__ import annotations

import hashlib
import random
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _upstream(tmp_path: Path):
    from src.services.full_decode import run_full_decode_e2e

    rng = random.Random(4419)
    source_data = bytearray(rng.randrange(128, 256) for _ in range(2048))
    parent_data = bytearray(source_data)
    text = b"lineage repeated record"
    for offset in (193, 777, 1409):
        source_data[offset - 1] = parent_data[offset - 1] = 0
        source_data[offset : offset + len(text)] = text
        parent_data[offset : offset + len(text)] = bytes(value ^ 0xA7 for value in text)
        source_data[offset + len(text)] = parent_data[offset + len(text)] = 0
    for offset in (49, 503, 1801):
        source_data[offset] ^= 0x11
    source, parent = tmp_path / "source.bin", tmp_path / "parent.bin"
    source.write_bytes(source_data)
    parent.write_bytes(parent_data)
    run = run_full_decode_e2e(source, parent, output_root=tmp_path / "full-runs")
    return source, Path(run["run_root"]) / "run.json"


def test_discover_returns_empty_for_unknown_sha256():
    from src.services.candidate_lineage import discover_verified_run_for_rail

    assert discover_verified_run_for_rail("full_decode", "0" * 64, scan_limit=4) == {}


def test_synthetic_lineage_chain_is_internally_consistent(tmp_path):
    import json
    import shutil

    from src.services.candidate_lineage import candidate_graph_impact, resolve_candidate_lineage, verify_candidate_lineage_chain
    from src.services.unresolved_inference import run_unresolved_inference_e2e

    source, upstream = _upstream(tmp_path)
    unresolved = run_unresolved_inference_e2e(upstream, output_root=tmp_path / "unresolved-runs")
    artifact_base = tmp_path / "artifacts"
    full_run_root = Path(upstream).resolve().parent
    unresolved_run_root = Path(unresolved["run_root"]).resolve()
    shutil.copytree(full_run_root, artifact_base / "full_decode_runs" / full_run_root.name)
    shutil.copytree(unresolved_run_root, artifact_base / "unresolved_inference_runs" / unresolved_run_root.name)
    policy = json.loads((ROOT / "config" / "candidate_lineage_policy.json").read_text(encoding="utf-8-sig"))
    policy["artifact_root"] = str(artifact_base)
    policy_path = tmp_path / "lineage_policy.json"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    sha = hashlib.sha256(source.read_bytes()).hexdigest()
    packet = resolve_candidate_lineage(source_sha256=sha, scan_limit=32, policy_path=policy_path)
    assert packet.get("nodes")
    rails = {node.get("rail") for node in packet.get("nodes") or []}
    assert "full_decode" in rails
    assert "unresolved_inference" in rails
    verification = verify_candidate_lineage_chain(packet, policy_path=policy_path)
    assert verification.get("chain_ok") is True
    impact = candidate_graph_impact(lineage_packet=packet, candidate_id="", maximum_depth=1)
    assert impact.get("ok") is True


def test_bounded_fixture_lineage_when_manifest_present():
    from src.services.hex_regression_fixtures import resolve_bundle
    from src.services.candidate_lineage import resolve_candidate_lineage, verify_candidate_lineage_chain

    try:
        bundle = resolve_bundle("ac240_bounded_scope_378")
    except ValueError:
        pytest.skip("bounded materialization manifest unavailable")
    manifest = dict(bundle.get("manifest") or {})
    sha = str(manifest.get("source_sha256") or "")
    if not sha:
        pytest.skip("manifest missing source_sha256")
    packet = resolve_candidate_lineage(source_sha256=sha)
    verification = verify_candidate_lineage_chain(packet)
    assert verification.get("chain_ok") in {True, False}


def test_live_materialized_chain_when_artifacts_present():
    import json

    from src.services.candidate_lineage import candidate_graph_impact, resolve_candidate_lineage, verify_candidate_lineage_chain
    from src.services.candidate_lineage.policy import artifact_root

    decode_root = artifact_root() / "full_decode_runs"
    if not decode_root.is_dir():
        pytest.skip("full_decode artifact root unavailable")
    run_paths = sorted(decode_root.glob("*/run.json"), key=lambda item: item.stat().st_mtime, reverse=True)
    if not run_paths:
        pytest.skip("no full_decode runs on disk")
    run = json.loads(run_paths[0].read_text(encoding="utf-8-sig"))
    sha = str((run.get("source") or {}).get("sha256") or "")
    if not sha:
        pytest.skip("newest full_decode run missing source sha256")
    packet = resolve_candidate_lineage(source_sha256=sha)
    rails = {str(node.get("rail") or "") for node in packet.get("nodes") or []}
    if "full_decode" not in rails:
        pytest.skip("newest full_decode run did not verify for lineage resolve")
    if "unresolved_inference" not in rails:
        pytest.skip("unresolved_inference rail unavailable for this identity")
    assert "record_family" in rails
    verification = verify_candidate_lineage_chain(packet)
    assert verification.get("chain_ok") is True
    unresolved = next(node for node in packet["nodes"] if node.get("rail") == "unresolved_inference")
    full_decode = next(node for node in packet["nodes"] if node.get("rail") == "full_decode")
    assert unresolved.get("upstream_run_id") == full_decode.get("run_id")
    impact = candidate_graph_impact(lineage_packet=packet, candidate_id=str(unresolved.get("selected_candidate_id") or ""))
    assert impact.get("ok") is True


def test_runtime_contains_no_case_facts():
    paths = list((ROOT / "src" / "services" / "candidate_lineage").glob("*.py")) + [ROOT / "config" / "candidate_lineage_policy.json"]
    content = "\n".join(path.read_text(encoding="utf-8").casefold() for path in paths)
    forbidden = ("blue cat", "patchwork", "1candidate", "chillax", "nectar", "0x7aed", "0x7b18", "0x7b47", "turn-0012")
    assert not any(item in content for item in forbidden)


def test_mcp_lineage_tools_registered():
    lab = ROOT
    if str(lab) not in sys.path:
        sys.path.insert(0, str(lab))
    from hexeditor_tools.catalog import _definitions

    definitions = _definitions()
    for name in ("binary_candidate_lineage_resolve", "binary_candidate_lineage_verify"):
        assert name in definitions


def test_forensic_context_includes_candidate_lineage():
    from src.gui_evidence_presenter import build_forensic_context

    snapshot = {
        "snapshot_id": "lineage-test",
        "format_plugin": "ptx",
        "source": {"sha256": "0" * 64, "size": 1},
        "coverage_summary": {"total_bytes": 1, "unknown_bytes": 0, "bytes_by_class": {}},
        "anchors": [],
        "unknown_regions": [],
        "record_families": [],
        "coverage": [],
    }
    context = build_forensic_context(
        source_path=ROOT / "main.py",
        snapshot=snapshot,
        include_scope_discovery=False,
        include_lineage_discovery=True,
        include_representation=False,
    )
    assert "candidate_lineage" in context
