from __future__ import annotations

import json
from pathlib import Path

from src.services.transform_preview import inspect_transform_preview, iter_full_file_preview, load_transform_preview_policy


def _discovery_with_candidate(tmp_path: Path, source: Path, candidate: Path) -> dict:
    return {
        "verified": True,
        "matched_role": "parent",
        "run": {
            "source": {"sha256": "source-sha"},
            "parent": {"path": str(source), "sha256": "parent-sha"},
            "artifacts": {"candidate": str(candidate), "inverse": str(candidate.parent / "inverse.json")},
        },
        "inspected": {
            "run_root": str(candidate.parent.parent),
            "candidate": {"artifact_path": str(candidate), "source_sha256": "source-sha", "parent_sha256": "parent-sha"},
        },
    }


def test_policy_registers_all_presentation_modes():
    policy = load_transform_preview_policy()
    assert {item["id"] for item in policy["modes"]} == {"raw", "transform_preview", "materialized", "semantic"}


def test_raw_mode_is_source_exact(tmp_path: Path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"abcdef")
    result = inspect_transform_preview(source, offset=1, length=3, mode="raw")
    assert result["raw_bytes"] == b"bcd"
    assert result["output_bytes"] == b"bcd"
    assert result["source_mutated"] is False
    assert source.read_bytes() == b"abcdef"


def test_transform_preview_replays_when_descriptors_exist(tmp_path: Path, monkeypatch):
    source = tmp_path / "parent.bin"
    candidate = tmp_path / "candidate_root" / "candidate.bin"
    candidate.parent.mkdir()
    source.write_bytes(b"AAbbCCdd")
    candidate.write_bytes(b"AAXXCCdd")
    proof_path = candidate.parent / "proof_spans.json"
    proof_path.write_text(
        json.dumps(
            [{"offset": 2, "length": 2, "scope_id": "scope-a", "proof_id": "proof-a", "provider_id": "test-provider"}]
        ),
        encoding="utf-8",
    )
    (candidate.parent / "inverse.json").write_text("[]", encoding="utf-8")
    monkeypatch.setattr(
        "src.services.transform_preview.inspect._discover_lineage",
        lambda rail, source_sha, scan_limit: _discovery_with_candidate(tmp_path, source, candidate),
    )
    result = inspect_transform_preview(source, offset=0, length=8, mode="transform_preview", use_cache=False)
    assert result["output_bytes"] == b"AAXXCCdd"
    assert result["state"] == "verified_preview"
    assert len(result["chain_steps"]) == 1
    assert "no_verified_materialized_candidate" not in result["diagnostics"]


def test_transform_preview_without_descriptors_keeps_source_bytes(tmp_path: Path, monkeypatch):
    source, candidate = tmp_path / "source.bin", tmp_path / "candidate.bin"
    source.write_bytes(b"raw-data")
    candidate.write_bytes(b"new-data")
    (candidate.parent / "inverse.json").write_text("[]", encoding="utf-8")
    monkeypatch.setattr(
        "src.services.transform_preview.inspect._discover_lineage",
        lambda rail, source_sha, scan_limit: _discovery_with_candidate(tmp_path, source, candidate),
    )
    result = inspect_transform_preview(source, offset=0, length=8, mode="transform_preview", use_cache=False)
    assert result["output_bytes"] == b"raw-data"
    assert result["state"] == "source_only"
    assert "no_verified_preview_descriptor_for_scope" in result["diagnostics"]
    assert "no_verified_materialized_candidate" not in result["diagnostics"]


def test_missing_lineage_preview_reports_preview_lineage_not_materialized(tmp_path: Path, monkeypatch):
    source = tmp_path / "source.bin"
    source.write_bytes(b"raw")
    monkeypatch.setattr("src.services.transform_preview.inspect._discover_lineage", lambda rail, source_sha, scan_limit: {})
    result = inspect_transform_preview(source, offset=0, length=3, mode="transform_preview", use_cache=False)
    assert result["output_bytes"] == b"raw"
    assert result["state"] == "unavailable"
    assert result["diagnostics"] == ["no_verified_preview_lineage"]


def test_materialized_requires_candidate_file(tmp_path: Path, monkeypatch):
    source = tmp_path / "source.bin"
    source.write_bytes(b"raw")
    monkeypatch.setattr("src.services.transform_preview.inspect._discover_lineage", lambda rail, source_sha, scan_limit: {})
    result = inspect_transform_preview(source, offset=0, length=3, mode="materialized", use_cache=False)
    assert result["state"] == "unavailable"
    assert result["diagnostics"] == ["no_verified_materialized_candidate"]


def test_semantic_mode_composes_plaintext_and_binary(tmp_path: Path, monkeypatch):
    source = tmp_path / "source.bin"
    source.write_bytes(b"Hello\x00\xff")
    graph_path = tmp_path / "graph.json"
    graph_path.write_text(json.dumps({"nodes": [
        {"node_type": "CoverageSegment", "attributes": {"offset": 0, "length": 5, "class": "verified_plaintext"}},
        {"node_type": "CoverageSegment", "attributes": {"offset": 5, "length": 2, "class": "preserved_binary"}},
    ]}), encoding="utf-8")
    monkeypatch.setattr(
        "src.services.transform_preview.inspect._discover_lineage",
        lambda rail, source_sha, scan_limit: {
            "verified": True,
            "inspected": {"artifacts": {"semantic_graph": str(graph_path)}},
        }
        if rail == "unresolved_inference"
        else {},
    )
    result = inspect_transform_preview(source, offset=0, length=7, mode="semantic", use_cache=False)
    assert "Hello" in result["decoded_text"]
    assert "preserved_binary" in result["decoded_text"]
    assert result["state"] == "verified_graph"


def test_semantic_mode_keeps_uncovered_gaps_visible(tmp_path: Path, monkeypatch):
    source = tmp_path / "source.bin"
    source.write_bytes(b"ABCDEFG")
    graph_path = tmp_path / "graph.json"
    graph_path.write_text(json.dumps({"nodes": [
        {"node_type": "CoverageSegment", "attributes": {"offset": 2, "length": 3, "class": "verified_plaintext"}},
    ]}), encoding="utf-8")
    monkeypatch.setattr(
        "src.services.transform_preview.inspect._discover_lineage",
        lambda rail, source_sha, scan_limit: {
            "verified": True,
            "inspected": {"artifacts": {"semantic_graph": str(graph_path)}},
        }
        if rail == "unresolved_inference"
        else {},
    )
    result = inspect_transform_preview(source, offset=0, length=7, mode="semantic", use_cache=False)
    assert "<unresolved offset=0x0 length=2>" in result["decoded_text"]
    assert "CDE" in result["decoded_text"]
    assert "<unresolved offset=0x5 length=2>" in result["decoded_text"]


def test_text_inspector_modes_come_from_policy(monkeypatch):
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    from PyQt5.QtWidgets import QApplication
    from src.text_inspector_widget import TextInspectorWidget

    app = QApplication.instance() or QApplication([])
    widget = TextInspectorWidget()
    assert {widget.mode_selector.itemData(index) for index in range(widget.mode_selector.count())} == {"raw", "transform_preview", "materialized", "semantic"}
    captured = []
    widget.set_goto_source_callback(captured.append)
    widget._last_result = {"offset": 27}
    widget.goto_source_button.click()
    assert captured == [27]


def test_partition_range_covers_gaps_and_proof_spans(tmp_path: Path):
    candidate_dir = tmp_path / "candidate_root"
    candidate_dir.mkdir()
    proof_path = candidate_dir / "proof_spans.json"
    proof_path.write_text(
        json.dumps(
            [
                {"offset": 2, "length": 3, "scope_id": "scope-a", "proof_id": "proof-a", "provider_id": "test-provider"},
            ]
        ),
        encoding="utf-8",
    )
    (candidate_dir / "inverse.json").write_text("[]", encoding="utf-8")
    candidate_file = candidate_dir / "candidate.bin"
    candidate_file.write_bytes(b"x" * 10)
    inspected = {"artifacts": {"candidate": str(candidate_file)}}
    from src.services.transform_preview.resolver import partition_range

    result = partition_range(
        inspected=inspected,
        source_sha256="source-sha",
        parent_sha256="parent-sha",
        range_offset=0,
        range_length=10,
        scope_sources=["full_decode_proof_spans"],
    )
    classes = [span["presentation_class"] for span in result["spans"]]
    assert classes == ["raw_plaintext", "preview_plaintext", "raw_plaintext"]
    assert len(result["descriptors"]) == 1
    assert result["conflicts"] == []


def test_partition_range_reports_overlap_conflicts(tmp_path: Path):
    candidate_dir = tmp_path / "candidate_root"
    candidate_dir.mkdir()
    proof_path = candidate_dir / "proof_spans.json"
    proof_path.write_text(
        json.dumps(
            [
                {"offset": 1, "length": 4, "scope_id": "scope-a", "proof_id": "proof-a", "provider_id": "test-provider"},
                {"offset": 3, "length": 4, "scope_id": "scope-b", "proof_id": "proof-b", "provider_id": "test-provider"},
            ]
        ),
        encoding="utf-8",
    )
    (candidate_dir / "inverse.json").write_text("[]", encoding="utf-8")
    candidate_file = candidate_dir / "candidate.bin"
    candidate_file.write_bytes(b"x" * 10)
    inspected = {"artifacts": {"candidate": str(candidate_file)}}
    from src.services.transform_preview.resolver import partition_range

    result = partition_range(
        inspected=inspected,
        source_sha256="source-sha",
        parent_sha256="parent-sha",
        range_offset=0,
        range_length=10,
        scope_sources=["full_decode_proof_spans"],
    )
    assert len(result["conflicts"]) == 1
    assert result["conflicts"][0]["kind"] == "overlapping_proof_span"


def test_replay_materialization_scopes_for_parent_role():
    from src.services.transform_preview.executor import replay_materialization_scopes

    opened = b"AAAAbbbbCCCC"
    parent = b"AAAAbbbbCCCC"
    source = b"AAAAXXXXCCCC"
    descriptors = [{"descriptor_id": "d1", "offset": 4, "length": 4, "steps": [{"step_id": "step-1"}]}]
    output, steps, diagnostics = replay_materialization_scopes(
        opened_slice=opened,
        parent_slice=parent,
        source_slice=source,
        descriptors=descriptors,
        identity_role="parent",
        range_offset=0,
    )
    assert output == b"AAAAXXXXCCCC"
    assert len(steps) == 1
    assert steps[0]["step_id"] == "step-1"
    assert diagnostics == []


def test_verify_inverse_replay_roundtrip():
    from src.services.transform_preview.executor import verify_inverse_replay

    parent = bytes.fromhex("0102030405060708")
    output = bytes.fromhex("aabbccddeeff0011")
    inverse = [
        {"offset": 0, "length": 4, "bytes_hex": "01020304"},
        {"offset": 4, "length": 4, "bytes_hex": "05060708"},
    ]
    check = verify_inverse_replay(
        output_slice=output,
        parent_slice=parent,
        inverse_entries=inverse,
        range_offset=0,
    )
    assert check["ok"] is True


def test_transform_preview_replays_descriptors_when_proof_spans_exist(tmp_path: Path, monkeypatch):
    source = tmp_path / "parent.bin"
    candidate = tmp_path / "candidate_root" / "candidate.bin"
    candidate.parent.mkdir()
    source.write_bytes(b"AAbbCCdd")
    candidate.write_bytes(b"AAXXCCdd")
    proof_path = candidate.parent / "proof_spans.json"
    proof_path.write_text(
        json.dumps(
            [{"offset": 2, "length": 2, "scope_id": "scope-a", "proof_id": "proof-a", "provider_id": "test-provider"}]
        ),
        encoding="utf-8",
    )
    (candidate.parent / "inverse.json").write_text("[]", encoding="utf-8")
    monkeypatch.setattr(
        "src.services.transform_preview.inspect._discover_lineage",
        lambda rail, source_sha, scan_limit: _discovery_with_candidate(tmp_path, source, candidate),
    )
    result = inspect_transform_preview(source, offset=0, length=8, mode="transform_preview", use_cache=False)
    assert result["output_bytes"] == b"AAXXCCdd"
    assert result["state"] == "verified_preview"
    assert len(result["chain_steps"]) == 1
    assert len(result["composite_spans"]) == 3


def test_mapping_marks_preview_spans_as_block():
    from src.services.transform_preview.mapping import aggregate_mapping, mappings_for_spans

    spans = [
        {"offset": 0, "length": 2, "presentation_class": "raw_plaintext"},
        {"offset": 2, "length": 2, "presentation_class": "preview_plaintext", "descriptor_id": "d1"},
    ]
    mappings = mappings_for_spans(spans=spans, range_offset=0, range_length=4)
    assert mappings[0]["kind"] == "one_to_one"
    assert mappings[0]["exact"] is True
    assert mappings[1]["kind"] == "block"
    assert mappings[1]["exact"] is False
    aggregate = aggregate_mapping(mappings, range_offset=0, output_length=4)
    assert aggregate["kind"] == "composite"
    assert len(aggregate["segments"]) == 2


def test_iter_full_file_preview_pages(tmp_path: Path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"0123456789")
    policy = load_transform_preview_policy()
    policy = dict(policy)
    policy["full_file_export"] = {"page_bytes": 4, "max_total_bytes": 10}
    pages = list(iter_full_file_preview(source, mode="raw", policy=policy))
    assert len(pages) == 3
    assert pages[0]["output_bytes"] == b"0123"
    assert pages[1]["offset"] == 4
    assert pages[2]["output_bytes"] == b"89"
