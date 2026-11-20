from __future__ import annotations

from pathlib import Path

from src.services.semantic_pseudocode import (
    load_semantic_pseudocode_policy,
    render_semantic_graph,
    render_semantic_pseudocode_for_path,
)


def test_policy_is_schema_valid():
    policy = load_semantic_pseudocode_policy()
    assert policy["policy_id"] == "semantic-pseudocode-view"


def test_renderer_preserves_truth_ranges_and_attributes():
    graph = {
        "graph_id": "graph-test",
        "nodes": [
            {
                "node_id": "span-a",
                "node_type": "ByteSpan",
                "truth_state": "verified",
                "attributes": {"offset": 8, "length": 2, "value": 5},
            },
            {
                "node_id": "rejected",
                "node_type": "Representation",
                "truth_state": "falsified",
                "attributes": {},
            },
        ],
    }
    rendered = "\n".join(render_semantic_graph(graph, source_bytes=b"01234567\x05\x06"))
    assert "verified byte ByteSpan_span_a[2]" in rendered
    assert "0x05, 0x06" in rendered
    assert "rejected" not in rendered


def test_verified_plaintext_renders_as_escaped_text_and_binary_stays_bytes():
    graph = {
        "graph_id": "graph-text",
        "nodes": [
            {"node_id": "plain", "node_type": "CoverageSegment", "truth_state": "verified", "attributes": {"offset": 0, "length": 12, "class": "verified_plaintext"}},
            {"node_id": "binary", "node_type": "CoverageSegment", "truth_state": "verified", "attributes": {"offset": 12, "length": 2, "class": "preserved_binary"}},
        ],
    }
    rendered = "\n".join(render_semantic_graph(graph, source_bytes=b"d_Control 24\x94\x05"))
    assert 'verified semantic_plaintext const char span_0x0_plain[] = "d_Control 24";' in rendered
    assert "verified byte preserved_binary_binary[2]" in rendered
    assert "0x94, 0x05" in rendered


def test_default_full_view_does_not_omit_span_bytes():
    payload = bytes(range(80))
    graph = {
        "graph_id": "graph-full",
        "nodes": [
            {"node_id": "all", "node_type": "CoverageSegment", "truth_state": "verified", "attributes": {"offset": 0, "length": len(payload), "class": "preserved_binary"}},
        ],
    }
    rendered = "\n".join(render_semantic_graph(graph, source_bytes=payload))
    assert "omitted by policy" not in rendered
    assert "0x00" in rendered
    assert "0x4F" in rendered


def test_no_graph_fallback_is_explicitly_unresolved(tmp_path: Path, monkeypatch):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"\x00\x01\x02")
    monkeypatch.setattr("src.services.semantic_pseudocode._verified_graph_for_path", lambda path, policy: None)
    rendered = "\n".join(render_semantic_pseudocode_for_path(sample))
    assert "unresolved byte data_0x0[3] = { 0x00, 0x01, 0x02 };" in rendered
    assert "Semantic structure unavailable" in rendered
    assert "semantic plaintext" in rendered or "semantic_plaintext" in rendered


def test_fallback_plaintext_tiers_distinguish_semantic_from_representation(tmp_path: Path, monkeypatch):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"\x00")
    monkeypatch.setattr("src.services.semantic_pseudocode._verified_graph_for_path", lambda path, policy: None)
    monkeypatch.setattr(
        "src.services.semantic_pseudocode._full_decode_plaintext_segments",
        lambda path, cfg: [
            {"offset": 0, "length": 17, "class": "verified_plaintext"},
            {"offset": 32, "length": 16, "class": "verified_plaintext"},
        ],
    )
    payload = b"Pro tools projekt" + (b"\x00" * 15) + b"&&&&&&&&&&&&&&&&"
    sample.write_bytes(payload)
    rendered = "\n".join(render_semantic_pseudocode_for_path(sample))
    assert "verified semantic_plaintext" in rendered
    assert "verified verified_printable_bytes" in rendered
    assert "coverage_class=verified_plaintext" in rendered


def test_plaintext_clusters_render_as_c_structs(tmp_path: Path, monkeypatch):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"d_Post Gain 2\x00d_Post Gain 2\x00")
    monkeypatch.setattr("src.services.semantic_pseudocode._verified_graph_for_path", lambda path, policy: None)
    monkeypatch.setattr("src.services.semantic_pseudocode._full_decode_plaintext_segments", lambda path, cfg: [])
    rendered = "\n".join(render_semantic_pseudocode_for_path(sample))
    assert "struct repeated_plaintext_cluster cluster_1 = {" in rendered
    assert "repeated_semantic_cluster" in rendered
    assert "struct byte_span cluster_1_occurrences[2] = {" in rendered
    assert "plaintext_cluster cluster_N @ {" not in rendered


def test_disassembler_routes_non_pe_to_semantic_pseudocode(tmp_path: Path, monkeypatch):
    from src.disassembler import DisassemblerWorker

    sample = tmp_path / "arbitrary.data"
    sample.write_bytes(b"not a portable executable")
    monkeypatch.setattr("src.services.semantic_pseudocode._verified_graph_for_path", lambda path, policy: None)
    completed, failed = [], []
    worker = DisassemblerWorker(str(sample), {})
    worker.disassembly_finished.connect(lambda *parts: completed.append(parts))
    worker.disassembly_failed.connect(failed.append)
    worker.run()
    assert not failed
    assert completed
    assert any("unresolved byte data_0x" in line for line in completed[0][1])
