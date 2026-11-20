"""Tests for GUI forensic evidence presenter (no Qt required)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

INVESTIGATION = ROOT / "tests" / "fixtures" / "private" / "investigation"


def _minimal_snapshot(*, anchors=None, unknown=None):
    return {
        "snapshot_id": "test-snapshot",
        "format_plugin": "pe",
        "source": {"sha256": "abc", "size": 1024},
        "coverage_summary": {"total_bytes": 1024, "unknown_bytes": 512, "bytes_by_class": {"unknown": 512}},
        "anchors": anchors or [{"anchor_id": "a1", "kind": "string", "span": {"offset": 64, "length": 8}, "occurrence_count": 2, "evidence_level": "verified"}],
        "unknown_regions": unknown or [{"region_id": "u1", "span": {"offset": 256, "length": 128}, "classification": "unknown", "features": {"entropy": 7.1}, "neighbor_anchor_ids": ["a1"]}],
        "record_families": [{"family_id": "f1", "kind": "repeated_anchor_context", "support": 2, "evidence_level": "candidate", "anchor_ids": ["a1"]}],
        "coverage": [{"offset": 0, "length": 64, "class": "verified", "node_ids": ["n1"]}],
    }


def test_ui_policy_loads():
    from src.services.ui_policy import load_ui_policy, panel_columns, theme_color

    policy = load_ui_policy()
    assert policy["policy_id"] == "hex-editor-ui"
    assert "offset" in panel_columns(policy, "runtime_timecodes")
    assert theme_color(policy, "timecode.reference").startswith("#")


def test_presenter_builds_anchor_and_unknown_rows():
    from src.gui_evidence_presenter import present_anchor_rows, present_unknown_rows, present_coverage_rows

    snapshot = _minimal_snapshot()
    anchors = present_anchor_rows(snapshot)
    unknown = present_unknown_rows(snapshot)
    coverage = present_coverage_rows(snapshot)
    assert anchors[0]["offset"] == 64
    assert unknown[0]["offset"] == 256
    assert any(row[0] == "total_bytes" for row in coverage)


def test_hex_overlay_spans_from_snapshot():
    from src.gui_evidence_presenter import build_hex_overlay_spans
    from src.services.ui_policy import load_ui_policy, load_budget

    policy = load_ui_policy()
    cap = load_budget(policy, "max_forensic_overlay_spans")
    snapshot = _minimal_snapshot()
    assert build_hex_overlay_spans(snapshot=snapshot, policy=policy) == []

    enabled = dict(policy)
    flags = dict(enabled.get("feature_flags") or {})
    flags["hex_forensic_overlays"] = True
    enabled["feature_flags"] = flags
    overlays = dict(enabled.get("hex_overlays") or {})
    overlays["show_anchors"] = True
    enabled["hex_overlays"] = overlays
    spans = build_hex_overlay_spans(snapshot=snapshot, policy=enabled)
    assert len(spans) <= cap
    tokens = {item["theme_token"] for item in spans}
    assert tokens


def test_investigation_artifacts_when_present(investigation_copy):
    from src.gui_evidence_presenter import present_investigation_artifacts

    result = present_investigation_artifacts(investigation_copy)
    assert result["investigation_root"]
    assert isinstance(result["ledger_events"], list)


@pytest.fixture
def investigation_copy(tmp_path):
    if not INVESTIGATION.is_dir():
        pytest.skip("AC240 investigation unavailable")
    target = tmp_path / "inv"
    target.mkdir()
    for name in ("manifest.json", "state.json"):
        (target / name).write_text((INVESTIGATION / name).read_text(encoding="utf-8"), encoding="utf-8")
    layout_dir = target / "probe_ledger"
    layout_dir.mkdir()
    for rel in ("events.jsonl", "best_rejected.json", "derived_windows.json"):
        src = INVESTIGATION / "probe_ledger" / rel
        if src.is_file():
            (layout_dir / rel).write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    checkpoint_dir = target / "checkpoints"
    checkpoint_dir.mkdir(exist_ok=True)
    cp = INVESTIGATION / "checkpoints" / "probe_state.json"
    if cp.is_file():
        (checkpoint_dir / "probe_state.json").write_text(cp.read_text(encoding="utf-8"), encoding="utf-8")
    return target


def test_transform_scope_evidence_from_alternate_scope_run(tmp_path):
    from src.services.alternate_scope import run_alternate_scope_proof
    from src.gui_evidence_presenter import present_transform_scope_evidence

    ac240 = ROOT / "ac240.ptx"
    if ac240.is_file():
        source = ac240
    else:
        source = tmp_path / "sample.ptx"
        source.write_bytes(b"\x00" * 512 + b"\x01" * 256)
    policy = json.loads((ROOT / "config" / "alternate_scope_policy.json").read_text(encoding="utf-8"))
    policy_path = tmp_path / "policy.json"
    policy["budgets"]["maximum_descriptor_executions"] = 2
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    run = run_alternate_scope_proof(source, output_root=tmp_path / "runs", candidate_hex="94", boundary_hint=100, policy_path=policy_path)
    run_json = Path(run["run_root"]) / "run.json"
    evidence = present_transform_scope_evidence(run_json)
    assert "range_count" in evidence["summary"]
    assert "run_id" in evidence["summary"]


def test_build_forensic_context_integration(investigation_copy):
    from src.gui_evidence_presenter import build_forensic_context

    bundle = json.loads((investigation_copy / "manifest.json").read_text(encoding="utf-8"))
    snapshot = _minimal_snapshot()
    snapshot["source"]["sha256"] = str(bundle.get("source_sha256") or "abc")
    context = build_forensic_context(
        source_path=str(bundle.get("source_path") or "sample.ptx"),
        snapshot=snapshot,
        investigation_root=str(investigation_copy),
    )
    assert context["anchor_rows"]
    assert context["investigation"]["investigation_root"]
    assert isinstance(context["hex_overlay_spans"], list)


def test_no_hardcoded_gui_forbidden_literals():
    forbidden = ("ac240.ptx", "943d8d8b", "if offset ==", "0x94")
    for relative in (
        "src/gui_evidence_presenter.py",
        "src/services/ui_policy.py",
        "src/binary_inspector_widget.py",
    ):
        source = (ROOT / relative).read_text(encoding="utf-8")
        assert not any(token in source for token in forbidden)


def test_app_wiring_helpers_exist():
    from src.app import HexEditorApp

    assert hasattr(HexEditorApp, "_refresh_forensic_context")
    assert hasattr(HexEditorApp, "goto_offset_from_signal")
    assert hasattr(HexEditorApp, "analyze_current_binary")


def test_binary_semantic_graph_explorer_filters_and_navigates():
    from PyQt5.QtWidgets import QApplication
    from src.binary_inspector_widget import BinaryInspectorWidget
    from src.services.ui_policy import load_ui_policy

    app = QApplication.instance() or QApplication([])
    widget = BinaryInspectorWidget()
    assert hasattr(widget, "static_tabs")
    assert widget.static_tabs.count() == 17
    assert widget.static_tabs.currentIndex() == 0
    widget._select_static_section(2)
    assert widget.static_tabs.currentIndex() == 2
    snapshot = _minimal_snapshot()
    context = {
        "ui_policy": load_ui_policy(),
        "unresolved_inference": {
            "status": "partial_unresolved",
            "verified": True,
            "decision": {"unresolved_bytes": 3},
            "graph_summary": {"graph_id": "graph-test", "node_count": 2, "edge_count": 1, "validation": {"valid": True, "errors": []}},
            "graph_nodes": [
                {"node_id": "span", "node_type": "ByteSpan", "truth_state": "observed", "attributes": {"offset": 73, "length": 4}},
                {"node_id": "proof", "node_type": "OwnershipProof", "truth_state": "verified", "attributes": {}},
            ],
            "graph_edges": [{"edge_id": "edge", "edge_type": "supported_by", "source_id": "span", "target_id": "proof", "truth_state": "verified", "evidence_refs": ["evidence"]}],
            "ownership_proofs": [], "artifacts": {"semantic_graph": "graph.json"},
        },
    }
    widget.update_snapshot(snapshot, generation=1, forensic_context=context)
    assert widget.graph_nodes_table.rowCount() == 2
    assert "2 nodes" in widget.graph_banner.text()
    widget.graph_state_filter.setCurrentText("verified")
    app.processEvents()
    assert widget.graph_nodes_table.rowCount() == 1
    widget.graph_state_filter.setCurrentText("All")
    app.processEvents()
    widget.graph_nodes_table.selectRow(0)
    assert widget.graph_edges_table.rowCount() == 1


def test_binary_inspector_empty_state_has_recovery_action():
    from PyQt5.QtWidgets import QApplication
    from src.binary_inspector_widget import BinaryInspectorWidget

    app = QApplication.instance() or QApplication([])
    widget = BinaryInspectorWidget()
    assert "open or analyze" in widget.header.text().lower()
    assert widget.overview_table.rowCount() == 2
    assert widget.analyze_button.isEnabled()
    assert not widget.goto_button.isEnabled()


def test_snapshot_analysis_starts_even_when_inspector_hidden(monkeypatch):
    from types import SimpleNamespace

    from src.app import HexEditorApp

    controller = HexEditorApp.__new__(HexEditorApp)
    controller.main_window = SimpleNamespace(
        binary_inspector_widget=SimpleNamespace(clear=lambda: None),
        dock_is_visible=lambda _name: False,
        deliver_dock_update=lambda *_args, **_kwargs: None,
    )
    controller.snapshot_controller = SimpleNamespace(generation=1)
    controller._pending_forensic_timer = SimpleNamespace(stop=lambda: None)
    controller._cleanup_snapshot_thread = lambda: None
    controller._cleanup_forensic_thread = lambda: None
    controller._pending_binary_analysis = ("stale.exe", ".exe")

    started = {"ok": False}

    class FakeWorker:
        def __init__(self, *_args, **_kwargs):
            started["ok"] = True

        def moveToThread(self, *_args, **_kwargs):
            return None

    monkeypatch.setattr("src.app.SnapshotAnalysisWorker", FakeWorker)
    monkeypatch.setattr(
        "src.app.QThread",
        lambda: SimpleNamespace(
            started=SimpleNamespace(connect=lambda *_args, **_kwargs: None),
            start=lambda: None,
            finished=SimpleNamespace(connect=lambda *_args, **_kwargs: None),
        ),
    )
    monkeypatch.setattr("src.runtime.format_router.detect_format_plugin", lambda *_a, **_k: "pe")
    monkeypatch.setattr("src.runtime.config.load_binary_dynamic_config", lambda: {"pe_suffixes": [".exe"]})

    HexEditorApp._start_snapshot_analysis(controller, "file.exe", ".exe")
    assert started["ok"] is True
    assert controller._pending_binary_analysis is None


def test_hidden_binary_inspector_defers_forensic_work():
    from types import SimpleNamespace
    from src.app import HexEditorApp

    controller = HexEditorApp.__new__(HexEditorApp)
    controller.main_window = SimpleNamespace(
        binary_inspector_widget=object(),
        dock_is_visible=lambda _name: False,
    )
    HexEditorApp._start_deferred_forensic_context(
        controller,
        "generic.ptx",
        {"snapshot_id": "snapshot", "source": {"sha256": "digest"}},
        7,
    )
    assert controller._pending_forensic_payload["generation"] == 7
    assert not hasattr(controller, "_forensic_thread")
