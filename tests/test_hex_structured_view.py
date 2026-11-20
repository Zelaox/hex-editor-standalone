"""Tests for hex structured view plan — overlay engine, pair diff, invariants."""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def test_app_does_not_import_pytest_fixture_loader():
    app_path = ROOT / "src" / "app.py"
    tree = ast.parse(app_path.read_text(encoding="utf-8"))
    imports = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imports.update(
        f"{node.module}.{alias.name}" if node.module else alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        for alias in node.names
    )
    assert "src.services.hex_regression_fixtures" not in imports


def test_ui_policy_incremental_overlay_mode():
    from src.services.ui_policy import load_ui_policy

    policy = load_ui_policy()
    assert policy["load_budgets"]["hex_overlay_apply_mode"] == "incremental"
    assert "show_pair_diff" not in policy["hex_overlays"]


def test_pair_diff_spans_merge_runs():
    from src.services.binary_byte_diff import build_pair_diff_spans, count_changed_bytes
    from src.services.ui_policy import load_ui_policy

    source = bytes([0, 0, 1, 1, 2, 2])
    candidate = bytes([0, 1, 1, 1, 2, 3])
    policy = load_ui_policy()
    spans = build_pair_diff_spans(source, candidate, policy=policy)
    assert count_changed_bytes(source, candidate) == 2
    assert spans
    assert all("theme_token" in span for span in spans)


def test_legacy_fixture_bundle_resolves(tmp_path, monkeypatch):
    from src.services.hex_regression_fixtures import resolve_bundle
    from src.services import hex_regression_fixtures
    from src.services.binary_byte_diff import count_changed_bytes

    (tmp_path / 'source.ptx').write_bytes(bytes(range(64)))
    (tmp_path / 'candidate.ptx').write_bytes(b'X' + bytes(range(1, 64)))
    monkeypatch.setattr(hex_regression_fixtures, 'load_fixture_registry', lambda: {
        'pytest_only': True, 'fixture_bundles': [{'bundle_id': 'synthetic',
        'bundle_role': 'legacy_materialized_decode', 'root': str(tmp_path),
        'files': {'source_ptx': 'source.ptx', 'decrypt_candidate_ptx': 'candidate.ptx'}}]})
    bundle = resolve_bundle("synthetic")
    assert bundle["bundle_role"] == "legacy_materialized_decode"
    source = Path(bundle["source_path"]).read_bytes()
    candidate = Path(bundle["candidate_path"]).read_bytes()
    assert len(source) == len(candidate)
    assert count_changed_bytes(source, candidate) > 0


@pytest.mark.skipif(
    not any(
        Path(__file__).resolve().parents[2].joinpath("data", "artifacts", "hex_editor").rglob("*.manifest.json")
    ),
    reason="no materialization manifests in lab artifact store",
)
def test_bounded_fixture_or_manifest_role():
    from src.services.hex_regression_fixtures import resolve_bundle
    from src.services.binary_byte_diff import count_changed_bytes

    bundle = resolve_bundle("ac240_bounded_scope_378")
    assert bundle["bundle_role"] == "bounded_scope_candidate"
    manifest = dict(bundle.get("manifest") or {})
    if manifest:
        expected = int(manifest.get("changed_bytes") or 0)
        source = Path(bundle["source_path"]).read_bytes()
        candidate = Path(bundle["candidate_path"]).read_bytes()
        assert count_changed_bytes(source, candidate) == expected


def test_overlay_refresh_preserves_document_epoch():
    from PyQt5.QtWidgets import QApplication, QPlainTextEdit

    app = QApplication.instance() or QApplication([])
    text_edit = QPlainTextEdit()
    from src.hex_editor import HexEditor
    from src.services.ui_policy import load_ui_policy

    editor = HexEditor(text_edit)
    editor.configure_ui_policy(load_ui_policy())
    ptx = ROOT / "1ac240.ptx"
    if not ptx.is_file():
        pytest.skip("1ac240.ptx unavailable")
    assert editor.load_file(str(ptx)) is True
    for _ in range(300):
        app.processEvents()
        if editor.file_data:
            break
    assert editor.file_data, "hex load did not finish"
    before_epoch = editor.document_content_epoch()
    before_line = editor._document_top_line()
    editor.set_forensic_overlay_spans(
        [{"offset": 256, "length": 16, "theme_token": "anchor.verified", "role": "anchor", "priority": 0}]
    )
    assert editor.document_content_epoch() == before_epoch
    assert editor._document_top_line() == before_line
