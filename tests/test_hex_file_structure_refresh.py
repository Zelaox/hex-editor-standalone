"""Regression tests for file structure, timecodes, and viewport status bar."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest


def test_update_status_bar_works_in_viewport_mode():
    from src.app import HexEditorApp

    app = HexEditorApp.__new__(HexEditorApp)
    app.hex_editor = MagicMock()
    app.hex_editor._document_mutation_active = False
    app.hex_editor.file_path = r"C:\sample.ptx"
    app.hex_editor.file_data = None
    app.hex_editor.file_size = 6_000_000
    app.hex_editor.bytes_per_line = 16
    app.hex_editor.get_selection.return_value = None
    app.main_window = MagicMock()
    app.main_window.hex_editor.textCursor.return_value = MagicMock(
        position=lambda: 0,
    )
    app.main_window.hex_editor.document.return_value.findBlock.return_value = MagicMock(
        blockNumber=lambda: 0,
        position=lambda: 0,
    )
    app.main_window.dock_is_visible.return_value = False
    app._text_inspector_timer = MagicMock()
    app._text_inspector_debounce_ms = 250

    app.update_status_bar()

    app.main_window.update_status_bar.assert_called_once()
    _, file_size, _ = app.main_window.update_status_bar.call_args[0]
    assert file_size == 6_000_000


def test_format_router_sniffs_ptx_session_header(tmp_path: Path):
    from src.runtime.format_router import detect_format_plugin

    sample = tmp_path / "candidate17.bin"
    sample.write_bytes(b"\x03" + b"\x00" * 20 + b"Pro Tools Session File\x00")
    assert detect_format_plugin(sample) == "ptx"


def test_finish_ptx_parse_emits_display_refresh():
    from src.hex_editor import HexEditor

    hex_editor = HexEditor.__new__(HexEditor)
    hex_editor._parse_generation = 1
    hex_editor.ptx_handler = None
    hex_editor.timecodes = []
    hex_editor.logger = MagicMock()
    hex_editor.display_refresh_requested = MagicMock()
    hex_editor.timecodes_found = MagicMock()

    handler = MagicMock()
    handler.timecodes = [{"offset": 0x84090, "value": "00:00:00:01", "type": "reference"}]
    hex_editor._finish_ptx_parse(1, handler, success=True)

    hex_editor.timecodes_found.emit.assert_called_once()
    hex_editor.display_refresh_requested.emit.assert_called_once()
    assert len(hex_editor.timecodes) == 1
