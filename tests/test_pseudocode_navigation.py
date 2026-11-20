from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

from PyQt5.QtWidgets import QApplication, QPlainTextEdit

from src.services.region_routed_pseudocode import render_region_routed_bundle
from src.services.region_routed_pseudocode.navigation import ranges_for_selection
from src.services.region_routed_pseudocode.navigation import navigation_generation_matches
from src.services.region_routed_pseudocode.policies import load_pseudocode_navigation_policy
from src.services.region_routed_pseudocode.source_map_build import entry_file_offset


def test_disjoint_selection_ranges_do_not_merge_gap():
    nav = load_pseudocode_navigation_policy()
    source_map = [
        {"ir_id": "a", "line_start": 10, "line_end": 10, "file_offset": 0x12F00, "offset": 0x12F00, "length": 7, "producer_id": "decompiler"},
        {"ir_id": "b", "line_start": 20, "line_end": 20, "file_offset": 0x13A5C, "offset": 0x13A5C, "length": 16, "producer_id": "unknown"},
    ]
    result = ranges_for_selection(source_map, start_line=10, end_line=20, navigation_policy=nav)
    assert result is not None
    assert len(result["ranges"]) == 2
    offsets = sorted(int(item["file_offset"]) for item in result["ranges"])
    assert offsets == [0x12F00, 0x13A5C]
    assert int(result["anchor_file_offset"]) == 0x12F00
    assert not any(item["length"] > 100 for item in result["ranges"])


def test_legacy_untyped_va_resolution_maps_before_goto():
    import os

    windir = os.environ.get("SystemRoot") or r"C:\Windows"
    candidate = Path(windir) / "System32" / "notepad.exe"
    if not candidate.is_file():
        import pytest

        pytest.skip("no system PE")
    from src.services.region_routed_pseudocode.address_resolve import resolve_raw_to_file_offset
    from src.services.region_routed_pseudocode.policies import load_pseudocode_navigation_policy

    nav = load_pseudocode_navigation_policy()
    file_size = candidate.stat().st_size
    va = 0x140001000
    resolved = resolve_raw_to_file_offset(
        va,
        file_size=file_size,
        source_path=candidate,
        navigation_policy=nav,
    )
    if resolved is None:
        va = 0x100401000
        resolved = resolve_raw_to_file_offset(
            va,
            file_size=file_size,
            source_path=candidate,
            navigation_policy=nav,
        )
    assert resolved is not None
    assert resolved[0] < file_size


def test_explicit_virtual_address_never_shortcuts_to_same_numeric_file_offset(monkeypatch, tmp_path):
    from src.services.region_routed_pseudocode import address_resolve

    source = tmp_path / "typed-coordinate.exe"
    source.write_bytes(b"MZ" + (b"\x00" * 0x3FE))
    monkeypatch.setattr(
        address_resolve,
        "_load_pe_resolver",
        lambda _module: lambda _path, _value: 0x180,
    )
    nav = load_pseudocode_navigation_policy()

    va_result = address_resolve.resolve_coordinate_to_file_offset(
        0x20,
        coordinate_space="virtual_address",
        file_size=source.stat().st_size,
        source_path=source,
        navigation_policy=nav,
    )
    file_result = address_resolve.resolve_coordinate_to_file_offset(
        0x20,
        coordinate_space="file_offset",
        file_size=source.stat().st_size,
        source_path=source,
        navigation_policy=nav,
    )

    assert va_result == (0x180, 1)
    assert file_result == (0x20, 1)


def test_clicked_va_token_uses_va_mapping_not_file_comment(monkeypatch):
    import src.services.region_routed_pseudocode.navigation as navigation

    line = "/* va=0x20 file=0x88 */ mov eax, ebx;"

    def resolve(value, *, coordinate_space, **_kwargs):
        if coordinate_space == "virtual_address":
            return 0x44, 1
        return int(value), 1

    monkeypatch.setattr(navigation, "resolve_coordinate_to_file_offset", resolve)
    result = ranges_for_selection(
        [],
        start_line=0,
        end_line=0,
        navigation_policy=load_pseudocode_navigation_policy(),
        line_texts=[line],
        file_size=0x1000,
        selection_start_column=line.index("va=") + len("va=0x"),
    )

    assert result is not None
    assert result["anchor_file_offset"] == 0x44
    assert result["anchor_source_coordinate"] == {
        "coordinate_space": "virtual_address",
        "value": 0x20,
    }


def test_parser_first_beats_coarse_region_entry():
    nav = load_pseudocode_navigation_policy()
    line = "    unresolved byte data_0x336F0[16] = { 0x00 };"
    source_map = [
        {
            "ir_id": "region-gap",
            "line_start": 0,
            "line_end": 9999,
            "file_offset": 0,
            "offset": 0,
            "length": 0x40000,
            "producer_id": "unknown",
        }
    ]
    result = ranges_for_selection(
        source_map,
        start_line=0,
        end_line=0,
        navigation_policy=nav,
        line_texts=[line],
        file_size=0x50000,
    )
    assert result is not None
    assert result["anchor_file_offset"] == 0x336F0


def test_semantic_cluster_header_maps_to_its_first_occurrence(tmp_path):
    sample = tmp_path / "semantic-clusters.bin"
    repeated = b"d_Post Gain 2"
    sample.write_bytes(repeated + b"\x00prefix\x00" + repeated + b"\x00")

    bundle = render_region_routed_bundle(sample)
    lines = list(bundle["lines"])
    header_line = next(
        index for index, text in enumerate(lines)
        if "verified repeated_semantic_cluster" in text
    )
    occurrence_line = next(
        index for index in range(header_line, len(lines))
        if ".offset = 0x" in lines[index]
    )
    occurrence_offset = int(lines[occurrence_line].split(".offset = 0x", 1)[1].split("ULL", 1)[0], 16)

    result = ranges_for_selection(
        bundle["source_map"],
        start_line=header_line,
        end_line=occurrence_line - 1,
        navigation_policy=load_pseudocode_navigation_policy(),
        line_texts=lines,
        file_size=sample.stat().st_size,
        source_path=sample,
    )

    assert result is not None
    assert result["anchor_file_offset"] == occurrence_offset
    assert result["ranges"] == [{"file_offset": occurrence_offset, "length": len(repeated)}]


def test_data_parser_beats_stale_out_of_range_byte_marker():
    nav = load_pseudocode_navigation_policy()
    line = "/* @byte:0x1400010EC */ unresolved byte data_0xEC[4] = { 0x00 };"
    result = ranges_for_selection(
        [],
        start_line=0,
        end_line=0,
        navigation_policy=nav,
        line_texts=[line],
        file_size=0x1000,
    )
    assert result is not None
    assert result["anchor_file_offset"] == 0xEC
    assert result["ranges"] == [{"file_offset": 0xEC, "length": 4}]


def test_parse_unresolved_byte_line():
    nav = load_pseudocode_navigation_policy()
    line = "    unresolved byte data_0x13200[16] = { 0x00 };"
    result = ranges_for_selection(
        [],
        start_line=0,
        end_line=0,
        navigation_policy=nav,
        line_texts=[line],
    )
    assert result is not None
    assert result["ranges"][0]["file_offset"] == 0x13200
    assert result["ranges"][0]["length"] == 16


def test_pe_decompiler_sub_map_uses_file_offset():
    windir = os.environ.get("SystemRoot") or r"C:\Windows"
    candidate = Path(windir) / "System32" / "notepad.exe"
    if not candidate.is_file():
        import pytest

        pytest.skip("no system PE")
    bundle = render_region_routed_bundle(candidate)
    file_size = int((bundle["region_map_document"].get("source") or {}).get("size") or 0)
    insn_entries = [
        entry
        for entry in bundle["source_map"]
        if entry.get("producer_id") == "decompiler" and "-insn-" in str(entry.get("ir_id") or "")
    ]
    assert insn_entries
    for entry in insn_entries:
        off = entry_file_offset(entry)
        assert off < file_size


def test_byte_marker_matches_file_offset_in_text():
    windir = os.environ.get("SystemRoot") or r"C:\Windows"
    candidate = Path(windir) / "System32" / "notepad.exe"
    if not candidate.is_file():
        import pytest

        pytest.skip("no system PE")
    bundle = render_region_routed_bundle(candidate)
    lines = bundle["lines"]
    for entry in bundle["source_map"]:
        if "-insn-" in str(entry.get("ir_id") or ""):
            line_no = int(entry.get("line_start") or 0)
            if 0 <= line_no < len(lines):
                text = lines[line_no]
                if "@byte:" in text:
                    marker_part = text.split("@byte:")[1].split()[0]
                    marker_val = int(marker_part.rstrip("*/"), 16)
                    assert marker_val == entry_file_offset(entry)
                    assert marker_val < int((bundle["region_map_document"].get("source") or {}).get("size") or 0)
            break


def test_generation_guard_uses_file_identity_without_click_time_hashing(tmp_path):
    nav = load_pseudocode_navigation_policy()
    source = tmp_path / "sample.bin"
    source.write_bytes(b"navigation")
    stored = {
        "source_path": str(source),
        "source_sha256": "render-time-hash",
        "region_map_digest": "render-time-map",
    }
    same_file = {
        "source_path": str(source.resolve()),
        "source_sha256": "different-value-is-not-checked-on-click",
        "region_map_digest": "different-value-is-not-checked-on-click",
    }
    other = tmp_path / "other.bin"
    other.write_bytes(b"navigation")

    assert navigation_generation_matches(stored, same_file, navigation_policy=nav)
    assert not navigation_generation_matches(
        stored,
        {**same_file, "source_path": str(other)},
        navigation_policy=nav,
    )


def test_gui_navigation_finishes_on_mapped_va_target_after_highlight_render(tmp_path, monkeypatch):
    from src.app import HexEditorApp
    from src.hex_editor import HexEditor
    import src.services.region_routed_pseudocode.navigation as navigation
    from src.utils import FileCache, bytes_to_hex_view

    qt_app = QApplication.instance() or QApplication([])
    source = tmp_path / "navigation.bin"
    data = bytes(range(256)) * 16
    source.write_bytes(data)

    hex_widget = QPlainTextEdit()
    hex_editor = HexEditor(hex_widget)
    hex_editor._hex_view_mode = "full"
    hex_editor.file_path = str(source)
    hex_editor.file_size = len(data)
    hex_editor.file_data = data
    hex_editor.file_cache = FileCache(str(source))
    hex_editor._apply_hex_text(bytes_to_hex_view(data), restore_scroll=False)

    pseudocode = QPlainTextEdit()
    line = "/* va=0x200 file=0x400 */ mov eax, ebx;"
    pseudocode.setPlainText(line)
    pseudocode_cursor = pseudocode.textCursor()
    pseudocode_cursor.setPosition(line.index("va=") + len("va=0x"))
    pseudocode.setTextCursor(pseudocode_cursor)

    real_resolver = navigation.resolve_coordinate_to_file_offset

    def resolve(value, *, coordinate_space, **kwargs):
        if coordinate_space == "virtual_address":
            return 0x400, 1
        return real_resolver(value, coordinate_space=coordinate_space, **kwargs)

    monkeypatch.setattr(navigation, "resolve_coordinate_to_file_offset", resolve)

    class StatusBar:
        def __init__(self):
            self.messages = []

        def showMessage(self, message, _timeout):
            self.messages.append(message)

    status = StatusBar()
    controller = HexEditorApp.__new__(HexEditorApp)
    controller.main_window = SimpleNamespace(
        pseudocode_text=pseudocode,
        statusBar=lambda: status,
    )
    controller.hex_editor = hex_editor
    controller.disassembly_thread = None
    controller._pseudocode_source_map = [{
        "ir_id": "coarse-region",
        "line_start": 0,
        "line_end": 0,
        "file_offset": 0,
        "length": len(data),
        "producer_id": "unknown",
    }]
    controller._pseudocode_source_map_error = ""
    controller._pseudocode_navigation_generation = {"source_path": str(source)}
    controller._nav_sync_in_progress = False
    controller._nav_suppress_hex_to_pseudo = False

    HexEditorApp._sync_pseudocode_to_hex(controller)

    assert hex_editor.get_cursor_byte_offset() == 0x400
    assert hex_widget.textCursor().selectedText() == "00"
    assert hex_editor._pseudocode_navigation_spans == [(0x400, 1)]
    assert status.messages and "mapped VA 0x200 to file offset 0x400" in status.messages[-1]

    hex_editor.close()
    hex_widget.close()
    pseudocode.close()
    qt_app.processEvents()


def test_gui_cluster_selection_jumps_to_cluster_occurrence_not_region_start(tmp_path):
    from src.app import HexEditorApp
    from src.hex_editor import HexEditor
    from src.utils import FileCache, bytes_to_hex_view

    qt_app = QApplication.instance() or QApplication([])
    source = tmp_path / "cluster-navigation.bin"
    repeated = b"d_Post Gain 2"
    data = (b"\x00" * 0x100) + repeated + b"\x00prefix\x00" + repeated + b"\x00"
    source.write_bytes(data)
    bundle = render_region_routed_bundle(source)
    lines = list(bundle["lines"])
    header_line = next(i for i, text in enumerate(lines) if "verified repeated_semantic_cluster" in text)
    preview_line = next(i for i in range(header_line, len(lines)) if ".preview =" in lines[i])

    hex_widget = QPlainTextEdit()
    hex_editor = HexEditor(hex_widget)
    hex_editor._hex_view_mode = "full"
    hex_editor.file_path = str(source)
    hex_editor.file_size = len(data)
    hex_editor.file_data = data
    hex_editor.file_cache = FileCache(str(source))
    hex_editor._apply_hex_text(bytes_to_hex_view(data), restore_scroll=False)

    pseudocode = QPlainTextEdit()
    pseudocode.setPlainText("\n".join(lines))
    cursor = pseudocode.textCursor()
    start_block = pseudocode.document().findBlockByNumber(header_line)
    end_block = pseudocode.document().findBlockByNumber(preview_line)
    cursor.setPosition(start_block.position())
    cursor.setPosition(end_block.position() + end_block.length() - 1, cursor.KeepAnchor)
    pseudocode.setTextCursor(cursor)

    class StatusBar:
        def __init__(self):
            self.messages = []

        def showMessage(self, message, _timeout):
            self.messages.append(message)

    status = StatusBar()
    controller = HexEditorApp.__new__(HexEditorApp)
    controller.main_window = SimpleNamespace(pseudocode_text=pseudocode, statusBar=lambda: status)
    controller.hex_editor = hex_editor
    controller.disassembly_thread = None
    controller._pseudocode_source_map = list(bundle["source_map"])
    controller._pseudocode_source_map_error = ""
    controller._pseudocode_navigation_generation = {"source_path": str(source)}
    controller._nav_sync_in_progress = False
    controller._nav_suppress_hex_to_pseudo = False

    HexEditorApp._sync_pseudocode_to_hex(controller)

    assert hex_editor.get_cursor_byte_offset() == 0x100
    assert hex_editor._pseudocode_navigation_spans == [(0x100, len(repeated))]
    assert status.messages and "file offset 0x100" in status.messages[-1]

    hex_editor.close()
    hex_widget.close()
    pseudocode.close()
    qt_app.processEvents()


def test_gui_navigation_reports_stale_source_path(tmp_path):
    from src.app import HexEditorApp

    qt_app = QApplication.instance() or QApplication([])
    loaded = tmp_path / "loaded.bin"
    rendered = tmp_path / "rendered.bin"
    loaded.write_bytes(b"loaded")
    rendered.write_bytes(b"rendered")
    pseudocode = QPlainTextEdit()
    pseudocode.setPlainText("unresolved byte data_0x1[1] = { 0x00 };")

    class StatusBar:
        def __init__(self):
            self.messages = []

        def showMessage(self, message, _timeout):
            self.messages.append(message)

    status = StatusBar()
    controller = HexEditorApp.__new__(HexEditorApp)
    controller.main_window = SimpleNamespace(pseudocode_text=pseudocode, statusBar=lambda: status)
    controller.hex_editor = SimpleNamespace(file_path=str(loaded), file_size=loaded.stat().st_size)
    controller.disassembly_thread = None
    controller._pseudocode_source_map = [{
        "ir_id": "line-entry", "line_start": 0, "line_end": 0,
        "file_offset": 1, "length": 1, "producer_id": "unknown",
    }]
    controller._pseudocode_source_map_error = ""
    controller._pseudocode_navigation_generation = {"source_path": str(rendered)}
    controller._nav_sync_in_progress = False
    controller._nav_suppress_hex_to_pseudo = False

    HexEditorApp._sync_pseudocode_to_hex(controller)

    assert status.messages
    assert "different loaded file" in status.messages[-1]
    pseudocode.close()
    qt_app.processEvents()
