from PyQt5.QtWidgets import QApplication, QPlainTextEdit

from src.hex_editor import HexEditor
from src.utils import bytes_to_hex_view


def test_goto_offset_uses_grouped_hex_layout_and_selects_target_byte():
    app = QApplication.instance() or QApplication([])
    widget = QPlainTextEdit()
    editor = HexEditor(widget)
    editor.file_data = bytes(range(64))
    editor.file_size = len(editor.file_data)
    editor._apply_hex_text(bytes_to_hex_view(editor.file_data), restore_scroll=False)

    assert editor.goto_offset(0x2D) is True

    cursor = widget.textCursor()
    assert cursor.selectedText() == "2D"
    assert editor.get_cursor_byte_offset() == 0x2D
    assert cursor.blockNumber() == 2

    editor.close()
    widget.close()
    app.processEvents()


def test_goto_offset_uses_absolute_document_line_after_centering_full_view():
    app = QApplication.instance() or QApplication([])
    widget = QPlainTextEdit()
    widget.resize(900, 360)
    editor = HexEditor(widget)
    editor._hex_view_mode = "full"
    editor.file_data = bytes(range(256)) * 16
    editor.file_size = len(editor.file_data)
    editor._apply_hex_text(bytes_to_hex_view(editor.file_data), restore_scroll=False)

    target = 0x400
    assert target // editor.bytes_per_line > editor._viewport_line_count() // 2
    assert editor.goto_offset(target) is True

    cursor = widget.textCursor()
    assert cursor.selectedText() == f"{editor.file_data[target]:02X}"
    assert editor.get_cursor_byte_offset() == target
    assert cursor.blockNumber() == target // editor.bytes_per_line

    editor.close()
    widget.close()
    app.processEvents()


def test_hex_columns_include_renderer_group_spacing():
    app = QApplication.instance() or QApplication([])
    editor = HexEditor(QPlainTextEdit())

    assert editor._hex_column_for_byte(0) == 11
    assert editor._hex_column_for_byte(4) == 24
    assert editor._hex_column_for_byte(15) == 59

    editor.close()
    app.processEvents()
