from __future__ import annotations

from PyQt5.QtGui import QPalette
from PyQt5.QtWidgets import QApplication

from src.ui import HexEditorMainWindow


def test_dark_mode_styles_native_qt_controls():
    app = QApplication.instance() or QApplication([])
    window = HexEditorMainWindow()
    window.toggle_dark_mode(True)
    stylesheet = QApplication.instance().styleSheet()
    assert "QMenuBar" in stylesheet
    assert "QTabBar::tab" in stylesheet
    assert "QHeaderView::section" in stylesheet
    assert "QPushButton:disabled" in stylesheet
    palette = QApplication.palette()
    assert palette.color(QPalette.Window).lightness() < palette.color(QPalette.WindowText).lightness()
    window.toggle_dark_mode(False)
    assert QApplication.instance().styleSheet() == ""
    window.close()
    assert app is not None
