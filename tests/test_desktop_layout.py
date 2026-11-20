"""Tests for desktop layout persistence."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def test_ui_policy_declares_layout_persistence():
    from src.services.ui_policy import load_ui_policy

    policy = load_ui_policy()
    persistence = policy["desktop_persistence"]
    assert persistence["settings_organization"]
    assert persistence["settings_application"]
    assert persistence["layout_autosave_debounce_ms"] > 0
    assert persistence["main_window_object_name"]
    assert persistence["main_toolbar_object_name"]
    assert isinstance(policy["dock_defaults"], dict)
    hints = policy["dock_layout_hints"]["binary_inspector_dock"]
    assert hints["static_section_nav"]["orientation"] == "horizontal"
    assert hints["static_section_nav"]["nav_mode"] == "tab_widget"


def test_binary_inspector_stays_floating_when_user_floats():
    from PyQt5.QtWidgets import QApplication

    from src.services.ui_policy import load_ui_policy
    from src.ui import HexEditorMainWindow

    app = QApplication.instance() or QApplication([])
    policy = load_ui_policy()
    window = HexEditorMainWindow()
    window.create_dock_widgets()
    window.install_layout_persistence(policy)
    window.resize(1400, 900)
    window.show()
    app.processEvents()
    dock = window.binary_inspector_dock
    dock.setVisible(True)
    dock.setFloating(True)
    app.processEvents()
    assert dock.isFloating() is True
    dock.setVisible(True)
    app.processEvents()
    assert dock.isFloating() is True


def test_toolbar_object_name_before_layout_save():
    from PyQt5.QtWidgets import QApplication

    from src.services.ui_policy import load_ui_policy
    from src.ui import HexEditorMainWindow

    app = QApplication.instance() or QApplication([])
    policy = load_ui_policy()
    window = HexEditorMainWindow()
    window.create_dock_widgets()
    window.create_toolbar()
    window.create_menu_bar()
    window.install_layout_persistence(policy)
    assert window.toolbar.objectName() == policy["desktop_persistence"]["main_toolbar_object_name"]
    window.saveState()


def test_all_docks_have_object_names():
    from PyQt5.QtWidgets import QApplication

    from src.ui import HexEditorMainWindow

    app = QApplication.instance() or QApplication([])
    window = HexEditorMainWindow()
    window.create_dock_widgets()
    window.create_menu_bar()
    expected = {
        "disassembly_dock",
        "pseudocode_dock",
        "text_inspector_dock",
        "symbols_dock",
        "bookmarks_dock",
        "search_results_dock",
        "file_structure_dock",
        "runtime_overview_dock",
        "binary_inspector_dock",
    }
    actual = {
        child.objectName()
        for child in window.findChildren(type(window.disassembly_dock))
    }
    assert expected.issubset(actual)


def test_layout_roundtrip(tmp_path, monkeypatch):
    from PyQt5.QtCore import QSettings
    from PyQt5.QtWidgets import QApplication

    from src.services.desktop_layout import restore_layout, save_layout
    from src.services.ui_policy import load_ui_policy
    from src.ui import HexEditorMainWindow

    QSettings.setDefaultFormat(QSettings.IniFormat)
    QSettings.setPath(QSettings.IniFormat, QSettings.UserScope, str(tmp_path))

    policy = load_ui_policy()
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    app = QApplication.instance() or QApplication([])

    window = HexEditorMainWindow()
    window.create_dock_widgets()
    window.create_menu_bar()
    window.install_layout_persistence(policy)
    window.resize(1400, 900)
    window.show()
    app.processEvents()
    window.binary_inspector_dock.setVisible(True)
    window.file_structure_dock.setVisible(False)
    app.processEvents()

    save_layout(window, policy)
    assert restore_layout(window, policy) is True

    window2 = HexEditorMainWindow()
    window2.create_dock_widgets()
    window2.create_menu_bar()
    window2.show()
    app.processEvents()
    restored = restore_layout(window2, policy)
    app.processEvents()
    assert restored is True
    assert window2.binary_inspector_dock.isVisible() is True
    assert window2.file_structure_dock.isVisible() is False
