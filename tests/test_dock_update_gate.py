"""Tests for visibility-gated dock updates."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def test_floating_dock_applies_immediately():
    from PyQt5.QtWidgets import QApplication, QDockWidget, QLabel, QMainWindow

    from src.services.dock_update_gate import DockUpdateRegistry, dock_panel_shown

    app = QApplication.instance() or QApplication([])
    window = QMainWindow()
    dock = QDockWidget("Panel", window)
    dock.setObjectName("test_dock")
    dock.setWidget(QLabel("content"))
    window.addDockWidget(1, dock)
    window.show()
    dock.setFloating(True)
    app.processEvents()
    assert dock_panel_shown(dock) is True

    registry = DockUpdateRegistry(window)
    registry.register(dock)
    applied = {"count": 0}
    registry.deliver("test_dock", lambda: applied.__setitem__("count", applied["count"] + 1))
    assert applied["count"] == 1


def test_hidden_dock_defers_until_reopened():
    from PyQt5.QtWidgets import QApplication, QDockWidget, QLabel, QMainWindow

    from src.services.dock_update_gate import DockUpdateRegistry

    app = QApplication.instance() or QApplication([])
    window = QMainWindow()
    dock = QDockWidget("Panel", window)
    dock.setObjectName("test_dock")
    dock.setWidget(QLabel("content"))
    window.addDockWidget(1, dock)
    window.show()
    app.processEvents()

    registry = DockUpdateRegistry(window)
    registry.register(dock)
    dock.setVisible(False)
    app.processEvents()

    applied = {"count": 0}

    def apply() -> None:
        applied["count"] += 1

    registry.deliver("test_dock", apply)
    assert applied["count"] == 0

    dock.setVisible(True)
    app.processEvents()
    assert applied["count"] == 1


def test_visible_dock_applies_immediately():
    from PyQt5.QtWidgets import QApplication, QDockWidget, QLabel, QMainWindow

    from src.services.dock_update_gate import DockUpdateRegistry

    app = QApplication.instance() or QApplication([])
    window = QMainWindow()
    dock = QDockWidget("Panel", window)
    dock.setObjectName("test_dock")
    dock.setWidget(QLabel("content"))
    window.addDockWidget(1, dock)
    window.show()
    app.processEvents()

    registry = DockUpdateRegistry(window)
    registry.register(dock)

    applied = {"count": 0}
    registry.deliver("test_dock", lambda: applied.__setitem__("count", applied["count"] + 1))
    assert applied["count"] == 1
