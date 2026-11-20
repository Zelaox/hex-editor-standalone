"""Defer dock panel updates while hidden; flush latest payload when reopened."""

from __future__ import annotations

from typing import Callable, Dict, List, Optional, Union

from PyQt5.QtWidgets import QDockWidget, QMainWindow

ApplyFn = Callable[[], None]
PendingUpdate = Union[ApplyFn, List[ApplyFn]]


def dock_panel_shown(dock: QDockWidget) -> bool:
    """True when the dock panel is actually shown to the user (including floating)."""
    if dock.isHidden():
        return False
    if dock.isVisible():
        return True
    if dock.isFloating():
        widget = dock.widget()
        return widget is not None and not widget.isHidden()
    return False


class DockUpdateGate:
    """Hold the latest deferred update for one dock panel."""

    def __init__(self, dock: QDockWidget) -> None:
        self._dock = dock
        self._pending: Optional[PendingUpdate] = None
        dock.visibilityChanged.connect(self._on_visibility_changed)

    @property
    def object_name(self) -> str:
        return str(self._dock.objectName() or "")

    def deliver(self, apply: ApplyFn, *, coalesce: bool = True) -> None:
        if dock_panel_shown(self._dock):
            self._pending = None
            apply()
            return
        if coalesce:
            self._pending = apply
            return
        if self._pending is None:
            self._pending = [apply]
        elif isinstance(self._pending, list):
            self._pending.append(apply)
        else:
            self._pending = [self._pending, apply]

    def clear(self) -> None:
        self._pending = None

    def _on_visibility_changed(self, visible: bool) -> None:
        if not visible or self._pending is None:
            return
        pending = self._pending
        self._pending = None
        if isinstance(pending, list):
            for apply in pending:
                apply()
            return
        pending()


class DockUpdateRegistry:
    """Registry of dock update gates keyed by dock objectName."""

    def __init__(self, window: QMainWindow) -> None:
        self._window = window
        self._gates: Dict[str, DockUpdateGate] = {}

    def register(self, dock: QDockWidget) -> DockUpdateGate:
        name = str(dock.objectName() or "")
        if not name:
            raise ValueError("dock requires objectName for update gating")
        gate = DockUpdateGate(dock)
        self._gates[name] = gate
        return gate

    def register_docks(self, docks: Dict[str, QDockWidget]) -> None:
        for dock in docks.values():
            self.register(dock)

    def gate(self, object_name: str) -> DockUpdateGate:
        gate = self._gates.get(str(object_name or ""))
        if gate is None:
            raise ValueError(f"no dock update gate registered for {object_name}")
        return gate

    def deliver(self, object_name: str, apply: ApplyFn, *, coalesce: bool = True) -> None:
        self.gate(object_name).deliver(apply, coalesce=coalesce)

    def clear_all(self) -> None:
        for gate in self._gates.values():
            gate.clear()

    def is_visible(self, object_name: str) -> bool:
        dock = self._window.findChild(QDockWidget, str(object_name or ""))
        if dock is None:
            return False
        return dock_panel_shown(dock)
