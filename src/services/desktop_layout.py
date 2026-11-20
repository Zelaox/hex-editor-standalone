"""Persist main-window geometry and dock layout via QSettings (SSOT: ui_policy)."""

from __future__ import annotations

from typing import Any, Callable, Dict, Mapping, Optional

from PyQt5.QtCore import QSettings, QTimer, QObject, QEvent
from PyQt5.QtWidgets import QDockWidget, QMainWindow


def settings_store(policy: Mapping[str, Any]) -> QSettings:
    persistence = dict(policy.get("desktop_persistence") or {})
    organization = str(persistence.get("settings_organization") or "")
    application = str(persistence.get("settings_application") or "")
    if not organization or not application:
        raise ValueError("ui policy missing desktop_persistence.settings_organization/application")
    return QSettings(QSettings.defaultFormat(), QSettings.UserScope, organization, application)


def dock_widgets(window: QMainWindow) -> Dict[str, QDockWidget]:
    docks: Dict[str, QDockWidget] = {}
    for child in window.findChildren(QDockWidget):
        name = str(child.objectName() or "")
        if name:
            docks[name] = child
    return docks


def apply_dock_defaults(window: QMainWindow, policy: Mapping[str, Any]) -> None:
    defaults = dict(policy.get("dock_defaults") or {})
    for object_name, visible in defaults.items():
        dock = window.findChild(QDockWidget, str(object_name))
        if dock is not None:
            dock.setVisible(bool(visible))


def restore_layout(window: QMainWindow, policy: Mapping[str, Any]) -> bool:
    store = settings_store(policy)
    geometry = store.value("geometry")
    state = store.value("windowState")
    if geometry:
        window.restoreGeometry(geometry)
    if state:
        window.restoreState(state)
    return bool(state)


def save_layout(window: QMainWindow, policy: Mapping[str, Any], *, recent_files: Optional[list] = None) -> None:
    store = settings_store(policy)
    store.setValue("geometry", window.saveGeometry())
    store.setValue("windowState", window.saveState())
    if recent_files is not None:
        store.setValue("recentFiles", recent_files)
    dark_mode = bool(getattr(window, "dark_mode_enabled", False))
    store.setValue("darkMode", dark_mode)
    store.sync()


def load_recent_files(policy: Mapping[str, Any]) -> list:
    store = settings_store(policy)
    recent = store.value("recentFiles", [])
    return list(recent or [])


def load_dark_mode(policy: Mapping[str, Any], *, default: bool) -> bool:
    store = settings_store(policy)
    return bool(store.value("darkMode", default, type=bool))


class LayoutAutosave(QObject):
    """Debounced layout persistence while the user rearranges docks."""

    def __init__(
        self,
        window: QMainWindow,
        *,
        policy: Mapping[str, Any],
        on_save: Optional[Callable[[], None]] = None,
    ) -> None:
        super().__init__(window)
        self._window = window
        self._policy = dict(policy)
        self._on_save = on_save
        self._suspended = False
        debounce_ms = int((dict(policy.get("desktop_persistence") or {})).get("layout_autosave_debounce_ms") or 0)
        if debounce_ms <= 0:
            raise ValueError("ui policy missing desktop_persistence.layout_autosave_debounce_ms")
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.setInterval(debounce_ms)
        self._timer.timeout.connect(self._flush)

    def attach(self) -> None:
        for dock in dock_widgets(self._window).values():
            dock.visibilityChanged.connect(self.schedule)
            dock.topLevelChanged.connect(self.schedule)
            dock.dockLocationChanged.connect(self.schedule)
        self._window.installEventFilter(self)

    def eventFilter(self, watched, event) -> bool:  # noqa: N802 - Qt API
        if watched is self._window and event.type() in {
            QEvent.Resize,
            QEvent.Move,
            QEvent.WindowStateChange,
        }:
            self.schedule()
        return False

    def set_suspended(self, suspended: bool) -> None:
        self._suspended = bool(suspended)
        if self._suspended:
            self._timer.stop()

    def schedule(self, *_args) -> None:
        if self._suspended:
            return
        self._timer.start()

    def flush(self) -> None:
        self._flush()

    def _flush(self) -> None:
        save_layout(self._window, self._policy)
        if self._on_save is not None:
            self._on_save()
