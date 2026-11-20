"""Optional inbox/outbox bridge from an external host (MCP, UVE, AI Lab) to the desktop editor."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict

from PyQt5.QtCore import QObject, QTimer, pyqtSignal

logger = logging.getLogger("hex_editor.lab_bridge")


class LabCommandBridge(QObject):
    command_received = pyqtSignal(dict)

    def __init__(self, runtime_root: str | Path, parent=None):
        super().__init__(parent)
        self.runtime_root = Path(runtime_root).resolve()
        self.inbox = self.runtime_root / "inbox"
        self.outbox = self.runtime_root / "outbox"
        self.inbox.mkdir(parents=True, exist_ok=True)
        self.outbox.mkdir(parents=True, exist_ok=True)
        self._seen: set[str] = set()
        self._timer = QTimer(self)
        self._timer.timeout.connect(self.poll_inbox)
        self._timer.start(400)

    def poll_inbox(self) -> None:
        for path in sorted(self.inbox.glob("*.json")):
            command_id = path.stem
            if command_id in self._seen:
                continue
            try:
                command = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                logger.warning("Skipping invalid command %s: %s", path, exc)
                try:
                    path.unlink(missing_ok=True)
                except OSError:
                    pass
                continue
            self._seen.add(command_id)
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
            self.command_received.emit(command)

    def acknowledge(self, command: Dict[str, Any], *, ok: bool, detail: str = "") -> None:
        payload = {
            "schema_version": 1,
            "command_id": command.get("command_id"),
            "action": command.get("action"),
            "ok": ok,
            "detail": detail,
            "path": command.get("path") or "",
        }
        target = self.outbox / f"{payload['command_id']}.json"
        temp = target.with_suffix(".tmp")
        temp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        temp.replace(target)
