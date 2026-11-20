"""Shared Hex Editor desktop process manager and live command bridge."""

from __future__ import annotations

from src.project import project_root

import json
import os
import subprocess
import sys
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from hexeditor_tools.file_access import normalize_input_path, resolve_and_validate

_MANAGERS: Dict[Path, "HexEditorDesktopManager"] = {}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class HexEditorDesktopManager:
    def __init__(self, lab_root: Path):
        self.lab_root = lab_root.resolve()
        config_path = self.lab_root / "config" / "hex_editor.json"
        self.config = json.loads(config_path.read_text(encoding="utf-8"))
        self.editor_root = (self.lab_root / self.config["application_path"]).resolve()
        self.entry_point = self.editor_root / self.config["entry_point"]
        self.runtime_root = (self.lab_root / self.config.get("runtime_root", "data/runtime/hex_editor")).resolve()
        self.inbox = self.runtime_root / "inbox"
        self.outbox = self.runtime_root / "outbox"
        self.state_path = self.runtime_root / "state.json"
        self.inbox.mkdir(parents=True, exist_ok=True)
        self.outbox.mkdir(parents=True, exist_ok=True)
        self._process: Optional[subprocess.Popen] = None
        self._lock = threading.Lock()

    def _read_state(self) -> Dict[str, Any]:
        if not self.state_path.is_file():
            return {}
        try:
            return json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError):
            return {}

    def _write_state(self, state: Dict[str, Any]) -> None:
        self.runtime_root.mkdir(parents=True, exist_ok=True)
        temp = self.state_path.with_suffix(f".{os.getpid()}.tmp")
        temp.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")
        os.replace(temp, self.state_path)

    @staticmethod
    def _pid_alive(pid: int) -> bool:
        if pid <= 0:
            return False
        if sys.platform == "win32":
            try:
                import ctypes

                handle = ctypes.windll.kernel32.OpenProcess(0x100000, False, pid)
                if handle:
                    ctypes.windll.kernel32.CloseHandle(handle)
                    return True
                return False
            except Exception:
                return False
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False

    def _tracked_running(self) -> bool:
        with self._lock:
            if self._process is not None and self._process.poll() is None:
                return True
        state = self._read_state()
        pid = int(state.get("pid") or 0)
        return self._pid_alive(pid)

    def status(self) -> Dict[str, Any]:
        state = self._read_state()
        running = self._tracked_running()
        current = {
            "state": "running" if running else "stopped",
            "pid": state.get("pid"),
            "owned": bool(state.get("owned")),
            "current_path": state.get("current_path"),
            "last_command_id": state.get("last_command_id"),
            "updated_at": state.get("updated_at"),
            "runtime_root": str(self.runtime_root),
        }
        return {
            "ok": True,
            "desktop": current,
            "bridge": {
                "inbox": str(self.inbox),
                "outbox": str(self.outbox),
            },
        }

    def _validated_path(self, path: str | None) -> str:
        if not path:
            return ""
        normalized = normalize_input_path(path)
        if not normalized:
            raise ValueError("Path is required")
        result = resolve_and_validate(normalized)
        if not result.get("ok"):
            raise ValueError(result.get("error", "Path is not allowlisted"))
        resolved = Path(result["path"])
        if not resolved.is_file():
            raise FileNotFoundError(f"File not found: {resolved}")
        return str(resolved)

    def enqueue_command(
        self,
        action: str,
        *,
        path: str = "",
        offset: int | None = None,
        source: str = "mcp",
        turn_id: str = "",
        payload: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        command = {
            "schema_version": 1,
            "command_id": uuid.uuid4().hex,
            "action": action,
            "path": self._validated_path(path) if path else "",
            "source": source,
            "turn_id": turn_id,
            "created_at": _utc_now(),
        }
        if offset is not None:
            command["offset"] = int(offset)
        if payload is not None:
            command["payload"] = dict(payload)
        target = self.inbox / f"{command['command_id']}.json"
        temp = target.with_suffix(f".{os.getpid()}.tmp")
        temp.write_text(json.dumps(command, indent=2, sort_keys=True), encoding="utf-8")
        os.replace(temp, target)
        state = self._read_state()
        state.update(
            {
                "last_command_id": command["command_id"],
                "pending_action": action,
                "pending_path": command["path"],
                "updated_at": _utc_now(),
            }
        )
        self._write_state(state)
        return command

    def launch(self, path: str | None = None, *, source: str = "mcp", turn_id: str = "") -> Dict[str, Any]:
        resolved = self._validated_path(path) if path else ""
        if self._tracked_running():
            if resolved:
                command = self.enqueue_command("open", path=resolved, source=source, turn_id=turn_id)
                return {
                    "ok": True,
                    "operation": "hex_editor_open_desktop",
                    "delivery": "live_command",
                    "already_running": True,
                    "command": command,
                    "desktop": self.status()["desktop"],
                }
            return {
                "ok": True,
                "operation": "hex_editor_open_desktop",
                "delivery": "already_running",
                "already_running": True,
                "desktop": self.status()["desktop"],
            }

        command = [sys.executable, str(self.entry_point), "--lab-bridge", str(self.runtime_root)]
        if resolved:
            command.extend(["--open", resolved])
        kwargs: Dict[str, Any] = {
            "cwd": str(self.editor_root),
            "stdin": subprocess.DEVNULL,
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
        }
        if sys.platform == "win32":
            kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        with self._lock:
            self._process = subprocess.Popen(command, **kwargs)
            pid = self._process.pid
        self._write_state(
            {
                "pid": pid,
                "owned": True,
                "state": "running",
                "current_path": resolved or "",
                "source": source,
                "turn_id": turn_id,
                "updated_at": _utc_now(),
            }
        )
        return {
            "ok": True,
            "operation": "hex_editor_open_desktop",
            "delivery": "process_started",
            "already_running": False,
            "pid": pid,
            "opened_path": resolved or "",
            "desktop": self.status()["desktop"],
        }

    def record_desktop_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        state = self._read_state()
        state.update(
            {
                "current_path": event.get("path") or state.get("current_path") or "",
                "last_event": event.get("event") or "",
                "updated_at": _utc_now(),
            }
        )
        self._write_state(state)
        ack_path = self.outbox / f"{event.get('command_id') or uuid.uuid4().hex}.json"
        temp = ack_path.with_suffix(f".{os.getpid()}.tmp")
        temp.write_text(json.dumps({**event, "recorded_at": _utc_now()}, indent=2), encoding="utf-8")
        os.replace(temp, ack_path)
        return {"ok": True}


def get_hex_editor_desktop_manager(lab_root: Path | None = None) -> HexEditorDesktopManager:
    root = (lab_root or Path.cwd()).resolve()
    if root not in _MANAGERS:
        _MANAGERS[root] = HexEditorDesktopManager(root)
    return _MANAGERS[root]
