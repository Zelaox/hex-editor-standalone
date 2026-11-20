"""Background worker for transform preview requests."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Mapping

from PyQt5.QtCore import QObject, pyqtSignal


class TransformPreviewWorker(QObject):
    finished = pyqtSignal(dict)
    failed = pyqtSignal(str, int)
    progress = pyqtSignal(dict)

    def __init__(
        self,
        *,
        source_path: str | Path,
        offset: int,
        length: int,
        mode: str,
        policy: Mapping[str, Any] | None,
        generation: int,
        full_file: bool = False,
    ) -> None:
        super().__init__()
        self._source_path = str(source_path)
        self._offset = int(offset)
        self._length = int(length)
        self._mode = str(mode)
        self._policy = dict(policy or {})
        self._generation = int(generation)
        self._full_file = bool(full_file)

    def run(self) -> None:
        try:
            from src.services.transform_preview.export import export_full_file_preview
            from src.services.transform_preview.inspect import inspect_transform_preview

            resolved = Path(self._source_path).expanduser().resolve()
            if self._full_file:
                report = export_full_file_preview(resolved, mode=self._mode, policy=self._policy)
                self.finished.emit(
                    {
                        "operation": "full_file_export",
                        "report": report,
                        "source_path": str(resolved),
                        "generation": self._generation,
                    }
                )
                return
            result = inspect_transform_preview(
                resolved,
                offset=self._offset,
                length=self._length,
                mode=self._mode,
                policy=self._policy,
            )
            self.finished.emit(
                {
                    "result": result,
                    "source_path": str(resolved),
                    "generation": self._generation,
                }
            )
        except Exception as exc:
            self.failed.emit(str(exc), self._generation)
