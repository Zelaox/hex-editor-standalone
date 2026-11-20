"""Transform preview generation orchestration with stale protection."""

from __future__ import annotations

from typing import Any, Callable, Dict, Mapping, Optional

from PyQt5.QtCore import QThread

from src.transform_preview_worker import TransformPreviewWorker


ApplyFn = Callable[[Dict[str, Any]], None]


class TransformPreviewController:
    def __init__(self) -> None:
        self._generation = 0
        self._thread: Optional[QThread] = None
        self._worker: Optional[TransformPreviewWorker] = None
        self._last_payload: Optional[Dict[str, Any]] = None

    @property
    def generation(self) -> int:
        return self._generation

    def bump_generation(self) -> int:
        self._generation += 1
        self.cancel()
        return self._generation

    def is_stale(self, generation: int) -> bool:
        return int(generation) != self._generation

    def cancel(self) -> None:
        if self._thread is not None and self._thread.isRunning():
            self._thread.requestInterruption()
            self._thread.quit()
            self._thread.wait(2000)
        self._cleanup_thread()

    def _cleanup_thread(self) -> None:
        self._thread = None
        self._worker = None

    def request_preview(
        self,
        *,
        source_path: str,
        offset: int,
        length: int,
        mode: str,
        policy: Mapping[str, Any],
        on_finished: ApplyFn,
        on_failed: Callable[[str, int], None],
        full_file: bool = False,
    ) -> int:
        generation = self.bump_generation()
        self._worker = TransformPreviewWorker(
            source_path=source_path,
            offset=offset,
            length=length,
            mode=mode,
            policy=policy,
            generation=generation,
            full_file=full_file,
        )
        self._thread = QThread()
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.finished.connect(lambda payload: self._handle_finished(payload, on_finished))
        self._worker.failed.connect(on_failed)
        self._worker.finished.connect(self._thread.quit)
        self._worker.failed.connect(self._thread.quit)
        self._thread.finished.connect(self._cleanup_thread)
        self._thread.start()
        return generation

    def _handle_finished(self, payload: Dict[str, Any], on_finished: ApplyFn) -> None:
        generation = int(payload.get("generation") or 0)
        if self.is_stale(generation):
            return
        self._last_payload = dict(payload)
        on_finished(payload)

    def last_payload(self) -> Optional[Dict[str, Any]]:
        return dict(self._last_payload) if self._last_payload else None
