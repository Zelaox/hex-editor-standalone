"""Background workers for binary snapshot and forensic context analysis."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from PyQt5.QtCore import QObject, pyqtSignal


class SnapshotAnalysisWorker(QObject):
    """Run analyze_binary_snapshot off the Qt main thread."""

    finished = pyqtSignal(dict)
    failed = pyqtSignal(str, int)

    def __init__(
        self,
        source_path: str | Path,
        *,
        policy: Mapping[str, Any] | None,
        generation: int,
    ) -> None:
        super().__init__()
        self._source_path = str(source_path)
        self._policy = dict(policy or {})
        self._generation = int(generation)

    def run(self) -> None:
        try:
            from src.services.binary_runtime import analyze_binary_snapshot

            resolved = Path(self._source_path).expanduser().resolve()
            result = analyze_binary_snapshot(resolved, policy=self._policy)
            self.finished.emit(
                {
                    "result": result,
                    "source_path": str(resolved),
                    "generation": self._generation,
                }
            )
        except Exception as exc:
            self.failed.emit(str(exc), self._generation)


class ForensicContextWorker(QObject):
    """Build full forensic context off the Qt main thread."""

    finished = pyqtSignal(dict)
    failed = pyqtSignal(str, int)

    def __init__(
        self,
        *,
        source_path: str,
        snapshot: Mapping[str, Any],
        generation: int,
        investigation_root: Optional[str] = None,
        workspace_root: Optional[str] = None,
        include_representation: bool = True,
        include_scope_discovery: bool = True,
        include_lineage_discovery: bool = True,
    ) -> None:
        super().__init__()
        self._source_path = str(source_path)
        self._snapshot = dict(snapshot)
        self._generation = int(generation)
        self._investigation_root = investigation_root
        self._workspace_root = workspace_root
        self._include_representation = bool(include_representation)
        self._include_scope_discovery = bool(include_scope_discovery)
        self._include_lineage_discovery = bool(include_lineage_discovery)

    def run(self) -> None:
        try:
            from src.gui_evidence_presenter import build_forensic_context

            context = build_forensic_context(
                source_path=self._source_path,
                snapshot=self._snapshot,
                investigation_root=self._investigation_root,
                workspace_root=self._workspace_root,
                include_representation=self._include_representation,
                include_scope_discovery=self._include_scope_discovery,
                include_lineage_discovery=self._include_lineage_discovery,
            )
            self.finished.emit(
                {
                    "context": context,
                    "source_path": self._source_path,
                    "snapshot": self._snapshot,
                    "generation": self._generation,
                }
            )
        except Exception as exc:
            self.failed.emit(str(exc), self._generation)
