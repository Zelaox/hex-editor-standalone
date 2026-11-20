"""Serializable contracts shared by the desktop app and external MCP/CLI hosts."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List


@dataclass(frozen=True)
class Finding:
    kind: str
    value: Any
    provenance: str
    confidence: str = "verified"
    offset: int | None = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AnalysisResult:
    ok: bool
    operation: str
    source: Dict[str, Any]
    findings: List[Dict[str, Any]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
