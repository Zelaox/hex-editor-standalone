"""Shared transform hook types and probe context."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

from src.services.ptx_crypto_config import (
    case_by_id,
    probe_pipeline_config,
    reference_sha256_for_case,
)
from src.services.ptx_crypto_primitives import sha256_digest
from src.services.ptx_scoring_regions import anchors_for_case


def lab_root() -> Path:
    return Path(__file__).resolve().parents[3]


@dataclass
class TransformProbeContext:
    raw: bytes
    case: Optional[Dict[str, Any]]
    defaults: Dict[str, Any]
    pipeline: Dict[str, Any]
    xor_start: int
    reference_sha: str
    source_sha: str
    anchors: List[Dict[str, Any]]
    body_windows: List[Dict[str, Any]]
    reference_bytes: Optional[bytes] = None
    crypto_case_id: str = ""
    classifier: Dict[str, Any] = field(default_factory=dict)
    registry: Dict[str, Any] = field(default_factory=dict)
    timings_ms: Dict[str, float] = field(default_factory=dict)

    @classmethod
    def build_preview(
        cls,
        raw: bytes,
        *,
        source_sha: str,
        scope_offset: int = 0,
    ) -> "TransformProbeContext":
        from src.services.ptx_crypto_config import probe_pipeline_config

        return cls(
            raw=raw,
            case=None,
            defaults={},
            pipeline=probe_pipeline_config({}),
            xor_start=max(0, int(scope_offset)),
            reference_sha="",
            source_sha=str(source_sha or sha256_digest(raw)),
            anchors=[],
            body_windows=[{"offset": 0, "length": len(raw)}],
        )

    @classmethod
    def build(
        cls,
        raw: bytes,
        *,
        case: Optional[Dict[str, Any]],
        defaults: Dict[str, Any],
        source_sha: str,
        body_windows: List[Dict[str, Any]],
        classifier: Optional[Mapping[str, Any]] = None,
        registry: Optional[Mapping[str, Any]] = None,
    ) -> "TransformProbeContext":
        xor_start = int((case or {}).get("decrypt", {}).get("xor_start_offset") or defaults.get("xor_start_offset") or 16)
        return cls(
            raw=raw,
            case=case,
            defaults=defaults,
            pipeline=probe_pipeline_config(defaults),
            xor_start=xor_start,
            reference_sha=reference_sha256_for_case(case),
            source_sha=str(source_sha or sha256_digest(raw)),
            anchors=list(anchors_for_case(case)),
            body_windows=list(body_windows),
            reference_bytes=load_reference_bytes(case),
            crypto_case_id=str((case or {}).get("id") or ""),
            classifier=dict(classifier or {}),
            registry=dict(registry or {}),
        )


def load_reference_bytes(case: Optional[Mapping[str, Any]]) -> Optional[bytes]:
    if not case:
        return None
    ref_id = str((case.get("decrypt") or {}).get("reference_case_id") or "")
    if not ref_id:
        return None
    ref_case = case_by_id(ref_id)
    if not ref_case:
        return None
    rel = str(ref_case.get("path") or "")
    if not rel:
        return None
    path = (lab_root() / rel).resolve()
    if not path.is_file():
        return None
    return path.read_bytes()


def read_window(raw: bytes, offset: int, length: int) -> tuple[bytes, int]:
    start = max(0, int(offset))
    end = min(len(raw), start + max(64, int(length)))
    if start >= len(raw):
        return b"", start
    return raw[start:end], start
