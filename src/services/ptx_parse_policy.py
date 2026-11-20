"""Load PTX parse policy — timecode patterns, content sniff markers (NO HARDCODE in runtime)."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Mapping, Set


def _root() -> Path:
    return Path(__file__).resolve().parents[2]


@lru_cache(maxsize=1)
def load_ptx_parse_policy(path: str | None = None) -> Dict[str, Any]:
    target = Path(path).expanduser().resolve() if path else _root() / "config" / "ptx_parse_policy.json"
    if not target.is_file():
        raise FileNotFoundError(f"missing ptx parse policy: {target}")
    policy = json.loads(target.read_text(encoding="utf-8"))
    if int(policy.get("schema_version") or 0) < 1:
        raise ValueError("ptx_parse_policy schema_version unsupported")
    return policy


def session_marker_bytes(*, policy: Mapping[str, Any] | None = None) -> tuple[bytes, ...]:
    cfg = dict((dict(policy or load_ptx_parse_policy()).get("content_sniff") or {}))
    markers = cfg.get("session_markers")
    if not isinstance(markers, list) or not markers:
        raise ValueError("ptx_parse_policy.content_sniff.session_markers is required")
    return tuple(str(item).encode("ascii", errors="ignore") for item in markers)


def timecode_anchor_bytes(*, policy: Mapping[str, Any] | None = None) -> tuple[bytes, ...]:
    cfg = dict((dict(policy or load_ptx_parse_policy()).get("content_sniff") or {}))
    patterns = cfg.get("timecode_anchor_patterns")
    if not isinstance(patterns, list) or not patterns:
        raise ValueError("ptx_parse_policy.content_sniff.timecode_anchor_patterns is required")
    return tuple(str(item).encode("ascii", errors="ignore") for item in patterns)


def timecode_reference_offsets(*, policy: Mapping[str, Any] | None = None) -> Set[int]:
    extraction = dict((dict(policy or load_ptx_parse_policy()).get("timecode_extraction") or {}))
    offsets = extraction.get("reference_offsets")
    if not isinstance(offsets, list) or not offsets:
        raise ValueError("ptx_parse_policy.timecode_extraction.reference_offsets is required")
    return {int(item) for item in offsets}


def timecode_regex_patterns(*, policy: Mapping[str, Any] | None = None) -> List[bytes]:
    extraction = dict((dict(policy or load_ptx_parse_policy()).get("timecode_extraction") or {}))
    patterns = extraction.get("regex_patterns")
    if not isinstance(patterns, list) or not patterns:
        raise ValueError("ptx_parse_policy.timecode_extraction.regex_patterns is required")
    return [str(item).encode("ascii") for item in patterns]
