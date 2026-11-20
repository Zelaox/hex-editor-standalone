"""Bridge legacy ptx_converter to authoritative src pipeline."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any, Dict, List

from src.services.ptx_parse_result import build_parse_result


def parse_audio_tracks_from_bytes(data: bytes) -> List[Dict[str, Any]]:
    """Parse track-like structures from decrypted bytes via shared analyze path."""
    if not data:
        raise ValueError("empty PTX payload")
    with tempfile.NamedTemporaryFile(suffix=".ptx", delete=False) as handle:
        handle.write(data)
        temp_path = Path(handle.name)
    try:
        result = build_parse_result(temp_path)
        if not result.get("ok"):
            raise ValueError(result.get("error") or "PTX parse failed")
        metadata = dict(result.get("metadata") or {})
        track_names = metadata.get("track_names")
        if isinstance(track_names, list) and track_names:
            tracks: List[Dict[str, Any]] = []
            for index, name in enumerate(track_names):
                label = str(name)
                tracks.append(
                    {
                        "id": index + 1,
                        "name": label,
                        "type": 2 if label.lower().startswith("inst") else 1,
                        "audio_clips": [],
                    }
                )
            return tracks
        verified = dict(result.get("header") or {})
        session_strings = list(verified.get("session_strings") or [])
        if session_strings:
            return [
                {
                    "id": 1,
                    "name": str(session_strings[0]),
                    "type": 1,
                    "audio_clips": [],
                }
            ]
        raise ValueError("no verified track or session metadata in parse result")
    finally:
        temp_path.unlink(missing_ok=True)
