"""Shared path normalization for Hex Editor domain and desktop entry points."""

from __future__ import annotations

from pathlib import Path
from typing import Union


def normalize_input_path(path: Union[str, Path]) -> str:
    """Strip wrapping quotes from pasted Windows paths before resolution."""
    raw = str(path or "").strip()
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in {'"', "'"}:
        raw = raw[1:-1].strip()
    return raw


def resolve_existing_file(path: Union[str, Path]) -> Path:
    """Normalize, resolve, and require an existing file."""
    normalized = normalize_input_path(path)
    if not normalized:
        raise FileNotFoundError("File path is required")
    resolved = Path(normalized).expanduser().resolve()
    if not resolved.is_file():
        raise FileNotFoundError(f"Binary file not found: {resolved}")
    return resolved
