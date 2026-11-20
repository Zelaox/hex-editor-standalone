"""Resolve displayed numeric values to absolute file offsets (policy-driven)."""

from __future__ import annotations

import importlib
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Tuple


def _load_pe_resolver(module_path: str):
    module = importlib.import_module(module_path)
    resolver = getattr(module, "file_offset_for_virtual_address", None)
    if resolver is None:
        raise ValueError(f"pe_address_resolution module missing file_offset_for_virtual_address: {module_path}")
    return resolver


def resolve_raw_to_file_offset(
    raw_value: int,
    *,
    file_size: int,
    source_path: Path | None,
    navigation_policy: Mapping[str, Any],
) -> Optional[Tuple[int, int]]:
    value = int(raw_value)
    if file_size <= 0:
        return (value, 1) if value >= 0 else None
    if 0 <= value < file_size:
        return value, 1
    pe_cfg = dict(navigation_policy.get("pe_address_resolution") or {})
    if not bool(pe_cfg.get("enabled")) or source_path is None or not source_path.is_file():
        return None
    module_path = str(pe_cfg.get("module") or "").strip()
    if not module_path:
        return None
    resolver = _load_pe_resolver(module_path)
    mapped = resolver(source_path.expanduser().resolve(), value)
    if mapped is None:
        return None
    mapped_int = int(mapped)
    if file_size > 0 and (mapped_int < 0 or mapped_int >= file_size):
        return None
    return mapped_int, 1


def resolve_coordinate_to_file_offset(
    raw_value: int,
    *,
    coordinate_space: str,
    file_size: int,
    source_path: Path | None,
    navigation_policy: Mapping[str, Any],
) -> Optional[Tuple[int, int]]:
    """Resolve an explicitly typed coordinate without guessing from its magnitude."""
    value = int(raw_value)
    space = str(coordinate_space or "").strip()
    if space == "file_offset":
        if value < 0 or (file_size > 0 and value >= file_size):
            return None
        return value, 1
    if space != "virtual_address":
        raise ValueError(f"unsupported navigation coordinate space: {space}")

    pe_cfg = dict(navigation_policy.get("pe_address_resolution") or {})
    if not bool(pe_cfg.get("enabled")) or source_path is None or not source_path.is_file():
        return None
    module_path = str(pe_cfg.get("module") or "").strip()
    if not module_path:
        return None
    resolver = _load_pe_resolver(module_path)
    mapped = resolver(source_path.expanduser().resolve(), value)
    if mapped is None:
        return None
    mapped_int = int(mapped)
    if mapped_int < 0 or (file_size > 0 and mapped_int >= file_size):
        return None
    return mapped_int, 1
