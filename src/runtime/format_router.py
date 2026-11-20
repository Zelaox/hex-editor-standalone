"""Format plugin detection and routing — suffix routes only, never profile selection."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Mapping

from src.runtime.config import load_binary_dynamic_config


def detect_format_plugin(path: str | Path, *, cfg: Mapping[str, Any] | None = None) -> str:
    config = dict(cfg or load_binary_dynamic_config())
    resolved = Path(path).expanduser().resolve()
    if resolved.is_file():
        from src.services.region_routed_pseudocode.policies import load_format_detect_registry
        from src.services.browser_forensics.detection import detect_storage_header
        storage = detect_storage_header(resolved, load_format_detect_registry())
        if storage:
            return storage
    suffix = resolved.suffix.lower()
    if suffix in {item.lower() for item in config.get("pe_suffixes") or []}:
        return "pe"
    data = b""
    if resolved.is_file():
        with resolved.open("rb") as stream:
            data = stream.read(4096)
    if len(data) >= 2 and data[:2] == b"MZ":
        return "pe"
    return "unknown"


def route_format_plugin(path: str | Path, *, cfg: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    plugin = detect_format_plugin(path, cfg=cfg)
    if plugin == "unknown":
        raise ValueError("unsupported binary format for runtime analysis")
    return {"format_plugin": plugin, "path": str(Path(path).expanduser().resolve())}