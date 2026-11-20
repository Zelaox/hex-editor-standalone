"""Format plugin detection and routing — suffix routes only, never profile selection."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Mapping

from src.runtime.config import load_binary_dynamic_config


def _sniff_ptx_content(data: bytes, *, cfg: Mapping[str, Any] | None = None) -> bool:
    from src.services.ptx_parse_policy import session_marker_bytes, timecode_anchor_bytes

    if len(data) < 4:
        return False
    magic = data[:4]
    if magic in (b"PTX0", b"PTX\x00"):
        return True
    if magic.startswith(b"\x03") or magic.decode("ascii", errors="ignore").startswith("\x03"):
        if any(marker in data for marker in session_marker_bytes()):
            return True
        if any(pattern in data for pattern in timecode_anchor_bytes()):
            return True
    return False


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
    if suffix in {item.lower() for item in config.get("ptx_suffixes") or []}:
        return "ptx"
    if suffix in {item.lower() for item in config.get("pe_suffixes") or []}:
        return "pe"
    if resolved.is_file():
        with resolved.open("rb") as stream:
            data = stream.read(4096)
    else:
        data = b""
    if len(data) >= 2 and data[:2] == b"MZ":
        return "pe"
    if _sniff_ptx_content(data):
        return "ptx"
    return "unknown"


def route_format_plugin(path: str | Path, *, cfg: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    plugin = detect_format_plugin(path, cfg=cfg)
    if plugin == "unknown":
        raise ValueError("unsupported binary format for runtime analysis")
    return {"format_plugin": plugin, "path": str(Path(path).expanduser().resolve())}
