"""Registry-driven format detection for pseudocode routing."""

from __future__ import annotations

import importlib
from pathlib import Path
from typing import Any, Dict, Mapping, Tuple


def _match_prefix(data: bytes, prefix_hex: str, max_skip: int, *, ascii_case_insensitive: bool = False) -> bool:
    needle = bytes.fromhex(str(prefix_hex))
    if not needle:
        return False
    window = data[: max(len(data), max_skip + len(needle))]
    for skip in range(max(0, int(max_skip)) + 1):
        segment = window[skip : skip + len(needle)]
        if ascii_case_insensitive:
            if segment.lower() == needle.lower():
                return True
        elif segment == needle:
            return True
    return False


def detect_format(
    path: Path,
    *,
    registry: Mapping[str, Any],
    prefix_bytes: int,
) -> Tuple[str, str, float]:
    """Return (format_plugin, region_class, confidence)."""
    data = path.read_bytes()[: max(0, int(prefix_bytes))] if path.is_file() else b""
    defaults = dict(registry.get("plugin_defaults") or {})
    for rule in registry.get("prefix_rules") or []:
        if not isinstance(rule, Mapping):
            continue
        if _match_prefix(
            data,
            str(rule.get("prefix_hex") or ""),
            int(rule.get("max_leading_skip_bytes") or 0),
            ascii_case_insensitive=bool(rule.get("ascii_case_insensitive")),
        ):
            plugin = str(rule.get("format_plugin") or "unknown")
            region_class = str(rule.get("region_class") or (defaults.get(plugin) or {}).get("region_class") or "unknown_data")
            confidence = float(rule.get("confidence") or (defaults.get(plugin) or {}).get("confidence") or 0.0)
            return plugin, region_class, confidence

    module_name = str(registry.get("delegate_router_module") or "")
    callable_name = str(registry.get("delegate_router_callable") or "")
    if module_name and callable_name:
        from src.runtime.config import load_binary_dynamic_config

        mod = importlib.import_module(module_name)
        fn = getattr(mod, callable_name)
        plugin = str(fn(path, cfg=load_binary_dynamic_config()))
    else:
        plugin = "unknown"

    meta = dict(defaults.get(plugin) or defaults.get("unknown") or {})
    return (
        plugin,
        str(meta.get("region_class") or "unknown_data"),
        float(meta.get("confidence") or 0.0),
    )
