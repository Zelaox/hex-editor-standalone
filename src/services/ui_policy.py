"""Load Hex Editor UI policy from config SSOT."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Mapping

from jsonschema import Draft202012Validator


def _root() -> Path:
    return Path(__file__).resolve().parents[2]


def _config_path() -> Path:
    return _root() / "config" / "ui_policy.json"


def _schema_path() -> Path:
    return _root() / "schemas" / "ui_policy.schema.json"


def load_ui_policy(path: str | Path | None = None) -> Dict[str, Any]:
    target = Path(path).expanduser().resolve() if path else _config_path()
    policy = json.loads(target.read_text(encoding="utf-8-sig"))
    schema = json.loads(_schema_path().read_text(encoding="utf-8"))
    errors = sorted(Draft202012Validator(schema).iter_errors(policy), key=lambda item: list(item.path))
    if errors:
        raise ValueError(f"ui policy invalid: {errors[0].message}")
    if int(policy.get("schema_version") or 0) != 1:
        raise ValueError("unsupported ui policy schema version")
    budgets = dict(policy.get("load_budgets") or {})
    required_budgets = (
        "max_forensic_overlay_spans",
        "max_inspector_table_rows",
        "max_highlight_ops_per_visible_section",
        "defer_forensic_context_ms",
        "scope_run_scan_limit",
        "scroll_debounce_ms",
        "scroll_highlight_defer_ms",
        "text_inspector_debounce_ms",
        "hex_view_mode",
        "hex_viewport_file_bytes",
        "hex_viewport_document_lines",
        "hex_viewport_overscan_lines",
        "hex_overlay_apply_mode",
        "hex_overlay_viewport_margin_lines",
    )
    missing = [name for name in required_budgets if name not in budgets]
    if missing:
        raise ValueError(f"ui policy missing load_budgets: {missing}")
    apply_mode = str(budgets.get("hex_overlay_apply_mode") or "")
    if apply_mode != "incremental":
        raise ValueError("ui policy load_budgets.hex_overlay_apply_mode must be incremental")
    view_mode = str(budgets.get("hex_view_mode") or "")
    if view_mode not in {"full", "viewport", "auto"}:
        raise ValueError("ui policy load_budgets.hex_view_mode must be full, viewport, or auto")
    if view_mode in {"viewport", "auto"}:
        for key in (
            "hex_viewport_file_bytes",
            "hex_viewport_document_lines",
            "hex_viewport_overscan_lines",
        ):
            if key not in budgets:
                raise ValueError(f"ui policy missing load_budgets.{key}")
        if int(budgets["hex_viewport_file_bytes"]) <= 0:
            raise ValueError("ui policy load_budgets.hex_viewport_file_bytes must be positive")
        if int(budgets["hex_viewport_document_lines"]) <= 0:
            raise ValueError("ui policy load_budgets.hex_viewport_document_lines must be positive")
        if int(budgets["hex_viewport_overscan_lines"]) < 0:
            raise ValueError("ui policy load_budgets.hex_viewport_overscan_lines must be non-negative")
    persistence = dict(policy.get("desktop_persistence") or {})
    required_persistence = (
        "settings_organization",
        "settings_application",
        "layout_autosave_debounce_ms",
        "main_window_object_name",
        "main_toolbar_object_name",
    )
    missing_persistence = [name for name in required_persistence if name not in persistence]
    if missing_persistence:
        raise ValueError(f"ui policy missing desktop_persistence: {missing_persistence}")
    if not isinstance(policy.get("dock_defaults"), dict):
        raise ValueError("ui policy missing dock_defaults")
    return policy


def load_budget(policy: Mapping[str, Any], key: str) -> int:
    budgets = dict(policy.get("load_budgets") or {})
    if key not in budgets:
        raise ValueError(f"ui policy missing load_budgets.{key}")
    return int(budgets[key])


def panel_columns(policy: Mapping[str, Any], panel_id: str) -> list[str]:
    panel = dict((policy.get("panels") or {}).get(panel_id) or {})
    columns = panel.get("columns")
    if not isinstance(columns, list) or not columns:
        raise ValueError(f"ui policy missing panels.{panel_id}.columns")
    return [str(item) for item in columns]


def theme_color(policy: Mapping[str, Any], token: str) -> str:
    colors = dict(policy.get("theme_tokens") or {})
    value = colors.get(token)
    if not value:
        raise ValueError(f"ui policy missing theme token: {token}")
    return str(value)


def hex_overlay_enabled(policy: Mapping[str, Any], key: str) -> bool:
    if not feature_enabled(policy, "hex_forensic_overlays"):
        return False
    overlays = dict(policy.get("hex_overlays") or {})
    return bool(overlays.get(key, False))


def feature_enabled(policy: Mapping[str, Any], key: str) -> bool:
    flags = dict(policy.get("feature_flags") or {})
    if key not in flags:
        return False
    return bool(flags[key])


def float_zero_epsilon(policy: Mapping[str, Any]) -> float:
    display = dict(policy.get("display_format") or {})
    if "float_zero_epsilon" not in display:
        raise ValueError("ui policy missing display_format.float_zero_epsilon")
    return float(display["float_zero_epsilon"])


def format_display_scalar(value: Any, *, policy: Mapping[str, Any]) -> str:
    """Normalize signed-zero floats and render inspector-safe display text."""
    if isinstance(value, bool):
        return str(value)
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        epsilon = float_zero_epsilon(policy)
        if abs(value) < epsilon:
            return "0.0"
        return str(value)
    return str(value)
