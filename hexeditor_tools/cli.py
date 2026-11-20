"""Portable CLI front-end for Hex Editor MCP tools (JSON stdout, no MCP server required)."""

from __future__ import annotations

from src.project import project_root

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

_TOOL_VERSION = "1.0.0"
_LAB_ROOT_ENV_KEYS = ("HEX_EDITOR_ROOT",)


def resolve_lab_root(*, start: Path | None = None) -> Path:
    """Resolve this standalone application's root, without enclosing Lab discovery."""
    for key in _LAB_ROOT_ENV_KEYS:
        raw = os.environ.get(key, "").strip()
        if not raw:
            continue
        candidate = Path(raw).expanduser().resolve()
        if _is_lab_root(candidate) and candidate == project_root():
            return candidate
        raise RuntimeError('HEX_EDITOR_ROOT must identify this standalone checkout')
    return project_root()


def _is_lab_root(path: Path) -> bool:
    return (
        path.is_dir()
        and (path / "config" / "hex_editor.json").is_file()
        and (path / "hexeditor_tools").is_dir()
    )


def bootstrap_lab_runtime(lab_root: Path) -> Path:
    """Bind the standalone checkout; never import a parent workspace."""
    root = lab_root.resolve()
    lab_str = str(root)
    if lab_str not in sys.path:
        sys.path.insert(0, lab_str)
    if root != project_root():
        raise RuntimeError('Expected this standalone checkout')
    editor = root
    if editor.is_dir():
        editor_str = str(editor)
        if editor_str not in sys.path:
            sys.path.insert(0, editor_str)
    os.chdir(lab_str)
    return root


def _load_hex_editor_config(lab_root: Path) -> Dict[str, Any]:
    path = lab_root / "config" / "hex_editor.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    if int(payload.get("schema_version") or 0) != 1:
        raise ValueError(f"Unsupported hex_editor.json schema at {path}")
    return payload


def _enabled_tool_names(hex_config: Mapping[str, Any]) -> frozenset[str]:
    enabled = hex_config.get("enabled_operations") or []
    names = {str(item).strip() for item in enabled if str(item).strip()}
    dashboard = hex_config.get("dashboard_output_operations") or []
    names.update(str(item).strip() for item in dashboard if str(item).strip())
    names.add("hex_editor_desktop_status")
    names.add("hex_editor_open_desktop")
    names.add("export_binary_analysis")
    return frozenset(names)


def load_tool_catalog(lab_root: Path) -> Dict[str, Dict[str, Any]]:
    from hexeditor_tools.catalog import _definitions

    hex_config = _load_hex_editor_config(lab_root)
    allowed = _enabled_tool_names(hex_config)
    catalog: Dict[str, Dict[str, Any]] = {}
    for name, definition in _definitions().items():
        if name not in allowed:
            continue
        catalog[name] = {
            "name": name,
            "tool_id": f"{name}_{_TOOL_VERSION.replace('.', '_')}",
            "description": definition.get("description", ""),
            "parameters": dict(definition.get("parameters") or {}),
            "effect": definition.get("effect", "unknown"),
            "tags": list(definition.get("tags") or []),
            "function": definition["function"],
        }
    return catalog


def _coerce_value(raw: str, spec: Mapping[str, Any]) -> Any:
    kind = str(spec.get("type") or "string").lower()
    if kind == "integer":
        return int(raw, 0)
    if kind == "boolean":
        normalized = raw.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
        raise ValueError(f"Expected boolean, got {raw!r}")
    return raw


def _build_arguments(
    parameters: Mapping[str, Mapping[str, Any]],
    *,
    json_payload: Mapping[str, Any] | None,
    cli_pairs: Iterable[Tuple[str, str]],
) -> Dict[str, Any]:
    merged: Dict[str, Any] = {}
    if json_payload:
        merged.update(json_payload)

    for key, raw in cli_pairs:
        key = key.replace("-", "_")
        if key not in parameters:
            raise ValueError(f"Unknown parameter {key!r} for this tool")
        merged[key] = _coerce_value(raw, parameters[key])

    arguments: Dict[str, Any] = {}
    for name, spec in parameters.items():
        if name in merged:
            arguments[name] = merged[name]
            continue
        if spec.get("required"):
            raise ValueError(f"Missing required parameter: {name}")
        if "default" in spec:
            arguments[name] = spec["default"]

    extra = set(merged) - set(parameters)
    if extra:
        raise ValueError(f"Unexpected parameters: {', '.join(sorted(extra))}")
    return arguments


def run_tool(
    lab_root: Path,
    tool_name: str,
    arguments: Mapping[str, Any],
) -> Dict[str, Any]:
    catalog = load_tool_catalog(lab_root)
    entry = catalog.get(tool_name)
    if entry is None:
        known = ", ".join(sorted(catalog))
        raise ValueError(f"Unknown or disabled tool {tool_name!r}. Known: {known}")

    function = entry["function"]
    result = function(**dict(arguments))
    if not isinstance(result, dict):
        return {"ok": True, "tool": tool_name, "result": result}
    return result


def list_tools_payload(lab_root: Path) -> Dict[str, Any]:
    catalog = load_tool_catalog(lab_root)
    tools = []
    for name in sorted(catalog):
        entry = catalog[name]
        tools.append(
            {
                "name": name,
                "tool_id": entry["tool_id"],
                "description": entry["description"],
                "effect": entry["effect"],
                "parameters": entry["parameters"],
            }
        )
    return {
        "ok": True,
        "operation": "hex_tool_cli_list",
        "lab_root": str(lab_root.resolve()),
        "tool_count": len(tools),
        "tools": tools,
    }


def describe_tool_payload(lab_root: Path, tool_name: str) -> Dict[str, Any]:
    catalog = load_tool_catalog(lab_root)
    entry = catalog.get(tool_name)
    if entry is None:
        raise ValueError(f"Unknown or disabled tool: {tool_name}")
    return {
        "ok": True,
        "operation": "hex_tool_cli_describe",
        "tool": {
            "name": tool_name,
            "tool_id": entry["tool_id"],
            "description": entry["description"],
            "effect": entry["effect"],
            "tags": entry["tags"],
            "parameters": entry["parameters"],
        },
    }


def _parse_param_pairs(entries: Iterable[str]) -> List[Tuple[str, str]]:
    pairs: List[Tuple[str, str]] = []
    for entry in entries:
        if "=" not in entry:
            raise ValueError(f"--param expects key=value, got {entry!r}")
        key, value = entry.split("=", 1)
        key = key.strip()
        if not key:
            raise ValueError(f"--param expects key=value, got {entry!r}")
        pairs.append((key, value))
    return pairs


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run Hex Editor analysis tools from the shell (same contracts as MCP Tool Registry).",
    )
    parser.add_argument(
        "--project-root", "--lab-root", dest="lab_root",
        default="",
        help="Standalone checkout root (defaults to the installed source location).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="List enabled hex tools and parameters.")

    describe = sub.add_parser("describe", help="Describe one tool.")
    describe.add_argument("tool", help="Tool name, e.g. binary_file_info")

    run = sub.add_parser("run", help="Execute one tool; prints JSON result on stdout.")
    run.add_argument("tool", help="Tool name")
    run.add_argument(
        "--args-json",
        default="",
        help="JSON object of tool arguments (merged with --param key=value).",
    )
    run.add_argument(
        "--param",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="Repeat tool parameter as key=value (overrides --args-json on conflict).",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        if args.lab_root:
            lab_root = Path(args.lab_root).expanduser().resolve()
            if not _is_lab_root(lab_root):
                raise RuntimeError(f"--lab-root is not a valid Hex Editor application root: {lab_root}")
        else:
            lab_root = resolve_lab_root(start=Path.cwd())
        bootstrap_lab_runtime(lab_root)

        if args.command == "list":
            payload = list_tools_payload(lab_root)
            print(json.dumps(payload, indent=2, sort_keys=True, default=str))
            return 0

        if args.command == "describe":
            payload = describe_tool_payload(lab_root, args.tool)
            print(json.dumps(payload, indent=2, sort_keys=True, default=str))
            return 0

        if args.command == "run":
            catalog = load_tool_catalog(lab_root)
            entry = catalog.get(args.tool)
            if entry is None:
                raise ValueError(f"Unknown or disabled tool: {args.tool}")
            json_payload: Dict[str, Any] = {}
            if args.args_json:
                parsed = json.loads(args.args_json)
                if not isinstance(parsed, dict):
                    raise ValueError("--args-json must be a JSON object")
                json_payload = parsed
            cli_pairs = _parse_param_pairs(args.param or [])
            arguments = _build_arguments(
                entry["parameters"],
                json_payload=json_payload,
                cli_pairs=cli_pairs,
            )
            result = run_tool(lab_root, args.tool, arguments)
            print(json.dumps(result, indent=2, sort_keys=True, default=str))
            if result.get("ok") is False:
                return 2
            return 0

        parser.error(f"Unknown command: {args.command}")
        return 2
    except (ValueError, RuntimeError, json.JSONDecodeError, TypeError) as exc:
        error = {"ok": False, "operation": "hex_tool_cli", "error": str(exc)}
        print(json.dumps(error, indent=2, sort_keys=True), file=sys.stderr)
        return 1
    except Exception as exc:  # pragma: no cover - surfaced for operators
        error = {"ok": False, "operation": "hex_tool_cli", "error": repr(exc)}
        print(json.dumps(error, indent=2, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
