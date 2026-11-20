"""Application-owned, fail-closed file access for GUI, CLI and MCP."""
from __future__ import annotations

import json
import os
from pathlib import Path

from src.project import project_root


def normalize_input_path(value: str | Path) -> str:
    raw = str(value or '').strip()
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in ('"', "'"):
        raw = raw[1:-1].strip()
    return raw


def get_allowed_roots() -> list[Path]:
    configured = os.environ.get('HEX_EDITOR_WORKSPACE_CONFIG', '').strip()
    config = Path(configured).expanduser().resolve() if configured else project_root() / 'config/workspace_roots.json'
    data = json.loads(config.read_text(encoding='utf-8-sig'))
    return [(project_root() / Path(value).expanduser()).resolve()
            for value in data.get('allowed_roots', []) if str(value).strip()]


def resolve_and_validate(value: str | Path) -> dict:
    raw = normalize_input_path(value)
    if not raw:
        return {'ok': False, 'error': 'Path is required'}
    if '..' in Path(raw).parts:
        return {'ok': False, 'error': 'Path traversal not allowed'}
    try:
        path = Path(raw).expanduser()
        path = (project_root() / path).resolve()
        roots = get_allowed_roots()
    except (OSError, ValueError, TypeError) as exc:
        return {'ok': False, 'error': f'Invalid workspace configuration or path: {exc}'}
    if not roots:
        return {'ok': False, 'error': 'No allowed workspace roots configured'}
    if not any(path.is_relative_to(root) for root in roots):
        return {'ok': False, 'error': 'Path is outside allowed workspace roots', 'path': str(path)}
    return {'ok': True, 'path': path}
