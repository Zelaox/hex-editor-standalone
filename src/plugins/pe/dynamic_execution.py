"""PE dynamic execution orchestrator — policy-driven, never called from parser."""

from __future__ import annotations

import importlib
import json
from pathlib import Path
from typing import Any, Dict, Mapping

from src.plugins.pe.execution_merge import merge_static_runtime
from src.plugins.pe.execution_trace import build_runtime_execution_snapshot
from src.runtime.config import load_execution_policy, resolve_execution_policy


def _lab_root() -> Path:
    from src.project import project_root
    return project_root()


def _load_backend_registry() -> Dict[str, Any]:
    path = _lab_root() / "config" / "execution_backends" / "registry.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _resolve_backend(backend_id: str, mode: str):
    registry = _load_backend_registry()
    for item in registry.get("backends") or []:
        if str(item.get("backend_id")) == backend_id:
            allowed_modes = [str(value) for value in item.get("allowed_modes") or []]
            if mode not in allowed_modes:
                raise ValueError(f"backend {backend_id} does not allow execution mode {mode}")
            module_path = str(item.get("module") or "")
            if not module_path:
                raise ValueError(f"backend {backend_id} missing module")
            return importlib.import_module(module_path), dict(item)
    raise ValueError(f"unknown execution backend: {backend_id}")


def pe_execution_preflight(
    static_snapshot: Mapping[str, Any],
    *,
    policy: Mapping[str, Any] | None = None,
    mode: str | None = None,
) -> Dict[str, Any]:
    if str(static_snapshot.get("format_plugin") or "") != "pe":
        raise ValueError("dynamic execution requires PE static snapshot")
    resolved = resolve_execution_policy(dict(policy or load_execution_policy()), mode=mode)
    backend_id = str(resolved.get("backend_id") or "")
    try:
        _, backend_entry = _resolve_backend(backend_id, str(resolved.get("mode") or ""))
        backend_available = True
        backend_error = ""
    except (ValueError, ImportError) as exc:
        backend_entry = {}
        backend_available = False
        backend_error = str(exc)
    return {
        "ok": backend_available,
        "operation": "pe_execution_preflight",
        "static_snapshot_id": static_snapshot.get("snapshot_id"),
        "resolved_policy": resolved,
        "requires_confirmation": True,
        "launch_allowed": backend_available,
        "backend": backend_entry,
        "status": "ready" if backend_available else "execution_backend_unavailable",
        "error": backend_error,
    }


def pe_execution_run(
    target_path: str | Path,
    static_snapshot: Mapping[str, Any],
    *,
    confirmed: bool = False,
    policy: Mapping[str, Any] | None = None,
    mode: str | None = None,
) -> Dict[str, Any]:
    if not confirmed:
        raise ValueError("pe_execution_run requires explicit confirmation")
    if str(static_snapshot.get("format_plugin") or "") != "pe":
        raise ValueError("dynamic execution requires PE static snapshot")
    resolved = resolve_execution_policy(dict(policy or load_execution_policy()), mode=mode)
    backend_id = str(resolved.get("backend_id") or "")
    try:
        backend, backend_entry = _resolve_backend(backend_id, str(resolved.get("mode") or ""))
    except (ValueError, ImportError) as exc:
        return {"ok": False, "operation": "pe_execution_run", "status": "execution_backend_unavailable", "error": str(exc)}
    target = Path(target_path).expanduser().resolve()
    backend_result = backend.run(target, static_snapshot=static_snapshot, resolved_policy=resolved)
    runtime_snapshot = build_runtime_execution_snapshot(
        static_snapshot=static_snapshot,
        backend_result=backend_result,
        resolved_policy=resolved,
    )
    merge = merge_static_runtime(static_snapshot, runtime_snapshot)
    return {
        "ok": bool(backend_result.get("ok")),
        "operation": "pe_execution_run",
        "backend_id": backend_id,
        "backend_executes_target": bool(backend_entry.get("executes_target", True)),
        "runtime_snapshot": runtime_snapshot,
        "merge": merge,
        "status": runtime_snapshot.get("signals", {}).get("status"),
    }


def pe_execution_get_trace(runtime_snapshot: Mapping[str, Any]) -> Dict[str, Any]:
    """Bounded read-only summary of runtime events — no relaunch."""
    events = list(runtime_snapshot.get("events") or [])
    bounded = events[:256]
    return {
        "ok": True,
        "operation": "pe_execution_get_trace",
        "runtime_snapshot_id": runtime_snapshot.get("runtime_snapshot_id"),
        "static_snapshot_id": runtime_snapshot.get("static_snapshot_id"),
        "event_count": len(events),
        "events": bounded,
        "truncated": len(events) > len(bounded),
        "signals": dict(runtime_snapshot.get("signals") or {}),
    }


def pe_execution_merge_view(
    static_snapshot: Mapping[str, Any],
    runtime_snapshot: Mapping[str, Any],
) -> Dict[str, Any]:
    merge = merge_static_runtime(static_snapshot, runtime_snapshot)
    return {"ok": True, "operation": "pe_execution_merge_view", **merge}
