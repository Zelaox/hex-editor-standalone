"""Deterministic synthetic execution trace for tests and sandbox fallback."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Dict, Mapping


def run(
    target_path: Path,
    *,
    static_snapshot: Mapping[str, Any],
    resolved_policy: Mapping[str, Any],
) -> Dict[str, Any]:
    started = time.time()
    events = [
        {
            "kind": "process_start",
            "timestamp": started,
            "observation_source": "stub_runner",
            "confidence": "observed",
        },
        {
            "kind": "module_loaded",
            "module_path": "kernel32.dll",
            "timestamp": started + 0.01,
            "observation_source": "stub_runner",
            "confidence": "observed",
        },
    ]
    entry_nodes = [n for n in static_snapshot.get("nodes") or [] if n.get("kind") == "entry_point"]
    if entry_nodes:
        entry = entry_nodes[0]
        rva = ((entry.get("attributes") or {}).get("entry_rva")) or 0
        events.append(
            {
                "kind": "executed_region",
                "rva": rva,
                "execution_count": 1,
                "timestamp": started + 0.02,
                "observation_source": "stub_runner",
                "static_node_id": entry.get("id"),
                "confidence": "observed",
            }
        )
    import_nodes = [n for n in static_snapshot.get("nodes") or [] if n.get("kind") == "import_symbol"][:1]
    for node in import_nodes:
        events.append(
            {
                "kind": "import_call",
                "label": node.get("label"),
                "static_node_id": node.get("id"),
                "actually_called": True,
                "timestamp": started + 0.03,
                "observation_source": "stub_runner",
                "confidence": "observed",
            }
        )
    events.append({"kind": "process_exit", "exit_code": 0, "timestamp": time.time(), "observation_source": "stub_runner"})
    return {
        "ok": True,
        "backend_id": "stub_runner",
        "events": events,
        "duration_seconds": time.time() - started,
    }
