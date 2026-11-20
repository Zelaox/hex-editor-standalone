"""Local subprocess runner with policy timeout — static modules must not import this for launch."""

from __future__ import annotations

import subprocess
import time
from pathlib import Path
from typing import Any, Dict, Mapping


def run(
    target_path: Path,
    *,
    static_snapshot: Mapping[str, Any],
    resolved_policy: Mapping[str, Any],
) -> Dict[str, Any]:
    if not target_path.is_file():
        return {"ok": False, "error": "target missing", "backend_id": "local_isolated_runner", "events": []}
    max_seconds = max(1, int(resolved_policy.get("max_runtime_seconds") or 30))
    started = time.time()
    events = [
        {
            "kind": "process_start",
            "timestamp": started,
            "observation_source": "local_isolated_runner",
            "confidence": "observed",
        }
    ]
    try:
        completed = subprocess.run(
            [str(target_path)],
            capture_output=True,
            timeout=max_seconds,
            check=False,
        )
        exit_code = int(completed.returncode)
        events.append(
            {
                "kind": "process_exit",
                "exit_code": exit_code,
                "stdout_bytes": len(completed.stdout or b""),
                "stderr_bytes": len(completed.stderr or b""),
                "timestamp": time.time(),
                "observation_source": "local_isolated_runner",
                "confidence": "observed",
            }
        )
    except subprocess.TimeoutExpired:
        events.append(
            {
                "kind": "process_timeout",
                "max_runtime_seconds": max_seconds,
                "timestamp": time.time(),
                "observation_source": "local_isolated_runner",
                "confidence": "observed",
            }
        )
        return {
            "ok": True,
            "backend_id": "local_isolated_runner",
            "events": events,
            "duration_seconds": time.time() - started,
            "status": "timeout",
        }
    except OSError as exc:
        return {"ok": False, "error": str(exc), "backend_id": "local_isolated_runner", "events": events}
    if bool(resolved_policy.get("capture_modules")):
        events.append(
            {
                "kind": "collector_skipped",
                "collector": "capture_modules",
                "message": "Module capture requires external instrumentation; not available in local runner v1",
                "observation_source": "local_isolated_runner",
                "confidence": "inferred",
            }
        )
    return {
        "ok": True,
        "backend_id": "local_isolated_runner",
        "events": events,
        "duration_seconds": time.time() - started,
        "status": "completed",
    }
