"""Normalize execution events into RuntimeExecutionSnapshot."""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any, Dict, List, Mapping


def build_runtime_execution_snapshot(
    *,
    static_snapshot: Mapping[str, Any],
    backend_result: Mapping[str, Any],
    resolved_policy: Mapping[str, Any],
) -> Dict[str, Any]:
    events = list(backend_result.get("events") or [])
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    source_sha = str((static_snapshot.get("source") or {}).get("sha256") or "")
    for index, event in enumerate(events):
        kind = str(event.get("kind") or "runtime_event")
        nid = f"runtime-{hashlib.sha256(json.dumps(event, sort_keys=True).encode()).hexdigest()[:16]}"
        nodes.append(
            {
                "id": nid,
                "kind": kind,
                "label": kind,
                "confidence": float(1.0 if event.get("confidence") == "observed" else 0.5),
                "evidence_class": "runtime_observed",
                "attributes": dict(event),
                "parser_rule": str(event.get("observation_source") or "execution_trace"),
            }
        )
        static_id = event.get("static_node_id")
        if static_id:
            edges.append(
                {
                    "id": f"merge-{index}",
                    "kind": "runtime_observed_for",
                    "source_id": nid,
                    "target_id": str(static_id),
                    "confidence": 0.9,
                    "evidence": ["execution_merge"],
                }
            )
    execution_id = f"exec-{uuid.uuid4().hex}"
    canonical = json.dumps({"source_sha256": source_sha, "nodes": nodes, "policy": resolved_policy}, sort_keys=True)
    return {
        "schema_version": 1,
        "runtime_execution_id": execution_id,
        "static_snapshot_id": static_snapshot.get("snapshot_id"),
        "backend_id": backend_result.get("backend_id"),
        "policy_mode": resolved_policy.get("mode"),
        "nodes": nodes,
        "edges": edges,
        "events": events,
        "signals": {
            "event_count": len(events),
            "duration_seconds": backend_result.get("duration_seconds"),
            "status": backend_result.get("status") or ("completed" if backend_result.get("ok") else "failed"),
        },
        "runtime_snapshot_id": f"runtime-{hashlib.sha256(canonical.encode()).hexdigest()}",
    }
