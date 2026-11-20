"""Compatible one-change PTX experiment diff with mechanical evidence only."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Mapping

from src.services.binary_snapshot_diff import diff_binary_snapshots


def _validate_manifest(manifest: Mapping[str, Any], left: Mapping[str, Any], right: Mapping[str, Any]) -> None:
    required = ("schema_version", "baseline_sha256", "variant_sha256", "operation", "expected_change")
    if any(key not in manifest for key in required):
        raise ValueError("experiment manifest is incomplete")
    if int(manifest["schema_version"]) != 1:
        raise ValueError("experiment manifest schema unsupported")
    if str(manifest["baseline_sha256"]) != str((left.get("source") or {}).get("sha256")) or str(manifest["variant_sha256"]) != str((right.get("source") or {}).get("sha256")):
        raise ValueError("experiment manifest source hashes do not match snapshots")


def structural_experiment_diff(left: Mapping[str, Any], right: Mapping[str, Any], manifest: Mapping[str, Any]) -> Dict[str, Any]:
    _validate_manifest(manifest, left, right)
    diff = diff_binary_snapshots(left, right)
    descriptor = {"manifest": dict(manifest), "left_snapshot_id": left.get("snapshot_id"), "right_snapshot_id": right.get("snapshot_id"), "compatibility": diff["compatibility"]}
    experiment_id = "experiment-" + hashlib.sha256(json.dumps(descriptor, sort_keys=True, default=str).encode("utf-8")).hexdigest()
    changed = list((diff.get("parsed") or {}).get("changed_node_ids") or []) if diff.get("status") == "compared" else []
    return {"ok": diff.get("status") == "compared", "operation": "ptx_structural_experiment_diff", "experiment_id": experiment_id, "manifest": dict(manifest), "compatibility": diff["compatibility"], "field_candidates": [{"node_id": node_id, "evidence_level": "candidate", "promotion_allowed": False} for node_id in changed], "diff": diff, "mechanical_authority": True, "model_role": "advisory_only"}


def load_experiment_manifest(path: str | Path) -> Dict[str, Any]:
    return json.loads(Path(path).expanduser().resolve().read_text(encoding="utf-8"))
