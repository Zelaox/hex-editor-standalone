"""Policy-driven discovery of verified runs and materialization manifests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

from src.services.candidate_lineage.policy import (
    artifact_root,
    import_rail_callable,
    load_candidate_lineage_policy,
    rail_artifact_dir,
    selection_limits,
)
from src.services.materialization_manifest import discover_materialization_manifests


def _read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _identity_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _run_matches_identity(run: Mapping[str, Any], query_sha256: str, identity_roles: List[str]) -> Optional[str]:
    for role in identity_roles:
        block = dict(run.get(role) or {})
        sha = str(block.get("sha256") or "")
        if sha and sha == query_sha256:
            return role
    return None


def discover_verified_run_for_rail(
    rail_id: str,
    query_sha256: str,
    *,
    policy: Mapping[str, Any] | None = None,
    scan_limit: int | None = None,
    artifact_root_override: str | Path | None = None,
) -> Dict[str, Any]:
    """Return newest verified run + inspect payload for one rail, or empty dict."""
    if not query_sha256:
        return {}
    bundle = dict(policy or load_candidate_lineage_policy())
    limits = selection_limits(policy=bundle)
    limit = int(scan_limit if scan_limit is not None else limits["scan_limit"])
    rail = next((item for item in bundle.get("rails") or [] if str(item.get("rail_id") or "") == rail_id), None)
    if rail is None:
        return {}
    base = rail_artifact_dir(rail, policy=bundle, artifact_root_override=artifact_root_override)
    if not base.is_dir():
        return {}
    run_glob = str(rail.get("run_glob") or "*/run.json")
    paths = sorted(base.glob(run_glob), key=lambda item: item.stat().st_mtime_ns, reverse=True)[: max(1, limit)]
    verify = import_rail_callable(rail, "verify_callable")
    inspect = import_rail_callable(rail, "inspect_callable")
    identity_roles = list(rail.get("identity_roles") or [])
    root = artifact_root(policy=bundle, override=artifact_root_override)
    alternates: List[Dict[str, Any]] = []
    for path in paths:
        try:
            run = _read_json(path)
        except (OSError, json.JSONDecodeError):
            continue
        matched_role = _run_matches_identity(run, query_sha256, identity_roles)
        if matched_role is None:
            continue
        verified = verify(path)
        if not verified.get("ok"):
            alternates.append({"run_id": run.get("run_id"), "verified": False, "run_path": str(path.resolve())})
            continue
        inspected = inspect(path)
        if not inspected.get("verified"):
            alternates.append({"run_id": run.get("run_id"), "verified": False, "run_path": str(path.resolve())})
            continue
        try:
            rel = path.resolve().relative_to(root).as_posix()
        except ValueError:
            rel = path.name
        return {
            "rail": rail_id,
            "run_id": run.get("run_id"),
            "run_path": str(path.resolve()),
            "run_path_rel": rel,
            "matched_role": matched_role,
            "verified": True,
            "status": run.get("status"),
            "run": run,
            "inspected": inspected,
            "verification": verified,
            "alternates": alternates,
        }
    return {}


def discover_materialization_for_identity(
    query_sha256: str,
    *,
    policy: Mapping[str, Any] | None = None,
    artifact_root_override: str | Path | None = None,
) -> List[Dict[str, Any]]:
    if not query_sha256:
        return []
    bundle = dict(policy or load_candidate_lineage_policy())
    materialization = dict(bundle.get("materialization") or {})
    under = str(materialization.get("under_subdir") or "")
    operation = str(materialization.get("manifest_operation") or "")
    if not under:
        return []
    manifests = discover_materialization_manifests(source_sha256=query_sha256, under_subdir=under)
    if operation:
        manifests = [item for item in manifests if str(item.get("operation") or "") == operation]
    rows: List[Dict[str, Any]] = []
    root = artifact_root(policy=bundle, override=artifact_root_override)
    for manifest in manifests:
        manifest_path = Path(str(manifest.get("manifest_path") or ""))
        try:
            rel = manifest_path.relative_to(root).as_posix()
        except ValueError:
            rel = manifest_path.name
        rows.append(
            {
                "rail": "materialization",
                "manifest_path": str(manifest_path.resolve()),
                "manifest_path_rel": rel,
                "source_sha256": str(manifest.get("source_sha256") or ""),
                "destination": str(manifest.get("destination") or ""),
                "operation": str(manifest.get("operation") or ""),
                "manifest": manifest,
            }
        )
    return rows
