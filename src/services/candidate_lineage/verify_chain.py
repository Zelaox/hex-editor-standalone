"""Cross-rail hash verification for candidate lineage packets."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

from src.services.candidate_lineage.policy import load_candidate_lineage_policy


def _read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _identity_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _node_by_rail(nodes: List[Mapping[str, Any]], rail_id: str) -> Optional[Dict[str, Any]]:
    for node in nodes:
        if str(node.get("rail") or "") == rail_id:
            return dict(node)
    return None


def _resolve_dot_path(source: Mapping[str, Any], path: str) -> Any:
    current: Any = source
    for part in str(path or "").split("."):
        if not part:
            continue
        if not isinstance(current, Mapping):
            return None
        current = current.get(part)
    return current


def _candidate_sha256_from_full_decode(node: Mapping[str, Any]) -> Optional[str]:
    identities = dict(node.get("identities") or {})
    candidate = dict(identities.get("candidate") or {})
    sha = str(candidate.get("sha256") or "")
    if sha:
        return sha
    run = dict(node.get("run") or {})
    artifacts = dict(run.get("artifacts") or {})
    candidate_path = str(artifacts.get("candidate") or "")
    if candidate_path and Path(candidate_path).is_file():
        return _identity_sha256(Path(candidate_path))
    manifest_path = str(artifacts.get("candidate_manifest") or "")
    if manifest_path and Path(manifest_path).is_file():
        manifest = _read_json(Path(manifest_path))
        output_sha = str(manifest.get("output_sha256") or "")
        if output_sha:
            return output_sha
    return None


def _value_for_node(node: Mapping[str, Any], path: str) -> Any:
    rail = str(node.get("rail") or "")
    if path == "run_id":
        return node.get("run_id")
    if path == "upstream_run_id":
        value = node.get("upstream_run_id")
        if value:
            return value
        return _resolve_dot_path(dict(node.get("run") or {}), path)
    if path == "candidate.sha256":
        identities = dict(node.get("identities") or {})
        candidate = dict(identities.get("candidate") or {})
        sha = str(candidate.get("sha256") or "")
        if sha:
            return sha
        if rail == "full_decode":
            return _candidate_sha256_from_full_decode(node)
        return _resolve_dot_path(dict(node.get("run") or {}), path)
    run = dict(node.get("run") or {})
    resolved = _resolve_dot_path(run, path)
    if resolved is not None:
        return resolved
    identities = dict(node.get("identities") or {})
    return _resolve_dot_path(identities, path)


def _identity_hash_checks(nodes: List[Mapping[str, Any]], *, re_read: bool) -> List[Dict[str, Any]]:
    checks: List[Dict[str, Any]] = []
    if not re_read:
        return checks
    for node in nodes:
        run = dict(node.get("run") or {})
        for role, block in (("source", run.get("source")), ("parent", run.get("parent")), ("candidate", run.get("candidate"))):
            if not isinstance(block, Mapping):
                continue
            expected = str(block.get("sha256") or "")
            path_value = str(block.get("path") or "")
            if not expected:
                continue
            label = f"{node.get('rail')}.{role}_bytes"
            if not path_value or not Path(path_value).is_file():
                checks.append(
                    {
                        "label": label,
                        "expected_sha256": expected,
                        "actual_sha256": "",
                        "ok": True,
                        "identity_path_missing": True,
                    }
                )
                continue
            actual = _identity_sha256(Path(path_value))
            checks.append(
                {
                    "label": label,
                    "expected_sha256": expected,
                    "actual_sha256": actual,
                    "ok": actual == expected,
                    "identity_path_missing": False,
                }
            )
        if str(node.get("rail") or "") == "full_decode":
            sha = _candidate_sha256_from_full_decode(node)
            if sha:
                checks.append(
                    {
                        "label": "full_decode.candidate_bytes",
                        "expected_sha256": sha,
                        "actual_sha256": sha,
                        "ok": True,
                        "identity_path_missing": False,
                    }
                )
    return checks


def verify_candidate_lineage_chain(packet: Mapping[str, Any], *, policy_path: str | Path | None = None) -> Dict[str, Any]:
    policy = load_candidate_lineage_policy(policy_path=policy_path)
    nodes = list(packet.get("nodes") or [])
    hash_cfg = dict(policy.get("hash_verification") or {})
    re_read = bool(hash_cfg.get("re_read_identities_on_resolve"))
    hash_checks = _identity_hash_checks(nodes, re_read=re_read)
    edges: List[Dict[str, Any]] = list(packet.get("edges") or [])
    cross_checks = list(hash_cfg.get("cross_rail_checks") or [])
    for spec in cross_checks:
        left = _node_by_rail(nodes, str(spec.get("left_rail") or ""))
        right = _node_by_rail(nodes, str(spec.get("right_rail") or ""))
        check_id = str(spec.get("id") or "")
        left_path = str(spec.get("left_path") or "")
        right_path = str(spec.get("right_path") or "")
        if left is None or right is None:
            hash_checks.append(
                {
                    "label": check_id,
                    "expected_sha256": "",
                    "actual_sha256": "",
                    "ok": True,
                    "skipped": True,
                    "reason": "rail_missing",
                }
            )
            continue
        left_value = _value_for_node(left, left_path)
        right_value = _value_for_node(right, right_path)
        ok = left_value is not None and right_value is not None and str(left_value) == str(right_value)
        hash_checks.append(
            {
                "label": check_id,
                "expected_sha256": str(right_value or ""),
                "actual_sha256": str(left_value or ""),
                "ok": ok,
                "identity_path_missing": False,
                "check_kind": "identity_match" if "sha256" in left_path else "run_link",
                "left_run_id": left.get("run_id"),
                "right_run_id": right.get("run_id"),
            }
        )
        edges.append(
            {
                "kind": "identity_match" if "candidate" in left_path else "upstream_run",
                "field": left_path,
                "left_run_id": left.get("run_id"),
                "right_run_id": right.get("run_id"),
                "ok": ok,
            }
        )
    run_nodes = [node for node in nodes if str(node.get("rail") or "") != "materialization"]
    chain_ok = all(item.get("ok") for item in hash_checks if not item.get("skipped"))
    verified = bool(run_nodes) and all(bool(node.get("verified")) for node in run_nodes)
    return {
        "operation": "candidate_lineage_verify",
        "verified": verified,
        "chain_ok": chain_ok,
        "hash_checks": hash_checks,
        "edges": edges,
        "ok": verified and chain_ok,
    }
