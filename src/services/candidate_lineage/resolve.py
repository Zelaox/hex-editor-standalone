"""Build candidate lineage packets from discovered rails."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

from src.services.candidate_lineage.discover import discover_materialization_for_identity, discover_verified_run_for_rail
from src.services.candidate_lineage.policy import load_candidate_lineage_policy, selection_limits
from src.services.candidate_lineage.verify_chain import verify_candidate_lineage_chain


def _read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _identity_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _sha256_from_file_or_block(block: Mapping[str, Any]) -> Dict[str, Any]:
    payload = dict(block)
    path_value = str(payload.get("path") or "")
    if path_value and Path(path_value).is_file():
        payload["sha256"] = _identity_sha256(Path(path_value))
    return payload


def _build_full_decode_node(discovery: Mapping[str, Any]) -> Dict[str, Any]:
    run = dict(discovery.get("run") or {})
    inspected = dict(discovery.get("inspected") or {})
    artifacts = dict(run.get("artifacts") or {})
    identities = {
        "source": _sha256_from_file_or_block(dict(run.get("source") or {})),
        "parent": _sha256_from_file_or_block(dict(run.get("parent") or {})),
    }
    candidate_sha = ""
    candidate_path = str(artifacts.get("candidate") or "")
    if candidate_path and Path(candidate_path).is_file():
        candidate_sha = _identity_sha256(Path(candidate_path))
        identities["candidate"] = {"path": candidate_path, "sha256": candidate_sha, "size": Path(candidate_path).stat().st_size}
    manifest_path = str(artifacts.get("candidate_manifest") or "")
    selected_id = str(run.get("selected_candidate_id") or "")
    if manifest_path:
        artifacts_out = {
            "candidate_manifest": manifest_path,
            "decision": str(artifacts.get("decision") or ""),
            "candidate": candidate_path,
        }
    else:
        artifacts_out = {"decision": str(artifacts.get("decision") or ""), "candidate": candidate_path}
    return {
        "rail": "full_decode",
        "run_id": run.get("run_id"),
        "run_path_rel": discovery.get("run_path_rel"),
        "verified": True,
        "status": run.get("status"),
        "identities": identities,
        "selected_candidate_id": selected_id,
        "artifacts": artifacts_out,
        "inspected": inspected,
        "run": run,
    }


def _build_unresolved_node(discovery: Mapping[str, Any]) -> Dict[str, Any]:
    run = dict(discovery.get("run") or {})
    inspected = dict(discovery.get("inspected") or {})
    artifacts = dict(run.get("artifacts") or {})
    graph_summary = dict(inspected.get("graph_summary") or {})
    candidate_manifest = dict(inspected.get("candidate") or {})
    return {
        "rail": "unresolved_inference",
        "run_id": run.get("run_id"),
        "run_path_rel": discovery.get("run_path_rel"),
        "upstream_run_id": run.get("upstream_run_id"),
        "verified": True,
        "status": run.get("status"),
        "identities": {
            "source": _sha256_from_file_or_block(dict(run.get("source") or {})),
            "parent": _sha256_from_file_or_block(dict(run.get("parent") or {})),
            "candidate": _sha256_from_file_or_block(dict(run.get("candidate") or {})),
        },
        "selected_candidate_id": str(candidate_manifest.get("candidate_id") or ""),
        "graph_id": graph_summary.get("graph_id"),
        "artifacts": {
            "semantic_graph": str(artifacts.get("semantic_graph") or ""),
            "semantic_graph_index": str(artifacts.get("semantic_graph_index") or ""),
            "candidate_manifest": str(artifacts.get("candidate_manifest") or ""),
        },
        "inspected": inspected,
        "run": run,
    }


def _build_record_family_node(discovery: Mapping[str, Any]) -> Dict[str, Any]:
    run = dict(discovery.get("run") or {})
    inspected = dict(discovery.get("inspected") or {})
    return {
        "rail": "record_family",
        "run_id": run.get("run_id"),
        "run_path_rel": discovery.get("run_path_rel"),
        "verified": True,
        "status": run.get("status"),
        "identities": {
            "source": _sha256_from_file_or_block(dict(run.get("source") or {})),
            "parent": _sha256_from_file_or_block(dict(run.get("parent") or {})),
        },
        "candidate_ids": list(run.get("candidate_ids") or []),
        "inspected": inspected,
        "run": run,
    }


def _build_materialization_nodes(rows: List[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    nodes: List[Dict[str, Any]] = []
    for row in rows:
        manifest = dict(row.get("manifest") or {})
        nodes.append(
            {
                "rail": "materialization",
                "manifest_path_rel": row.get("manifest_path_rel"),
                "verified": True,
                "source_sha256": row.get("source_sha256"),
                "destination": row.get("destination"),
                "operation": row.get("operation"),
                "manifest": manifest,
            }
        )
    return nodes


def _graph_edges(nodes: List[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    edges: List[Dict[str, Any]] = []
    by_id = {str(node.get("run_id") or ""): node for node in nodes if node.get("run_id")}
    for node in nodes:
        if str(node.get("rail") or "") != "unresolved_inference":
            continue
        upstream = str(node.get("upstream_run_id") or "")
        if upstream and upstream in by_id:
            edges.append({"kind": "upstream_run", "from_run_id": upstream, "to_run_id": node.get("run_id"), "ok": True})
        graph_id = node.get("graph_id")
        if graph_id:
            edges.append({"kind": "graph_for_run", "run_id": node.get("run_id"), "graph_id": graph_id})
    return edges


def _detect_query_role(query_sha256: str, nodes: List[Mapping[str, Any]]) -> str:
    for node in nodes:
        identities = dict(node.get("identities") or {})
        for role, block in identities.items():
            if str(dict(block).get("sha256") or "") == query_sha256:
                return role
        if str(node.get("source_sha256") or "") == query_sha256:
            return "source"
    return "unknown"


def resolve_candidate_lineage(
    *,
    source_sha256: str | None = None,
    file_path: str | Path | None = None,
    policy_path: str | Path | None = None,
    scan_limit: int | None = None,
    artifact_root_override: str | Path | None = None,
) -> Dict[str, Any]:
    policy = load_candidate_lineage_policy(policy_path=policy_path)
    limits = selection_limits(policy=policy)
    limit = int(scan_limit if scan_limit is not None else limits["scan_limit"])
    query_sha = str(source_sha256 or "")
    if not query_sha:
        path = Path(file_path).expanduser().resolve() if file_path else None
        if path is None or not path.is_file():
            return {
                "schema_version": 1,
                "operation": "candidate_lineage_resolve",
                "query_identity": {"sha256": "", "role": "unknown"},
                "verified": False,
                "chain_ok": False,
                "nodes": [],
                "edges": [],
                "hash_checks": [],
                "newest_selector": {"strategy": "mtime_desc", "scan_limit": limit},
            }
        query_sha = _identity_sha256(path)

    nodes: List[Dict[str, Any]] = []
    alternates: List[Dict[str, Any]] = []
    for rail_id in ("full_decode", "unresolved_inference", "record_family"):
        discovery = discover_verified_run_for_rail(
            rail_id,
            query_sha,
            policy=policy,
            scan_limit=limit,
            artifact_root_override=artifact_root_override,
        )
        alternates.extend(list(discovery.get("alternates") or []))
        if not discovery.get("verified"):
            continue
        if rail_id == "full_decode":
            nodes.append(_build_full_decode_node(discovery))
        elif rail_id == "unresolved_inference":
            nodes.append(_build_unresolved_node(discovery))
        else:
            nodes.append(_build_record_family_node(discovery))

    materializations = discover_materialization_for_identity(
        query_sha,
        policy=policy,
        artifact_root_override=artifact_root_override,
    )
    nodes.extend(_build_materialization_nodes(materializations))

    edges = _graph_edges(nodes)
    run_nodes = [node for node in nodes if str(node.get("rail") or "") != "materialization"]
    packet: Dict[str, Any] = {
        "schema_version": 1,
        "operation": "candidate_lineage_resolve",
        "query_identity": {"sha256": query_sha, "role": _detect_query_role(query_sha, nodes)},
        "verified": bool(run_nodes) and all(bool(node.get("verified")) for node in run_nodes),
        "chain_ok": False,
        "nodes": nodes,
        "edges": edges,
        "hash_checks": [],
        "alternates": alternates,
        "newest_selector": {"strategy": "mtime_desc", "scan_limit": limit},
    }
    verification = verify_candidate_lineage_chain(packet, policy_path=policy_path)
    packet["hash_checks"] = verification.get("hash_checks") or []
    for edge in verification.get("edges") or []:
        if edge not in edges:
            edges.append(edge)
    packet["edges"] = edges
    packet["chain_ok"] = bool(verification.get("chain_ok"))
    packet["verified"] = bool(run_nodes) and all(bool(node.get("verified")) for node in run_nodes)
    return packet
