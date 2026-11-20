"""Presenter rows for Binary Inspector candidate lineage sections."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping


def present_lineage_overview_rows(packet: Mapping[str, Any]) -> List[tuple[str, Any]]:
    if not packet:
        return [("status", "not_run")]
    return [
        ("chain_ok", packet.get("chain_ok")),
        ("verified", packet.get("verified")),
        ("query_role", (packet.get("query_identity") or {}).get("role")),
        ("node_count", len(packet.get("nodes") or [])),
        ("edge_count", len(packet.get("edges") or [])),
    ]


def present_lineage_rail_rows(packet: Mapping[str, Any]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for node in packet.get("nodes") or []:
        rail = str(node.get("rail") or "")
        if rail == "materialization":
            rows.append(
                {
                    "rail": rail,
                    "run_id": "",
                    "status": node.get("operation") or "manifest",
                    "verified": node.get("verified"),
                    "candidate_id": node.get("destination") or "",
                    "graph_id": "",
                    "upstream": "",
                }
            )
            continue
        candidate_id = str(node.get("selected_candidate_id") or "")
        if not candidate_id and node.get("candidate_ids"):
            candidate_id = ",".join(str(item) for item in node.get("candidate_ids") or [])
        rows.append(
            {
                "rail": rail,
                "run_id": node.get("run_id") or "",
                "status": node.get("status") or "",
                "verified": node.get("verified"),
                "candidate_id": candidate_id,
                "graph_id": node.get("graph_id") or "",
                "upstream": node.get("upstream_run_id") or "",
            }
        )
    return rows


def present_lineage_hash_rows(packet: Mapping[str, Any]) -> List[Dict[str, Any]]:
    return [
        {
            "label": item.get("label"),
            "ok": item.get("ok"),
            "expected": item.get("expected_sha256"),
            "actual": item.get("actual_sha256"),
            "path_missing": item.get("identity_path_missing"),
        }
        for item in packet.get("hash_checks") or []
    ]


def present_lineage_file_match(*, file_sha256: str, packet: Mapping[str, Any]) -> Dict[str, Any]:
    query = dict(packet.get("query_identity") or {})
    lineage_sha = str(query.get("sha256") or "")
    role = str(query.get("role") or "unknown")
    matched = bool(file_sha256 and lineage_sha and file_sha256 == lineage_sha)
    graph_id = ""
    for node in packet.get("nodes") or []:
        if str(node.get("rail") or "") == "unresolved_inference":
            graph_id = str(node.get("graph_id") or "")
            break
    return {
        "file_sha256": file_sha256,
        "lineage_sha256": lineage_sha,
        "matched": matched,
        "role": role,
        "graph_id": graph_id,
        "chain_ok": packet.get("chain_ok"),
        "verified": packet.get("verified"),
    }


def present_lineage_verify_message(
    *,
    file_path: str,
    file_sha256: str,
    packet: Mapping[str, Any],
    verification: Mapping[str, Any],
) -> str:
    match = present_lineage_file_match(file_sha256=file_sha256, packet=packet)
    lines = [
        f"File: {file_path}",
        f"File SHA-256: {file_sha256}",
        f"Lineage match: {'YES' if match.get('matched') else 'NO'} (role={match.get('role')})",
        f"chain_ok={verification.get('chain_ok')} verified={verification.get('verified')}",
    ]
    if match.get("graph_id"):
        lines.append(f"Binary semantic graph: {match.get('graph_id')}")
    lines.append("")
    for item in verification.get("hash_checks") or []:
        status = "ok" if item.get("ok") else "FAIL"
        if item.get("skipped"):
            lines.append(f"{status} {item.get('label')}: skipped ({item.get('reason')})")
            continue
        kind = str(item.get("check_kind") or "hash")
        if kind == "run_link":
            lines.append(
                f"{status} {item.get('label')}: left={item.get('actual_sha256')} right={item.get('expected_sha256')}"
            )
        else:
            lines.append(
                f"{status} {item.get('label')}: expected={item.get('expected_sha256')} actual={item.get('actual_sha256')}"
            )
    if match.get("matched") and match.get("graph_id"):
        lines.append("")
        lines.append("Open Binary Inspector → Binary graph tab to browse the semantic graph.")
    return "\n".join(lines)


def present_lineage_candidate_rows(packet: Mapping[str, Any]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for node in packet.get("nodes") or []:
        rail = str(node.get("rail") or "")
        if rail == "materialization":
            rows.append(
                {
                    "rail": rail,
                    "candidate_id": node.get("destination") or "",
                    "run_id": "",
                    "graph_id": "",
                    "sha256": node.get("source_sha256") or "",
                }
            )
            continue
        identities = dict(node.get("identities") or {})
        candidate = dict(identities.get("candidate") or {})
        candidate_ids = list(node.get("candidate_ids") or [])
        if candidate_ids:
            for candidate_id in candidate_ids:
                rows.append(
                    {
                        "rail": rail,
                        "candidate_id": candidate_id,
                        "run_id": node.get("run_id") or "",
                        "graph_id": node.get("graph_id") or "",
                        "sha256": candidate.get("sha256") or "",
                    }
                )
        else:
            rows.append(
                {
                    "rail": rail,
                    "candidate_id": node.get("selected_candidate_id") or "",
                    "run_id": node.get("run_id") or "",
                    "graph_id": node.get("graph_id") or "",
                    "sha256": candidate.get("sha256") or "",
                }
            )
    return rows
