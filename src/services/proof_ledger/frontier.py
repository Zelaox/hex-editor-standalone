"""Lineage-level Pareto frontier accumulator."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Sequence

from .core import _lineage_dir, _read, _write, load_proof_ledger_bundle


def _axis_values(manifest: Mapping[str, Any], *, ledger_bundle: Mapping[str, Any]) -> Dict[str, int]:
    values: Dict[str, int] = {}
    for axis in ledger_bundle["policy"]["acceptance_axes"]:
        axis_id = str(axis["axis_id"])
        source = str(axis.get("source") or "")
        if source == "manifest.unresolved_bytes":
            values[axis_id] = int(manifest.get("unresolved_bytes") or 0)
        elif source == "manifest.changed_bytes":
            values[axis_id] = int(manifest.get("changed_bytes") or 0)
        elif source == "manifest.reference_metrics.reference_diff_bytes":
            values[axis_id] = int((manifest.get("reference_metrics") or {}).get("reference_diff_bytes") or 0)
        elif source == "coverage.summary.verified_plaintext":
            values[axis_id] = int(manifest.get("proof_owned_changed_bytes") or 0)
        elif source == "ledger.protected_span_count":
            values[axis_id] = int(manifest.get("proof_owned_changed_bytes") or 0)
        else:
            values[axis_id] = 0
    return values


def _dominates(left: Mapping[str, int], right: Mapping[str, int], *, ledger_bundle: Mapping[str, Any]) -> bool:
    axes = list(ledger_bundle["policy"]["acceptance_axes"])
    not_worse = True
    strictly_better = False
    for axis in axes:
        axis_id = str(axis["axis_id"])
        left_value = int(left.get(axis_id) or 0)
        right_value = int(right.get(axis_id) or 0)
        direction = str(axis.get("direction") or "minimize")
        if direction == "maximize":
            if left_value < right_value:
                not_worse = False
            if left_value > right_value:
                strictly_better = True
        else:
            if left_value > right_value:
                not_worse = False
            if left_value < right_value:
                strictly_better = True
    return not_worse and strictly_better


def pareto_frontier(members: Sequence[Mapping[str, Any]], *, ledger_bundle: Mapping[str, Any]) -> List[Dict[str, Any]]:
    frontier: List[Dict[str, Any]] = []
    for candidate in members:
        dominated = False
        for other in members:
            if other is candidate:
                continue
            if _dominates(dict(other.get("axis_values") or {}), dict(candidate.get("axis_values") or {}), ledger_bundle=ledger_bundle):
                dominated = True
                break
        if not dominated:
            frontier.append(dict(candidate))
    return frontier


def accumulate_lineage_frontier(
    lineage_key: str,
    candidate_manifests: Sequence[Mapping[str, Any]],
    *,
    bundle: Mapping[str, Any] | None = None,
) -> Dict[str, Any]:
    bundle = dict(bundle or load_proof_ledger_bundle())
    lineage_dir = _lineage_dir(bundle, lineage_key)
    existing_path = lineage_dir / "frontier.json"
    existing_members: List[Dict[str, Any]] = []
    if existing_path.is_file():
        existing_payload = _read(existing_path)
        existing_members = list(existing_payload.get("members") or [])
    incoming = []
    for manifest in candidate_manifests:
        if not manifest:
            continue
        axis_values = _axis_values(manifest, ledger_bundle=bundle)
        incoming.append(
            {
                "candidate_id": str(manifest.get("candidate_id") or ""),
                "output_sha256": str(manifest.get("output_sha256") or ""),
                "axis_values": axis_values,
                "manifest": dict(manifest),
            }
        )
    combined: Dict[str, Dict[str, Any]] = {str(item.get("candidate_id") or item.get("output_sha256")): item for item in existing_members}
    for item in incoming:
        key = str(item.get("candidate_id") or item.get("output_sha256"))
        combined[key] = item
    members = list(combined.values())
    frontier_members = pareto_frontier(members, ledger_bundle=bundle)
    payload = {
        "schema_version": 1,
        "lineage_key": lineage_key,
        "member_count": len(members),
        "frontier_count": len(frontier_members),
        "members": members,
        "frontier": frontier_members,
    }
    _write(existing_path, payload)
    return payload


def attempt_compatible_union(
    branch_a: bytes,
    branch_b: bytes,
    parent: bytes,
    protected_spans: Sequence[Mapping[str, Any]],
) -> Dict[str, Any]:
    if len(branch_a) != len(branch_b) or len(branch_a) != len(parent):
        return {"ok": False, "reason": "size_mismatch", "bytes": parent}
    desired: Dict[int, int] = {}
    conflicts: List[int] = []
    for index, (left, right, base) in enumerate(zip(branch_a, branch_b, parent)):
        proposals = {value for value in (left, right) if value != base}
        if len(proposals) > 1:
            conflicts.append(index)
            continue
        if proposals:
            desired[index] = next(iter(proposals))
    for record in protected_spans:
        offset, length = int(record["span"]["offset"]), int(record["span"]["length"])
        for index in range(offset, offset + length):
            if index in desired and desired[index] != branch_a[index] and desired[index] != branch_b[index]:
                conflicts.append(index)
    if conflicts:
        return {"ok": False, "reason": "protected_or_byte_conflict", "conflict_count": len(set(conflicts)), "bytes": parent}
    candidate = bytearray(parent)
    for index, value in desired.items():
        candidate[index] = value
    return {"ok": True, "reason": "compatible_union", "bytes": bytes(candidate), "changed_bytes": len(desired)}
