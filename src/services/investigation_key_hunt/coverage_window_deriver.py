"""Derive probe windows from investigation snapshot and calibration case evidence."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Mapping, Optional, Sequence


def _digest(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _clip_window(
    *,
    name: str,
    offset: int,
    length: int,
    role: str,
    evidence_refs: Sequence[str],
    file_size: int,
    min_length: int,
) -> Optional[Dict[str, Any]]:
    start = max(0, int(offset))
    end = min(int(file_size), start + max(int(length), int(min_length)))
    if start >= file_size or end <= start or (end - start) < int(min_length):
        return None
    return {
        "name": str(name),
        "offset": start,
        "length": end - start,
        "role": str(role),
        "evidence_refs": sorted(str(item) for item in evidence_refs),
    }


def _case_evidence_windows(
    case: Optional[Mapping[str, Any]],
    *,
    roles: Sequence[str],
    file_size: int,
    default_length: int,
    min_length: int,
) -> List[Dict[str, Any]]:
    if not case:
        return []
    allowed = {str(item) for item in roles}
    output: List[Dict[str, Any]] = []
    decrypt = dict(case.get("decrypt") or {})
    for item in decrypt.get("evidence_windows") or []:
        if not isinstance(item, dict):
            continue
        role = str(item.get("role") or "")
        if role not in allowed:
            continue
        window = _clip_window(
            name=str(item.get("name") or role),
            offset=int(item.get("offset") or 0),
            length=int(item.get("length") or default_length),
            role=role,
            evidence_refs=[f"case.decrypt.evidence_windows.{item.get('name') or role}"],
            file_size=file_size,
            min_length=min_length,
        )
        if window:
            output.append(window)
    return output


def _unknown_region_windows(
    snapshot_brief: Mapping[str, Any],
    *,
    derivation: Mapping[str, Any],
    file_size: int,
    max_regions: int,
) -> List[Dict[str, Any]]:
    max_printable = float(derivation["max_printable_ratio_for_cipher_sample"])
    min_entropy = float(derivation["min_entropy_for_unknown_region"])
    default_length = int(derivation["default_window_length"])
    min_length = int(derivation["min_window_length"])
    excluded_roles = {str(item) for item in derivation.get("exclude_unknown_roles") or []}
    regions = list(snapshot_brief.get("top_unknown_regions") or [])
    scored: List[tuple[float, Dict[str, Any]]] = []
    for region in regions:
        if not isinstance(region, dict):
            continue
        features = dict(region.get("features") or {})
        printable = float(features.get("printable_ratio") or 0.0)
        entropy = float(features.get("entropy") or 0.0)
        if printable > max_printable:
            continue
        if entropy < min_entropy:
            continue
        span = dict(region.get("span") or {})
        region_id = str(region.get("region_id") or "")
        role = str(region.get("role") or "unknown")
        if role in excluded_roles:
            continue
        window = _clip_window(
            name=f"unknown-{region_id}" if region_id else f"unknown-{span.get('offset')}",
            offset=int(span.get("offset") or 0),
            length=int(span.get("length") or default_length),
            role=role,
            evidence_refs=[f"snapshot_brief.top_unknown_regions.{region_id or _digest(span)}"],
            file_size=file_size,
            min_length=min_length,
        )
        if window:
            scored.append((entropy, window))
    scored.sort(key=lambda item: (-item[0], item[1]["offset"]))
    return [item[1] for item in scored[: max(0, int(max_regions))]]


def derive_coverage_windows(
    bundle: Mapping[str, Any],
    *,
    policy: Mapping[str, Any],
    case: Optional[Mapping[str, Any]] = None,
    file_size: int | None = None,
) -> Dict[str, Any]:
    derivation = dict(policy.get("window_derivation") or {})
    size = int(file_size if file_size is not None else bundle.get("source_size") or 0)
    if size <= 0:
        raise ValueError("derive_coverage_windows requires positive file_size")
    brief = dict(bundle.get("snapshot_brief") or {})
    roles = list(derivation.get("case_evidence_roles") or [])
    min_length = int(derivation["min_window_length"])
    default_length = int(derivation["default_window_length"])
    max_regions = int((policy.get("budgets") or {}).get("max_unknown_regions") or 0)
    case_windows = _case_evidence_windows(case, roles=roles, file_size=size, default_length=default_length, min_length=min_length)
    unknown_windows = _unknown_region_windows(brief, derivation=derivation, file_size=size, max_regions=max_regions)
    ordered: List[Dict[str, Any]] = []
    seen: set[tuple[int, int]] = set()
    sequences = [case_windows, unknown_windows] if derivation.get("prefer_case_evidence_first") else [unknown_windows, case_windows]
    for group in sequences:
        for window in group:
            key = (int(window["offset"]), int(window["length"]))
            if key in seen:
                continue
            seen.add(key)
            ordered.append(window)
    if not ordered:
        raise ValueError("blocked_by_policy: no probe windows derivable from investigation evidence")
    artifact = {
        "schema_version": 1,
        "operation": "investigation_derived_probe_windows",
        "investigation_id": str(bundle.get("investigation_id") or ""),
        "source_sha256": str(bundle.get("source_sha256") or ""),
        "source_size": size,
        "policy_digest": str(policy.get("policy_digest") or ""),
        "windows": ordered,
    }
    artifact["artifact_digest"] = _digest({key: value for key, value in artifact.items() if key != "artifact_digest"})
    return artifact
