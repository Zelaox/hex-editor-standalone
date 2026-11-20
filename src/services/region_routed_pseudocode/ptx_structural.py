"""PTX structural pseudocode from ptx_analyze findings (kind/value, not payload)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Mapping, Sequence


def _safe_name(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch == "_" else "_" for ch in value)


def _finding_name(finding: Mapping[str, Any]) -> str:
    return str(finding.get("label") or finding.get("kind") or "finding")


def _truth_prefix(finding: Mapping[str, Any]) -> str:
    confidence = str(finding.get("confidence") or "observed")
    if confidence == "verified":
        return "verified"
    if confidence in {"heuristic", "inferred"}:
        return "observed"
    return "inconclusive"


def _literal(value: Any, *, max_chars: int = 200) -> str:
    encoded = json.dumps(value, ensure_ascii=False, default=str)
    if max_chars > 0 and len(encoded) > max_chars:
        return json.dumps(encoded[: max(0, max_chars - 3)] + "...", ensure_ascii=False)
    return encoded


def _render_finding(finding: Mapping[str, Any], *, budgets: Mapping[str, Any]) -> List[str]:
    name = _finding_name(finding)
    safe = _safe_name(name)
    prefix = _truth_prefix(finding)
    value = finding.get("value")
    provenance = str(finding.get("provenance") or "")
    lines: List[str] = [f"    /* finding={name} provenance={provenance} */"]

    if name == "header" and isinstance(value, dict):
        for key in ("layout", "magic", "version", "body_encrypted", "session_bit_prefix"):
            if key in value:
                lines.append(f"    {prefix} auto header_{key} = {_literal(value.get(key))};")
        session_strings = value.get("session_strings")
        if isinstance(session_strings, list) and session_strings:
            lines.append(f"    {prefix} size_t session_string_count = {len(session_strings)}U;")
            for index, item in enumerate(session_strings[: int(budgets.get("max_session_strings") or 8)]):
                lines.append(f"    {prefix} string session_string_{index} = {_literal(item)};")
        encryption_info = value.get("encryption_info")
        if isinstance(encryption_info, dict):
            lines.append(f"    {prefix} struct header_encryption_info = /* keys {_literal(sorted(encryption_info.keys()))} */;")
        return lines

    if name == "sections" and isinstance(value, list):
        max_sections = int(budgets.get("max_sections") or 8)
        lines.append(f"    {prefix} size_t section_count = {len(value)}U;")
        for index, section in enumerate(value[:max_sections]):
            if not isinstance(section, dict):
                continue
            lines.append(
                f"    {prefix} struct section_{index} {{ offset = {_literal(section.get('offset'))}; "
                f"type_name = {_literal(section.get('type_name'))}; size = {_literal(section.get('size'))}; }};"
            )
        omitted = max(0, len(value) - max_sections)
        if omitted:
            lines.append(f"    /* sections: {omitted} more omitted by render budget */")
        return lines

    if name == "timecodes" and isinstance(value, list):
        max_timecodes = int(budgets.get("max_timecodes") or 12)
        lines.append(f"    {prefix} size_t timecode_count = {len(value)}U;")
        for index, item in enumerate(value[:max_timecodes]):
            if not isinstance(item, dict):
                continue
            offset = item.get("offset")
            display = item.get("value") or item.get("timecode") or item.get("display")
            off_text = f"0x{int(offset):X}" if isinstance(offset, int) else _literal(offset)
            lines.append(f"    {prefix} struct timecode_{index} {{ offset = {off_text}; value = {_literal(display)}; }};")
        omitted = max(0, len(value) - max_timecodes)
        if omitted:
            lines.append(f"    /* timecodes: {omitted} more omitted by render budget */")
        return lines

    if name == "metadata" and isinstance(value, dict):
        keys = sorted(str(key) for key in value.keys())
        max_keys = int(budgets.get("max_metadata_keys") or 16)
        lines.append(f"    {prefix} struct metadata_keys {{ count = {len(keys)}U; keys = {_literal(keys[:max_keys])}; }};")
        return lines

    if name == "consistency_checks" and isinstance(value, dict):
        lines.append(f"    verified struct consistency_checks = /* {len(value)} check groups */;")
        return lines

    if name == "byte_evidence" and isinstance(value, dict):
        windows = value.get("windows") if isinstance(value.get("windows"), list) else []
        lines.append(f"    verified size_t byte_evidence_window_count = {len(windows)}U;")
        return lines

    if name == "epistemic_state" and isinstance(value, dict):
        lines.append(f"    verified struct epistemic_state = /* policy-compiled state */;")
        return lines

    if isinstance(value, list):
        lines.append(f"    {prefix} array {safe}[{len(value)}] = /* ptx_analyze list */;")
    elif isinstance(value, dict):
        keys = sorted(str(key) for key in value.keys())
        lines.append(f"    {prefix} struct {safe} {{ keys = {_literal(keys[:16])}; }};")
    else:
        lines.append(f"    {prefix} auto {safe} = {_literal(value)};")
    return lines


def append_semantic_plaintext_clusters(
    path: Path,
    data: bytes,
    *,
    policy_path: str,
) -> List[str]:
    from src.services.semantic_pseudocode import (
        _load_plaintext_tiers_policy,
        _render_plaintext_clusters,
        load_semantic_pseudocode_policy,
    )

    rel = Path(policy_path)
    if not rel.is_absolute():
        rel = Path(__file__).resolve().parents[3] / policy_path
    cfg = load_semantic_pseudocode_policy(rel)
    tiers = _load_plaintext_tiers_policy(cfg)
    cluster_lines = _render_plaintext_clusters(data, cfg, tiers_policy=tiers)
    if not cluster_lines:
        return []
    return ["    /* semantic plaintext clusters (same rail as pre-region-routed PTX view) */"] + cluster_lines


def produce_ptx_structural_lines(
    path: Path,
    data: bytes,
    *,
    region_offset: int,
    region_length: int,
    ptx_plugin_cfg: Mapping[str, Any],
) -> List[str]:
    from src.services.ptx_analysis import analyze_ptx

    lines = [
        f"/* structured_data producer format_plugin=ptx @ 0x{region_offset:X}[{region_length}] */",
        "verified struct PTXSessionRegion {",
        f"    verified size_t span_length = {region_length}U;",
    ]
    analysis = analyze_ptx(path)
    if not analysis.get("ok"):
        lines.append(f"    inconclusive string analyze_error = {_literal(analysis.get('error') or 'ptx_analyze failed')};")
        lines.append("}")
        return lines

    budgets = dict(ptx_plugin_cfg.get("render_budgets") or {})
    for finding in analysis.get("findings") or []:
        if isinstance(finding, Mapping):
            lines.extend(_render_finding(finding, budgets=budgets))

    if bool(ptx_plugin_cfg.get("append_semantic_plaintext_clusters")):
        policy_path = str(ptx_plugin_cfg.get("semantic_policy_path") or "config/semantic_pseudocode_policy.json")
        lines.extend(append_semantic_plaintext_clusters(path, data, policy_path=policy_path))

    lines.append("}")
    return lines
