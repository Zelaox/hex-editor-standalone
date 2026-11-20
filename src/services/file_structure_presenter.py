"""Build File Structure dock items from parse results, DB cache, and artifacts."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple


StructureItem = Tuple[str, Optional[int]]


def _truncate_preview(text: str, limit: int) -> str:
    if limit <= 0 or len(text) <= limit:
        return text
    return text[: max(0, limit - 1)] + "…"


def cached_source_summary(source_sha256: str) -> List[StructureItem]:
    if not source_sha256:
        return []
    try:
        from src.services.learning_db import lookup_parser_coverage

        row = lookup_parser_coverage(source_sha256)
    except Exception:
        return []
    if not row:
        return []
    items: List[StructureItem] = [
        ("DB cache (parser):", None),
        (f"  unknown_bytes: {row.get('unknown_bytes')}", None),
        (f"  coverage_complete: {row.get('coverage_complete')}", None),
    ]
    if row.get("timecode_count") is not None:
        items.append((f"  timecode_count: {row.get('timecode_count')}", None))
    if row.get("plaintext_run_count") is not None:
        items.append((f"  plaintext_run_count: {row.get('plaintext_run_count')}", None))
    return items


def plaintext_run_items(file_path: str, *, preview_limit: int) -> List[StructureItem]:
    if not file_path:
        return []
    try:
        from src.services.plaintext_runs import discover_printable_runs_for_path

        runs = discover_printable_runs_for_path(file_path)
    except Exception:
        return []
    if not runs:
        return []
    items: List[StructureItem] = [("Plaintext runs:", None)]
    for row in runs[:256]:
        preview = _truncate_preview(str(row.get("preview") or ""), preview_limit)
        items.append((f"  0x{int(row['offset']):X} [{int(row['length'])}]: {preview}", int(row["offset"])))
    if len(runs) > 256:
        items.append((f"  … {len(runs) - 256} more runs omitted", None))
    return items


def preserved_binary_items(source_sha256: str) -> List[StructureItem]:
    if not source_sha256:
        return []
    try:
        from src.services.learning_db import discover_rail_run_via_learning_db

        discovery = discover_rail_run_via_learning_db("preserved_binary_inference", source_sha256)
    except Exception:
        discovery = None
    if not discovery:
        return []
    inspected = dict(discovery.get("inspected") or {})
    decision = dict(inspected.get("decision") or {})
    candidate = dict(inspected.get("candidate") or {})
    run = dict(discovery.get("run") or {})
    artifacts = dict(run.get("artifacts") or {})
    items: List[StructureItem] = [
        ("Preserved ownership:", None),
        (f"  owned_preserved_bytes: {decision.get('owned_preserved_bytes')}", None),
        (f"  unowned_preserved_bytes: {decision.get('unowned_preserved_bytes')}", None),
        (f"  structural_metadata_bytes: {candidate.get('structural_metadata_bytes')}", None),
    ]
    summary_path = Path(str(artifacts.get("forensic_bundle_manifest") or "")).parent / "structural_metadata_summary.json"
    if not summary_path.is_file() and artifacts.get("forensic_bundle"):
        summary_path = Path(str(artifacts["forensic_bundle"])) / "structural_metadata_summary.json"
    if summary_path.is_file():
        try:
            import json

            summary = json.loads(summary_path.read_text(encoding="utf-8-sig"))
            items.append((f"  verified_length_of_count: {summary.get('verified_length_of_count')}", None))
            items.append((f"  verified_length_field_bytes: {summary.get('verified_length_field_bytes')}", None))
        except (OSError, json.JSONDecodeError, ValueError):
            pass
    bundle_root = artifacts.get("forensic_bundle")
    if bundle_root:
        items.append((f"  forensic_bundle: {bundle_root}", None))
    return items


def knowledge_metrics_items(source_sha256: str) -> List[StructureItem]:
    if not source_sha256:
        return []
    try:
        from src.services.forensic_knowledge_metrics import (
            load_forensic_knowledge_metrics_policy,
            load_knowledge_coverage_for_source,
        )

        payload = load_knowledge_coverage_for_source(source_sha256)
        if not payload:
            return []
        labels = dict(load_forensic_knowledge_metrics_policy()["policy"]["display_labels"])
        percentages = dict(payload.get("percentages") or {})
    except Exception:
        return []
    items: List[StructureItem] = [("Forensic knowledge (bytes):", None)]
    for key in ("byte_ownership", "structural_knowledge", "semantic_knowledge", "plaintext_readable"):
        label = str(labels.get(key) or key)
        value = percentages.get(key)
        if value is None:
            continue
        items.append((f"  {label}: {value}%", None))
    return items


def record_family_items(source_sha256: str) -> List[StructureItem]:
    if not source_sha256:
        return []
    inspected: Mapping[str, Any] | None = None
    try:
        from src.services.learning_db import discover_rail_run_via_learning_db

        discovery = discover_rail_run_via_learning_db("record_family", source_sha256)
        inspected = discovery.get("inspected") if discovery else None
    except Exception:
        inspected = None
    if not inspected:
        return []
    families = list(inspected.get("families") or [])
    if not families:
        return []
    items: List[StructureItem] = [("Record families:", None)]
    for family in families:
        family_id = str(family.get("family_id") or "family")
        occurrences = list(family.get("occurrences") or [])
        items.append((f"  {family_id} ({len(occurrences)} occurrences)", None))
        for occurrence in occurrences[:32]:
            offset = int(occurrence.get("offset") or 0)
            length = int(occurrence.get("length") or 0)
            role = str(occurrence.get("role") or "")
            label = f"    {role} 0x{offset:X}[{length}]" if role else f"    0x{offset:X}[{length}]"
            items.append((label, offset))
    return items


def handler_structure_items(file_handler, *, preview_limit: int) -> List[StructureItem]:
    items: List[StructureItem] = []
    if file_handler is None:
        return items
    if hasattr(file_handler, "parsing_complete") and not file_handler.parsing_complete:
        file_handler.parse()
    if hasattr(file_handler, "sections"):
        for index, section in enumerate(file_handler.sections):
            items.append((f"Section {index}: {section.get_section_type_name()}", int(section.data_offset)))
    if hasattr(file_handler, "timecodes"):
        for tc in file_handler.timecodes:
            label = f"Timecode: {tc.get('value', 'Unknown')}"
            if tc.get("reference_point", False):
                label = f"Reference {label}"
            items.append((label, int(tc.get("offset") or 0)))
    if hasattr(file_handler, "file_path") and file_handler.file_path:
        items.extend(plaintext_run_items(str(file_handler.file_path), preview_limit=preview_limit))
    return items
