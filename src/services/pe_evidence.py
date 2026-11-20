"""Byte evidence and consistency checks for heuristic PE parsing."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Mapping, Sequence

from src.services.binary_byte_evidence import format_byte_window


def build_pe_consistency_checks(
    *,
    file_size: int,
    pe_info: Mapping[str, Any] | None,
) -> List[Dict[str, Any]]:
    checks: List[Dict[str, Any]] = []
    info = dict(pe_info or {})
    optional = dict(info.get("optional_header") or {})

    size_of_image = optional.get("SizeOfImage")
    if isinstance(size_of_image, int) and size_of_image > file_size * 64:
        checks.append(
            {
                "code": "size_of_image_implausible",
                "severity": "advisory",
                "blocking": False,
                "message": (
                    f"OptionalHeader.SizeOfImage={size_of_image} is far larger than file size={file_size}. "
                    "Treat mapped-image fields as parser hypotheses until byte-backed."
                ),
            }
        )

    entry_rva = optional.get("AddressOfEntryPoint")
    if entry_rva is not None and not info.get("entry_section_name"):
        checks.append(
            {
                "code": "entry_section_unresolved",
                "severity": "advisory",
                "blocking": False,
                "message": (
                    f"Entry point RVA 0x{int(entry_rva):X} did not resolve to a section — "
                    "disassembly may fail or be misaligned."
                ),
            }
        )

    machine = optional.get("Machine")
    if machine and machine not in {0x014C, 0x8664, 0x0200}:
        checks.append(
            {
                "code": "nonstandard_machine",
                "severity": "advisory",
                "blocking": False,
                "message": f"Machine type 0x{int(machine):04X} is uncommon — verify architecture before disasm.",
            }
        )
    return checks


def build_byte_evidence(path: Path, pe_info: Mapping[str, Any] | None = None) -> List[Dict[str, Any]]:
    resolved = path.expanduser().resolve()
    windows: List[Dict[str, Any]] = []
    windows.append({**format_byte_window(resolved, 0, 64), "label": "dos_header_mz"})
    try:
        e_lfanew = int((pe_info or {}).get("e_lfanew") or 0)
    except (TypeError, ValueError):
        e_lfanew = 0
    if e_lfanew > 0:
        windows.append(
            {
                **format_byte_window(resolved, max(0, e_lfanew - 4), 64),
                "label": "pe_signature_window",
            }
        )
    return windows


def enrich_pe_analysis(result: Dict[str, Any], path: Path) -> Dict[str, Any]:
    if not result.get("ok"):
        return result
    pe_info = {}
    for finding in result.get("findings") or []:
        if str(finding.get("label") or finding.get("kind") or "") == "pe_header":
            pe_info = dict(finding.get("value") or {})
            break
    file_size = int((result.get("source") or {}).get("size") or path.stat().st_size)
    checks = build_pe_consistency_checks(file_size=file_size, pe_info=pe_info)
    evidence = build_byte_evidence(path, pe_info)
    findings = list(result.get("findings") or [])
    findings.append({"label": "consistency_checks", "value": checks, "confidence": "verified", "provenance": "pe_evidence"})
    findings.append({"label": "byte_evidence", "value": evidence, "confidence": "verified", "provenance": "pe_evidence"})
    result = dict(result)
    result["findings"] = findings
    return result
