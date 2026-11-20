"""Consistency checks and raw byte evidence for heuristic PTX parsing."""

from __future__ import annotations

import binascii
from pathlib import Path
from typing import Any, Dict, List, Mapping, Sequence


def _hex_lines(data: bytes, start_offset: int, bytes_per_line: int = 16) -> List[str]:
    lines: List[str] = []
    for index in range(0, len(data), bytes_per_line):
        chunk = data[index : index + bytes_per_line]
        addr = start_offset + index
        hex_part = " ".join(f"{byte:02x}" for byte in chunk)
        ascii_part = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in chunk)
        lines.append(f"{addr:08x}  {hex_part:<{bytes_per_line * 3}}  {ascii_part}")
    return lines


def format_byte_window(path: Path, offset: int, length: int = 64) -> Dict[str, Any]:
    resolved = path.expanduser().resolve()
    file_size = resolved.stat().st_size
    start = max(0, int(offset))
    end = min(file_size, start + max(1, int(length)))
    with resolved.open("rb") as handle:
        handle.seek(start)
        data = handle.read(end - start)
    return {
        "offset": start,
        "length": len(data),
        "file_size": file_size,
        "hexdump": _hex_lines(data, start),
    }


def build_consistency_checks(
    *,
    file_size: int,
    header: Mapping[str, Any] | None,
    sections: Sequence[Mapping[str, Any]] | None,
    timecodes: Sequence[Mapping[str, Any]] | None,
) -> List[Dict[str, Any]]:
    checks: List[Dict[str, Any]] = []
    header = dict(header or {})
    sections = list(sections or [])
    timecodes = list(timecodes or [])

    layout = str(header.get("layout") or "legacy_binary")
    misaligned = dict(header.get("misaligned_binary_fields") or {})
    header_size = header.get("size")
    if header_size is None:
        header_size = misaligned.get("size")
    encryption_type = header.get("encryption_type")
    if encryption_type is None:
        encryption_type = misaligned.get("encryption_type")

    if isinstance(header_size, int) and header_size != file_size:
        checks.append(
            {
                "code": "header_size_mismatch",
                "severity": "advisory",
                "blocking": False,
                "message": (
                    f"Parser header.size={header_size} but actual file size={file_size}. "
                    "This suggests header field misalignment or wrong endian/structure hypothesis — "
                    "not automatic proof of file corruption."
                ),
                "details": {"header_size": header_size, "file_size": file_size, "layout": layout},
            }
        )

    magic = str(header.get("magic") or "")
    if magic and magic not in {"PTX0", "PTX\x00"} and not magic.startswith("\x03"):
        checks.append(
            {
                "code": "nonstandard_magic",
                "severity": "advisory",
                "blocking": False,
                "message": (
                    f"Magic bytes decode as {magic!r}. .ptx is ambiguous across products; "
                    "treat format identity as unverified until independently confirmed."
                ),
                "details": {"magic": magic},
            }
        )

    if encryption_type not in (None, 0):
        checks.append(
            {
                "code": "encryption_field_unverified",
                "severity": "advisory",
                "blocking": False,
                "message": (
                    f"Parser interprets uint32 at 0x10 as encryption_type={encryption_type}. "
                    "That is not proof of a specific encryption algorithm — only an unverified field label."
                ),
                "details": {"encryption_type": encryption_type, "layout": layout},
            }
        )

    for section in sections[:8]:
        raw_offset = section.get("offset")
        section_size = section.get("size")
        if isinstance(section_size, int) and section_size > file_size:
            checks.append(
                {
                    "code": "section_size_implausible",
                    "severity": "advisory",
                    "blocking": False,
                    "message": (
                        f"Section at {raw_offset} claims size={section_size}, "
                        f"which exceeds file size {file_size}. Likely parser misread."
                    ),
                    "details": {"offset": raw_offset, "size": section_size},
                }
            )

    suspicious_timecodes = [
        item for item in timecodes if str(item.get("value") or "") in {"88:88", "99:99", "00:00"}
    ]
    for item in suspicious_timecodes[:6]:
        checks.append(
            {
                "code": "timecode_regex_hit_unverified",
                "severity": "advisory",
                "blocking": False,
                "message": (
                    f"Timecode-like pattern {item.get('value')!r} at offset {item.get('offset')} "
                    "matched a regex only. It may be random bytes, padding, compressed/encrypted data, "
                    "or a misaligned field — not proof of corruption."
                ),
                "details": {"offset": item.get("offset"), "value": item.get("value")},
            }
        )

    if not checks:
        checks.append(
            {
                "code": "no_obvious_parser_contradiction",
                "severity": "info",
                "blocking": False,
                "message": "No obvious parser contradictions detected by current heuristics.",
                "details": {},
            }
        )
    return checks


def build_byte_evidence(
    path: Path,
    *,
    header_size: int = 32,
    section_offsets: Sequence[int] | None = None,
    timecode_offsets: Sequence[int] | None = None,
    window: int = 48,
) -> List[Dict[str, Any]]:
    evidence: List[Dict[str, Any]] = []
    evidence.append(
        {
            "label": "header_bytes_0x00",
            "hypothesis": "PTX header candidate (32 bytes)",
            "confidence": "heuristic",
            **format_byte_window(path, 0, header_size),
        }
    )
    evidence.append(
        {
            "label": "encryption_field_window_0x10",
            "hypothesis": "Parser maps bytes 0x10-0x13 to encryption_type uint32",
            "confidence": "heuristic",
            **format_byte_window(path, 0x10, 16),
        }
    )
    for offset in list(section_offsets or [])[:4]:
        evidence.append(
            {
                "label": f"section_candidate_{offset}",
                "hypothesis": f"Claimed section header near offset {offset}",
                "confidence": "heuristic",
                **format_byte_window(path, int(offset), window),
            }
        )
    for offset in list(timecode_offsets or [])[:6]:
        evidence.append(
            {
                "label": f"timecode_hit_{offset}",
                "hypothesis": f"Regex timecode hit context near offset {offset}",
                "confidence": "heuristic",
                **format_byte_window(path, max(0, int(offset) - 8), window),
            }
        )
    return evidence


def enrich_ptx_analysis(result: Dict[str, Any], path: Path) -> Dict[str, Any]:
    """Attach consistency checks and byte evidence to a ptx_analyze result."""
    if not result.get("ok"):
        return result

    header_value: Dict[str, Any] = {}
    sections_value: List[Dict[str, Any]] = []
    timecodes_value: List[Dict[str, Any]] = []
    for finding in result.get("findings") or []:
        label = str(finding.get("label") or finding.get("kind") or "")
        value = finding.get("value")
        if label == "header" and isinstance(value, dict):
            header_value = value
        elif label == "sections" and isinstance(value, list):
            sections_value = [item for item in value if isinstance(item, dict)]
        elif label == "timecodes" and isinstance(value, list):
            timecodes_value = [item for item in value if isinstance(item, dict)]

    file_size = int((result.get("source") or {}).get("size") or path.stat().st_size)
    consistency = build_consistency_checks(
        file_size=file_size,
        header=header_value,
        sections=sections_value,
        timecodes=timecodes_value,
    )

    section_offsets: List[int] = []
    for section in sections_value:
        raw = section.get("offset")
        if isinstance(raw, str) and raw.startswith("0x"):
            section_offsets.append(int(raw, 16))
        elif isinstance(raw, int):
            section_offsets.append(raw)

    timecode_offsets = [
        int(item["offset"])
        for item in timecodes_value
        if isinstance(item.get("offset"), int)
    ]

    evidence = build_byte_evidence(
        path,
        section_offsets=section_offsets,
        timecode_offsets=timecode_offsets,
    )

    enriched = dict(result)
    warnings = list(enriched.get("warnings") or [])
    warnings.extend(
        [
            "Findings labeled heuristic/inferred are parser hypotheses — not verified file facts.",
            "Compare each claimed field against the byte evidence windows before drawing conclusions.",
            "Do not equate encryption_type integers with a known encryption algorithm.",
        ]
    )
    enriched["warnings"] = warnings
    enriched["findings"] = list(enriched.get("findings") or []) + [
        {
            "label": "consistency_checks",
            "value": consistency,
            "provenance": "ptx_evidence.build_consistency_checks",
            "confidence": "verified",
        },
        {
            "label": "byte_evidence",
            "value": evidence,
            "provenance": "ptx_evidence.build_byte_evidence",
            "confidence": "verified",
        },
    ]
    try:
        from hexeditor_tools.evidence import (
            compile_epistemic_state_from_ptx_analysis,
        )

        epistemic = compile_epistemic_state_from_ptx_analysis(enriched, byte_evidence=evidence)
        enriched["findings"].append(
            {
                "label": "epistemic_state",
                "value": epistemic,
                "provenance": "hex_epistemic_contract",
                "confidence": "verified",
            }
        )
        enriched["epistemic_state"] = epistemic
    except Exception:
        pass
    return enriched
