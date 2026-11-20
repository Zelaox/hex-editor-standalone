"""Structured PE analysis with explicit heuristic provenance."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from src.services.binary_inspection import binary_file_info
from src.services.contracts import AnalysisResult, Finding
from src.services.pe_evidence import enrich_pe_analysis

_PE_SUFFIXES = {".exe", ".dll", ".sys", ".scr"}


def analyze_pe(path: str | Path) -> Dict[str, Any]:
    resolved = Path(path).expanduser().resolve()
    info = binary_file_info(resolved)
    source = info["source"]
    warnings = [
        "PE structures, imports, and exports are inferred via pefile — not a malware verdict.",
        "Do not treat section names or entry points as proof of behavior without byte-backed follow-up.",
    ]
    if resolved.suffix.lower() not in _PE_SUFFIXES:
        return AnalysisResult(
            ok=False,
            operation="pe_analyze",
            source=source,
            warnings=warnings,
            error="File does not look like a PE binary extension",
        ).to_dict()

    try:
        import pefile
    except ImportError as exc:
        return AnalysisResult(
            ok=False,
            operation="pe_analyze",
            source=source,
            warnings=warnings,
            error=f"pefile not available: {exc}",
        ).to_dict()

    try:
        pe = pefile.PE(str(resolved))
    except pefile.PEFormatError as exc:
        return AnalysisResult(
            ok=False,
            operation="pe_analyze",
            source=source,
            warnings=warnings,
            error=f"Not a valid PE file: {exc}",
        ).to_dict()
    except Exception as exc:
        return AnalysisResult(
            ok=False,
            operation="pe_analyze",
            source=source,
            warnings=warnings,
            error=f"PE analysis failed: {exc}",
        ).to_dict()

    optional = pe.OPTIONAL_HEADER
    entry_rva = int(optional.AddressOfEntryPoint)
    entry_section = None
    for section in pe.sections:
        start = int(section.VirtualAddress)
        end = start + int(section.Misc_VirtualSize)
        if start <= entry_rva < end:
            entry_section = section
            break

    pe_header = {
        "e_lfanew": int(pe.DOS_HEADER.e_lfanew),
        "machine": int(pe.FILE_HEADER.Machine),
        "number_of_sections": int(pe.FILE_HEADER.NumberOfSections),
        "timestamp": int(pe.FILE_HEADER.TimeDateStamp),
        "optional_header": {
            "Magic": hex(int(optional.Magic)),
            "AddressOfEntryPoint": entry_rva,
            "ImageBase": int(optional.ImageBase),
            "SizeOfImage": int(optional.SizeOfImage),
            "Subsystem": int(optional.Subsystem),
        },
        "entry_section_name": (
            section.Name.rstrip(b"\x00").decode("ascii", errors="replace") if entry_section else None
        ),
        "is_64bit": int(optional.Magic) == 0x20B,
    }

    sections: List[Dict[str, Any]] = []
    for section in pe.sections[:32]:
        sections.append(
            {
                "name": section.Name.rstrip(b"\x00").decode("ascii", errors="replace"),
                "virtual_address": int(section.VirtualAddress),
                "virtual_size": int(section.Misc_VirtualSize),
                "raw_size": int(section.SizeOfRawData),
                "raw_pointer": int(section.PointerToRawData),
            }
        )

    imports: List[str] = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT[:16]:
            dll = entry.dll.decode("utf-8", errors="replace")
            for imp in entry.imports[:8]:
                if imp.name:
                    imports.append(f"{dll}.{imp.name.decode('utf-8', errors='replace')}")
                elif imp.ordinal is not None:
                    imports.append(f"{dll}.#{imp.ordinal}")

    exports: List[str] = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols[:32]:
            if exp.name:
                exports.append(exp.name.decode("utf-8", errors="replace"))

    findings = [
        Finding("pe_header", pe_header, "pefile.PE", "heuristic").to_dict(),
        Finding("sections", sections, "pefile.PE.sections", "heuristic").to_dict(),
        Finding("imports", imports[:32], "pefile.DIRECTORY_ENTRY_IMPORT", "heuristic").to_dict(),
        Finding("exports", exports[:32], "pefile.DIRECTORY_ENTRY_EXPORT", "heuristic").to_dict(),
    ]
    result = AnalysisResult(
        ok=True,
        operation="pe_analyze",
        source=source,
        findings=findings,
        warnings=warnings,
    ).to_dict()
    return enrich_pe_analysis(result, resolved)
