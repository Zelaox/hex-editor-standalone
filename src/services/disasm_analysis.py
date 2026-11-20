"""Bounded, headless PE disassembly via Capstone — no Qt dependency."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from src.services.binary_inspection import binary_file_info
from src.services.contracts import AnalysisResult, Finding

DEFAULT_MAX_INSTRUCTIONS = 96
HARD_MAX_INSTRUCTIONS = 512
_PE_SUFFIXES = {".exe", ".dll", ".sys", ".scr"}


def disasm_pe_entry(path: str | Path, *, max_instructions: int = DEFAULT_MAX_INSTRUCTIONS) -> Dict[str, Any]:
    resolved = Path(path).expanduser().resolve()
    info = binary_file_info(resolved)
    source = info["source"]
    warnings = [
        "Disassembly is bounded and starts at the PE entry point — not full binary coverage.",
        "Mnemonics are observations at mapped RVAs; control-flow meaning stays hypothetical.",
    ]
    limit = max(1, min(int(max_instructions), HARD_MAX_INSTRUCTIONS))

    if resolved.suffix.lower() not in _PE_SUFFIXES:
        return AnalysisResult(
            ok=False,
            operation="disasm_readonly",
            source=source,
            warnings=warnings,
            error="Disassembly plugin requires a PE file extension",
        ).to_dict()

    try:
        import pefile
        from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs
    except ImportError as exc:
        return AnalysisResult(
            ok=False,
            operation="disasm_readonly",
            source=source,
            warnings=warnings,
            error=f"pefile/capstone not available: {exc}",
        ).to_dict()

    try:
        pe = pefile.PE(str(resolved), fast_load=True)
    except pefile.PEFormatError as exc:
        return AnalysisResult(
            ok=False,
            operation="disasm_readonly",
            source=source,
            warnings=warnings,
            error=f"Not a valid PE file: {exc}",
        ).to_dict()

    is_64 = pe.OPTIONAL_HEADER.Magic == 0x20B
    md = Cs(CS_ARCH_X86, CS_MODE_64 if is_64 else CS_MODE_32)
    md.detail = False
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    entry_rva = int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    mapped = pe.get_memory_mapped_image()
    code = mapped[entry_rva : entry_rva + 0x1000]

    instructions: List[Dict[str, Any]] = []
    for idx, (address, size, mnemonic, op_str) in enumerate(md.disasm_lite(code, image_base + entry_rva)):
        if idx >= limit:
            break
        instructions.append(
            {
                "address": hex(int(address)),
                "size": int(size),
                "mnemonic": str(mnemonic),
                "operands": str(op_str),
            }
        )

    if not instructions:
        return AnalysisResult(
            ok=False,
            operation="disasm_readonly",
            source=source,
            warnings=warnings,
            error="No instructions disassembled at entry point",
        ).to_dict()

    findings = [
        Finding(
            "disasm_entry",
            {
                "architecture": "x86_64" if is_64 else "x86",
                "image_base": hex(image_base),
                "entry_rva": hex(entry_rva),
                "instruction_count": len(instructions),
                "instructions": instructions,
            },
            "capstone.disasm_lite",
            "verified",
        ).to_dict()
    ]
    return AnalysisResult(
        ok=True,
        operation="disasm_readonly",
        source=source,
        findings=findings,
        warnings=warnings,
    ).to_dict()
