"""PE structural pseudocode for non-executable sections and file-level PE findings."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Mapping


def _literal(value: Any, *, max_chars: int = 180) -> str:
    encoded = json.dumps(value, ensure_ascii=False, default=str)
    if max_chars > 0 and len(encoded) > max_chars:
        return json.dumps(encoded[: max(0, max_chars - 3)] + "...", ensure_ascii=False)
    return encoded


def produce_pe_structural_lines(
    path: Path,
    *,
    region_offset: int,
    region_length: int,
    section_name: str,
    pe_plugin_cfg: Mapping[str, Any],
) -> List[str]:
    lines = [
        f"/* structural_data PE section={section_name} @ 0x{region_offset:X}[{region_length}] */",
        f"verified struct PESectionRegion_{section_name.replace('.', '_')} {{",
        f"    verified size_t span_length = {region_length}U;",
        f"    verified string section_name = {_literal(section_name)};",
    ]
    try:
        import pefile

        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories()
    except Exception as exc:
        lines.append(f"    inconclusive string pe_parse_error = {_literal(str(exc))};")
        lines.append("}")
        return lines

    max_imports = int((pe_plugin_cfg.get("render_budgets") or {}).get("max_import_dlls") or 8)
    max_sections = int((pe_plugin_cfg.get("render_budgets") or {}).get("max_sections") or 16)

    if section_name.lower() == ".idata" or "import" in section_name.lower():
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            dll_count = 0
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                if dll_count >= max_imports:
                    break
                dll = entry.dll.decode("utf-8", errors="replace") if entry.dll else "?"
                lines.append(f"    observed struct import_dll_{dll_count} {{ name = {_literal(dll)}; }};")
                dll_count += 1
            lines.append(f"    observed size_t import_dll_count = {dll_count}U;")

    for index, section in enumerate(pe.sections[:max_sections]):
        name = section.Name.rstrip(b"\x00").decode("ascii", errors="replace")
        if name != section_name:
            continue
        lines.append(f"    verified uint32_t virtual_size = {int(section.Misc_VirtualSize)}U;")
        lines.append(f"    verified uint32_t raw_size = {int(section.SizeOfRawData)}U;")
        lines.append(f"    verified uint32_t raw_ptr = {int(section.PointerToRawData)}U;")
        lines.append(f"    verified string characteristics = {_literal(hex(int(section.Characteristics)))};")
        break

    optional = pe.OPTIONAL_HEADER
    if region_offset == 0 and region_length > 0:
        lines.append(f"    observed struct pe_optional_header_hint {{ entry_rva = 0x{int(optional.AddressOfEntryPoint):X}; image_base = 0x{int(optional.ImageBase):X}; }};")

    lines.append("}")
    return lines
