"""PE virtual-address to file-offset mapping (no hardcoded section names)."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, Optional


def file_offset_for_virtual_address(path: Path, virtual_address: int) -> Optional[int]:
    import pefile

    pe = pefile.PE(str(path), fast_load=True)
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    rva = int(virtual_address) - image_base
    if rva < 0:
        return None
    for section in pe.sections:
        va_start = image_base + int(section.VirtualAddress)
        va_end = va_start + max(int(section.Misc_VirtualSize), int(section.SizeOfRawData))
        if va_start <= int(virtual_address) < va_end:
            raw_start = int(section.PointerToRawData)
            return raw_start + (int(virtual_address) - va_start)
    return None


def build_va_to_file_map(path: Path) -> Dict[int, int]:
    import pefile

    mapping: Dict[int, int] = {}
    pe = pefile.PE(str(path), fast_load=True)
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    for section in pe.sections:
        raw_start = int(section.PointerToRawData)
        raw_size = int(section.SizeOfRawData)
        if raw_size <= 0:
            continue
        va_start = image_base + int(section.VirtualAddress)
        for delta in range(raw_size):
            mapping[va_start + delta] = raw_start + delta
    return mapping
