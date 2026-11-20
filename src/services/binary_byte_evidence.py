"""Raw byte window formatting for PE/binary evidence."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List


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