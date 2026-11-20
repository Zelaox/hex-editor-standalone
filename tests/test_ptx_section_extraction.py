from __future__ import annotations

import struct
from pathlib import Path

import pytest

from src.ptx_handler import PTXFile, PTXSection


def _handler_with_section(tmp_path: Path, *, declared_size: int = 20) -> tuple[PTXFile, bytes]:
    payload = b"DATA"
    section_header = struct.pack("<IIII", 1, declared_size, 0, 0)
    source = tmp_path / "sections.ptx"
    source.write_bytes(b"PTX0" + b"\x00" * 28 + section_header + payload)
    handler = PTXFile(str(source))
    handler.sections = [PTXSection(section_header, 32)]
    handler.parsing_complete = True
    return handler, payload


def test_extract_section_data_returns_bytes_and_writes_atomically(tmp_path: Path):
    handler, payload = _handler_with_section(tmp_path)
    assert handler.extract_section_data(0) == payload
    destination = tmp_path / "out" / "section.bin"
    result = handler.extract_section_data(0, str(destination))
    assert result == str(destination.resolve())
    assert destination.read_bytes() == payload
    assert not destination.with_name(f".{destination.name}.tmp").exists()
    handler.close()


def test_extract_section_data_rejects_out_of_bounds(tmp_path: Path):
    handler, _ = _handler_with_section(tmp_path, declared_size=4096)
    with pytest.raises(ValueError, match="bounds exceed"):
        handler.extract_section_data(0, str(tmp_path / "must-not-exist.bin"))
    assert not (tmp_path / "must-not-exist.bin").exists()
    handler.close()
