"""Rebuild PTX from ptx-section-extract artifact layout."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Mapping

from src.constants import PTX_HEADER_SIZE, PTX_SECTION_HEADER_SIZE
from src.ptx_rebuilder import PTXRebuilder


def _load_sections(extract_dir: Path) -> List[Dict[str, Any]]:
    sections_path = extract_dir / "sections.json"
    if not sections_path.is_file():
        raise FileNotFoundError(f"sections.json missing: {sections_path}")
    entries = json.loads(sections_path.read_text(encoding="utf-8-sig"))
    loaded: List[Dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, Mapping) or entry.get("status") != "extracted":
            continue
        rel = str(entry.get("path") or "")
        blob_path = extract_dir / rel
        if not blob_path.is_file():
            raise FileNotFoundError(f"section blob missing: {blob_path}")
        data = blob_path.read_bytes()
        loaded.append(
            {
                "index": int(entry.get("index") or 0),
                "type": int(entry.get("type") or 0),
                "type_name": str(entry.get("type_name") or "unknown"),
                "data": data,
                "size": len(data),
                "offset": entry.get("offset"),
            }
        )
    loaded.sort(key=lambda item: item["index"])
    return loaded


def rebuild_from_extract_artifact(extract_dir: str | Path, output_path: str | Path, *, encrypt: bool = False) -> Dict[str, Any]:
    root = Path(extract_dir).resolve()
    header_path = root / "header.bin"
    if not header_path.is_file():
        raise FileNotFoundError(f"header.bin missing: {header_path}")
    header_data = header_path.read_bytes()
    if len(header_data) < PTX_HEADER_SIZE:
        raise ValueError("header.bin shorter than PTX_HEADER_SIZE")

    sections = _load_sections(root)
    rebuilder = PTXRebuilder()
    rebuilder.header_data = header_data[:PTX_HEADER_SIZE]
    rebuilder.sections = sections
    timecodes_path = root / "timecodes.json"
    if timecodes_path.is_file():
        rebuilder.timecodes = json.loads(timecodes_path.read_text(encoding="utf-8-sig"))
    metadata_path = root / "metadata.json"
    if metadata_path.is_file():
        meta = json.loads(metadata_path.read_text(encoding="utf-8-sig"))
        rebuilder.metadata = dict(meta.get("metadata") or meta)

    out = Path(output_path).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    if not rebuilder.rebuild(str(out), encrypt=encrypt, encryption_key=None):
        raise RuntimeError("PTX rebuild from extract artifact failed")
    return {"output_path": str(out), "section_count": len(sections), "encrypt": encrypt}
