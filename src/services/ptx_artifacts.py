"""Managed, copy-only exports for binary and PTX analysis artifacts."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from src.constants import PTX_HEADER_SIZE, PTX_SECTION_HEADER_SIZE
from src.services.artifact_store import ArtifactStore
from src.services.binary_inspection import binary_file_info
from src.services.path_utils import resolve_existing_file
from src.services.ptx_analysis import analyze_ptx


def export_analysis(path: str | Path, artifact_root: str | Path) -> Dict[str, Any]:
    source = resolve_existing_file(path)
    store = ArtifactStore(artifact_root, "analysis-export", source)
    try:
        analysis = analyze_ptx(source) if source.suffix.lower() == ".ptx" else binary_file_info(source)
        store.write_json("analysis.json", analysis)
        return store.finalize(
            {
                "analysis_ok": bool(analysis.get("ok")),
                "finding_count": len(analysis.get("findings", [])),
                "warnings": analysis.get("warnings", []),
            }
        )
    except Exception:
        store.abort()
        raise


def extract_ptx_sections(path: str | Path, artifact_root: str | Path) -> Dict[str, Any]:
    source = resolve_existing_file(path)
    if source.suffix.lower() != ".ptx":
        raise ValueError("PTX section extraction requires a .ptx file")
    from src.ptx_handler import PTXFile

    store = ArtifactStore(artifact_root, "ptx-section-extract", source)
    handler = None
    try:
        handler = PTXFile(str(source))
        if not handler.parse():
            raise ValueError("PTX parser rejected the file or could not parse it")
        store.write_bytes("header.bin", handler.file_cache.get_data(0, min(PTX_HEADER_SIZE, handler.file_size)))
        section_details = []
        for index, section in enumerate(handler.sections):
            data_size = section.size - PTX_SECTION_HEADER_SIZE
            data_end = section.data_offset + data_size
            if data_size < 0 or data_end > handler.file_size:
                section_details.append(
                    {"index": index, "status": "skipped", "reason": "section bounds exceed source"}
                )
                continue
            name = f"sections/section_{index:04d}.bin"
            data = handler.file_cache.get_data(section.data_offset, data_size)
            store.write_bytes(name, data)
            section_details.append(
                {
                    "index": index,
                    "status": "extracted",
                    "path": name,
                    "type": section.type,
                    "type_name": section.get_section_type_name(),
                    "offset": section.offset,
                    "data_offset": section.data_offset,
                    "size": data_size,
                }
            )
        store.write_json("metadata.json", handler.metadata)
        store.write_json("timecodes.json", handler.timecodes)
        store.write_json("sections.json", section_details)
        return store.finalize(
            {
                "parser": "PTXFile",
                "confidence": "heuristic",
                "section_count": len(handler.sections),
                "extracted_section_count": sum(item["status"] == "extracted" for item in section_details),
                "skipped_section_count": sum(item["status"] == "skipped" for item in section_details),
                "warnings": ["PTX section boundaries are reverse-engineered heuristics."],
            }
        )
    except Exception:
        store.abort()
        raise
    finally:
        if handler is not None:
            handler.close()
