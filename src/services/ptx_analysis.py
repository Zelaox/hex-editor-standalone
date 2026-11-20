"""Structured PTX analysis with explicit heuristic provenance."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from src.runtime.config import load_binary_dynamic_config
from src.runtime.format_router import detect_format_plugin
from src.services.binary_inspection import binary_file_info
from src.services.contracts import AnalysisResult, Finding
from src.services.ptx_evidence import enrich_ptx_analysis


def analyze_ptx(path: str | Path) -> Dict[str, Any]:
    resolved = Path(path).expanduser().resolve()
    info = binary_file_info(resolved)
    source = info["source"]
    warnings = [
        "PTX structures and timecodes are inferred from reverse-engineering heuristics.",
        "Do not treat this result as an authoritative PTX format specification.",
    ]
    if detect_format_plugin(resolved, cfg=load_binary_dynamic_config()) != "ptx":
        return AnalysisResult(
            ok=False,
            operation="ptx_analyze",
            source=source,
            warnings=warnings,
            error="File is not a PTX-shaped binary",
        ).to_dict()

    from src.ptx_handler import PTXFile

    handler = None
    try:
        handler = PTXFile(str(resolved))
        if not handler.parse():
            return AnalysisResult(
                ok=False,
                operation="ptx_analyze",
                source=source,
                warnings=warnings,
                error="PTX parser rejected the file or could not parse it",
            ).to_dict()

        findings = []
        if handler.header:
            findings.append(Finding("header", handler.header.to_dict(), "PTXHeader", "inferred").to_dict())
        findings.append(
            Finding(
                "sections",
                [section.to_dict() for section in handler.sections],
                "PTXFile._parse_sections",
                "heuristic",
            ).to_dict()
        )
        findings.append(
            Finding("timecodes", handler.timecodes, "PTXFile._extract_timecodes", "heuristic").to_dict()
        )
        findings.append(
            Finding("metadata", handler.metadata, "PTXFile._extract_metadata", "heuristic").to_dict()
        )
        result = AnalysisResult(
            ok=True,
            operation="ptx_analyze",
            source=source,
            findings=findings,
            warnings=warnings,
        ).to_dict()
        return enrich_ptx_analysis(result, resolved)
    except Exception as exc:
        return AnalysisResult(
            ok=False,
            operation="ptx_analyze",
            source=source,
            warnings=warnings,
            error=f"PTX analysis failed: {exc}",
        ).to_dict()
    finally:
        if handler is not None and handler.file_cache:
            handler.file_cache.close()
