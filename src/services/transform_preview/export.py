"""Full-file transform preview export."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Iterator, Mapping

from src.services.transform_preview.inspect import inspect_transform_preview, iter_full_file_preview


def export_full_file_preview(
    source_path: str | Path,
    *,
    mode: str,
    policy: Mapping[str, Any],
    destination: str | Path | None = None,
) -> Dict[str, Any]:
    path = Path(source_path).expanduser().resolve()
    pages = list(iter_full_file_preview(path, mode=mode, policy=policy))
    span_map: list[dict] = []
    diagnostics: list[str] = []
    output_parts: list[bytes] = []
    for page in pages:
        output_parts.append(bytes(page.get("output_bytes") or b""))
        span_map.extend(list(page.get("composite_spans") or []))
        diagnostics.extend(list(page.get("diagnostics") or []))
    combined = b"".join(output_parts)
    uncovered = []
    for page in pages:
        uncovered.extend(list(page.get("coverage_gaps") or []))
    report = {
        "operation": "transform_preview_full_file_export",
        "source_path": str(path),
        "mode": mode,
        "page_count": len(pages),
        "output_length": len(combined),
        "source_sha256": str((pages[0] if pages else {}).get("source_sha256") or ""),
        "span_map": span_map,
        "diagnostics": sorted(set(diagnostics)),
        "coverage_gaps": uncovered,
        "complete": len(uncovered) == 0 and len(pages) > 0,
    }
    if destination is not None:
        dest = Path(destination).expanduser().resolve()
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(combined)
        sidecar = dest.with_suffix(dest.suffix + ".preview-report.json")
        sidecar.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
        report["destination"] = str(dest)
        report["report_path"] = str(sidecar)
    report["output_digest"] = hashlib.sha256(combined).hexdigest()
    return report
