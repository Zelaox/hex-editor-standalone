"""PTX plaintext calibration scan — pytest/script only, not desktop GUI."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Mapping, Sequence

from src.ptx_handler import PTXFile
from src.services.plaintext_runs import discover_printable_runs, discover_repeated_digest_clusters
from src.services.ptx_parse_policy import load_ptx_parse_policy, timecode_regex_patterns


def _root() -> Path:
    return Path(__file__).resolve().parents[2]


def load_calibration_manifest(path: str | Path | None = None) -> Dict[str, Any]:
    target = Path(path).expanduser().resolve() if path else _root() / "config" / "ptx_plaintext_calibration.json"
    manifest = json.loads(target.read_text(encoding="utf-8"))
    if not manifest.get("pytest_only"):
        raise ValueError("ptx plaintext calibration manifest must set pytest_only=true")
    return manifest


def resolve_calibration_bundle_path(bundle: Mapping[str, Any]) -> Path:
    resolve_via = str(bundle.get("resolve_via") or "")
    if resolve_via == "hex_regression_fixtures":
        fixtures_path = _root() / "config" / "hex_regression_fixtures.json"
        fixtures = json.loads(fixtures_path.read_text(encoding="utf-8"))
        bundle_ref = str(bundle.get("fixture_bundle_ref") or "")
        file_role = str(bundle.get("file_role") or "")
        match = next((item for item in fixtures.get("fixture_bundles") or [] if str(item.get("bundle_id")) == bundle_ref), None)
        if match is None:
            raise ValueError(f"unknown fixture bundle: {bundle_ref}")
        files = dict(match.get("files") or {})
        rel = str(files.get(file_role) or "")
        if not rel:
            raise ValueError(f"fixture bundle missing file role: {file_role}")
        root = Path(str(match.get("root") or ""))
        if not root.is_absolute():
            raise ValueError("calibration fixture bundle root must be absolute")
        return (root / rel).resolve()
    raise ValueError(f"unsupported calibration resolve_via: {resolve_via}")


def scan_ptx_plaintext_signals(path: str | Path) -> Dict[str, Any]:
    resolved = Path(path).expanduser().resolve()
    if not resolved.is_file():
        raise ValueError(f"calibration source missing: {resolved}")
    data = resolved.read_bytes()
    policy = load_ptx_parse_policy()
    runs = discover_printable_runs(data)
    clusters = discover_repeated_digest_clusters(
        runs,
        minimum_occurrences=2,
    )
    timecode_hits: List[Dict[str, Any]] = []
    for pattern in timecode_regex_patterns(policy=policy):
        for match in re.finditer(pattern.decode("ascii"), data.decode("latin1", errors="ignore")):
            timecode_hits.append({"offset": match.start(), "value": match.group(0)})
    handler = PTXFile(str(resolved))
    handler.parse()
    return {
        "schema_version": 1,
        "source_path": str(resolved),
        "source_sha256": hashlib.sha256(data).hexdigest(),
        "printable_runs": runs,
        "repeated_digest_clusters": clusters,
        "timecode_hits": timecode_hits,
        "ptx_timecode_count": len(handler.timecodes or []),
        "minimums": {
            "printable_run_count": len(runs),
            "repeated_digest_cluster_count": len(clusters),
            "timecode_hit_count": len(timecode_hits),
            "ptx_timecode_count": len(handler.timecodes or []),
        },
    }


def write_expectations(scan: Mapping[str, Any], output_path: str | Path) -> Path:
    target = Path(output_path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": 1,
        "source_sha256": scan.get("source_sha256"),
        "minimums": dict(scan.get("minimums") or {}),
    }
    target.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return target
