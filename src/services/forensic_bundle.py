"""Export preserved-binary forensic bundles and structural findings."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Mapping, Sequence

from jsonschema import Draft202012Validator


def _root() -> Path:
    return Path(__file__).resolve().parents[2]


def _read(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, default=str) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def _segment_lookup(coverage: Mapping[str, Any]) -> Dict[str, Mapping[str, Any]]:
    return {str(item["segment_id"]): item for item in coverage.get("segments") or []}


def compile_structural_findings(
    *,
    run_id: str,
    source_sha256: str,
    spans: Sequence[Mapping[str, Any]],
    boundaries: Sequence[Mapping[str, Any]],
    representations: Sequence[Mapping[str, Any]],
    dependencies: Mapping[str, Any],
    coverage: Mapping[str, Any],
    proofs: Sequence[Mapping[str, Any]],
) -> List[Dict[str, Any]]:
    segments = _segment_lookup(coverage)
    boundary_by_span = {str(item["span_id"]): item for item in boundaries}
    structural_spans = {
        str(item["span_id"])
        for item in proofs
        if str((item.get("gate_statuses") or {}).get("structural_metadata")) == "passed"
    }
    rows: List[Dict[str, Any]] = []
    for edge in dependencies.get("edges") or []:
        if str(edge.get("edge_type")) != "length_of" or str(edge.get("state")) != "verified":
            continue
        span_id = str(edge.get("source_span_id"))
        if span_id not in structural_spans:
            continue
        span = next((item for item in spans if str(item["span_id"]) == span_id), None)
        if not span:
            continue
        representation = next((item for item in representations if item.get("representation_id") == edge.get("representation_id")), None)
        target = segments.get(str(edge.get("target_segment_id")))
        boundary = boundary_by_span.get(span_id)
        verified_roles: List[str] = []
        if representation:
            verified_roles.append(
                f"length_field width={int(representation['width'])} value={int(representation['value'])} endian={representation.get('endian')}"
            )
        rows.append(
            {
                "span_id": span_id,
                "offset": int(span["offset"]),
                "length": int(span["length"]),
                "verified_roles": verified_roles,
                "dependency_ids": [str(edge["dependency_id"])],
                "neighbor_segment_ids": [
                    value
                    for value in (
                        (boundary or {}).get("left_segment_id"),
                        (boundary or {}).get("right_segment_id"),
                    )
                    if value
                ],
                "target_segment": {
                    "segment_id": str(target["segment_id"]) if target else None,
                    "class": str(target.get("class")) if target else None,
                    "offset": int(target["offset"]) if target else None,
                    "length": int(target["length"]) if target else None,
                },
            }
        )
    return rows


def _structural_metadata_summary(
    findings: Sequence[Mapping[str, Any]],
    overlay: Mapping[str, Any],
    representations: Sequence[Mapping[str, Any]],
) -> Dict[str, Any]:
    structural_span_ids = {str(item["span_id"]) for item in findings}
    owned_preserved = int((overlay.get("summary") or {}).get("owned_preserved_binary") or 0)
    verified_length_field_bytes = 0
    for item in representations:
        if str(item.get("span_id")) not in structural_span_ids:
            continue
        if str(item.get("state")) != "tested":
            continue
        verified_length_field_bytes += int(item.get("width") or 0)
    span_bytes = sum(int(item["length"]) for item in findings)
    return {
        "owned_preserved_bytes": owned_preserved,
        "structural_span_count": len(structural_span_ids),
        "structural_span_bytes": span_bytes,
        "verified_length_field_bytes": verified_length_field_bytes,
        "span_tail_unknown_bytes": max(0, span_bytes - verified_length_field_bytes),
        "verified_length_of_count": len(findings),
    }


def export_preserved_forensic_bundle(
    preserved_run_path: str | Path,
    *,
    full_decode_run_path: str | Path | None = None,
) -> Dict[str, Any]:
    from src.services.preserved_binary_inference import verify_preserved_binary_inference_run

    path = Path(preserved_run_path).resolve()
    run_file = path / "run.json" if path.is_dir() else path
    if not verify_preserved_binary_inference_run(run_file).get("ok"):
        raise ValueError("preserved run failed verification")
    run = _read(run_file)
    root = Path(run["run_root"]).resolve()
    artifacts = run["artifacts"]
    spans = _read(Path(artifacts["preserved_baseline"]))
    boundaries = _read(Path(artifacts["boundaries"]))
    representations = _read(Path(artifacts["representations"]))
    dependencies = _read(Path(artifacts["dependency_graph"]))
    proofs = _read(Path(artifacts["ownership_proofs"]))
    overlay = _read(Path(artifacts["ownership_overlay"]))

    upstream_id = str(run.get("upstream_run_id") or "")
    from src.services.full_decode import verify_full_decode_run

    fd_run_file: Path | None = None
    if full_decode_run_path:
        candidate = Path(full_decode_run_path).resolve()
        fd_run_file = candidate if candidate.name == "run.json" else candidate / "run.json"
    else:
        search_root = _root() / "data" / "artifacts" / "hex_editor"
        for run_json in search_root.rglob("run.json"):
            try:
                upstream = _read(run_json)
            except (OSError, json.JSONDecodeError):
                continue
            if str(upstream.get("run_id")) != upstream_id:
                continue
            if verify_full_decode_run(run_json).get("ok"):
                fd_run_file = run_json
                break
    if not fd_run_file or not fd_run_file.is_file():
        raise ValueError("full-decode run path could not be resolved for knowledge metrics")
    fd_run = _read(fd_run_file)
    fd_coverage = _read(Path(fd_run["artifacts"]["coverage"]))

    findings = compile_structural_findings(
        run_id=str(run["run_id"]),
        source_sha256=str(run["source"]["sha256"]),
        spans=spans,
        boundaries=boundaries,
        representations=representations,
        dependencies=dependencies,
        coverage=fd_coverage,
        proofs=proofs,
    )
    summary = _structural_metadata_summary(findings, overlay, representations)

    from src.services.forensic_knowledge_metrics import compile_knowledge_coverage_from_runs

    knowledge = compile_knowledge_coverage_from_runs(fd_run_file, run_file)

    bundle_root = root / "exports" / "forensic_bundle"
    bundle_root.mkdir(parents=True, exist_ok=True)
    manifest = {
        "schema_version": 1,
        "preserved_run_id": run["run_id"],
        "upstream_full_decode_run_id": upstream_id,
        "source_sha256": run["source"]["sha256"],
        "paths": {},
    }
    paths = {
        "findings.json": bundle_root / "findings.json",
        "structural_metadata_summary.json": bundle_root / "structural_metadata_summary.json",
        "detector_results.json": bundle_root / "detector_results.json",
        "metrics/knowledge_coverage.json": bundle_root / "metrics" / "knowledge_coverage.json",
    }
    _write(paths["findings.json"], {"schema_version": 1, "findings": findings, "finding_count": len(findings)})
    _write(paths["structural_metadata_summary.json"], {"schema_version": 1, **summary})
    _write(
        paths["detector_results.json"],
        {
            "schema_version": 1,
            "identity": str(Path(artifacts["identity"])),
            "boundaries": str(Path(artifacts["boundaries"])),
            "representations": str(Path(artifacts["representations"])),
            "dependency_graph": str(Path(artifacts["dependency_graph"])),
            "ownership_proofs": str(Path(artifacts["ownership_proofs"])),
            "ownership_overlay": str(Path(artifacts["ownership_overlay"])),
        },
    )
    _write(paths["metrics/knowledge_coverage.json"], knowledge)
    for key, value in paths.items():
        manifest["paths"][key] = str(value.resolve())
    manifest["digest"] = _digest(manifest)
    _write(bundle_root / "manifest.json", manifest)

    _write_finding_ledger_records(run, findings)

    return {
        "bundle_root": str(bundle_root),
        "manifest_path": str(bundle_root / "manifest.json"),
        "knowledge_coverage_path": str(paths["metrics/knowledge_coverage.json"]),
        "finding_count": len(findings),
        "manifest": manifest,
    }


def _write_finding_ledger_records(run: Mapping[str, Any], findings: Sequence[Mapping[str, Any]]) -> None:
    from src.services.preserved_binary_inference.core import load_preserved_bundle
    from src.services.record_family.core import FindingLedger

    bundle = load_preserved_bundle()
    ledger_cfg = dict(bundle["policy"].get("finding_ledger") or {})
    if not ledger_cfg:
        return
    ledger_root = (_root() / str(ledger_cfg["root"])).resolve()
    ledger = FindingLedger(ledger_root, {"policy": {"finding_ledger": ledger_cfg}})
    run_id = str(run["run_id"])
    source_sha = str(run["source"]["sha256"])
    for row in findings:
        ledger.add(
            kind="structural_length_of",
            state="experimental_verified",
            source_sha256=source_sha,
            span={"offset": int(row["offset"]), "length": int(row["length"])},
            producer={"run_id": run_id, "artifact": "preserved_binary_inference"},
            evidence_refs=list(row.get("dependency_ids") or []),
            summary="Verified adjacent length_of preserved prefix",
        )
    ledger.rebuild_indexes()


def render_structural_pseudocode_lines(findings_path: str | Path, source: bytes, *, policy: Mapping[str, Any]) -> List[str]:
    payload = _read(Path(findings_path).resolve())
    findings = list(payload.get("findings") or [])
    if not findings:
        return []
    templates = dict(policy.get("structural_findings") or {})
    template_id = str(templates.get("record_prefix_template_id") or "record_prefix_length_of")
    lines = [f"/* structural_findings template={template_id} count={len(findings)} */"]
    for row in sorted(findings, key=lambda item: int(item["offset"])):
        offset = int(row["offset"])
        length = int(row["length"])
        prefix = source[offset : offset + length]
        role = (row.get("verified_roles") or [""])[0]
        lines.append(f"struct preserved_record_prefix /* 0x{offset:X} len={length} */ {{")
        if role.startswith("length_field"):
            first = prefix[0] if prefix else 0
            lines.append(f"    verified uint8 payload_length = {first}; /* {role} */")
        if length > 1:
            tail = prefix[1:]
            lines.append(f"    byte field_unknown[{len(tail)}] = {{ {_byte_hex(tail)} }};")
        deps = ", ".join(str(item) for item in row.get("dependency_ids") or [])
        lines.append(f"}}; /* evidence: {deps} */")
    return lines


def _byte_hex(data: bytes) -> str:
    return ", ".join(f"0x{value:02X}" for value in data)
