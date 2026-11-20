"""PTX pipeline orchestration: bind → analyze → extract → graph → export."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from src.services.artifact_store import ArtifactStore
from src.services.path_utils import resolve_existing_file
from src.services.ptx_artifacts import extract_ptx_sections
from src.services.ptx_export import run_export
from src.services.ptx_parse_result import build_parse_result
from src.services.ptx_pipeline_policy import pipeline_artifact_root
from src.services.ptx_session_graph import compile_session_graph
from src.services.ptx_source_resolver import resolve_ptx_source


def _read_spec(path: str | Path) -> Dict[str, Any]:
    resolved = Path(path).expanduser().resolve()
    payload = json.loads(resolved.read_text(encoding="utf-8-sig"))
    if not isinstance(payload, dict):
        raise ValueError("spec file must contain a JSON object")
    return payload


def run_bind(spec: Mapping[str, Any], *, artifact_root: str | Path | None = None) -> Dict[str, Any]:
    binding = resolve_ptx_source(spec)
    root = Path(artifact_root).resolve() if artifact_root else pipeline_artifact_root()
    source = resolve_existing_file(binding["bound_path"])
    store = ArtifactStore(root, "ptx-pipeline-bind", source)
    try:
        store.write_json("source_binding.json", binding)
        return store.finalize({"stage": "bind", "binding_kind": binding["binding_kind"]})
    except Exception:
        store.abort()
        raise


def run_analyze(
    binding: Mapping[str, Any],
    *,
    artifact_root: str | Path | None = None,
) -> Dict[str, Any]:
    root = Path(artifact_root).resolve() if artifact_root else pipeline_artifact_root()
    source = resolve_existing_file(str(binding["bound_path"]))
    parse_result = build_parse_result(source)
    store = ArtifactStore(root, "ptx-pipeline-analyze", source)
    try:
        store.write_json("source_binding.json", dict(binding))
        store.write_json("parse_result.json", parse_result)
        return store.finalize(
            {
                "stage": "analyze",
                "parse_ok": parse_result.get("ok"),
                "section_count": len(parse_result.get("sections") or []),
                "timecode_count": len(parse_result.get("timecodes") or []),
            }
        )
    except Exception:
        store.abort()
        raise


def run_extract(
    binding: Mapping[str, Any],
    *,
    artifact_root: str | Path | None = None,
) -> Dict[str, Any]:
    root = Path(artifact_root).resolve() if artifact_root else pipeline_artifact_root()
    source = resolve_existing_file(str(binding["bound_path"]))
    outcome = extract_ptx_sections(source, root)
    return {**outcome, "stage": "extract"}


def run_graph(
    binding: Mapping[str, Any],
    *,
    parse_artifact_dir: str | Path | None = None,
    extract_artifact_dir: str | Path | None = None,
    artifact_root: str | Path | None = None,
) -> Dict[str, Any]:
    root = Path(artifact_root).resolve() if artifact_root else pipeline_artifact_root()
    source = resolve_existing_file(str(binding["bound_path"]))
    parse_dir = Path(parse_artifact_dir).resolve() if parse_artifact_dir else None
    parse_result_path = (parse_dir / "parse_result.json") if parse_dir else None
    if parse_result_path and parse_result_path.is_file():
        parse_result = json.loads(parse_result_path.read_text(encoding="utf-8-sig"))
    else:
        parse_result = build_parse_result(source)

    sections_manifest: Optional[Dict[str, Any]] = None
    if extract_artifact_dir:
        manifest_path = Path(extract_artifact_dir).resolve() / "manifest.json"
        if manifest_path.is_file():
            sections_manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))

    graph = compile_session_graph(binding=binding, parse_result=parse_result, sections_manifest=sections_manifest)
    store = ArtifactStore(root, "ptx-pipeline-graph", source)
    try:
        store.write_json("source_binding.json", dict(binding))
        store.write_json("parse_result.json", parse_result)
        store.write_json("session_graph.json", graph)
        details: Dict[str, Any] = {
            "stage": "graph",
            "snapshot_id": graph.get("snapshot_id"),
        }
        if extract_artifact_dir:
            details["extract_artifact_directory"] = str(Path(extract_artifact_dir).resolve())
        return store.finalize(details)
    except Exception:
        store.abort()
        raise


def run_pipeline(
    spec: Mapping[str, Any],
    *,
    stages: Optional[list[str]] = None,
    artifact_root: str | Path | None = None,
    export_format: str | None = None,
) -> Dict[str, Any]:
    wanted = [item.strip().lower() for item in (stages or ["bind", "analyze", "extract", "graph"])]
    binding = resolve_ptx_source(spec)
    results: Dict[str, Any] = {"binding": binding, "stages": {}}

    if "bind" in wanted:
        results["stages"]["bind"] = run_bind(spec, artifact_root=artifact_root)
        binding = json.loads(
            Path(results["stages"]["bind"]["artifact_directory"], "source_binding.json").read_text(encoding="utf-8-sig")
        )

    parse_dir = None
    extract_dir = None
    graph_dir = None

    if "analyze" in wanted:
        results["stages"]["analyze"] = run_analyze(binding, artifact_root=artifact_root)
        parse_dir = results["stages"]["analyze"]["artifact_directory"]

    if "extract" in wanted:
        results["stages"]["extract"] = run_extract(binding, artifact_root=artifact_root)
        extract_dir = results["stages"]["extract"]["artifact_directory"]

    if "graph" in wanted:
        results["stages"]["graph"] = run_graph(
            binding,
            parse_artifact_dir=parse_dir,
            extract_artifact_dir=extract_dir,
            artifact_root=artifact_root,
        )
        graph_dir = results["stages"]["graph"]["artifact_directory"]

    if export_format:
        if not graph_dir:
            results["stages"]["graph"] = run_graph(
                binding,
                parse_artifact_dir=parse_dir,
                extract_artifact_dir=extract_dir,
                artifact_root=artifact_root,
            )
            graph_dir = results["stages"]["graph"]["artifact_directory"]
        results["stages"]["export"] = run_export(
            graph_artifact_dir=graph_dir,
            export_format=export_format,
            artifact_root=artifact_root,
        )

    results["ok"] = True
    return results


def load_spec_file(path: str | Path) -> Dict[str, Any]:
    return _read_spec(path)
