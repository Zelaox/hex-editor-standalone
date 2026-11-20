"""Export PTX session graphs to downstream formats (policy-gated)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Mapping

from src.services.artifact_store import ArtifactStore, file_identity
from src.services.ptx_rebuild_from_extract import rebuild_from_extract_artifact
from src.services.path_utils import resolve_existing_file
from src.services.ptx_pipeline_policy import load_ptx_converter_policy, load_ptx_pipeline_policy, pipeline_artifact_root


def _verified_clips(graph: Mapping[str, Any]) -> list:
    verified = dict(graph.get("verified_facts") or {})
    clips = verified.get("audio_clips")
    if isinstance(clips, list):
        return clips
    return []


def export_ptx_rebuild(
    *,
    graph: Mapping[str, Any],
    extract_artifact_dir: str | Path,
    artifact_root: str | Path,
    output_name: str = "rebuilt.ptx",
) -> Dict[str, Any]:
    converter = load_ptx_converter_policy()
    ptx_cfg = dict((converter.get("formats") or {}).get("ptx_rebuild") or {})
    if not ptx_cfg.get("enabled", True):
        raise ValueError("ptx_rebuild export disabled by ptx_converter_policy")

    extract_dir = Path(extract_artifact_dir).resolve()
    if not extract_dir.is_dir():
        raise ValueError(f"extract artifact directory missing: {extract_dir}")

    manifest_path = extract_dir / "manifest.json"
    if not manifest_path.is_file():
        raise ValueError(f"extract manifest missing: {manifest_path}")

    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    source_path = resolve_existing_file(str((manifest.get("source_before") or {}).get("path") or ""))

    store = ArtifactStore(artifact_root, "ptx-pipeline-export", source_path)
    try:
        out_path = store.staging / output_name
        encrypt = bool(ptx_cfg.get("encrypt_default", False))
        rebuild_from_extract_artifact(extract_dir, out_path, encrypt=encrypt)
        store.write_json("session_graph.json", dict(graph))
        experiment = {
            "schema_version": 1,
            "baseline_sha256": file_identity(source_path)["sha256"],
            "variant_sha256": file_identity(out_path)["sha256"],
            "operation": "ptx_rebuild",
            "expected_change": {"kind": "rebuild_from_extract", "encrypt": encrypt},
        }
        store.write_json("experiment_manifest.json", experiment)
        return store.finalize(
            {
                "export_format": "ptx",
                "output_file": output_name,
                "encrypt": encrypt,
                "baseline_sha256": experiment["baseline_sha256"],
                "variant_sha256": experiment["variant_sha256"],
            }
        )
    except Exception:
        store.abort()
        raise


def export_cpr_or_studio_one(
    *,
    graph: Mapping[str, Any],
    artifact_root: str | Path,
    output_format: str,
    output_name: str,
) -> Dict[str, Any]:
    converter = load_ptx_converter_policy()
    if not converter.get("enabled"):
        raise ValueError("ptx_converter disabled by policy (enabled=false)")
    fmt_cfg = dict((converter.get("formats") or {}).get(output_format) or {})
    if not fmt_cfg.get("enabled"):
        raise ValueError(f"export format disabled: {output_format}")
    if fmt_cfg.get("require_verified_clips") and not _verified_clips(graph):
        raise ValueError("no verified audio clips in session graph; CPR/Studio One export refused")

    binding_path = str((graph.get("source") or {}).get("path") or "")
    if not binding_path:
        raise ValueError("session graph missing source.path")
    source_path = resolve_existing_file(binding_path)
    store = ArtifactStore(artifact_root, "ptx-pipeline-export", source_path)
    try:
        from ptx_converter.formats.cpr_format import convert_to_cpr
        from ptx_converter.formats.studio_one_format import convert_to_studio_one

        out_path = store.staging / output_name
        audio_data = _verified_clips(graph)
        if output_format == "cpr":
            ok = convert_to_cpr(audio_data, str(out_path))
        elif output_format == "studio_one":
            ok = convert_to_studio_one(audio_data, str(out_path))
        else:
            raise ValueError(f"unsupported export format: {output_format}")
        if not ok:
            raise RuntimeError(f"{output_format} export failed")
        store.write_json("session_graph.json", dict(graph))
        return store.finalize({"export_format": output_format, "output_file": output_name})
    except Exception:
        store.abort()
        raise


def run_export(
    *,
    graph_artifact_dir: str | Path,
    export_format: str,
    artifact_root: str | Path | None = None,
) -> Dict[str, Any]:
    load_ptx_pipeline_policy()
    root = Path(artifact_root).resolve() if artifact_root else pipeline_artifact_root()
    graph_dir = Path(graph_artifact_dir).resolve()
    graph_path = graph_dir / "session_graph.json"
    if not graph_path.is_file():
        raise FileNotFoundError(f"session_graph.json not found: {graph_path}")
    graph = json.loads(graph_path.read_text(encoding="utf-8-sig"))
    extract_dir = graph_dir
    graph_manifest = graph_dir / "manifest.json"
    if graph_manifest.is_file():
        details = json.loads(graph_manifest.read_text(encoding="utf-8-sig")).get("details") or {}
        linked = details.get("extract_artifact_directory")
        if linked:
            extract_dir = Path(str(linked)).resolve()
    if not (extract_dir / "sections.json").is_file():
        sibling = graph_dir.parent
        for candidate in sorted(sibling.glob("ptx-section-extract-*")):
            if (candidate / "sections.json").is_file():
                extract_dir = candidate
                break

    if export_format == "ptx":
        return export_ptx_rebuild(graph=graph, extract_artifact_dir=extract_dir, artifact_root=root)
    return export_cpr_or_studio_one(
        graph=graph,
        artifact_root=root,
        output_format=export_format,
        output_name=f"export.{export_format}",
    )
