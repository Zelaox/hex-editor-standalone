from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.services.ptx_pipeline import run_export, run_pipeline
from src.services.ptx_schema_validate import validate_against_schema


def _fixtures() -> Path:
    return Path(__file__).resolve().parent / "fixtures" / "ptx_pipeline"


@pytest.fixture
def pipeline_tmp_root(tmp_path: Path) -> Path:
    root = tmp_path / "ptx_pipeline_runs"
    root.mkdir()
    return root


def test_pipeline_e2e_archive_through_export(pipeline_tmp_root: Path, archive_spec):
    spec = dict(archive_spec)
    outcome = run_pipeline(
        spec,
        stages=["bind", "analyze", "extract", "graph"],
        artifact_root=pipeline_tmp_root,
    )
    assert outcome.get("ok") is True
    graph_stage = outcome["stages"]["graph"]
    graph_dir = Path(graph_stage["artifact_directory"])
    graph = json.loads((graph_dir / "session_graph.json").read_text(encoding="utf-8-sig"))
    validate_against_schema("ptx_session_graph.schema.json", graph)
    verified = graph.get("verified_facts") or {}
    assert len(str(verified.get("source_sha256") or "")) == 64
    assert int(verified.get("source_size") or 0) > 0
    assert "hypotheses" in graph
    assert "parser_labels" in (graph.get("hypotheses") or {})

    export_out = run_export(
        graph_artifact_dir=graph_dir,
        export_format="ptx",
        artifact_root=pipeline_tmp_root,
    )
    assert export_out.get("ok") is True
    export_dir = Path(export_out["artifact_directory"])
    rebuilt = export_dir / "rebuilt.ptx"
    assert rebuilt.is_file()
    assert rebuilt.stat().st_size > 0


def test_parse_result_schema_on_analyze(pipeline_tmp_root: Path, archive_spec):
    spec = dict(archive_spec)
    outcome = run_pipeline(spec, stages=["analyze"], artifact_root=pipeline_tmp_root)
    analyze_dir = Path(outcome["stages"]["analyze"]["artifact_directory"])
    parse_result = json.loads((analyze_dir / "parse_result.json").read_text(encoding="utf-8-sig"))
    validate_against_schema("ptx_parse_result.schema.json", parse_result)
    assert parse_result.get("ok") is True
