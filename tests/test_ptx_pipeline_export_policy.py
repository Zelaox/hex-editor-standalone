from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.services.ptx_export import run_export
from src.services.ptx_pipeline import run_pipeline


def _fixtures() -> Path:
    return Path(__file__).resolve().parent / "fixtures" / "ptx_pipeline"


def test_cpr_export_disabled_by_policy(tmp_path: Path, archive_spec):
    spec = dict(archive_spec)
    outcome = run_pipeline(spec, stages=["graph"], artifact_root=tmp_path)
    graph_dir = Path(outcome["stages"]["graph"]["artifact_directory"])
    with pytest.raises(ValueError, match="disabled"):
        run_export(graph_artifact_dir=graph_dir, export_format="cpr", artifact_root=tmp_path)
