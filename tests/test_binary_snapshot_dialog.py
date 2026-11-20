from __future__ import annotations

import sys
from pathlib import Path

HEX_EDITOR = Path(__file__).resolve().parents[1]
if str(HEX_EDITOR) not in sys.path:
    sys.path.insert(0, str(HEX_EDITOR))

from src.snapshot_run_catalog import artifact_root, list_runs_for_source


def test_list_runs_for_ac240_ptx():
    target = HEX_EDITOR / "ac240.ptx"
    if not target.is_file():
        import pytest

        pytest.skip("ac240.ptx fixture missing")
    runs = list_runs_for_source(target)
    assert isinstance(runs, list)
    if runs:
        assert any(str(run.get("run_id") or "") for run in runs)


def test_artifact_root_from_config():
    root = artifact_root()
    assert root.name
    assert root.exists()
