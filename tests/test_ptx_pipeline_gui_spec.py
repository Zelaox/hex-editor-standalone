from __future__ import annotations

import pytest

from src.services.ptx_pipeline_gui_spec import build_source_spec, stages_from_selection


def test_build_filesystem_spec():
    spec = build_source_spec(kind="filesystem", filesystem_path=r"C:\temp\session.ptx")
    assert spec == {"kind": "filesystem", "path": r"C:\temp\session.ptx"}


def test_build_archive_spec():
    spec = build_source_spec(kind="archive", archive_id="abc-123")
    assert spec["kind"] == "archive"
    assert spec["archive_id"] == "abc-123"


def test_stages_from_selection_requires_one():
    with pytest.raises(ValueError):
        stages_from_selection({}, include_bind=False)


def test_stages_respect_order():
    stages = stages_from_selection(
        {"analyze": True, "graph": True, "bind": True},
        include_bind=True,
    )
    assert stages == ["bind", "analyze", "graph"]
