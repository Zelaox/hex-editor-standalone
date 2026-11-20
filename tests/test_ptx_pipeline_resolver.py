from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.services.ptx_source_archive import load_archive_registry
from src.services.ptx_source_resolver import resolve_ptx_source


def _fixtures() -> Path:
    return Path(__file__).resolve().parent / "fixtures" / "ptx_pipeline"


def test_archive_bind_round_trip(archive_spec):
    spec = dict(archive_spec)
    binding = resolve_ptx_source(spec)
    assert binding["binding_kind"] == "archive"
    assert binding["archive_id"] == spec["archive_id"]
    assert len(binding["source_sha256"]) == 64
    assert Path(binding["bound_path"]).is_file()


def test_missing_archive_id_fails(archive_spec):
    with pytest.raises(KeyError):
        resolve_ptx_source({"kind": "archive", "archive_id": "does-not-exist-0000000000000000"})


def test_filesystem_bind_requires_path(tmp_path: Path, archive_spec):
    sample = tmp_path / "mini.ptx"
    sample.write_bytes(b"PTX0" + b"\x00" * 32)
    binding = resolve_ptx_source({"kind": "filesystem", "path": str(sample)})
    assert binding["binding_kind"] == "filesystem"
    assert binding["source_size"] == sample.stat().st_size


def test_registry_contains_archive_fixture_id(archive_spec):
    registry = load_archive_registry()
    spec = dict(archive_spec)
    assert spec["archive_id"] in (registry.get("archives") or {})
