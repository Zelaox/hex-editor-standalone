from __future__ import annotations

import json
from pathlib import Path

from src.ptx_handler import PTXFile


def test_ptx_file_summary_is_json_safe(tmp_path: Path):
    source = tmp_path / "summary.ptx"
    source.write_bytes(b"PTX0" + b"\x00" * 60)
    handler = PTXFile(str(source))
    summary = handler.get_summary()
    encoded = json.dumps(summary, ensure_ascii=False, sort_keys=True)
    assert summary["schema_version"] == 1
    assert summary["source"]["size"] == source.stat().st_size
    assert summary["counts"]["sections"] == len(summary["sections"])
    assert "heuristic" in encoded
