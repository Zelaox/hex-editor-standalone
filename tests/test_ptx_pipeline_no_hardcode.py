from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.services.ptx_pipeline_policy import hex_editor_root, load_ptx_pipeline_policy


def test_no_forbidden_literals_in_runtime_tree():
    policy = load_ptx_pipeline_policy()
    manifest_path = hex_editor_root() / str(policy["no_hardcode_manifest_file"])
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    roots = [hex_editor_root() / name for name in manifest.get("scan_roots") or []]
    forbidden = [str(item) for item in (manifest.get("forbidden_substrings") or [])]
    allowed_fragments = [str(item) for item in (manifest.get("allowed_path_substrings") or [])]
    violations: list[str] = []
    for root in roots:
        if not root.is_dir():
            continue
        for path in root.rglob("*.py"):
            rel = path.relative_to(hex_editor_root()).as_posix()
            if any(fragment in rel for fragment in allowed_fragments):
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            for needle in forbidden:
                if needle in text:
                    violations.append(f"{rel}: contains forbidden substring {needle!r}")
    if violations:
        pytest.fail("\n".join(violations))
