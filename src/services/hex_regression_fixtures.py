"""Pytest-only regression fixture resolver — must not be imported by desktop GUI."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Mapping

from src.services.materialization_manifest import discover_materialization_manifests, manifest_paths


def _fixtures_path() -> Path:
    return Path(__file__).resolve().parents[2] / "config" / "hex_regression_fixtures.json"


def load_fixture_registry() -> Dict[str, Any]:
    path = _fixtures_path()
    if not path.is_file():
        raise ValueError(f"hex regression fixtures missing: {path}")
    payload = json.loads(path.read_text(encoding="utf-8-sig"))
    if not payload.get("pytest_only"):
        raise ValueError("hex_regression_fixtures.json must set pytest_only: true")
    return payload


def resolve_bundle(bundle_id: str) -> Dict[str, Any]:
    registry = load_fixture_registry()
    bundles = list(registry.get("fixture_bundles") or [])
    bundle = next((item for item in bundles if str(item.get("bundle_id") or "") == str(bundle_id)), None)
    if bundle is None:
        raise ValueError(f"unknown fixture bundle_id: {bundle_id}")

    role = str(bundle.get("bundle_role") or "")
    if bundle.get("resolve_via") == "materialization_manifest":
        selector = dict(bundle.get("manifest_selector") or {})
        under = str(selector.get("under_artifact_root") or "alternate_scope_gemma_live")
        manifests = discover_materialization_manifests(under_subdir=under)
        if not manifests:
            raise ValueError(f"no materialization manifests found under {under}")
        manifest = manifests[0]
        paths = manifest_paths(manifest)
        return {
            "bundle_id": bundle_id,
            "bundle_role": role,
            "source_path": paths["source_path"],
            "candidate_path": paths["candidate_path"],
            "manifest": manifest,
        }

    root = Path(str(bundle.get("root") or "")).expanduser()
    files = dict(bundle.get("files") or {})
    source_name = str(files.get("source_ptx") or "")
    candidate_name = str(files.get("decrypt_candidate_ptx") or "")
    if not root.is_dir() or not source_name or not candidate_name:
        raise ValueError(f"fixture bundle {bundle_id} missing root/files")
    source_path = (root / source_name).resolve()
    candidate_path = (root / candidate_name).resolve()
    if not source_path.is_file() or not candidate_path.is_file():
        raise ValueError(f"fixture bundle {bundle_id} files not found")
    return {
        "bundle_id": bundle_id,
        "bundle_role": role,
        "source_path": str(source_path),
        "candidate_path": str(candidate_path),
    }
