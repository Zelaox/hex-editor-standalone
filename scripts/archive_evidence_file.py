#!/usr/bin/env python3
"""Archive a stale evidence source file with content-addressed manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Mapping, Sequence


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(dict(payload), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load_policy(path: Path | None) -> Dict[str, Any]:
    policy_path = path or (_repo_root() / "config" / "source_archive_policy.json")
    policy = _read_json(policy_path.resolve())
    if int(policy.get("schema_version") or 0) != 1:
        raise ValueError(f"unsupported source_archive policy schema: {policy_path}")
    return policy


def _sha256_file(path: Path, *, chunk_bytes: int) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_bytes), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _archive_id(source_path: Path, sha256: str) -> str:
    stem = source_path.stem.replace(" ", "_")
    return f"{stem}-{sha256[:16]}"


def archive_file(
    *,
    source_path: Path,
    policy: Mapping[str, Any],
    workspace_root: Path,
    reason: str,
    dry_run: bool,
) -> Dict[str, Any]:
    if reason not in policy["reason_codes"]:
        raise ValueError(f"unsupported archive reason: {reason}")
    if not source_path.is_file():
        raise FileNotFoundError(f"source file not found: {source_path}")

    chunk_bytes = int(policy["sha256_chunk_bytes"])
    sha256 = _sha256_file(source_path, chunk_bytes=chunk_bytes)
    size = source_path.stat().st_size
    archive_root = workspace_root / str(policy["archive_root"])
    archive_id = _archive_id(source_path, sha256)
    archived_path = archive_root / archive_id / source_path.name
    manifest_path = archive_root / archive_id / str(policy["manifest_filename"])

    manifest = {
        "schema_version": 1,
        "archive_id": archive_id,
        "original_path": str(source_path.resolve()),
        "archived_path": str(archived_path.resolve()),
        "sha256": sha256,
        "size": size,
        "archived_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "reason": reason,
    }

    registry_path = workspace_root / str(policy["registry_path"])
    registry: Dict[str, Any]
    if registry_path.is_file():
        registry = _read_json(registry_path)
    else:
        registry = {"schema_version": 1, "archives": {}}

    if not dry_run:
        archived_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(source_path.resolve()), str(archived_path.resolve()))
        _write_json(manifest_path, manifest)
        archives = dict(registry.get("archives") or {})
        archives[archive_id] = {
            "sha256": sha256,
            "original_path": manifest["original_path"],
            "archived_path": manifest["archived_path"],
            "manifest_path": str(manifest_path.resolve()),
            "reason": reason,
        }
        registry["archives"] = archives
        _write_json(registry_path, registry)

    return {
        "schema_version": 1,
        "operation": "archive_evidence_file",
        "dry_run": dry_run,
        "manifest": manifest,
        "registry_path": str(registry_path.resolve()),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Archive a stale evidence source file.")
    parser.add_argument("source", help="Path to the source file to archive")
    parser.add_argument("--workspace-root", help="Workspace root (default: repo root)")
    parser.add_argument("--policy", help="Override source_archive_policy.json path")
    parser.add_argument("--reason", required=True, choices=[
        "superseded_by_newer_source",
        "stale_fixture",
        "user_requested_archive",
    ])
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(list(argv) if argv is not None else None)

    policy = _load_policy(Path(args.policy).resolve() if args.policy else None)
    workspace_root = Path(args.workspace_root).resolve() if args.workspace_root else _repo_root()
    result = archive_file(
        source_path=Path(args.source).expanduser().resolve(),
        policy=policy,
        workspace_root=workspace_root,
        reason=str(args.reason),
        dry_run=bool(args.dry_run),
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
