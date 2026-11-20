"""Atomic, manifest-backed artifact storage for Hex Editor operations."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict


def file_identity(path: str | Path) -> Dict[str, Any]:
    resolved = Path(path).resolve()
    digest = hashlib.sha256()
    with resolved.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    stat = resolved.stat()
    return {
        "path": str(resolved),
        "size": stat.st_size,
        "modified_ns": stat.st_mtime_ns,
        "sha256": digest.hexdigest(),
    }


class ArtifactStore:
    def __init__(self, root: str | Path, operation: str, source: str | Path):
        self.root = Path(root).resolve()
        self.operation = operation
        self.source = Path(source).resolve()
        self.operation_id = f"{operation}-{uuid.uuid4().hex}"
        self.staging = self.root / ".staging" / self.operation_id
        self.destination = self.root / self.operation_id
        self.source_before = file_identity(self.source)
        if self.destination.exists() or self.staging.exists():
            raise FileExistsError(f"Artifact operation already exists: {self.operation_id}")
        self.staging.mkdir(parents=True)

    def _target(self, relative_name: str) -> Path:
        if not relative_name or Path(relative_name).is_absolute() or ".." in Path(relative_name).parts:
            raise ValueError("Artifact names must be relative and may not traverse directories")
        target = (self.staging / relative_name).resolve()
        target.relative_to(self.staging)
        target.parent.mkdir(parents=True, exist_ok=True)
        return target

    def write_bytes(self, relative_name: str, content: bytes) -> Path:
        target = self._target(relative_name)
        temporary = target.with_name(f".{target.name}.tmp")
        temporary.write_bytes(content)
        os.replace(temporary, target)
        return target

    def write_json(self, relative_name: str, content: Any) -> Path:
        return self.write_bytes(
            relative_name,
            (json.dumps(content, indent=2, sort_keys=True, default=str) + "\n").encode("utf-8"),
        )

    def finalize(self, details: Dict[str, Any]) -> Dict[str, Any]:
        source_after = file_identity(self.source)
        if source_after != self.source_before:
            raise RuntimeError("Source file changed during artifact creation; output was not promoted")

        files = []
        for path in sorted(self.staging.rglob("*")):
            if path.is_file() and path.name != "manifest.json":
                identity = file_identity(path)
                files.append(
                    {
                        "path": path.relative_to(self.staging).as_posix(),
                        "size": identity["size"],
                        "sha256": identity["sha256"],
                    }
                )
        manifest = {
            "schema_version": 1,
            "operation_id": self.operation_id,
            "operation": self.operation,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "source_before": self.source_before,
            "source_after": source_after,
            "source_preserved": True,
            "files": files,
            "details": details,
        }
        self.write_json("manifest.json", manifest)
        self.destination.parent.mkdir(parents=True, exist_ok=True)
        os.replace(self.staging, self.destination)
        return {
            "ok": True,
            "operation": self.operation,
            "operation_id": self.operation_id,
            "artifact_directory": str(self.destination),
            "manifest": str(self.destination / "manifest.json"),
            "source_preserved": True,
            "files": files,
        }

    def abort(self) -> None:
        if self.staging.exists():
            shutil.rmtree(self.staging)
