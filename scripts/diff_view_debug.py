#!/usr/bin/env python3
"""Diff View debug report — config-driven, no baked-in paths or case literals."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _write_json(payload: Mapping[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(dict(payload), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _load_policy(path: Path | None) -> Dict[str, Any]:
    policy_path = path or (_repo_root() / "config" / "diff_view_debug_policy.json")
    policy = _read_json(policy_path.resolve())
    if int(policy.get("schema_version") or 0) != 1:
        raise ValueError(f"unsupported diff_view_debug policy schema: {policy_path}")
    return policy


def _require_keys(payload: Mapping[str, Any], keys: Sequence[str], *, label: str) -> None:
    missing = [key for key in keys if key not in payload]
    if missing:
        raise ValueError(f"{label} missing required keys: {missing}")


def _load_binary_diff_config(config_path: Path, policy: Mapping[str, Any]) -> Dict[str, Any]:
    cfg = _read_json(config_path.resolve())
    _require_keys(cfg, policy["binary_diff_config"]["required_keys"], label=str(config_path))
    if int(cfg.get("schema_version") or 0) != 1:
        raise ValueError(f"unsupported binary diff config schema: {config_path}")
    return cfg


def _resolve_user_state(workspace_root: Path, cfg: Mapping[str, Any], policy: Mapping[str, Any]) -> Dict[str, Any]:
    state_path = workspace_root / str(cfg["user_state_path"])
    if not state_path.is_file():
        raise FileNotFoundError(f"diff view user state not found: {state_path}")
    state = _read_json(state_path)
    _require_keys(state, policy["binary_diff_config"]["user_state_required_keys"], label=str(state_path))
    if int(state.get("schema_version") or 0) != 1:
        raise ValueError(f"unsupported diff view user state schema: {state_path}")
    return {"path": str(state_path.resolve()), "payload": state}


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _first_nested(payload: Mapping[str, Any], dotted: str) -> Any:
    current: Any = payload
    for part in dotted.split("."):
        if not isinstance(current, Mapping):
            return None
        current = current.get(part)
    return current


def _first_from_fields(payload: Mapping[str, Any], fields: Iterable[str]) -> Any:
    for field in fields:
        if "." in field:
            value = _first_nested(payload, field)
        else:
            value = payload.get(field)
        if value not in (None, ""):
            return value
    return None


def _analyze_pair(path_a: Path, path_b: Path, *, chunk_bytes: int, range_limit: int) -> Dict[str, Any]:
    if chunk_bytes <= 0 or range_limit <= 0:
        raise ValueError("chunk_bytes and range_limit must be positive")
    len_a = path_a.stat().st_size
    len_b = path_b.stat().st_size
    total = max(len_a, len_b)
    changed = 0
    first_changed: Optional[int] = None
    ranges: List[Tuple[int, int]] = []
    active_start: Optional[int] = None
    with path_a.open("rb") as fa, path_b.open("rb") as fb:
        for base in range(0, total, chunk_bytes):
            ba = fa.read(chunk_bytes)
            bb = fb.read(chunk_bytes)
            size = max(len(ba), len(bb))
            aa = ba.ljust(size, b"\x00")
            ab = bb.ljust(size, b"\x00")
            for index in range(size):
                different = aa[index] != ab[index] or (index >= min(len(ba), len(bb)) and len(ba) != len(bb))
                if different:
                    changed += 1
                    absolute = base + index
                    if first_changed is None:
                        first_changed = absolute
                    if active_start is None:
                        active_start = absolute
                elif active_start is not None:
                    if len(ranges) < range_limit:
                        ranges.append((active_start, base + index))
                    active_start = None
            if active_start is not None and size == 0:
                if len(ranges) < range_limit:
                    ranges.append((active_start, base))
                active_start = None
    if active_start is not None and len(ranges) < range_limit:
        ranges.append((active_start, total))
    compared_length = total
    return {
        "length_a": len_a,
        "length_b": len_b,
        "compared_length": compared_length,
        "changed_bytes": changed,
        "changed_ratio": (changed / compared_length) if compared_length else 0.0,
        "first_changed_offset": first_changed,
        "changed_ranges": [{"start": start, "end": end} for start, end in ranges],
        "ranges_truncated": len(ranges) >= range_limit,
    }


def _file_identity(path: Path) -> Dict[str, Any]:
    resolved = path.expanduser().resolve()
    return {
        "path": str(resolved),
        "exists": resolved.is_file(),
        "size": resolved.stat().st_size if resolved.is_file() else None,
        "sha256": _sha256_file(resolved) if resolved.is_file() else None,
    }


def _load_manifest(path: Path, policy: Mapping[str, Any]) -> Dict[str, Any]:
    manifest = _read_json(path.resolve())
    manifest_cfg = policy["manifest"]
    source_path = _first_from_fields(manifest, manifest_cfg["source_path_fields"])
    file_b_path = _first_from_fields(manifest, manifest_cfg["file_b_path_fields"])
    changed_bytes = _first_from_fields(manifest, manifest_cfg["changed_bytes_fields"])
    return {
        "path": str(path.resolve()),
        "source_path": str(source_path) if source_path else None,
        "file_b_path": str(file_b_path) if file_b_path else None,
        "manifest_changed_bytes": int(changed_bytes) if changed_bytes is not None else None,
    }


def _load_decision(path: Path, policy: Mapping[str, Any]) -> Dict[str, Any]:
    decision = _read_json(path.resolve())
    inv = policy["investigation"]
    unresolved = _first_from_fields(decision, inv["unresolved_bytes_fields"])
    status = _first_from_fields(decision, inv["status_fields"])
    return {
        "path": str(path.resolve()),
        "unresolved_bytes": int(unresolved) if unresolved is not None else None,
        "status": str(status) if status is not None else None,
    }


def build_report(
    *,
    diff_config_path: Path,
    workspace_root: Path,
    policy: Mapping[str, Any],
    path_a: Path | None = None,
    path_b: Path | None = None,
    manifest_path: Path | None = None,
    decision_path: Path | None = None,
) -> Dict[str, Any]:
    cfg = _load_binary_diff_config(diff_config_path, policy)
    user_state = _resolve_user_state(workspace_root, cfg, policy)
    state = dict(user_state["payload"])
    effective_a = Path(path_a or state["path_a"]).expanduser()
    effective_b = Path(path_b or state["path_b"]).expanduser()
    identity_a = _file_identity(effective_a)
    identity_b = _file_identity(effective_b)
    mismatches: List[str] = []
    if not identity_a["exists"] or not identity_b["exists"]:
        mismatches.append("ui_paths_missing_on_disk")
    raw: Dict[str, Any] | None = None
    if identity_a["exists"] and identity_b["exists"]:
        raw = _analyze_pair(
            Path(identity_a["path"]),
            Path(identity_b["path"]),
            chunk_bytes=int(cfg["analysis_chunk_bytes"]),
            range_limit=int(cfg["changed_range_limit"]),
        )
    manifest: Dict[str, Any] | None = None
    manifest_raw: Dict[str, Any] | None = None
    if manifest_path is not None:
        manifest = _load_manifest(manifest_path, policy)
        if manifest.get("file_b_path"):
            file_b = Path(str(manifest["file_b_path"])).expanduser()
            if str(file_b.resolve()) != str(Path(identity_b["path"]).resolve()):
                mismatches.append("ui_path_b_differs_from_manifest_file_b")
            if identity_a["exists"] and file_b.is_file():
                manifest_raw = _analyze_pair(
                    Path(identity_a["path"]),
                    file_b,
                    chunk_bytes=int(cfg["analysis_chunk_bytes"]),
                    range_limit=int(cfg["changed_range_limit"]),
                )
                if (
                    manifest.get("manifest_changed_bytes") is not None
                    and int(manifest["manifest_changed_bytes"]) != int(manifest_raw["changed_bytes"])
                ):
                    mismatches.append("manifest_changed_bytes_differs_from_raw_byte_count")
    decision: Dict[str, Any] | None = None
    if decision_path is not None:
        decision = _load_decision(decision_path, policy)
        if (
            raw is not None
            and decision.get("unresolved_bytes") == 0
            and int(raw["changed_bytes"]) > 0
        ):
            pass
        if (
            raw is not None
            and decision.get("unresolved_bytes") not in (None, 0)
            and int(raw["changed_bytes"]) == 0
        ):
            mismatches.append("investigation_unresolved_nonzero_while_raw_diff_zero")
    if raw is not None and state.get("path_b") and identity_b["exists"]:
        if str(Path(state["path_b"]).expanduser().resolve()) != str(Path(identity_b["path"]).resolve()):
            mismatches.append("cli_path_b_overrides_user_state")
    return {
        "schema_version": 1,
        "operation": "diff_view_debug",
        "policy_id": policy.get("policy_id"),
        "sources": {
            "diff_config": str(diff_config_path.resolve()),
            "workspace_root": str(workspace_root.resolve()),
            "user_state": user_state["path"],
            "manifest": str(manifest_path.resolve()) if manifest_path else None,
            "decision": str(decision_path.resolve()) if decision_path else None,
        },
        "ui_state": {
            "path_a": state.get("path_a"),
            "path_b": state.get("path_b"),
            "mode_id": state.get("mode_id"),
            "threshold": state.get("threshold"),
            "block_size": state.get("block_size"),
        },
        "effective_pair": {
            "path_a": identity_a,
            "path_b": identity_b,
        },
        "raw_byte_diff": raw,
        "manifest_binding": manifest,
        "manifest_raw_byte_diff": manifest_raw,
        "investigation_decision": decision,
        "mismatch_classes": sorted(set(mismatches)),
        "ok": not mismatches,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Diff View debug report (config-driven).")
    parser.add_argument("--diff-config", required=True, help="Path to configs/diff_view.json")
    parser.add_argument("--workspace-root", required=True, help="Root used to resolve user_state_path from diff config")
    parser.add_argument("--policy", help="Override diff_view_debug_policy.json path")
    parser.add_argument("--path-a", help="Override File A (default: user state path_a)")
    parser.add_argument("--path-b", help="Override File B (default: user state path_b)")
    parser.add_argument("--manifest", help="Materialization or candidate manifest JSON")
    parser.add_argument("--decision-json", help="Full-decode final/decision.json for unresolved_bytes cross-check")
    parser.add_argument("--output", help="Write report JSON to this path")
    args = parser.parse_args(list(argv) if argv is not None else None)
    policy = _load_policy(Path(args.policy).resolve() if args.policy else None)
    report = build_report(
        diff_config_path=Path(args.diff_config),
        workspace_root=Path(args.workspace_root),
        policy=policy,
        path_a=Path(args.path_a) if args.path_a else None,
        path_b=Path(args.path_b) if args.path_b else None,
        manifest_path=Path(args.manifest) if args.manifest else None,
        decision_path=Path(args.decision_json) if args.decision_json else None,
    )
    text = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        _write_json(report, Path(args.output))
    print(text)
    return 0 if report["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
