"""Build an explicit hash-deduplicated spec from operator-selected copy patterns."""
import argparse
import fnmatch
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT))
from src.services.browser_forensics.common import canonical, digest, file_hash, load_policy


def inventory(input_root, patterns, case_id, capture_id, heap_patterns=()):
    root = Path(input_root).resolve(strict=True)
    seen, skipped, selected = {}, [], []
    policy = load_policy()
    total = 0
    for source in sorted(root.rglob("*")):
        if not source.is_file():
            continue
        relative = source.relative_to(root).as_posix()
        if source.is_symlink() or not source.resolve().is_relative_to(root):
            skipped.append({"path": relative, "reason": "path_escape_or_link"})
            continue
        if not any(fnmatch.fnmatchcase(relative, p) for p in patterns):
            continue
        size = source.stat().st_size
        if size > policy["budgets"]["max_file_bytes"]:
            skipped.append({"path": relative, "size": size, "reason": "file_budget"})
            continue
        sha = file_hash(source)
        if sha in seen:
            seen[sha]["aliases"].append(relative)
            continue
        total += size
        if total > policy["budgets"]["max_total_bytes"] or len(selected) >= policy["budgets"]["max_files"]:
            raise ValueError("inventory_budget")
        item = {"path": relative, "sha256": sha}
        if any(fnmatch.fnmatchcase(relative, p) for p in heap_patterns):
            item["format_hint"] = "v8_heap_snapshot"
        # Application selection is supplied by CLI patterns, not a fixed account.
        if ".indexeddb.blob/" in relative:
            item["role"] = "blob"
        selected.append(item)
        seen[sha] = {**item, "size": size, "aliases": []}
    report = {"schema_version": 1, "patterns": patterns, "sources": list(seen.values()), "skipped": skipped}
    spec = {"schema_version": 1, "case_id": case_id, "capture_id": capture_id,
            "input_root": str(root), "snapshot_state": "unknown", "files": selected,
            "selection": {"rule": "explicit", "inventory_sha256": digest(report)}}
    return spec, report


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--input-root", required=True)
    p.add_argument("--include", action="append", required=True)
    p.add_argument("--heap-pattern", action="append", default=[])
    p.add_argument("--case-id", required=True)
    p.add_argument("--capture-id", required=True)
    p.add_argument("--output-directory", required=True)
    a = p.parse_args()
    input_root, output = Path(a.input_root).resolve(), Path(a.output_directory).resolve()
    from hexeditor_tools.cli import bootstrap_lab_runtime
    bootstrap_lab_runtime(ROOT)
    from hexeditor_tools.api import _forensic_root
    spec, report = inventory(_forensic_root(str(input_root)), a.include, a.case_id, a.capture_id, a.heap_pattern)
    _forensic_root(str(output)).mkdir(parents=True, exist_ok=False)
    (output/"spec.json").write_bytes(canonical(spec))
    (output/"inventory.json").write_bytes(canonical(report))
    print({"ok": True, "unique_sources": len(spec["files"]), "aliases": sum(len(s["aliases"]) for s in report["sources"]),
           "skipped": len(report["skipped"]), "spec_path": str(output/"spec.json")})


if __name__ == "__main__":
    main()
