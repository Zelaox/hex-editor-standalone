"""Export source workspaces and run the verified parser-learning rail."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lab-root", required=True)
    parser.add_argument("--source", action="append", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--format-plugin", required=True)
    parser.add_argument("--base-profile-id", required=True)
    parser.add_argument("--promotion-profile-id")
    args = parser.parse_args()
    lab = Path(args.lab_root).resolve()
    editor = lab / "Hex editor"
    sys.path[:0] = [str(editor), str(lab)]
    from src.services.binary_runtime import analyze_binary_snapshot
    from src.services.parser_learning import run_parser_learning
    from src.services.representation_registry import load_representation_policy
    from src.services.representation_sweep import sweep_region, write_representation_brief_cache

    dynamic_policy = json.loads((lab / "config" / "binary_dynamic_analysis.json").read_text(encoding="utf-8"))
    representation_policy = load_representation_policy()
    region_budget = int(representation_policy["budgets"]["default_tool_region_bytes"])
    output_root = Path(args.output).resolve()
    workspaces = []
    for index, value in enumerate(args.source):
        source = Path(value).resolve()
        snapshot = analyze_binary_snapshot(source, policy=dynamic_policy)["snapshot"]
        regions = list(snapshot.get("unknown_regions") or [])
        if not regions:
            raise ValueError(f"source has no unknown regions: {source}")
        region = regions[0]
        span = dict(region["span"])
        offset = int(span["offset"])
        length = min(int(span["length"]), region_budget)
        with source.open("rb") as handle:
            handle.seek(offset)
            data = handle.read(length)
        source_digest = hashlib.sha256(source.read_bytes()).hexdigest()
        workspace = output_root / "input_workspaces" / f"source-{index:04d}-{source_digest}"
        (workspace / "unknown").mkdir(parents=True, exist_ok=True)
        bounded_region = {**region, "region_id": f"bounded-{source_digest}-{offset}-{length}", "span": {"offset": offset, "length": length}}
        (workspace / "manifest.json").write_text(json.dumps({"source_before": {"sha256": source_digest}, "details": {"snapshot_id": snapshot["snapshot_id"], "format_plugin": snapshot["format_plugin"]}}, indent=2), encoding="utf-8")
        (workspace / "unknown" / "regions.json").write_text(json.dumps([bounded_region], indent=2), encoding="utf-8")
        write_representation_brief_cache(workspace, bounded_region["region_id"], sweep_region(data, offset=offset))
        workspaces.append(str(workspace))
    result = run_parser_learning(
        workspaces,
        output_workspace=output_root,
        format_plugin=args.format_plugin,
        base_profile_id=args.base_profile_id,
        promotion_profile_id=args.promotion_profile_id,
    )
    print(json.dumps({"exports": workspaces, "result": result}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
