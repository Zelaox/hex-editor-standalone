#!/usr/bin/env python3
"""Unified PTX pipeline CLI — bind, analyze, extract, graph, export."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _ensure_import_path() -> None:
    root = str(_repo_root())
    if root not in sys.path:
        sys.path.insert(0, root)


def _load_json_arg(value: str) -> dict:
    path = Path(value).expanduser()
    if path.is_file():
        return json.loads(path.read_text(encoding="utf-8-sig"))
    return json.loads(value)


def main(argv: list[str] | None = None) -> int:
    _ensure_import_path()
    from src.services.ptx_pipeline import (
        load_spec_file,
        run_analyze,
        run_bind,
        run_export,
        run_extract,
        run_graph,
        run_pipeline,
    )
    from src.services.ptx_source_resolver import resolve_ptx_source

    parser = argparse.ArgumentParser(description="PTX parser/converter pipeline")
    sub = parser.add_subparsers(dest="command", required=True)

    for name in ("bind", "analyze", "extract", "graph", "run"):
        cmd = sub.add_parser(name)
        cmd.add_argument("--spec-file", help="JSON file with source spec")
        cmd.add_argument("--spec", help="Inline JSON spec")
        cmd.add_argument("--artifact-root", help="Override artifact root from policy")

    export_cmd = sub.add_parser("export")
    export_cmd.add_argument("--graph-artifact-dir", required=True)
    export_cmd.add_argument("--format", default="ptx", choices=["ptx", "cpr", "studio_one"])
    export_cmd.add_argument("--artifact-root")

    args = parser.parse_args(argv)

    if args.command == "export":
        outcome = run_export(
            graph_artifact_dir=args.graph_artifact_dir,
            export_format=args.format,
            artifact_root=args.artifact_root,
        )
        print(json.dumps(outcome, indent=2))
        return 0

    if not args.spec_file and not args.spec:
        parser.error("--spec-file or --spec is required")

    spec = load_spec_file(args.spec_file) if args.spec_file else _load_json_arg(args.spec)

    if args.command == "bind":
        outcome = run_bind(spec, artifact_root=args.artifact_root)
    elif args.command == "analyze":
        binding = resolve_ptx_source(spec)
        outcome = run_analyze(binding, artifact_root=args.artifact_root)
    elif args.command == "extract":
        binding = resolve_ptx_source(spec)
        outcome = run_extract(binding, artifact_root=args.artifact_root)
    elif args.command == "graph":
        binding = resolve_ptx_source(spec)
        outcome = run_graph(binding, artifact_root=args.artifact_root)
    else:
        outcome = run_pipeline(spec, artifact_root=args.artifact_root, export_format=None)

    print(json.dumps(outcome, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
