"""Capture Wave 0 baseline, classify bottleneck, and emit debug deliverables."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", help="Evidence source file")
    parser.add_argument("parent", help="Equal-sized parent candidate")
    parser.add_argument("--output-root")
    parser.add_argument("--policy", help="Investigation debug policy path")
    parser.add_argument("--investigation-root", help="Optional investigation folder for key hunt probe")
    parser.add_argument("--lab-root", help="AI Lab root for optional Gemma health check")
    args = parser.parse_args()

    editor_root = Path(__file__).resolve().parents[1]
    sys.path[:0] = [str(editor_root)]
    if args.lab_root:
        sys.path.insert(0, str(Path(args.lab_root).resolve()))

    from src.services.investigation_debug import run_investigation_debug_e2e

    summary = run_investigation_debug_e2e(
        args.source,
        args.parent,
        output_root=args.output_root,
        policy_path=args.policy,
        investigation_root=args.investigation_root,
        lab_root=args.lab_root,
    )
    print(json.dumps(summary, indent=2, sort_keys=True, default=str))
    return 0 if summary.get("verified") else 1


if __name__ == "__main__":
    raise SystemExit(main())
