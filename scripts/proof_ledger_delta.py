"""Compile cross-run proof ledger deltas."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _root() -> Path:
    return Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description="Compile proof ledger cross-run delta")
    parser.add_argument("--from-run", required=True, help="Baseline run.json or run root")
    parser.add_argument("--to-run", required=True, help="Comparison run.json or run root")
    parser.add_argument(
        "--kind",
        default="run_to_run",
        choices=["parent_to_child", "run_to_run", "candidate_to_candidate"],
        help="Delta kind",
    )
    args = parser.parse_args()

    root = _root()
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

    from src.services.proof_ledger.delta_compiler import compile_cross_run_delta

    result = compile_cross_run_delta(args.from_run, args.to_run, args.kind)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
