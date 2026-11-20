"""Run and verify an evidence-driven multi-turn scope search."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.services.iterative_scope import inspect_iterative_run, run_iterative_scope_search, verify_iterative_run


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source")
    parser.add_argument("alternative")
    parser.add_argument("--output-root")
    parser.add_argument("--policy")
    parser.add_argument("--registry")
    args = parser.parse_args()
    run = run_iterative_scope_search(args.source, args.alternative, output_root=args.output_root, policy_path=args.policy, registry_path=args.registry)
    run_path = Path(run["run_root"]) / "run.json"
    verification = verify_iterative_run(run_path)
    inspection = inspect_iterative_run(run_path)
    print(json.dumps({"run": run, "verification": verification, "inspection": inspection}, indent=2, default=str))
    return 0 if verification["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
