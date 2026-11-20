"""Run and verify local transform regime discovery."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.services.local_transform import inspect_local_transform_run, run_local_transform_search, verify_local_transform_run


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source")
    parser.add_argument("--parent")
    parser.add_argument("--output-root")
    parser.add_argument("--policy")
    parser.add_argument("--registry")
    args = parser.parse_args()
    run = run_local_transform_search(args.source, parent_path=args.parent, output_root=args.output_root, policy_path=args.policy, registry_path=args.registry)
    run_path = Path(run["run_root"]) / "run.json"
    result = {"run": run, "verification": verify_local_transform_run(run_path), "inspection": inspect_local_transform_run(run_path)}
    print(json.dumps(result, indent=2, default=str))
    return 0 if result["verification"]["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
