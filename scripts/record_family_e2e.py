"""Run and verify evidence-driven record-family proof end to end."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.services.record_family import inspect_record_family_run, run_record_family_e2e, verify_record_family_run


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source")
    parser.add_argument("parent")
    parser.add_argument("--output-root")
    parser.add_argument("--ledger-root")
    parser.add_argument("--policy")
    parser.add_argument("--registry")
    args = parser.parse_args()
    run = run_record_family_e2e(args.source, args.parent, output_root=args.output_root, ledger_root=args.ledger_root, policy_path=args.policy, registry_path=args.registry)
    run_path = Path(run["run_root"]) / "run.json"
    result = {"run": run, "verification": verify_record_family_run(run_path), "inspection": inspect_record_family_run(run_path)}
    print(json.dumps(result, indent=2, sort_keys=True, default=str))
    return 0 if result["verification"]["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
