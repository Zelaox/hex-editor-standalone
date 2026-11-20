"""Run, verify and summarize full-file decode plus ASCII export."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.services.full_decode import inspect_full_decode_run, run_full_decode_e2e, verify_full_decode_run


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", help="Evidence source containing mechanically materialized bytes")
    parser.add_argument("parent", help="Equal-sized parent candidate")
    parser.add_argument("--output-root")
    parser.add_argument("--policy")
    parser.add_argument("--registry")
    parser.add_argument("--reference", help="Optional ground-truth reference binary for reference-aware composition")
    parser.add_argument("--summary-only", action="store_true")
    args = parser.parse_args()
    run = run_full_decode_e2e(
        args.source,
        args.parent,
        output_root=args.output_root,
        policy_path=args.policy,
        registry_path=args.registry,
        reference_path=args.reference,
    )
    run_path = Path(run["run_root"]) / "run.json"
    verification, inspection = verify_full_decode_run(run_path), inspect_full_decode_run(run_path)
    if args.summary_only:
        output = {"run_id": run["run_id"], "status": run["status"], "verified": verification["ok"], "run_root": run["run_root"], "candidate": inspection["candidate"], "coverage_summary": inspection["coverage"]["summary"], "exports": inspection["exports"]}
    else:
        output = {"run": run, "verification": verification, "inspection": inspection}
    print(json.dumps(output, indent=2, sort_keys=True, default=str))
    return 0 if verification["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
