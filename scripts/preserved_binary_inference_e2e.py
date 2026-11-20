"""Run preserved-binary ownership inference from a verified full-decode run."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.services.preserved_binary_inference import (
    inspect_preserved_binary_inference_run,
    run_preserved_binary_inference_e2e,
    verify_preserved_binary_inference_run,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("full_decode_run", help="Path to full-decode run.json or run root")
    parser.add_argument("--output-root")
    parser.add_argument("--policy")
    parser.add_argument("--registry")
    parser.add_argument("--summary-only", action="store_true")
    args = parser.parse_args()
    run = run_preserved_binary_inference_e2e(
        args.full_decode_run,
        output_root=args.output_root,
        policy_path=args.policy,
        registry_path=args.registry,
    )
    run_path = Path(run["run_root"]) / "run.json"
    verification = verify_preserved_binary_inference_run(run_path)
    inspection = inspect_preserved_binary_inference_run(run_path)
    if args.summary_only:
        output = {
            "run_id": run["run_id"],
            "status": run["status"],
            "verified": verification["ok"],
            "run_root": run["run_root"],
            "decision": inspection["decision"],
            "overlay_summary": inspection["ownership_overlay"]["summary"],
        }
    else:
        output = {"run": run, "verification": verification, "inspection": inspection}
    print(json.dumps(output, indent=2, sort_keys=True, default=str))
    return 0 if verification["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
