"""Run the evidence-driven alternate-scope proof from runtime observations."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.services.alternate_scope import run_alternate_scope_proof


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--candidate-hex", required=True)
    parser.add_argument("--boundary-hint", required=True, type=int)
    parser.add_argument("--previous-run")
    parser.add_argument("--policy")
    parser.add_argument("--registry")
    args = parser.parse_args()
    result = run_alternate_scope_proof(
        args.source,
        output_root=args.output,
        candidate_hex=args.candidate_hex,
        boundary_hint=args.boundary_hint,
        previous_run=args.previous_run,
        policy_path=args.policy,
        registry_path=args.registry,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
