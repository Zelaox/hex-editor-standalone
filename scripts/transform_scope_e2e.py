"""Run a bounded evidence-derived transform scope/gate proof."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lab-root", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--candidate-hex", required=True)
    parser.add_argument("--boundary-hint", required=True, type=int)
    args = parser.parse_args()
    lab = Path(args.lab_root).resolve()
    editor = lab / "Hex editor"
    sys.path[:0] = [str(editor), str(lab)]
    from src.services.transform_scope import run_transform_scope_proof

    result = run_transform_scope_proof(args.source, output_root=args.output, candidate_hex=args.candidate_hex, boundary_hint=args.boundary_hint)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
