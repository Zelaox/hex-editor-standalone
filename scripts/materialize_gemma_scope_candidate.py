"""Materialize a verified Gemma-selected scope transform into a separate file."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.services.alternate_scope import materialize_gemma_scope_candidate


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument("--run", required=True)
    parser.add_argument("--gemma-result", required=True)
    parser.add_argument("--destination", required=True)
    args = parser.parse_args()
    result = materialize_gemma_scope_candidate(args.source, args.run, args.gemma_result, args.destination)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
