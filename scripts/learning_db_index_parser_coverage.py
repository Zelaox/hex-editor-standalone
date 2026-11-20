"""Index parser coverage (unknown_bytes) for a source file into learning.sqlite."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.services.learning_db import index_parser_coverage_for_path, lookup_parser_coverage


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path, help="Source file to parse and index")
    args = parser.parse_args()
    result = index_parser_coverage_for_path(args.path)
    lookup = lookup_parser_coverage(str(result["source_sha256"]))
    print(
        f"[OK] indexed parser coverage sha256={result['source_sha256'][:16]}… "
        f"unknown_bytes={lookup and lookup.get('unknown_bytes')} "
        f"db={result['db_path']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
