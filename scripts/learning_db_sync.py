"""Backfill the learning DB from verified artifact rails."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _root() -> Path:
    return Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description="Sync hex editor learning DB from artifact rails")
    parser.add_argument("--rail", action="append", dest="rails", help="Restrict sync to one or more rail IDs")
    parser.add_argument("--skip-findings", action="store_true", help="Do not index finding ledger records")
    parser.add_argument("--scan-limit", type=int, default=None, help="Override configured backfill scan limit")
    parser.add_argument("--inspect", action="store_true", help="Print inspect summary after sync")
    parser.add_argument("--inspect-only", action="store_true", help="Read checkpointed index without initialization, migrations or sync")
    parser.add_argument("--forensic-root", action="append", default=[], help="Explicit allowlisted artifact root to rebuild forensic index from")
    args = parser.parse_args()

    root = _root()
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

    from src.services.learning_db import inspect_learning_db, inspect_learning_db_readonly, sync_learning_db

    if args.inspect_only:
        if args.forensic_root:
            parser.error("--inspect-only cannot be combined with --forensic-root")
        result = inspect_learning_db_readonly()
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result.get("ok") else 2

    if args.forensic_root:
        if str(root.parent) not in sys.path:
            sys.path.insert(0, str(root.parent))
        from src.services.learning_db import load_learning_db_bundle, index_browser_forensic_run
        from src.services.browser_forensics.common import load_policy
        from hexeditor_tools.api import _forensic_root
        policy = load_policy()
        bundle = load_learning_db_bundle()
        indexer = next(i for i in bundle["registry"]["indexers"] if i["indexer_id"] == policy["indexer_id"])
        limit = args.scan_limit or bundle["policy"]["sync"]["backfill_scan_limit"]
        indexed, failures = 0, 0
        for folder in args.forensic_root:
            for artifact in sorted(_forensic_root(folder).glob(indexer["backfill_glob"]))[:limit]:
                try:
                    result = index_browser_forensic_run(artifact.parent, policy=policy, bundle=bundle)
                    indexed += bool(result.get("indexed"))
                except (OSError, ValueError, KeyError):
                    failures += 1
        print(json.dumps({"ok": failures == 0, "indexed_runs": indexed, "failed_runs": failures}, sort_keys=True))
        return 0 if failures == 0 else 2

    result = sync_learning_db(
        rail_ids=args.rails,
        include_findings=not args.skip_findings,
        scan_limit=args.scan_limit,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    if args.inspect:
        print(json.dumps(inspect_learning_db(), indent=2, sort_keys=True))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
