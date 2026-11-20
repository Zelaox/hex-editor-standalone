"""Audit proof spans and hypothetical preservation losses across existing runs."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _root() -> Path:
    return Path(__file__).resolve().parents[1]


def _load_lineage_policy(root: Path) -> dict:
    from src.services.proof_ledger.core import load_proof_ledger_bundle

    bundle = load_proof_ledger_bundle()
    policy_path = root / str(bundle["policy"]["audit"]["lineage_policy_path"])
    return json.loads(policy_path.read_text(encoding="utf-8"))


def _discover_runs(root: Path, lineage_policy: dict, scan_limit: int) -> list[Path]:
    discovered: list[Path] = []
    for rail in lineage_policy.get("rails") or []:
        artifact_root = root / str(rail.get("artifact_root") or "")
        if not artifact_root.is_dir():
            continue
        for run_path in sorted(artifact_root.glob("**/run.json")):
            discovered.append(run_path)
            if len(discovered) >= scan_limit:
                return discovered
    return discovered


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit proof ledger spans and hypothetical losses")
    parser.add_argument("--from-run", dest="from_run", help="Baseline run.json or run root")
    parser.add_argument("--to-run", dest="to_run", help="Comparison run.json or run root")
    parser.add_argument("--scan-limit", type=int, default=None, help="Override configured scan limit")
    parser.add_argument("--output", help="Optional JSON report path")
    args = parser.parse_args()

    root = _root()
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

    from src.services.proof_ledger.core import (
        _read,
        audit_parent_child_loss,
        compile_proof_ledger_from_run,
        load_proof_ledger_bundle,
        load_protected_spans,
        lineage_key_from_run,
        query_lineage_ledger,
    )
    from src.services.proof_ledger.delta_compiler import _candidate_bytes, _parent_bytes, _run_file

    bundle = load_proof_ledger_bundle()
    report: dict = {"operation": "proof_ledger_audit", "entries": []}

    if args.from_run and args.to_run:
        from_path = Path(args.from_run).resolve()
        to_path = Path(args.to_run).resolve()
        from_run = _read(_run_file(from_path))
        to_run = _read(_run_file(to_path))
        key = lineage_key_from_run(to_run, bundle=bundle)
        protected = load_protected_spans(key, bundle=bundle)
        from_bytes = _candidate_bytes(from_path, from_run) or _parent_bytes(from_run)
        to_bytes = _candidate_bytes(to_path, to_run) or _parent_bytes(to_run)
        report["pair_audit"] = audit_parent_child_loss(from_bytes, to_bytes, protected)
        report["lineage_key"] = key
    else:
        lineage_policy = _load_lineage_policy(root)
        scan_limit = int(args.scan_limit or bundle["policy"]["audit"]["scan_limit"])
        for run_path in _discover_runs(root, lineage_policy, scan_limit):
            run = _read(run_path)
            rail_id = "full_decode"
            for rail in lineage_policy.get("rails") or []:
                artifact_root = str(rail.get("artifact_root") or "")
                if artifact_root and artifact_root in str(run_path).replace("\\", "/"):
                    rail_id = str(rail.get("rail_id") or rail_id)
                    break
            compile_result = compile_proof_ledger_from_run(run_path, rail_id, bundle=bundle)
            lineage = query_lineage_ledger(str(compile_result["lineage_key"]), bundle=bundle)
            report["entries"].append(
                {
                    "run_path": str(run_path),
                    "rail_id": rail_id,
                    "lineage_key": compile_result["lineage_key"],
                    "protected_span_count": compile_result["protected_span_count"],
                    "frontier_count": int((lineage.get("frontier") or {}).get("frontier_count") or 0),
                }
            )

    encoded = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        Path(args.output).write_text(encoded + "\n", encoding="utf-8")
    print(encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
