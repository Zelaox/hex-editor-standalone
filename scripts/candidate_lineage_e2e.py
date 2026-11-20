"""Resolve and verify candidate lineage across forensic rails."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.services.candidate_lineage import (
    candidate_graph_impact,
    resolve_candidate_lineage,
    verify_candidate_lineage_chain,
)


def _ascii_summary(packet: dict) -> str:
    lines = [
        f"operation={packet.get('operation')} chain_ok={packet.get('chain_ok')} verified={packet.get('verified')}",
        f"query={ (packet.get('query_identity') or {}).get('sha256', '') }",
    ]
    for node in packet.get("nodes") or []:
        lines.append(
            f"  rail={node.get('rail')} run_id={node.get('run_id')} status={node.get('status')} candidate={node.get('selected_candidate_id') or node.get('destination') or node.get('candidate_ids')}"
        )
    for check in packet.get("hash_checks") or []:
        flag = "ok" if check.get("ok") else "FAIL"
        lines.append(f"  check {flag}: {check.get('label')}")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    resolve_parser = sub.add_parser("resolve")
    resolve_parser.add_argument("--source-sha256")
    resolve_parser.add_argument("--file-path")
    verify_parser = sub.add_parser("verify")
    verify_parser.add_argument("--source-sha256")
    verify_parser.add_argument("--file-path")
    impact_parser = sub.add_parser("impact")
    impact_parser.add_argument("--source-sha256")
    impact_parser.add_argument("--file-path")
    impact_parser.add_argument("--candidate-id", default="")
    impact_parser.add_argument("--maximum-depth", type=int, default=1)
    args = parser.parse_args()

    if args.operation == "resolve":
        packet = resolve_candidate_lineage(source_sha256=args.source_sha256, file_path=args.file_path)
        print(_ascii_summary(packet))
        print(json.dumps(packet, indent=2, sort_keys=True, default=str))
        return 0 if packet.get("nodes") else 1
    if args.operation == "verify":
        packet = resolve_candidate_lineage(source_sha256=args.source_sha256, file_path=args.file_path)
        result = verify_candidate_lineage_chain(packet)
        print(json.dumps(result, indent=2, sort_keys=True, default=str))
        return 0 if result.get("ok") else 1
    packet = resolve_candidate_lineage(source_sha256=args.source_sha256, file_path=args.file_path)
    result = candidate_graph_impact(
        lineage_packet=packet,
        candidate_id=str(args.candidate_id or ""),
        maximum_depth=int(args.maximum_depth),
    )
    print(json.dumps(result, indent=2, sort_keys=True, default=str))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
