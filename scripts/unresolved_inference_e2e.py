"""Run, inspect, verify, resume or query unresolved ownership inference."""

from __future__ import annotations
import argparse, json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path: sys.path.insert(0, str(ROOT))
from src.services.unresolved_inference import inspect_unresolved_inference_run, query_binary_semantic_graph, resume_unresolved_inference_run, run_unresolved_inference_e2e, verify_unresolved_inference_run

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__); sub = parser.add_subparsers(dest="operation", required=True)
    item = sub.add_parser("run"); item.add_argument("full_decode_run"); item.add_argument("--output-root"); item.add_argument("--policy"); item.add_argument("--registry")
    for name in ("inspect", "verify", "resume"):
        item = sub.add_parser(name); item.add_argument("run")
    item = sub.add_parser("query"); item.add_argument("graph"); item.add_argument("query_operation", choices=("nodes_at_offset", "references_from", "references_to", "neighbors", "proof_path")); item.add_argument("--node-id"); item.add_argument("--offset", type=lambda value: int(value, 0)); item.add_argument("--maximum-depth", type=int, default=1); item.add_argument("--maximum-results", type=int, default=4096)
    args = parser.parse_args()
    if args.operation == "run": result = run_unresolved_inference_e2e(args.full_decode_run, output_root=args.output_root, policy_path=args.policy, registry_path=args.registry)
    elif args.operation == "inspect": result = inspect_unresolved_inference_run(args.run)
    elif args.operation == "verify": result = verify_unresolved_inference_run(args.run)
    elif args.operation == "resume": result = resume_unresolved_inference_run(args.run)
    else: result = query_binary_semantic_graph(args.graph, args.query_operation, node_id=args.node_id, offset=args.offset, maximum_depth=args.maximum_depth, maximum_results=args.maximum_results)
    print(json.dumps(result, indent=2, sort_keys=True, default=str)); return 0 if result.get("ok", result.get("verified", True)) else 1

if __name__ == "__main__": raise SystemExit(main())
