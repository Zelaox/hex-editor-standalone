"""Config-driven forensic rail orchestrator (delegates to registered stage callables)."""

from __future__ import annotations

import argparse
import importlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, Mapping

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _load_policy(path: Path) -> Dict[str, Any]:
    policy = json.loads(path.read_text(encoding="utf-8-sig"))
    required = {"schema_version", "policy_id", "revision", "stages"}
    if set(policy) != required or int(policy["schema_version"]) != 1:
        raise ValueError("invalid forensic orchestrator policy")
    return policy


def _invoke_stage(stage: Mapping[str, Any], *, source_path: Path, parent_path: Path, kwargs: Mapping[str, Any]) -> Any:
    module = importlib.import_module(str(stage["module"]))
    target = getattr(module, str(stage["callable"]))
    requires = {str(item) for item in stage.get("requires") or []}
    call_kwargs = dict(kwargs)
    if "source_path" in requires:
        call_kwargs["source_path"] = source_path
    if "parent_path" in requires:
        call_kwargs["parent_path"] = parent_path
    return target(**call_kwargs)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", help="Evidence source file")
    parser.add_argument("parent", help="Equal-sized parent candidate")
    parser.add_argument("--policy", default="config/forensic_investigation_orchestrator_policy.json")
    parser.add_argument("--output-root")
    parser.add_argument("--investigation-root")
    parser.add_argument("--lab-root")
    args = parser.parse_args()

    policy = _load_policy((ROOT / args.policy).resolve())
    source_path = Path(args.source).resolve()
    parent_path = Path(args.parent).resolve()
    shared = {
        "output_root": args.output_root,
        "investigation_root": args.investigation_root,
        "lab_root": args.lab_root,
    }
    results = []
    for stage in policy["stages"]:
        payload = _invoke_stage(stage, source_path=source_path, parent_path=parent_path, kwargs=shared)
        results.append({"stage_id": stage["stage_id"], "result": payload})
    print(json.dumps({"stages": results}, indent=2, sort_keys=True, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
