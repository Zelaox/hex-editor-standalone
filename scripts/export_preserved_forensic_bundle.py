"""Export preserved-binary forensic bundle (findings + knowledge metrics)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.services.forensic_bundle import export_preserved_forensic_bundle


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("preserved_run", help="Path to preserved run.json or run root")
    parser.add_argument("--full-decode-run", help="Optional full-decode run.json path")
    parser.add_argument("--update-run-artifacts", action="store_true", help="Write bundle paths into run.json artifacts")
    args = parser.parse_args()

    result = export_preserved_forensic_bundle(
        args.preserved_run,
        full_decode_run_path=args.full_decode_run,
    )
    if args.update_run_artifacts:
        run_file = Path(args.preserved_run).resolve()
        if run_file.is_dir():
            run_file = run_file / "run.json"
        run = json.loads(run_file.read_text(encoding="utf-8-sig"))
        run["artifacts"] = dict(run.get("artifacts") or {})
        run["artifacts"]["forensic_bundle"] = result["bundle_root"]
        run["artifacts"]["forensic_bundle_manifest"] = result["manifest_path"]
        run["artifacts"]["forensic_bundle_metrics"] = result["knowledge_coverage_path"]
        run_file.write_text(json.dumps(run, indent=2, sort_keys=True, ensure_ascii=False, default=str) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
