"""Run configured coverage-guided campaigns against an explicit synthetic corpus."""
import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.services.browser_forensics.common import load_policy, read_json, file_hash
from src.services.browser_forensics.sandbox import run_worker
from src.services.browser_forensics.private_recovery import recovery_policy


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--synthetic-corpus", required=True, help="Directory of approved synthetic .bin inputs, never live captures")
    parser.add_argument("--output", required=True)
    parser.add_argument("--policy")
    args = parser.parse_args()
    policy = load_policy(args.policy)
    files = sorted(Path(args.synthetic_corpus).glob("*.bin"))
    selected = [{"path": f.name, "sha256": file_hash(f)} for f in files if f.stat().st_size <= policy["fuzz"]["max_input_bytes"]]
    if not selected:
        parser.error("synthetic corpus is empty")
    result = run_worker({"operation": "fuzz", "files": selected, "policy": policy, "recovery_policy": recovery_policy(),
                         "registry": read_json(ROOT/policy["format_registry"])}, Path(args.synthetic_corpus), artifact_output=args.output)
    print({"ok": result.get("ok", False), "status": result["status"], "harnesses": len(result.get("harnesses", [])), "blockers": len(result.get("blockers", []))})
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
