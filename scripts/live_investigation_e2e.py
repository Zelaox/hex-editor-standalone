"""Run live investigation closure E2E with optional Gemma advisory."""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


def _resolve_llm(lab_root: Path, editor_root: Path):
    routing = json.loads((lab_root / "config" / "model_capability_routing.json").read_text(encoding="utf-8"))
    llm = json.loads((lab_root / "config" / "llm_config.json").read_text(encoding="utf-8"))
    capability = next(iter(routing["capabilities"].values()))
    agent_id = capability["agent_priority"][0]
    port = int(llm["agents"][agent_id]["launch_params"]["port"])
    endpoint = f"http://127.0.0.1:{port}"
    with urllib.request.urlopen(f"{endpoint}/health", timeout=15) as response:
        payload = json.loads(response.read().decode("utf-8"))
    if response.status != 200:
        raise RuntimeError(f"llm health check failed: {payload}")
    from hexeditor_tools.llm import LLMClient

    return LLMClient(endpoint), {"agent_id": agent_id, "port": port, "endpoint": endpoint}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", help="Evidence source file")
    parser.add_argument("parent", help="Equal-sized parent candidate")
    parser.add_argument("--lab-root", help="AI Lab root for live Gemma runs")
    parser.add_argument("--output-root")
    parser.add_argument("--policy", help="Live investigation policy path")
    parser.add_argument("--mechanical-only", action="store_true", help="Skip Gemma and use mechanical advisor")
    args = parser.parse_args()

    editor_root = Path(__file__).resolve().parents[1]
    sys.path[:0] = [str(editor_root)]
    if args.lab_root:
        sys.path.insert(0, str(Path(args.lab_root).resolve()))

    from src.services.live_investigation import gemma_advisory_action, load_live_investigation_policy, mechanical_advisory_action, run_live_investigation_e2e

    policy_bundle = load_live_investigation_policy(args.policy)
    advisor = mechanical_advisory_action
    gemma_meta = None
    started = time.monotonic()

    if not args.mechanical_only:
        if not args.lab_root:
            raise SystemExit("--lab-root is required unless --mechanical-only is set")
        lab_root = Path(args.lab_root).resolve()
        sys.path.insert(0, str(lab_root))
        try:
            client, gemma_meta = _resolve_llm(lab_root, editor_root)

            def advisor(packet):
                return gemma_advisory_action(packet, lab_root=lab_root, policy_bundle=policy_bundle, llm_client=client)

        except (urllib.error.URLError, TimeoutError, RuntimeError, ImportError) as exc:
            raise SystemExit(f"live Gemma unavailable: {exc}") from exc

    summary = run_live_investigation_e2e(args.source, args.parent, output_root=args.output_root, policy_path=args.policy, advisor=advisor, lab_root=args.lab_root)
    output = {
        "ok": bool(summary.get("verified")),
        "investigation_id": summary["investigation_id"],
        "artifact_root": summary["artifact_root"],
        "final_status": summary["final_status"],
        "turn_count": summary["turn_count"],
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "gemma": gemma_meta,
        "turns": summary["turns"],
    }
    print(json.dumps(output, indent=2, sort_keys=True, default=str))
    return 0 if output["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
