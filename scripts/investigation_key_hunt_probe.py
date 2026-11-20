"""Run a bounded, evidence-driven key probe for an investigation folder."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--investigation-root", required=True)
    parser.add_argument("--probe-phase-id", default="xor_l2_sweep")
    parser.add_argument("--window-source")
    parser.add_argument("--include-known", action="store_true", default=True)
    parser.add_argument("--no-include-known", action="store_false", dest="include_known")
    args = parser.parse_args()
    investigation = Path(args.investigation_root).resolve()
    lab = investigation.parents[2]
    editor = lab / "Hex editor"
    sys.path[:0] = [str(editor), str(lab)]
    from src.services.investigation_key_hunt import load_investigation_evidence
    from src.services.ptx_key_discovery import probe_ptx_decrypt_keys

    bundle = load_investigation_evidence(investigation)
    result = probe_ptx_decrypt_keys(
        bundle["source_path"],
        exhaustive=False,
        include_known=args.include_known,
        probe_phase_id=str(args.probe_phase_id or ""),
        investigation_root=str(investigation),
        window_source=str(args.window_source) if args.window_source else None,
        materialize_confirmed=False,
    )
    summary = {
        "ok": bool(result.get("ok")),
        "keys_found": bool(result.get("keys_found")),
        "best_key_hex": result.get("best_key_hex"),
        "best_score": (result.get("promotion_evidence") or {}).get("max_entropy_drop"),
        "probe_phase_id": result.get("probe_phase_id"),
        "window_source": result.get("window_source"),
        "investigation_probe_ledger": result.get("investigation_probe_ledger"),
        "next_key_cursor": result.get("next_key_cursor"),
        "phase_exhausted": result.get("phase_exhausted"),
    }
    print(json.dumps(summary, indent=2, sort_keys=True, default=str))
    return 0 if result.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main())
