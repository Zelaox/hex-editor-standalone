"""Scan PTX plaintext calibration bundles and write expectations artifacts."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _root() -> Path:
    return Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=None, help="Calibration manifest path")
    parser.add_argument("--bundle-id", type=str, default=None, help="Optional bundle id filter")
    parser.add_argument("--write-expectations", action="store_true", help="Write expectations JSON for each bundle")
    args = parser.parse_args()

    root = _root()
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

    from src.services.ptx_plaintext_calibration import (
        load_calibration_manifest,
        resolve_calibration_bundle_path,
        scan_ptx_plaintext_signals,
        write_expectations,
    )

    manifest = load_calibration_manifest(args.manifest)
    bundles = list(manifest.get("bundles") or [])
    if args.bundle_id:
        bundles = [item for item in bundles if str(item.get("bundle_id") or "") == args.bundle_id]
    if not bundles:
        raise SystemExit("no calibration bundles selected")

    for bundle in bundles:
        source = resolve_calibration_bundle_path(bundle)
        scan = scan_ptx_plaintext_signals(source)
        print(json.dumps({"bundle_id": bundle.get("bundle_id"), "source": str(source), "minimums": scan["minimums"]}, indent=2))
        if args.write_expectations:
            output = Path(str(bundle.get("expectations_source") or ""))
            if not output.is_absolute():
                output = (root / output).resolve()
            written = write_expectations(scan, output)
            print(json.dumps({"expectations_written": str(written)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
