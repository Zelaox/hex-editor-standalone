"""Promotion gate wiring for export manifests."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.services.export_promotion import resolve_export_promotion


def main() -> int:
    policy_disabled = {"export_promotion": {"enabled": False}}
    verdict = resolve_export_promotion(b"source", b"candidate", policy=policy_disabled)
    assert verdict["verified_decryption"] is False
    assert "export_promotion_disabled" in verdict["reject_reasons"]

    policy_enabled = {
        "export_promotion": {
            "enabled": True,
            "transform_start": 0,
            "reference_sha256": "",
            "crypto_defaults": {
                "min_cross_window_agreement": 2,
                "min_structural_improvements": 1,
                "min_entropy_drop": 0.35,
                "sha256_match_promotes": True,
                "promotion_policy": {"sha_match_requires_evidence_pass": True},
            },
        }
    }
    changed = resolve_export_promotion(b"\x00\x01", b"\x01\x01", policy=policy_enabled)
    assert changed["verified_decryption"] is False
    assert changed["reject_reasons"]
    print("[OK] export promotion wiring")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
