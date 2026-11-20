"""Read-only PTX decryption key probing — advanced XOR / SHA / AES analysis."""

from __future__ import annotations

import binascii
from pathlib import Path
from typing import Any, Dict, List

from src.services.binary_inspection import binary_file_info
from src.services.contracts import AnalysisResult, Finding
from src.services.ptx_crypto_analysis import analyze_ptx_crypto_candidates

from src.services.ptx_crypto_config import probe_pipeline_config

DEFAULT_SAMPLE_OFFSET = 16
DEFAULT_SAMPLE_LENGTH = 4096


def default_key_batch(*, exhaustive: bool = False) -> int:
    pipeline = probe_pipeline_config()
    sweep_limit = int(pipeline.get("sweep_key_limit") or 256)
    if exhaustive:
        return int(pipeline.get("exhaustive_key_batch") or sweep_limit)
    return int(pipeline.get("default_key_batch") or 16)


DEFAULT_KEY_BATCH = default_key_batch()

# Backward-compatible exports for ptx_auto_decrypt and tests.
KNOWN_KEYS: List[Dict[str, Any]] = []


def _parse_key_hex(key_hex: str) -> bytes:
    cleaned = str(key_hex or "").strip().replace(" ", "")
    if not cleaned or len(cleaned) % 2:
        raise ValueError("key_hex must be even-length hex")
    return bytes.fromhex(cleaned)


def _xor_apply(data: bytes, key: bytes) -> bytes:
    from src.services.ptx_crypto_primitives import xor_apply

    return xor_apply(data, key)


def probe_ptx_decrypt_keys(
    path: str | Path,
    *,
    sample_offset: int = DEFAULT_SAMPLE_OFFSET,
    sample_length: int = DEFAULT_SAMPLE_LENGTH,
    key_cursor: int = 0,
    key_batch: int | None = None,
    include_known: bool = True,
    artifact_output_dir: str | Path | None = None,
    exhaustive: bool = False,
    probe_phase_id: str = "",
    materialize_confirmed: bool = False,
    investigation_root: str | None = None,
    window_source: str | None = None,
) -> Dict[str, Any]:
    """Bounded read-only crypto probe (XOR + SHA validation + AES-128 trial lane)."""
    if key_batch is None:
        key_batch = default_key_batch(exhaustive=exhaustive)
    if investigation_root:
        from src.services.investigation_key_hunt import load_investigation_key_hunt_policy, load_checkpoint

        hunt_policy = load_investigation_key_hunt_policy()
        if not exhaustive:
            key_batch = int(hunt_policy["budgets"]["default_key_batch"])
        checkpoint = load_checkpoint(investigation_root, policy=hunt_policy)
        if checkpoint and probe_phase_id and str(checkpoint.get("probe_phase_id") or "") == str(probe_phase_id or ""):
            key_cursor = int(checkpoint.get("key_cursor") or key_cursor)
        if checkpoint.get("phase_exhausted"):
            return {
                "ok": True,
                "operation": "ptx_probe_decrypt_keys",
                "keys_found": bool(checkpoint.get("keys_found")),
                "probe_phase_id": probe_phase_id,
                "phase_exhausted": True,
                "key_cursor": int(checkpoint.get("key_cursor") or 0),
                "next_key_cursor": None,
                "investigation_probe_ledger": {"checkpoint": checkpoint, "resumed": True, "skipped": True},
            }
    resolved = Path(path).expanduser().resolve()
    info = binary_file_info(resolved)
    source = info["source"]
    warnings = [
        "Key candidates are hypotheses until SHA256/anchor validation passes promotion gate.",
        "Identity XOR (e.g. 0x00) is rejected when ciphertext body is unchanged.",
        "AES-128 ECB lane is advisory — XOR remains primary for AC240-family samples.",
        "Do not write decryption_key=... to verified_facts without cross-window confirmation.",
        "A verified key is never materialized unless materialize_confirmed=true.",
    ]

    if resolved.suffix.lower() != ".ptx":
        return AnalysisResult(
            ok=False,
            operation="ptx_probe_decrypt_keys",
            source=source,
            warnings=warnings,
            error="PTX key probe requires a .ptx file",
        ).to_dict()

    file_size = int(source.get("size") or resolved.stat().st_size)
    start = max(0, int(sample_offset))
    length = max(64, min(int(sample_length), 65536, file_size - start))
    if start >= file_size:
        return AnalysisResult(
            ok=False,
            operation="ptx_probe_decrypt_keys",
            source=source,
            warnings=warnings,
            error=f"sample_offset 0x{start:X} beyond file size {file_size}",
        ).to_dict()

    analysis = analyze_ptx_crypto_candidates(
        resolved,
        sample_offset=start,
        sample_length=length,
        key_cursor=key_cursor,
        key_batch=key_batch,
        include_known=include_known,
        source_sha256=str(source.get("sha256") or ""),
        file_size=file_size,
        probe_phase_id=str(probe_phase_id or ""),
        investigation_root=investigation_root,
        window_source=window_source,
    )
    candidates = list(analysis.get("candidates") or [])
    best = dict(analysis.get("best") or {})
    keys_found = bool(analysis.get("keys_found"))
    promotion_evidence = dict(analysis.get("promotion_evidence") or best.get("promotion_evidence") or {})
    transform_evidence = dict(
        analysis.get("transform_evidence") or best.get("transform_evidence") or promotion_evidence.get("transform_evidence") or {}
    )
    cursor = int(analysis.get("key_cursor") or 0)
    next_cursor = analysis.get("next_key_cursor")

    sample = resolved.read_bytes()[start : start + length]
    findings: List[Dict[str, Any]] = [
        Finding(
            "key_candidates",
            candidates[:16],
            "ptx_crypto_analysis.analyze_ptx_crypto_candidates",
            "heuristic",
        ).to_dict(),
        Finding(
            "probe_window",
            {
                "offset": start,
                "length": length,
                "hex_preview": binascii.hexlify(sample[:32]).decode("ascii"),
                "windows": analysis.get("probe_windows") or [],
            },
            "ptx_key_discovery",
            "verified",
        ).to_dict(),
        Finding(
            "crypto_summary",
            {
                "reference_sha256": analysis.get("reference_sha256"),
                "crypto_case_id": analysis.get("crypto_case_id"),
                "xor_start_offset": analysis.get("xor_start_offset"),
                "algorithms_evaluated": sorted({str(item.get("algorithm") or "") for item in candidates}),
            },
            "ptx_crypto_analysis",
            "verified",
        ).to_dict(),
    ]
    if best:
        findings.append(
            Finding(
                "best_candidate",
                best,
                "ptx_crypto_analysis.rank",
                "verified" if keys_found else "heuristic",
            ).to_dict()
        )
    if promotion_evidence:
        findings.append(
            Finding(
                "promotion_evidence",
                promotion_evidence,
                "ptx_promotion_gate.evaluate_promotion",
                "verified" if promotion_evidence.get("promoted") else "heuristic",
            ).to_dict()
        )
    if transform_evidence:
        findings.append(
            Finding(
                "transform_evidence",
                transform_evidence,
                "ptx_transform_evidence.compile_transform_evidence",
                "verified" if (transform_evidence.get("evidence_verdict") or {}).get("promote_allowed") else "heuristic",
            ).to_dict()
        )

    decrypted_artifact: Dict[str, Any] | None = None
    chat_ui_links: Dict[str, Any] | None = None
    if keys_found and best and not best.get("skip_materialize") and materialize_confirmed is True:
        from src.services.ptx_auto_decrypt import materialize_ptx_decrypt_copy

        materialized = materialize_ptx_decrypt_copy(
            resolved,
            str(best.get("key_hex") or ""),
            algorithm=str(best.get("algorithm") or "xor_single_byte"),
            xor_start_offset=int(analysis.get("xor_start_offset") or DEFAULT_SAMPLE_OFFSET),
            artifact_output_dir=artifact_output_dir,
        )
        if materialized.get("ok"):
            decrypted_artifact = materialized
            chat_ui_links = materialized.get("chat_ui_links")
            findings.append(
                Finding(
                    "decrypted_artifact",
                    {
                        "decrypted_path": materialized.get("decrypted_path"),
                        "source_snapshot_path": materialized.get("source_snapshot_path"),
                        "artifact_folder": materialized.get("artifact_folder"),
                        "sha256": materialized.get("sha256"),
                        "source_sha256": materialized.get("source_sha256"),
                        "sha256_match_reference": (best.get("full_file_validation") or {}).get(
                            "sha256_match_reference"
                        ),
                        "algorithm": materialized.get("algorithm"),
                        "chat_ui_links": chat_ui_links,
                    },
                    "ptx_auto_decrypt.materialize_ptx_decrypt_copy",
                    "verified",
                ).to_dict()
            )
        else:
            warnings.append(
                "keys_found=true but auto-decrypt materialize failed: "
                f"{materialized.get('error', 'unknown error')}"
            )
            keys_found = False

    payload = AnalysisResult(
        ok=True,
        operation="ptx_probe_decrypt_keys",
        source=source,
        findings=findings,
        warnings=warnings,
    ).to_dict()
    extra: Dict[str, Any] = {
        "keys_found": keys_found,
        "best_key_hex": str(best.get("key_hex") or ""),
        "best_algorithm": str(best.get("algorithm") or ""),
        "sample_offset": start,
        "xor_start_offset": int(analysis.get("xor_start_offset") or DEFAULT_SAMPLE_OFFSET),
        "promotion_evidence": promotion_evidence,
        "transform_evidence": transform_evidence,
        "key_cursor": cursor,
        "key_batch": int(analysis.get("key_batch") or key_batch),
        "sweep_key_limit": int(analysis.get("sweep_key_limit") or 256),
        "sweep_single_byte_limit": int(analysis.get("sweep_single_byte_limit") or 256),
        "next_key_cursor": next_cursor,
        "probe_phase_id": str(analysis.get("probe_phase_id") or probe_phase_id or ""),
        "phase_exhausted": bool(analysis.get("phase_exhausted")),
        "window_source": analysis.get("window_source"),
        "derived_windows_digest": analysis.get("derived_windows_digest"),
        "probe_timings_ms": analysis.get("probe_timings_ms") or {},
        "recommended_next": {
            "operation": "ptx_probe_decrypt_keys",
            "sample_offset": start,
            "sample_length": length,
            "key_cursor": next_cursor if next_cursor is not None else 0,
            "include_known": False,
            "reason": "Continue bounded crypto sweep until keys_found=true or all single-byte XOR keys tested.",
        }
        if not keys_found and next_cursor is not None
        else None,
    }
    if decrypted_artifact:
        extra["decrypted_artifact"] = decrypted_artifact
    if chat_ui_links:
        extra["chat_ui_links"] = chat_ui_links
        extra["chat_surface"] = {
            "must_include_in_reply": [chat_ui_links.get("must_include_in_reply", "")],
            "markdown_link": chat_ui_links.get("markdown_link", ""),
            "download_url": chat_ui_links.get("url", ""),
        }
    payload.update(extra)
    if investigation_root:
        import time

        from src.services.investigation_key_hunt import load_investigation_key_hunt_policy, record_probe_run

        hunt_policy = load_investigation_key_hunt_policy()
        window_resolution = {
            "window_source": analysis.get("window_source"),
            "policy_digest": analysis.get("window_policy_digest"),
            "derived_windows": {"artifact_digest": analysis.get("derived_windows_digest")},
            "body_windows": analysis.get("probe_windows") or [],
        }
        started = time.monotonic()
        ledger = record_probe_run(
            investigation_root,
            analysis=analysis,
            policy=hunt_policy,
            window_resolution=window_resolution,
            elapsed_seconds=sum(float(value) for value in (analysis.get("probe_timings_ms") or {}).values()) / 1000.0,
            started_monotonic=started,
        )
        payload["investigation_probe_ledger"] = ledger
    return payload
