"""Compile before/after delta, plaintext views, and reference diff for Gemma."""

from __future__ import annotations

import binascii
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

from src.services.crypto_calibration import load_crypto_calibration
from src.services.crypto_primitives import printable_ratio, sha256_digest
from src.services.binary_evidence_policy import evidence_policy
from src.services.crypto_scoring_regions import anchors_for_case, excluded_regions_for_case


def _lab_root() -> Path:
    from src.project import project_root
    return project_root()


def _resolve_reference_case(case: Optional[Mapping[str, Any]]) -> Optional[Dict[str, Any]]:
    if not case:
        return None
    ref_id = str((case.get("decrypt") or {}).get("reference_case_id") or "")
    if not ref_id:
        return None
    for item in load_crypto_calibration().get("cases") or []:
        if isinstance(item, dict) and str(item.get("id") or "") == ref_id:
            return dict(item)
    return None


def _load_reference_bytes(case: Optional[Mapping[str, Any]]) -> Optional[bytes]:
    ref_case = _resolve_reference_case(case)
    if not ref_case:
        return None
    rel = str(ref_case.get("path") or "")
    if not rel:
        return None
    path = (_lab_root() / rel).resolve()
    if not path.is_file():
        return None
    return path.read_bytes()


def evidence_windows_for_case(
    case: Optional[Mapping[str, Any]],
    *,
    file_size: int,
    crypto_defaults: Mapping[str, Any],
) -> List[Dict[str, Any]]:
    windows: List[Dict[str, Any]] = []
    if case:
        decrypt = dict(case.get("decrypt") or {})
        for item in decrypt.get("evidence_windows") or []:
            if isinstance(item, dict):
                windows.append(dict(item))
    if windows:
        return _normalize_windows(windows, file_size=file_size)
    policy = evidence_policy(crypto_defaults)
    max_len = int(policy["max_window_bytes"])
    for item in crypto_defaults.get("probe_windows") or []:
        if not isinstance(item, dict):
            continue
        start = int(item.get("offset") or 0)
        length = min(max_len, int(item.get("length") or max_len))
        if start < file_size:
            windows.append(
                {
                    "name": str(item.get("name") or hex(start)),
                    "offset": start,
                    "length": length,
                    "role": "transform_sample",
                }
            )
    if not windows:
        raise ValueError("no evidence windows computable — configure fixture evidence_windows or probe_windows")
    return _normalize_windows(windows, file_size=file_size)


def preserve_windows_for_case(case: Optional[Mapping[str, Any]], *, file_size: int) -> List[Dict[str, Any]]:
    windows: List[Dict[str, Any]] = []
    if case:
        decrypt = dict(case.get("decrypt") or {})
        for item in decrypt.get("preserve_evidence_windows") or []:
            if isinstance(item, dict):
                windows.append(dict(item))
    if not windows:
        for region in excluded_regions_for_case(case, file_size=file_size):
            start = int(region.get("start") or 0)
            end = int(region.get("end") or 0)
            if end > start:
                windows.append(
                    {
                        "name": str(region.get("reason") or "preserve"),
                        "offset": start,
                        "length": min(end - start, 256),
                        "role": "preserve",
                    }
                )
    return _normalize_windows(windows, file_size=file_size)


def _normalize_windows(windows: Sequence[Mapping[str, Any]], *, file_size: int) -> List[Dict[str, Any]]:
    normalized: List[Dict[str, Any]] = []
    for window in windows:
        start = max(0, int(window.get("offset") or 0))
        length = max(1, int(window.get("length") or 64))
        end = min(file_size, start + length)
        if start >= file_size or end <= start:
            continue
        normalized.append(
            {
                "name": str(window.get("name") or hex(start)),
                "offset": start,
                "length": end - start,
                "role": str(window.get("role") or "transform_sample"),
            }
        )
    return normalized


def decode_printable_view(data: bytes, *, max_chars: int) -> Dict[str, Any]:
    latin1 = data.decode("latin-1", errors="replace")
    utf8_ok = True
    try:
        utf8 = data.decode("utf-8")
    except UnicodeDecodeError:
        utf8_ok = False
        utf8 = latin1
    escaped = "".join(ch if ch.isprintable() and ch not in "\x00\r\n" else "." for ch in latin1[:max_chars])
    return {
        "latin1_preview": latin1[:max_chars],
        "utf8_preview": utf8[:max_chars],
        "utf8_valid": utf8_ok,
        "escaped": escaped,
        "printable_ratio": printable_ratio(data),
    }


def roundtrip_ok(data: bytes, encoding: str = "latin-1") -> bool:
    try:
        text = data.decode(encoding)
        return text.encode(encoding) == data
    except (UnicodeDecodeError, UnicodeEncodeError):
        return False


def delta_preview(
    before: bytes,
    after: bytes,
    *,
    base_offset: int,
    max_entries: int,
) -> List[Dict[str, Any]]:
    preview: List[Dict[str, Any]] = []
    limit = min(len(before), len(after))
    for index in range(limit):
        left = before[index]
        right = after[index]
        if left == right:
            continue
        preview.append(
            {
                "offset": base_offset + index,
                "before": f"0x{left:02x}",
                "after": f"0x{right:02x}",
                "xor": f"0x{left ^ right:02x}",
            }
        )
        if len(preview) >= max_entries:
            break
    return preview


def bounded_reference_diff(
    artifact: bytes,
    reference: bytes,
    *,
    max_hunks: int,
    max_hunk_bytes: int,
) -> Dict[str, Any]:
    if artifact == reference:
        return {
            "skipped": False,
            "identical": True,
            "hunk_count": 0,
            "hunks_preview": [],
        }
    hunks: List[Dict[str, Any]] = []
    limit = min(len(artifact), len(reference))
    index = 0
    while index < limit and len(hunks) < max_hunks:
        while index < limit and artifact[index] == reference[index]:
            index += 1
        if index >= limit:
            break
        start = index
        while index < limit and artifact[index] != reference[index] and (index - start) < max_hunk_bytes:
            index += 1
        hunks.append(
            {
                "offset": start,
                "length": index - start,
                "artifact_hex": binascii.hexlify(artifact[start:index]).decode("ascii"),
                "reference_hex": binascii.hexlify(reference[start:index]).decode("ascii"),
            }
        )
    size_mismatch = len(artifact) != len(reference)
    return {
        "skipped": False,
        "identical": False,
        "hunk_count": len(hunks) + (1 if size_mismatch else 0),
        "size_mismatch": size_mismatch,
        "hunks_preview": hunks,
    }


def _slice_window(data: bytes, window: Mapping[str, Any]) -> bytes:
    start = int(window["offset"])
    end = start + int(window["length"])
    return data[start:end]


def _compile_window_evidence(
    source: bytes,
    artifact: bytes,
    window: Mapping[str, Any],
    *,
    policy: Mapping[str, Any],
) -> Dict[str, Any]:
    before = _slice_window(source, window)
    after = _slice_window(artifact, window)
    max_chars = int(policy["max_printable_preview_chars"])
    before_view = decode_printable_view(before, max_chars=max_chars)
    after_view = decode_printable_view(after, max_chars=max_chars)
    deltas = delta_preview(
        before,
        after,
        base_offset=int(window["offset"]),
        max_entries=int(policy["max_delta_entries"]),
    )
    return {
        "name": str(window.get("name") or ""),
        "offset": int(window["offset"]),
        "length": int(window["length"]),
        "role": str(window.get("role") or "transform_sample"),
        "before_hex": binascii.hexlify(before[: int(policy["max_window_bytes"])]).decode("ascii"),
        "after_hex": binascii.hexlify(after[: int(policy["max_window_bytes"])]).decode("ascii"),
        "before_printable": before_view["escaped"],
        "after_printable": after_view["escaped"],
        "printable_ratio_before": before_view["printable_ratio"],
        "printable_ratio_after": after_view["printable_ratio"],
        "decode_encode_roundtrip_ok": roundtrip_ok(after, "latin-1"),
        "delta_count": sum(1 for left, right in zip(before, after) if left != right),
        "delta_preview": deltas,
        "unchanged": before == after,
    }


def compile_transform_evidence(
    source: bytes,
    artifact: bytes,
    *,
    case: Optional[Mapping[str, Any]],
    crypto_defaults: Mapping[str, Any],
    algorithm: str = "",
    key_hex: str = "",
    reference_bytes: bytes | None = None,
    include_reference_diff: bool = True,
    transform_regions: Optional[Sequence[Mapping[str, Any]]] = None,
    block_alignment: Optional[int] = None,
    iv_provenance: str = "",
    partial_tail_policy: str = "",
    decompression_success: Optional[bool] = None,
) -> Dict[str, Any]:
    policy = evidence_policy(crypto_defaults)
    file_size = len(source)
    windows = evidence_windows_for_case(case, file_size=file_size, crypto_defaults=crypto_defaults)
    preserve_windows = preserve_windows_for_case(case, file_size=file_size)

    window_evidence = [
        _compile_window_evidence(source, artifact, window, policy=policy) for window in windows
    ]
    preserve_checks: List[Dict[str, Any]] = []
    plaintext_regression = False
    for window in preserve_windows:
        before = _slice_window(source, window)
        after = _slice_window(artifact, window)
        ok = before == after
        reason = "unchanged" if ok else "preserve_region_mutated"
        if not ok:
            plaintext_regression = True
        preserve_checks.append(
            {
                "region": str(window.get("name") or ""),
                "offset": int(window["offset"]),
                "length": int(window["length"]),
                "ok": ok,
                "reason": reason,
            }
        )

    anchor_checks: List[Dict[str, Any]] = []
    anchor_improved = False
    for anchor in anchors_for_case(case):
        offset = int(anchor.get("offset") or 0)
        needle = anchor.get("needle")
        if isinstance(needle, str):
            needle = needle.encode("latin-1", errors="ignore")
        needle = bytes(needle or b"")
        if not needle or offset + len(needle) > len(artifact):
            continue
        in_source = needle in source[offset : offset + len(needle) + 32]
        in_artifact = needle in artifact[offset : offset + len(needle) + 32]
        ok = in_artifact
        if in_artifact and not in_source:
            anchor_improved = True
        if in_artifact:
            anchor_improved = True
        anchor_checks.append(
            {
                "label": str(anchor.get("label") or ""),
                "offset": hex(offset),
                "needle_found_before": in_source,
                "needle_found_after": in_artifact,
                "ok": ok,
            }
        )

    ref_case = _resolve_reference_case(case)
    reference_diff: Dict[str, Any]
    reference_acceptable: bool | None
    if not include_reference_diff:
        reference_diff = {"skipped": True, "identical": None, "hunk_count": 0, "hunks_preview": [], "reason": "deferred"}
        reference_acceptable = None
    elif reference_bytes is None:
        reference_bytes = _load_reference_bytes(case)
        if reference_bytes is None:
            reference_diff = {"skipped": True, "identical": None, "hunk_count": 0, "hunks_preview": []}
            reference_acceptable = None
        else:
            reference_diff = bounded_reference_diff(
                artifact,
                reference_bytes,
                max_hunks=int(policy["max_diff_hunks"]),
                max_hunk_bytes=int(policy["max_window_bytes"]),
            )
            reference_diff["reference_basename"] = Path(str(ref_case.get("path") or "")).name if ref_case else ""
            reference_diff["reference_sha256"] = sha256_digest(reference_bytes)
            reference_acceptable = bool(reference_diff.get("identical"))
    else:
        reference_diff = bounded_reference_diff(
            artifact,
            reference_bytes,
            max_hunks=int(policy["max_diff_hunks"]),
            max_hunk_bytes=int(policy["max_window_bytes"]),
        )
        reference_diff["reference_basename"] = Path(str(ref_case.get("path") or "")).name if ref_case else ""
        reference_diff["reference_sha256"] = sha256_digest(reference_bytes)
        reference_acceptable = bool(reference_diff.get("identical"))

    preserve_ok = all(item.get("ok") for item in preserve_checks) if preserve_checks else True
    min_improve = float(policy["min_printable_ratio_improvement"])
    for item in window_evidence:
        if str(item.get("role") or "") == "preserve":
            continue
        before_ratio = float(item.get("printable_ratio_before") or 0)
        after_ratio = float(item.get("printable_ratio_after") or 0)
        if before_ratio > 0.5 and (before_ratio - after_ratio) >= min_improve:
            plaintext_regression = True

    sha_match_ref = False
    ref_sha = str((case or {}).get("decrypt", {}).get("expected_sha256") or "").lower()
    artifact_sha = sha256_digest(artifact)
    if ref_sha and artifact_sha.lower() == ref_sha:
        sha_match_ref = True

    reject_reasons: List[str] = []
    if not preserve_ok:
        reject_reasons.append("preserve_region_mutated")
    if plaintext_regression:
        reject_reasons.append("plaintext_metadata_regression")
    if reference_acceptable is False:
        reject_reasons.append("reference_diff_unacceptable")

    promote_allowed = (
        preserve_ok
        and not plaintext_regression
        and (reference_acceptable is not False)
        and (anchor_improved or sha_match_ref)
    )

    result: Dict[str, Any] = {
        "source_sha256": sha256_digest(source),
        "artifact_sha256": artifact_sha,
        "algorithm": str(algorithm or ""),
        "key_hex": str(key_hex or ""),
        "windows": window_evidence,
        "preserve_checks": preserve_checks,
        "anchor_checks": anchor_checks,
        "reference_diff": reference_diff,
        "evidence_verdict": {
            "preserve_ok": preserve_ok,
            "anchor_improved": anchor_improved,
            "plaintext_regression": plaintext_regression,
            "reference_acceptable": reference_acceptable,
            "sha256_match_reference": sha_match_ref,
            "promote_allowed": promote_allowed,
            "reject_reasons": reject_reasons,
        },
    }
    if transform_regions is not None:
        result["transform_regions"] = [dict(item) for item in transform_regions]
    if block_alignment is not None:
        result["block_alignment"] = int(block_alignment)
    if iv_provenance:
        result["iv_provenance"] = str(iv_provenance)
    if partial_tail_policy:
        result["partial_tail_policy"] = str(partial_tail_policy)
    if decompression_success is not None:
        result["decompression_success"] = bool(decompression_success)
    return result
