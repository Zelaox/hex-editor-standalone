"""Learn and score byte profiles from explicit plaintext reference files."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Mapping, Sequence


def _lab_root() -> Path:
    from src.project import project_root
    return project_root()


def load_plaintext_profile_policy(path: str | Path | None = None) -> Dict[str, Any]:
    policy_path = Path(path).expanduser().resolve() if path else Path(__file__).resolve().parents[2] / "config" / "plaintext_profile_policy.json"
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    if int(policy.get("schema_version") or 0) != 1:
        raise ValueError("plaintext profile policy schema_version unsupported")
    return policy


def resolve_library_path(policy: Mapping[str, Any]) -> Path:
    target = (_lab_root() / str(policy.get("library_path") or "")).resolve()
    target.relative_to(_lab_root())
    return target


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _byte_class_sets(policy: Mapping[str, Any]) -> Dict[str, set[int]]:
    result: Dict[str, set[int]] = {}
    for name, spec in (policy.get("byte_classes") or {}).items():
        values = {int(value) for value in spec.get("bytes") or []}
        for start, end in spec.get("ranges") or []:
            values.update(range(int(start), int(end) + 1))
        if any(value < 0 or value > 255 for value in values):
            raise ValueError(f"byte class {name} contains values outside 0..255")
        result[str(name)] = values
    return result


def extract_plaintext_features(data: bytes, policy: Mapping[str, Any]) -> Dict[str, Any]:
    limits = dict(policy.get("limits") or {})
    bounded = bytes(data[: int(limits.get("max_candidate_bytes") or len(data))])
    total = len(bounded)
    histogram = [0] * 256
    for value in bounded:
        histogram[value] += 1
    normalized = [count / total if total else 0.0 for count in histogram]
    classes = {name: (sum(histogram[value] for value in values) / total if total else 0.0) for name, values in _byte_class_sets(policy).items()}
    try:
        text = bounded.decode("utf-8", errors="strict")
        utf8_validity = 1.0
    except UnicodeDecodeError:
        text = bounded.decode("utf-8", errors="replace")
        replacement_count = text.count("\ufffd")
        utf8_validity = max(0.0, 1.0 - replacement_count / max(1, len(text)))
    pattern = re.compile(str(policy.get("token_pattern") or r"\S+"))
    minimum = int(limits.get("minimum_token_length") or 1)
    maximum = int(limits.get("maximum_token_length") or 128)
    tokens = Counter()
    for match in pattern.finditer(text):
        token = match.group(0)
        if minimum <= len(token) <= maximum:
            tokens[_sha256(token.encode("utf-8"))] += 1
    top_limit = int(limits.get("top_token_hashes") or 256)
    sequences: Counter[str] = Counter()
    stride = max(1, int(limits.get("sequence_stride") or 1))
    for sequence_length in limits.get("sequence_lengths") or []:
        width = int(sequence_length)
        if width <= 0:
            raise ValueError("sequence lengths must be positive")
        for offset in range(0, max(0, total - width + 1), stride):
            sequences[_sha256(bounded[offset:offset + width])] += 1
    sequence_limit = int(limits.get("top_sequence_hashes") or 1024)
    return {"byte_count": total, "byte_histogram": normalized, "byte_classes": classes, "utf8_validity": utf8_validity, "token_hashes": dict(tokens.most_common(top_limit)), "sequence_hashes": dict(sequences.most_common(sequence_limit))}


def _merge_features(feature_sets: Sequence[Mapping[str, Any]], policy: Mapping[str, Any]) -> Dict[str, Any]:
    total = sum(int(item.get("byte_count") or 0) for item in feature_sets)
    histogram = [0.0] * 256
    class_totals: Dict[str, float] = Counter()
    utf8_total = 0.0
    tokens: Counter[str] = Counter()
    sequences: Counter[str] = Counter()
    for item in feature_sets:
        weight = int(item.get("byte_count") or 0)
        for index, value in enumerate(item.get("byte_histogram") or []):
            histogram[index] += float(value) * weight
        for name, value in (item.get("byte_classes") or {}).items():
            class_totals[str(name)] += float(value) * weight
        utf8_total += float(item.get("utf8_validity") or 0.0) * weight
        tokens.update({str(key): int(value) for key, value in (item.get("token_hashes") or {}).items()})
        sequences.update({str(key): int(value) for key, value in (item.get("sequence_hashes") or {}).items()})
    divisor = max(1, total)
    top_limit = int((policy.get("limits") or {}).get("top_token_hashes") or 256)
    sequence_limit = int((policy.get("limits") or {}).get("top_sequence_hashes") or 1024)
    return {"byte_count": total, "byte_histogram": [value / divisor for value in histogram], "byte_classes": {name: value / divisor for name, value in sorted(class_totals.items())}, "utf8_validity": utf8_total / divisor, "token_hashes": dict(tokens.most_common(top_limit)), "sequence_hashes": dict(sequences.most_common(sequence_limit))}


def build_plaintext_profile(profile_id: str, reference_paths: Sequence[str | Path], *, policy: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    cfg = dict(policy or load_plaintext_profile_policy())
    clean_id = str(profile_id or "").strip()
    if not clean_id or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", clean_id):
        raise ValueError("profile_id must be a lowercase stable identifier")
    limits = dict(cfg.get("limits") or {})
    paths = [Path(value).expanduser().resolve() for value in reference_paths]
    if not paths or len(paths) > int(limits.get("max_files_per_profile") or 0):
        raise ValueError("reference file count outside configured limits")
    allowed = {str(value).lower() for value in cfg.get("allowed_suffixes") or []}
    features = []
    sources = []
    total_bytes = 0
    for path in paths:
        if not path.is_file() or ("*" not in allowed and path.suffix.lower() not in allowed):
            raise ValueError(f"reference file is missing or suffix is not allowed: {path}")
        size = path.stat().st_size
        if size > int(limits.get("max_bytes_per_file") or 0):
            raise ValueError(f"reference file exceeds configured limit: {path}")
        total_bytes += size
        if total_bytes > int(limits.get("max_total_reference_bytes") or 0):
            raise ValueError("reference set exceeds configured total byte budget")
        data = path.read_bytes()
        features.append(extract_plaintext_features(data, cfg))
        sources.append({"sha256": _sha256(data), "size": size, "suffix": path.suffix.lower()})
    merged = _merge_features(features, cfg)
    return {"profile_id": clean_id, "reference_count": len(sources), "reference_bytes": total_bytes, "source_provenance": sources, "features": merged}


def update_plaintext_profile_library(profile_id: str, reference_paths: Sequence[str | Path], *, policy: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    cfg = dict(policy or load_plaintext_profile_policy())
    target = resolve_library_path(cfg)
    library = {"schema_version": 1, "policy_id": cfg.get("policy_id"), "policy_revision": cfg.get("revision"), "profiles": {}}
    if target.is_file():
        library = json.loads(target.read_text(encoding="utf-8"))
    profiles = dict(library.get("profiles") or {})
    if profile_id not in profiles and len(profiles) >= int((cfg.get("limits") or {}).get("max_profiles") or 0):
        raise ValueError("profile library reached configured profile limit")
    profiles[profile_id] = build_plaintext_profile(profile_id, reference_paths, policy=cfg)
    library = {"schema_version": 1, "policy_id": cfg.get("policy_id"), "policy_revision": cfg.get("revision"), "profiles": profiles}
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f".{target.name}.tmp")
    try:
        temporary.write_text(json.dumps(library, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(temporary, target)
    finally:
        if temporary.exists():
            temporary.unlink()
    return {"ok": True, "operation": "plaintext_profile_build", "profile_id": profile_id, "library_path": str(target), "profile": profiles[profile_id]}


def load_plaintext_profile_library(*, policy: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    cfg = dict(policy or load_plaintext_profile_policy())
    target = resolve_library_path(cfg)
    if not target.is_file():
        return {"schema_version": 1, "policy_id": cfg.get("policy_id"), "policy_revision": cfg.get("revision"), "profiles": {}}
    return json.loads(target.read_text(encoding="utf-8"))


def _cosine(left: Sequence[float], right: Sequence[float]) -> float:
    dot = sum(float(a) * float(b) for a, b in zip(left, right))
    left_norm = math.sqrt(sum(float(value) ** 2 for value in left))
    right_norm = math.sqrt(sum(float(value) ** 2 for value in right))
    return dot / (left_norm * right_norm) if left_norm and right_norm else 0.0


def score_plaintext_profiles(data: bytes, *, policy: Mapping[str, Any] | None = None, library: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    cfg = dict(policy or load_plaintext_profile_policy())
    lib = dict(library or load_plaintext_profile_library(policy=cfg))
    candidate = extract_plaintext_features(data, cfg)
    weights = {str(key): float(value) for key, value in (cfg.get("score_weights") or {}).items()}
    weight_total = sum(weights.values()) or 1.0
    results = []
    for profile_id, profile in (lib.get("profiles") or {}).items():
        reference = dict(profile.get("features") or {})
        histogram_score = _cosine(candidate["byte_histogram"], reference.get("byte_histogram") or [])
        class_names = sorted(set(candidate["byte_classes"]) | set(reference.get("byte_classes") or {}))
        class_score = sum(1.0 - abs(float(candidate["byte_classes"].get(name, 0.0)) - float((reference.get("byte_classes") or {}).get(name, 0.0))) for name in class_names) / max(1, len(class_names))
        candidate_tokens, reference_tokens = set(candidate["token_hashes"]), set(reference.get("token_hashes") or {})
        token_score = len(candidate_tokens & reference_tokens) / max(1, len(candidate_tokens | reference_tokens))
        candidate_sequences, reference_sequences = set(candidate["sequence_hashes"]), set(reference.get("sequence_hashes") or {})
        sequence_score = len(candidate_sequences & reference_sequences) / max(1, len(candidate_sequences | reference_sequences))
        utf8_score = 1.0 - abs(float(candidate["utf8_validity"]) - float(reference.get("utf8_validity") or 0.0))
        components = {"byte_histogram_cosine": histogram_score, "byte_class_similarity": class_score, "token_hash_similarity": token_score, "sequence_hash_similarity": sequence_score, "utf8_similarity": utf8_score}
        similarity = sum(components[name] * weights.get(name, 0.0) for name in components) / weight_total
        results.append({"profile_id": str(profile_id), "similarity": round(similarity, 6), "components": {name: round(value, 6) for name, value in components.items()}, "reference_count": int(profile.get("reference_count") or 0)})
    results.sort(key=lambda item: (-item["similarity"], item["profile_id"]))
    limited = results[: int(cfg.get("max_results") or 5)]
    best = limited[0] if limited else None
    return {"available": bool(limited), "best": best, "matches": limited, "minimum_similarity": float(cfg.get("minimum_similarity") or 0.0), "profile_match": bool(best and best["similarity"] >= float(cfg.get("minimum_similarity") or 0.0))}
