"""Operator-assisted, loaded-DOM observations; never browser storage or E2EE keys."""
from datetime import datetime
import re
from urllib.parse import urlsplit
import uuid

from .common import canonical, digest, editor_root, file_hash, read_json, validate
from .private_recovery import protect, recovery_policy, save_private_run


def live_profile(path=None):
    profile = read_json(path or editor_root()/"config/browser_live_dom_profile.json")
    validate(profile, "browser_live_dom_profile.schema.json")
    return profile


def _time(value):
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError("live_timestamp_type")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("live_timestamp_invalid") from None
    if parsed.tzinfo is None:
        raise ValueError("live_timestamp_timezone_required")
    return value


def normalize_observation(value, profile):
    """Never infer sender/time for adjacent bubbles or split pasted conversations."""
    if not isinstance(value, dict) or set(value) != {
        "schema_version", "profile_id", "profile_digest", "url", "conversation_id",
        "conversation_label", "observed_at", "groups"}:
        raise ValueError("live_envelope_fields")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise ValueError("live_schema_version")
    if value["profile_id"] != profile["id"] or value["profile_digest"] != digest(profile):
        raise ValueError("live_profile_mismatch")
    if not isinstance(value["url"], str) or len(value["url"]) > 4096:
        raise ValueError("live_url_type")
    url = urlsplit(value["url"])
    match = re.fullmatch(profile["conversation_path_pattern"], url.path)
    if (url.scheme+"://"+url.netloc not in profile["origins"] or url.username or url.password
            or url.query or url.fragment or not match or match.group(1) != value["conversation_id"]):
        raise ValueError("live_conversation_scope")
    label = value["conversation_label"]
    if not isinstance(label, str) or not label.strip() or len(label) > 512:
        raise ValueError("live_label_type")
    _time(value["observed_at"])
    if value["observed_at"] is None:
        raise ValueError("live_observation_time_required")
    groups = value["groups"]
    if not isinstance(groups, list) or not 0 < len(groups) <= profile["max_groups"]:
        raise ValueError("live_group_budget")
    rows, ordinal = [], 0
    source_hash = digest(value)
    for gi, group in enumerate(groups):
        if not isinstance(group, list):
            raise ValueError("live_group_type")
        for ri, row in enumerate(group):
            ordinal += 1
            if ordinal > profile["max_rows"]:
                raise ValueError("live_row_budget")
            if not isinstance(row, dict) or set(row) != {"text_parts", "sender", "timestamp"}:
                raise ValueError("live_row_fields")
            sender = row["sender"]
            if sender is not None and (not isinstance(sender, str) or not sender.strip() or len(sender) > 512):
                raise ValueError("live_sender_type")
            timestamp = _time(row["timestamp"])
            parts = row["text_parts"]
            if not isinstance(parts, list) or len(parts) > profile["max_parts_per_row"]:
                raise ValueError("live_parts_budget")
            for pi, text in enumerate(parts):
                if len(rows) >= profile["max_rows"]:
                    raise ValueError("live_text_observation_budget")
                if not isinstance(text, str) or not text.strip() or len(text) > profile["max_text_chars"]:
                    raise ValueError("live_text_budget")
                locator = {"group_ordinal": gi, "row_ordinal": ri, "part_ordinal": pi}
                rows.append({"candidate_id": digest({"source": source_hash, "locator": locator}),
                             "text": text, "sender": sender, "timestamp": timestamp,
                             "status": "live_dom_text_observation", "profile_id": profile["id"],
                             "thread": value["conversation_id"], "thread_label": label,
                             "source_path": "protected-source-observation", "source_sha256": source_hash,
                             "source_spans": [], "mapping_precision": "dom-observation", "locator": locator})
    if not rows:
        raise ValueError("live_no_text_observations")
    return rows


def seal_observation(value, output_workspace, case_id, *, profile=None, index_learning=True):
    profile = profile or live_profile()
    raw = canonical(value)
    if len(raw) > profile["max_input_bytes"]:
        raise ValueError("live_input_budget")
    if not isinstance(case_id, str) or not case_id.strip() or len(case_id) > 512:
        raise ValueError("live_case_id")
    rows = normalize_observation(value, profile)
    if protect(protect(b"preflight"), decrypt=True) != b"preflight":
        raise RuntimeError("private_storage_preflight_failed")
    config = recovery_policy()
    context = {"case_id": case_id, "capture_id": "live-dom-"+uuid.uuid4().hex}
    identity = {"source_observation_sha256": digest(value), "live_profile_digest": digest(profile),
                "recovery_policy_digest": digest(config),
                "implementation_sha256": file_hash(__file__)}
    payload = {"schema_version": 1, **context, "observation_kind": "live_dom",
               "source_observation": value, "candidates": rows, "analysis_identity_digest": digest(identity)}
    summary = {"schema_version": 1, **context, "status": "partial", "snapshot_state": "loaded_dom_only",
               "candidate_count": len(rows), "verified_message_count": 0,
               "structured_candidates": 0, "dom_candidates": len(rows), "storage": config["protected_storage"],
               "analysis_identity_digest": digest(identity), "source_observation_sha256": digest(value),
               "sender_present_count": sum(r["sender"] is not None for r in rows),
               "timestamp_present_count": sum(r["timestamp"] is not None for r in rows),
               "note": "Loaded DOM observations only; no complete history or E2EE decryption claim. Missing row metadata is unknown."}
    result = save_private_run(payload, summary, identity, config, output_workspace,
                              max_output_bytes=profile["max_input_bytes"]*3, index_learning=index_learning,
                              artifacts={"live_profile.json": profile})
    result["observation_kind"] = "live_dom"
    return result
