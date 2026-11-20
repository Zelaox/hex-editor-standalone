"""Current-user sealed recovery outputs. Never unwrap browser/session secrets."""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import html
import json
import os
from pathlib import Path
import uuid

from .common import canonical, confined, digest, editor_root, file_hash, load_policy, read_json, validate
from .engine import _prepare, _runtime_identity
from .sandbox import run_worker


def recovery_policy(path=None):
    policy = read_json(path or editor_root()/"config/browser_message_recovery_policy.json")
    validate(policy, "browser_forensics_recovery_policy.schema.json")
    return policy


def protect(data, *, decrypt=False):
    if os.name != "nt":
        raise RuntimeError("private_storage_unavailable_on_this_host")
    class Blob(ctypes.Structure):
        _fields_ = [("size", wintypes.DWORD), ("data", ctypes.POINTER(ctypes.c_ubyte))]
    storage = (ctypes.c_ubyte*len(data)).from_buffer_copy(data)
    source, target = Blob(len(data), storage), Blob()
    crypt32, kernel32 = ctypes.WinDLL("crypt32", use_last_error=True), ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    if decrypt:
        fn = crypt32.CryptUnprotectData
        fn.argtypes = [ctypes.POINTER(Blob), ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                       ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(Blob)]
        args = (ctypes.byref(source), None, None, None, None, 1, ctypes.byref(target))
    else:
        fn = crypt32.CryptProtectData
        fn.argtypes = [ctypes.POINTER(Blob), wintypes.LPCWSTR, ctypes.c_void_p, ctypes.c_void_p,
                       ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(Blob)]
        args = (ctypes.byref(source), "Hex Editor private recovery", None, None, None, 1, ctypes.byref(target))
    fn.restype = wintypes.BOOL
    if not fn(*args):
        raise RuntimeError("private_payload_protection_failed")
    try:
        return ctypes.string_at(target.data, target.size)
    finally:
        kernel32.LocalFree(target.data)


def recover(spec_path, output_workspace, *, policy_path=None, recovery_policy_path=None, index_learning=True):
    # Test platform protection before processing any private candidate bytes.
    if protect(protect(b"preflight"), decrypt=True) != b"preflight":
        raise RuntimeError("private_storage_preflight_failed")
    policy, config = load_policy(policy_path), recovery_policy(recovery_policy_path)
    spec = read_json(spec_path)
    root, files, identities = _prepare(spec, policy)
    registry = read_json(editor_root()/policy["format_registry"])
    build = _runtime_identity(policy)
    all_rows, summaries, runtime = {}, [], []
    for source in files:
        cursor = source.get("record_cursor", 0)
        page_summaries = []
        for _page in range(config["max_pages"]):
            worker = run_worker({"operation": "recover", "files": [{**source, "record_cursor": cursor}],
                                 "profiles": [], "policy": policy, "registry": registry, "build": build,
                                 "recovery_policy": config}, root)
            if worker.get("status") != "completed":
                raise RuntimeError("message_recovery_worker_"+worker.get("status", "failed"))
            if len(worker.get("files", [])) != 1:
                raise ValueError("recovery_worker_file_count")
            result = worker["files"][0]
            if result["path"] != source["path"] or result["sha256"] != source["sha256"]:
                raise ValueError("recovery_source_identity")
            runtime.append({key: worker.get(key) for key in ("python", "runtime_binary_sha256", "sandbox_binary_sha256")})
            for row in result.get("private_candidates", []):
                if row["source_path"] != source["path"] or row["source_sha256"] != source["sha256"]:
                    raise ValueError("candidate_source_identity")
                if row["status"] not in ("structured_message_candidate", "saved_dom_text_candidate", "unbound_blob_text_candidate"):
                    raise ValueError("unsupported_message_status")
                if not isinstance(row["text"], str) or len(row["text"]) > config["max_text_chars"]:
                    raise ValueError("candidate_text_budget")
                for span in row["source_spans"]:
                    if span["offset"] < 0 or span["length"] < 0 or span["offset"]+span["length"] > source["size"]:
                        raise ValueError("candidate_mapping_bounds")
                all_rows[row["candidate_id"]] = row
                if len(all_rows) > config["max_candidates"]:
                    raise ValueError("recovery_total_candidate_budget")
            page_summaries.append({"status": result["status"], "cursor": cursor,
                                   "candidate_count": len(result.get("private_candidates", [])),
                                   "statistics": result.get("recovery_statistics", {}),
                                   "known_field_counts": result.get("known_field_counts", {})})
            continuation = result.get("continuation", {}).get("record_cursor")
            if continuation is None:
                break
            if continuation <= cursor:
                raise ValueError("recovery_cursor_did_not_advance")
            cursor = continuation
        else:
            raise ValueError("recovery_page_budget")
        summaries.append({"path": source["path"], "sha256": source["sha256"], "pages": page_summaries})
    if any(file_hash(confined(root, f["path"])) != f["sha256"] for f in files):
        raise ValueError("input_changed")
    rows = sorted(all_rows.values(), key=lambda row: row["candidate_id"])
    context = {"case_id": spec["case_id"], "capture_id": spec["capture_id"]}
    identity = {"inputs": identities, "build": build, "policy_digest": digest(policy),
                "recovery_policy_digest": digest(config), "registry_digest": digest(registry), "runtime": runtime}
    payload = {"schema_version": 1, **context, "candidates": rows, "analysis_identity_digest": digest(identity)}
    summary = {"schema_version": 1, **context, "status": "partial", "snapshot_state": spec["snapshot_state"],
               "candidate_count": len(rows), "verified_message_count": 0,
               "structured_candidates": sum(r["status"] == "structured_message_candidate" for r in rows),
               "dom_candidates": sum(r["status"] == "saved_dom_text_candidate" for r in rows),
               "sources": summaries, "analysis_identity_digest": digest(identity),
               "storage": config["protected_storage"], "note": "Candidates are not verified/decrypted messages. No plaintext in this summary."}
    return save_private_run(payload, summary, identity, config, output_workspace,
                            max_output_bytes=policy["budgets"]["max_output_bytes"],
                            index_learning=index_learning, artifacts={"policy.json": policy, "registry.json": registry})


def save_private_run(payload, summary, identity, config, output_workspace, *, max_output_bytes,
                     index_learning=True, artifacts=None):
    """Shared authenticated envelope. No message text is persisted outside DPAPI."""
    sealed = protect(canonical(payload))
    if len(sealed) > max_output_bytes:
        raise ValueError("sealed_output_budget")
    run = Path(output_workspace).resolve()/("message-recovery-"+uuid.uuid4().hex)
    run.mkdir(parents=True, exist_ok=False)
    (run/"private.dpapi").write_bytes(sealed)
    summary = {**summary, "private_payload_file": "private.dpapi",
               "private_payload_sha256": file_hash(run/"private.dpapi")}
    summary["run_id"] = run.name
    summary["normalized_result_digest"] = digest({k: v for k,v in summary.items() if k not in ("private_payload_sha256", "run_id")})
    (run/"summary.json").write_bytes(canonical(summary))
    (run/"identity.json").write_bytes(canonical(identity))
    (run/"recovery_policy.json").write_bytes(canonical(config))
    for name, value in (artifacts or {}).items():
        confined(run, name).write_bytes(canonical(value))
    index_status = {"indexed": False, "reason": "disabled"}
    if index_learning:
        try:
            from src.services.learning_db import load_learning_db_bundle
            from src.services.learning_db.core import index_private_message_recovery
            bundle = load_learning_db_bundle()
            if bundle["policy"]["sync"]["on_run_complete"]:
                index_status = index_private_message_recovery(run, bundle=bundle)
            else:
                index_status = {"indexed": False, "reason": "auto_index_disabled"}
        except Exception as exc:
            index_status = {"indexed": False, "error_code": type(exc).__name__}
    return {"ok": True, "status": summary["status"], "run_path": str(run),
            "candidate_count": len(payload["candidates"]), "structured_candidates": summary["structured_candidates"],
            "dom_candidates": summary["dom_candidates"], "verified_message_count": 0,
            "storage": summary["storage"], "index_status": index_status}


def open_payload(run_path, case_id):
    root = Path(run_path).resolve()
    summary = read_json(confined(root, "summary.json"))
    projection = {k:v for k,v in summary.items() if k not in ("private_payload_sha256", "run_id", "normalized_result_digest")}
    if digest(projection) != summary["normalized_result_digest"]:
        raise ValueError("recovery_summary_digest_mismatch")
    if summary["case_id"] != case_id:
        raise ValueError("case_scope_mismatch")
    identity = read_json(confined(root, "identity.json"))
    if digest(identity) != summary["analysis_identity_digest"]:
        raise ValueError("recovery_identity_mismatch")
    target = confined(root, summary["private_payload_file"])
    if file_hash(target) != summary["private_payload_sha256"]:
        raise ValueError("private_payload_digest_mismatch")
    payload = json.loads(protect(target.read_bytes(), decrypt=True))
    if payload["case_id"] != case_id or payload["capture_id"] != summary["capture_id"]:
        raise ValueError("sealed_case_scope_mismatch")
    if payload["analysis_identity_digest"] != summary["analysis_identity_digest"]:
        raise ValueError("sealed_analysis_identity_mismatch")
    if len(payload["candidates"]) != summary["candidate_count"]:
        raise ValueError("sealed_candidate_count_mismatch")
    if payload.get("observation_kind") == "live_dom":
        from .live_dom import normalize_observation
        profile = read_json(confined(root, "live_profile.json"))
        validate(profile, "browser_live_dom_profile.schema.json")
        if digest(profile) != identity["live_profile_digest"]:
            raise ValueError("live_profile_digest_mismatch")
        observation = payload["source_observation"]
        if digest(observation) != identity["source_observation_sha256"] or digest(observation) != summary["source_observation_sha256"]:
            raise ValueError("live_source_digest_mismatch")
        if normalize_observation(observation, profile) != payload["candidates"]:
            raise ValueError("live_rows_mismatch")
    return payload


def private_html(payload):
    def escaped(value):
        return html.escape(str(value or ""), quote=True)
    live = payload.get("observation_kind") == "live_dom"
    parts = ["<h1>"+("Live chat text observations" if live else "Private text candidates — not verified messages")+"</h1>",
             "<p>No E2EE decryption is claimed. "+(
                 "Only loaded DOM text was captured. Missing per-message sender/time stays unknown. This is not a complete conversation export."
                 if live else "DOM rows may include interface text or another thread's contents.")+"</p>"]
    for row in payload["candidates"]:
        parts.append("<hr><h3>"+escaped(row.get("thread_label") or row.get("thread"))+" — "+escaped(row["status"])+"</h3><p>"+
                     escaped(row["text"]).replace("\n", "<br>")+"</p><p>Sender: "+escaped(row.get("sender") or "unknown")+
                     "; timestamp: "+escaped(row.get("timestamp") or "unknown")+"</p><p>Source: "+escaped(row["source_path"])+
                     "; locator: "+escaped(json.dumps(row["locator"], ensure_ascii=False))+"</p>")
    return "".join(parts)
