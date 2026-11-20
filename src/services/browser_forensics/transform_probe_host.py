"""Authenticated, masked structural-probe receipts and sealed recovered candidates."""
from pathlib import Path

from .common import canonical, confined, digest, editor_root, file_hash, load_policy, read_json, validate
from .engine import _prepare, _runtime_identity
from .private_recovery import recovery_policy, save_private_run, protect, open_payload
from .readable_export import export_policy
from .sandbox import run_worker


def probe_policy(path=None):
    config = read_json(path or editor_root()/"config/browser_transform_probe_policy.json")
    validate(config,"browser_forensics_transform_policy.schema.json")
    if (config["min_target_bytes"] > config["max_target_bytes"] or config["single_byte_min"] > config["single_byte_max"]
            or config["repeating_period_min"] > config["repeating_period_max"]):
        raise ValueError("transform_policy_bounds")
    return config


def run_probe(spec_path, output_workspace, *, policy_path=None, recovery_policy_path=None, transform_policy_path=None):
    if protect(protect(b"preflight"),decrypt=True) != b"preflight": raise RuntimeError("private_storage_preflight_failed")
    policy, rcfg, config = load_policy(policy_path), recovery_policy(recovery_policy_path), probe_policy(transform_policy_path)
    spec = read_json(spec_path)
    root,files,identities = _prepare(spec,policy)
    registry, media_config = read_json(editor_root()/policy["format_registry"]), export_policy()
    build = _runtime_identity(policy)
    build["shared_xor_executor_sha256"] = file_hash(editor_root()/"src/services/key_hunt_executors.py")
    rows, media, summaries, runtime = {},{},[],[]
    for source in files:
        result = run_worker({"operation":"transform_probe","files":[source],"policy":policy,"build":build,
                             "registry":registry,"recovery_policy":rcfg,"transform_policy":config,
                             "export_policy":media_config},root)
        if result.get("status") != "completed" or len(result.get("files",[])) != 1:
            raise RuntimeError("transform_worker_"+result.get("status","failed"))
        if result.get("shared_xor_executor_sha256") != build["shared_xor_executor_sha256"]:
            raise ValueError("transform_executor_identity")
        item = result["files"][0]
        if item["path"] != source["path"] or item["sha256"] != source["sha256"]:
            raise ValueError("transform_source_identity")
        for row in item["private_candidates"]:
            if (row["source_path"] != source["path"] or row["source_sha256"] != source["sha256"]
                    or row["status"] not in ("structured_message_candidate","saved_dom_text_candidate")
                    or len(row["text"]) > rcfg["max_text_chars"]):
                raise ValueError("transform_message_identity")
            for span in row["source_spans"]:
                if span["offset"] < 0 or span["length"] < 0 or span["offset"]+span["length"] > source["size"]:
                    raise ValueError("transform_mapping_bounds")
            rows[row["candidate_id"]] = row
        for entry in item["private_media"]:
            if entry["source_path"] != source["path"] or entry["source_sha256"] != source["sha256"]:
                raise ValueError("transform_media_identity")
            media[entry["sha256"]] = entry
        if len(rows) > rcfg["max_candidates"] or len(media) > media_config["media"]["max_items"]:
            raise ValueError("transform_result_budget")
        summaries.append({"path":source["path"],"sha256":source["sha256"],"status":item["status"],
                          "statistics":item["statistics"],"structures":item["structures"],"verified_decryption":False})
        runtime.append({key:result.get(key) for key in ("python","runtime_binary_sha256","sandbox_binary_sha256","shared_xor_executor_sha256")})
    if any(file_hash(confined(root,f["path"])) != f["sha256"] for f in files): raise ValueError("input_changed")
    identity = {"inputs":identities,"build":build,"policy_digest":digest(policy),"recovery_policy_digest":digest(rcfg),
                "transform_policy_digest":digest(config),"media_policy_digest":digest(media_config),"registry_digest":digest(registry),"runtime":runtime}
    context = {"case_id":spec["case_id"],"capture_id":spec["capture_id"]}
    payload = {"schema_version":1,**context,"observation_kind":"transform_probe","candidates":list(rows.values()),
               "derived_media":list(media.values()),"analysis_identity_digest":digest(identity)}
    summary = {"schema_version":1,**context,"status":"partial","snapshot_state":spec["snapshot_state"],
               "candidate_count":len(rows),"verified_message_count":0,"verified_decryption":False,
               "structured_candidates":sum(r["status"] == "structured_message_candidate" for r in rows.values()),
               "dom_candidates":sum(r["status"] == "saved_dom_text_candidate" for r in rows.values()),
               "derived_media_candidates":len(media),"sources":summaries,"analysis_identity_digest":digest(identity),
               "storage":rcfg["protected_storage"],"aes_status":config["aes_status"],
               "note":"Bounded transform hypotheses. Reversibility or readable words do not prove decryption, messages or complete coverage."}
    result = save_private_run(payload,summary,identity,rcfg,output_workspace,max_output_bytes=policy["budgets"]["max_output_bytes"],
                             artifacts={"policy.json":policy,"transform_policy.json":config,"registry.json":registry,"media_policy.json":media_config})
    result["derived_media_candidates"] = len(media)
    result["xor_trials"] = sum(s["statistics"].get("xor_trials",0) for s in summaries)
    result["accepted_structural_hypotheses"] = sum(s["statistics"].get("accepted_structural_hypotheses",0) for s in summaries)
    return result


def verify_probe(run_path,case_id):
    payload = open_payload(run_path,case_id)
    root = Path(run_path)
    identity = read_json(root/"identity.json")
    for name,key in (("policy.json","policy_digest"),("recovery_policy.json","recovery_policy_digest"),
                     ("transform_policy.json","transform_policy_digest"),("registry.json","registry_digest"),("media_policy.json","media_policy_digest")):
        if digest(read_json(root/name)) != identity[key]: raise ValueError("transform_saved_policy_mismatch")
    return {"ok":True,"candidate_count":len(payload["candidates"]),"derived_media_candidates":len(payload.get("derived_media",[])),"verified_decryption":False}
