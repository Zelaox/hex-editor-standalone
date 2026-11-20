"""Explicit plaintext export of authenticated observations and bounded media copies."""
import base64
import hashlib
import html
from pathlib import Path
import uuid

from .common import canonical, confined, digest, editor_root, file_hash, load_policy, read_json, validate
from .engine import _prepare, _runtime_identity
from .private_recovery import open_payload
from .sandbox import run_worker


def export_policy():
    config = read_json(editor_root()/"config/browser_readable_export_policy.json")
    validate(config, "browser_readable_export_policy.schema.json")
    return config


def export_readable(spec_path, output_workspace):
    spec, config = read_json(spec_path), export_policy()
    validate(spec, "browser_readable_export_spec.schema.json")
    if len(spec["runs"]) > config["max_runs"]:
        raise ValueError("readable_run_budget")
    by_id, inputs = {}, []
    for source in spec["runs"]:
        payload = open_payload(source["run_path"], source["case_id"])
        summary = read_json(Path(source["run_path"])/"summary.json")
        inputs.append({"run_id":summary["run_id"], "case_id":source["case_id"],
                       "analysis_identity_digest":summary["analysis_identity_digest"],
                       "private_payload_sha256":summary["private_payload_sha256"]})
        for row in payload["candidates"]:
            observed = row["status"] in config["history_statuses"]
            if not observed and (not spec["include_candidates"] or row["status"] not in config["candidate_statuses"]):
                continue
            key = digest({"candidate_id":row["candidate_id"], "status":row["status"], "source":row["source_sha256"]})
            if key not in by_id:
                by_id[key] = {**row, "source_runs":[], "export_section":"observations" if observed else "unverified_candidates"}
            by_id[key]["source_runs"].append(summary["run_id"])
            if len(by_id) > config["max_rows"]:
                raise ValueError("readable_row_budget")
    observations = [r for r in by_id.values() if r["export_section"] == "observations"]
    candidates = [r for r in by_id.values() if r["export_section"] == "unverified_candidates"]
    media, scans = {}, []
    if spec.get("media_spec_path"):
        policy = load_policy()
        media_spec = read_json(spec["media_spec_path"])
        root, files, identities = _prepare(media_spec, policy)
        build = _runtime_identity(policy)
        registry = read_json(editor_root()/policy["format_registry"])
        response = run_worker({"operation":"media_scan", "files":files, "policy":policy,
                               "build":build, "registry":registry, "export_policy":config}, root)
        if response.get("status") != "completed" or len(response.get("files",[])) != len(files):
            raise RuntimeError("media_worker_incomplete")
        returned = {row["path"]:row for row in response["files"]}
        if len(returned) != len(files): raise ValueError("media_duplicate_source")
        for source in files:
            result = returned[source["path"]]
            if result["path"] != source["path"] or result["sha256"] != source["sha256"]:
                raise ValueError("media_source_identity")
            scans.append({"path":source["path"], "sha256":source["sha256"], "status":result["status"],
                          "signature_hits":result["signature_hits"], "candidate_count":len(result["candidates"])})
            for entry in result["candidates"]:
                raw = base64.b64decode(entry.pop("data_base64"), validate=True)
                fmt = next((f for f in config["media"]["formats"] if f["id"] == entry["format_id"]), None)
                if (not fmt or entry["extension"] != fmt["extension"] or entry["mime"] != fmt["mime"]
                        or len(raw) != entry["size"] or len(raw) > config["media"]["max_media_bytes"]
                        or hashlib.sha256(raw).hexdigest() != entry["sha256"]
                        or entry["source_path"] != source["path"] or entry["source_sha256"] != source["sha256"]):
                    raise ValueError("media_artifact_identity")
                for span in entry["source_spans"]:
                    if span["offset"] < 0 or span["length"] <= 0 or span["offset"]+span["length"] > source["size"]:
                        raise ValueError("media_mapping_bounds")
                key = entry["sha256"]
                if key not in media:
                    media[key] = {"data":raw, "format":fmt, "sources":[]}
                media[key]["sources"].append(entry)
                if len(media) > config["media"]["max_items"] or sum(len(m["data"]) for m in media.values()) > config["max_output_bytes"]:
                    raise ValueError("media_total_budget")
        if any(file_hash(confined(root, f["path"])) != f["sha256"] for f in files):
            raise ValueError("media_input_changed")
        inputs.append({"media_inputs":identities, "build":build, "policy_digest":digest(policy), "registry_digest":digest(registry)})
    output = Path(output_workspace).resolve()/("readable-history-"+uuid.uuid4().hex)
    output.mkdir(parents=True, exist_ok=False)
    artifacts, written = {}, 0
    def write(name, value):
        nonlocal written
        written += len(value)
        if written > config["max_output_bytes"]:
            raise ValueError("readable_output_budget")
        target = confined(output, name)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(value)
        artifacts[name] = {"sha256":hashlib.sha256(value).hexdigest(), "size":len(value)}
    write("history.json", canonical({"status":"partial", "observations":observations}))
    write("candidates.json", canonical({"status":"unverified", "candidates":candidates}))
    text = ["PARTIAL LOCAL HISTORY — observed text, not a complete or server-verified archive.\n"]
    for row in observations:
        text.append("\n["+str(row.get("timestamp") or "time unknown")+"] "+str(row.get("thread_label") or row.get("thread") or "thread unknown")+
                    " | "+str(row.get("sender") or "sender unknown")+"\n"+row["text"]+"\n")
    write("history.txt", "".join(text).encode("utf-8"))
    media_rows = []
    for sha, item in sorted(media.items()):
        name = "media/"+sha+item["format"]["extension"]
        write(name, item["data"])
        media_rows.append({"path":name, "mime":item["format"]["mime"], "sha256":sha, "sources":item["sources"],
                           "association":"unassigned", "status":"framed_media_candidate"})
    write("media.json", canonical({"media":media_rows, "scans":scans}))
    def esc(v): return html.escape(str(v or "unknown"), quote=True)
    page = ['<!doctype html><html lang="sv"><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; img-src &#39;self&#39;; media-src &#39;self&#39;; style-src &#39;unsafe-inline&#39;; base-uri &#39;none&#39;; form-action &#39;none&#39;"><title>Local readable history</title>',
            '<h1>Lokal läsbar historik — partiell</h1><p>Detta är klartext på disk. Inte komplett historik eller E2EE-dekryptering. '
            'Saknade tider/avsändare är okända. Media är strukturkontrollerade kandidater, inte bevisat kopplade till en viss chatt.</p>']
    for label, rows in (("Observerad chatttext", observations), ("Obekräftade textkandidater — kan innehålla UI-text eller fel konversation", candidates)):
        page.append("<h2>"+label+" ("+str(len(rows))+")</h2>")
        for row in rows:
            page.append("<article><h3>"+esc(row.get("thread_label") or row.get("thread"))+"</h3><p>"+esc(row.get("sender"))+" | "+
                        esc(row.get("timestamp"))+" | "+esc(row["status"])+"</p><pre style=\"white-space:pre-wrap\">"+esc(row["text"])+"</pre></article>")
    page.append("<h2>Media — ej konversationskopplad ("+str(len(media_rows))+")</h2>")
    for row in media_rows:
        name = esc(row["path"])
        page.append('<figure>'+('<img loading="lazy" style="max-width:100%" src="'+name+'" alt="Local media candidate">' if row["mime"].startswith("image/") else
                                '<video controls preload="none" style="max-width:100%" src="'+name+'"></video>')+'<figcaption>'+esc(row["status"])+"</figcaption></figure>")
    page.append("</html>")
    write("index.html", "".join(page).encode("utf-8"))
    write("policy.json", canonical(config))
    manifest = {"schema_version":1, "case_id":spec["case_id"], "status":"partial", "plaintext":True,
                "observation_count":len(observations), "candidate_count":len(candidates), "media_count":len(media_rows),
                "inputs":inputs, "policy_digest":digest(config), "artifacts":artifacts}
    manifest["manifest_digest"] = digest(manifest)
    with (output/"manifest.json").open("xb") as stream: stream.write(canonical(manifest))
    return {"ok":True, "status":"partial", "plaintext":True, "export_path":str(output),
            "observation_count":len(observations), "candidate_count":len(candidates), "media_count":len(media_rows)}


def verify_readable(root):
    root = Path(root).resolve()
    manifest = read_json(root/"manifest.json")
    if digest({k:v for k,v in manifest.items() if k != "manifest_digest"}) != manifest["manifest_digest"]:
        raise ValueError("readable_manifest_mismatch")
    for name, identity in manifest["artifacts"].items():
        path = confined(root, name)
        if path.stat().st_size != identity["size"] or file_hash(path) != identity["sha256"]:
            raise ValueError("readable_artifact_mismatch")
    if digest(read_json(root/"policy.json")) != manifest["policy_digest"]:
        raise ValueError("readable_policy_mismatch")
    return {"ok":True, "status":manifest["status"], "observation_count":manifest["observation_count"],
            "candidate_count":manifest["candidate_count"], "media_count":manifest["media_count"]}
