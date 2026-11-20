"""Portable evidence runs, canonical replay and safe finding navigation."""
from __future__ import annotations

from datetime import datetime, timezone
import fnmatch
import html
import json
from pathlib import Path
import uuid
from jsonschema import ValidationError

from .common import canonical, confined, digest, editor_root, file_hash, load_policy, read_json, validate
from .sandbox import run_worker


def _utc():
    return datetime.now(timezone.utc).isoformat()


def _runtime_identity(policy):
    code = Path(__file__).resolve().parent
    build = {p.name: file_hash(p) for p in sorted(code.glob("*.py"))}
    for schema in sorted((editor_root()/"schemas").glob("browser_forensics*.schema.json")):
        build["schemas/"+schema.name] = file_hash(schema)
    return build


def _prepare(spec, policy):
    validate(spec, "browser_forensics_spec.schema.json")
    root = Path(spec["input_root"]).resolve(strict=True)
    limits = policy["budgets"]
    if len(spec["files"]) > limits["max_files"]:
        raise ValueError("file_budget")
    known = {p["id"] for p in policy["profiles"]}
    if set(spec.get("profiles", []))-known:
        raise ValueError("unknown_profile")
    files, identities, total, names = [], [], 0, set()
    for source in spec["files"]:
        path = confined(root, source["path"])
        relative = path.relative_to(root).as_posix()
        if relative in names:
            raise ValueError("duplicate_input")
        names.add(relative)
        size = path.stat().st_size
        total += size
        if size > limits["max_file_bytes"] or total > limits["max_total_bytes"]:
            raise ValueError("input_byte_budget")
        sha = file_hash(path)
        if source.get("sha256") and source["sha256"] != sha:
            raise ValueError("input_changed")
        entry = {**source, "path": relative, "sha256": sha, "size": size}
        files.append(entry)
        identities.append(entry)
    return root, sorted(files, key=lambda x: x["path"]), sorted(identities, key=lambda x: x["path"])


def _field_transforms(source, field):
    """Select contributing blocks, not every transform elsewhere in a file."""
    return [transform for transform in source.get("transforms", [])
            if not transform.get("input_spans") or any(
                physical.get("source_path", source["path"]) == source["path"] and
                physical["offset"] < block["offset"]+block["length"] and
                block["offset"] < physical["offset"]+physical["length"]
                for physical in field["source_spans"] for block in transform["input_spans"])]


def _aggregate(worker, spec, files, policy):
    if worker.get("status") != "completed":
        return {"status": worker.get("status", "failed"), "files": [], "findings": [],
                "error_code": worker.get("error_code", "worker_failed")}
    returned = worker.get("files", [])
    if len(returned) != len(files):
        raise ValueError("worker_result_file_count")
    by_path = {f["path"]: f for f in files}
    findings = []
    outputs = []
    logical_ids, version_ids = set(), set()
    for output in returned:
        item = by_path[output["path"]]
        if output["sha256"] != item["sha256"] or output["size"] != item["size"]:
            raise ValueError("worker_result_identity")
        unknowns = []
        for pattern in policy["companions"].get(output["detection"]["format_id"], []):
            parent = Path(output["path"]).parent
            if not any(Path(other).parent == parent and fnmatch.fnmatch(Path(other).name, pattern) for other in by_path):
                unknowns.append(pattern)
        if unknowns:
            output["missing_companion_patterns"] = unknowns
            if output["status"] == "completed":
                output["status"] = "partial"
        for record in output.get("records", []):
            key = record.get("key_digest")
            if key is None:
                key = {"source": item["sha256"], "locator": record["locator"]}
            record["logical_record_id"] = digest({"store": item.get("store_id", Path(item["path"]).parent.as_posix()),
                                                    "origin": item.get("origin"), "key": key})
            record["version_id"] = digest({"logical": record["logical_record_id"],
                                            "version": record.get("sequence", item["sha256"]),
                                            "deleted": record.get("deleted", False)})
            logical_ids.add(record["logical_record_id"])
            version_ids.add(record["version_id"])
            for field in record["fields"]:
                for s in field["source_spans"]:
                    src = s.get("source_path", output["path"])
                    if src not in by_path or s["offset"] < 0 or s["length"] < 0 or s["offset"]+s["length"] > by_path[src]["size"]:
                        raise ValueError("worker_source_span_bounds")
                    s["source_path"] = src
                    s["source_sha256"] = by_path[src]["sha256"]
                field["field_id"] = digest({"source": item["sha256"], "locator": record["locator"],
                    "ordinal": field["ordinal"], "path": item["path"]})
                for evidence in field.pop("findings", []):
                    finding = {"source_path": output["path"], "source_sha256": item["sha256"],
                               "store_id": item.get("store_id", Path(item["path"]).parent.as_posix()),
                               "origin": item.get("origin"), "locator": record["locator"],
                               "field_ordinal": field["ordinal"], "source_spans": field["source_spans"],
                               "mapping_precision": field["mapping_precision"], "evidence_class": "observed",
                               "transform_chain": _field_transforms(output, field), **evidence}
                    finding["finding_id"] = digest(finding)
                    field.setdefault("finding_ids", []).append(finding["finding_id"])
                    findings.append(finding)
        outputs.append(output)
    statuses = [f["status"] for f in outputs]
    status = "completed" if all(s == "completed" for s in statuses) else "partial"
    if statuses and all(s == "unsupported" for s in statuses):
        status = "unsupported"
    if any(s == "budget_exhausted" for s in statuses):
        status = "budget_exhausted"
    if spec["snapshot_state"] != "consistent" and status == "completed":
        status = "partial"
    return {"status": status, "files": outputs, "findings": sorted(findings, key=lambda f: f["finding_id"]),
            "snapshot_state": spec["snapshot_state"], "verified_message_count": 0,
            "logical_record_count": len(logical_ids), "record_version_count": len(version_ids),
            "coverage": {"listed_files": len(files), "parsed_files": sum(s == "completed" for s in statuses),
                         "partial_files": sum(s == "partial" for s in statuses),
                         "unsupported_files": sum(s == "unsupported" for s in statuses),
                         "scope": "manifest_only"}}


def analyze(spec_path, output_workspace, *, policy_path=None, index_learning=True, registry_override=None):
    policy = load_policy(policy_path)
    spec = read_json(spec_path)
    root, files, identities = _prepare(spec, policy)
    registry = registry_override or read_json(editor_root() / policy["format_registry"])
    build = _runtime_identity(policy)
    request = {"operation": "analyze", "files": files, "profiles": spec.get("profiles", []),
               "registry": registry, "policy": policy, "build": build}
    worker = run_worker(request, root)
    normalized = _aggregate(worker, spec, files, policy)
    try:
        changed = any(file_hash(confined(root, f["path"])) != f["sha256"] for f in files)
    except OSError:
        changed = True
    if changed:
        normalized = {"status": "input_changed", "files": [], "findings": [], "error_code": "input_changed"}
    identity = {"schema_version": 1, "case_id": spec["case_id"], "capture_id": spec["capture_id"],
                "snapshot_state": spec["snapshot_state"], "inputs": identities,
                "profiles": sorted(spec.get("profiles", [])), "policy_digest": digest(policy),
                "registry_digest": digest(registry), "build": build,
                "worker_python": worker.get("python"), "normalization": policy["normalization"]}
    identity["runtime_binary_sha256"] = worker.get("runtime_binary_sha256")
    normalized["analysis_identity"] = identity
    identity["sandbox_binary_sha256"] = worker.get("sandbox_binary_sha256")
    validate(normalized, "browser_forensics_result.schema.json")
    if len(canonical(normalized)) > policy["budgets"]["max_output_bytes"]:
        normalized = {"status": "budget_exhausted", "files": [], "findings": [],
                      "error_code": "normalized_output_budget", "analysis_identity": identity}
    result_digest = digest(normalized)
    workspace = Path(output_workspace).resolve()
    # Output must never be an evidence source or inside a listed file's parent via file collisions.
    run = workspace / ("browser-forensics-" + uuid.uuid4().hex)
    run.mkdir(parents=True, exist_ok=False)
    result_path = run / "result.json"
    result_path.write_bytes(canonical(normalized))
    manifest = {"schema_version": 1, "run_id": run.name, "created_at": _utc(), "input_root": str(root),
                "case_id": spec["case_id"], "capture_id": spec["capture_id"], "selection": spec.get("selection", {"rule": "explicit"}),
                "files": files, "analysis_identity_digest": digest(identity), "normalized_result_digest": result_digest,
                "result_file": result_path.name, "result_size": result_path.stat().st_size,
                "status": normalized["status"], "policy_digest": digest(policy), "registry_digest": digest(registry)}
    (run / "manifest.json").write_bytes(canonical(manifest))
    (run / "policy.json").write_bytes(canonical(policy))
    (run / "registry.json").write_bytes(canonical(registry))
    # Journal is outside canonical result: timestamps do not influence result identity.
    event = {"event": "analysis_saved", "at": _utc(), "previous": None,
             "result_digest": result_digest, "manifest_digest": digest(manifest)}
    event["digest"] = digest(event)
    (run / "events.jsonl").write_bytes(canonical(event)+b"\n")
    (run / "report.html").write_text(render_report(normalized, manifest), encoding="utf-8")
    index_status = {"indexed": False, "reason": "disabled"}
    if index_learning and normalized["status"] not in ("failed", "input_changed", "isolation_unavailable"):
        try:
            from src.services.learning_db import index_browser_forensic_run, load_learning_db_bundle
            learning_bundle = load_learning_db_bundle()
            if learning_bundle["policy"]["sync"]["on_run_complete"]:
                index_status = index_browser_forensic_run(run, policy=policy, bundle=learning_bundle)
            else:
                index_status = {"indexed": False, "reason": "auto_index_disabled"}
        except Exception as exc:
            index_status = {"indexed": False, "error_code": type(exc).__name__}
    return {"ok": normalized["status"] in ("completed", "partial", "unsupported", "budget_exhausted"),
            "status": normalized["status"], "run_path": str(run), "normalized_result_digest": result_digest,
            "analysis_identity_digest": digest(identity), "finding_count": len(normalized["findings"]),
            "index_status": index_status}


def verify(run_path, *, input_root=None):
    root = Path(run_path).resolve()
    try:
        manifest = read_json(confined(root, "manifest.json"))
        result_path = confined(root, manifest["result_file"])
        result = read_json(result_path)
        validate(result, "browser_forensics_result.schema.json")
        if file_hash(result_path) != manifest["normalized_result_digest"] or digest(result) != manifest["normalized_result_digest"]:
            raise ValueError("result_digest_mismatch")
        if digest(result["analysis_identity"]) != manifest["analysis_identity_digest"]:
            raise ValueError("analysis_identity_mismatch")
        if digest(read_json(root/"policy.json")) != manifest["policy_digest"] or digest(read_json(root/"registry.json")) != manifest["registry_digest"]:
            raise ValueError("policy_snapshot_mismatch")
        previous = None
        for line in confined(root, "events.jsonl").read_text(encoding="utf-8").splitlines():
            event = json.loads(line)
            claimed = event.pop("digest")
            if digest(event) != claimed or event["previous"] != previous:
                raise ValueError("journal_chain_mismatch")
            if event.get("manifest_digest") != digest(manifest):
                raise ValueError("manifest_digest_mismatch")
            previous = claimed
        if previous is None:
            raise ValueError("empty_journal")
        if input_root:
            for item in manifest["files"]:
                if file_hash(confined(input_root, item["path"])) != item["sha256"]:
                    raise ValueError("input_changed")
        return {"ok": True, "status": result["status"], "run_path": str(root),
                "normalized_result_digest": manifest["normalized_result_digest"],
                "source_hashes_checked": bool(input_root)}
    except (OSError, ValueError, KeyError, TypeError, ValidationError):
        return {"ok": False, "status": "failed", "error_code": "evidence_verification_failed"}


def replay(run_path, input_root, output_workspace, *, index_learning=True):
    checked = verify(run_path, input_root=input_root)
    if not checked["ok"]:
        return checked
    root = Path(run_path)
    result = read_json(root/"result.json")
    identity = result["analysis_identity"]
    policy = read_json(root/"policy.json")
    if _runtime_identity(policy) != identity["build"]:
        return {"ok": False, "status": "incompatible_build", "error_code": "replay_requires_matching_build"}
    manifest = read_json(root/"manifest.json")
    spec = {"schema_version": 1, "case_id": manifest["case_id"], "capture_id": manifest["capture_id"],
            "input_root": str(Path(input_root).resolve()), "snapshot_state": identity["snapshot_state"],
            "profiles": identity["profiles"],
            "files": [{k: v for k,v in f.items() if k != "size"} for f in manifest["files"]]}
    # New spec and run are output artifacts; the saved original is never edited.
    output = Path(output_workspace)
    output.mkdir(parents=True, exist_ok=True)
    spec_path = output/("replay-spec-"+uuid.uuid4().hex+".json")
    spec_path.write_bytes(canonical(spec))
    repeated = analyze(spec_path, output, policy_path=root/"policy.json", registry_override=read_json(root/"registry.json"),
                       index_learning=index_learning)
    repeated["replay_matches"] = repeated["normalized_result_digest"] == manifest["normalized_result_digest"]
    repeated["ok"] = repeated["ok"] and repeated["replay_matches"]
    return repeated


def inspect(run_path):
    checked = verify(run_path)
    if not checked["ok"]:
        return checked
    root = Path(run_path)
    manifest = read_json(root / "manifest.json")
    result = read_json(root / "result.json")
    return {**checked, "manifest": manifest, "coverage": result.get("coverage"),
            "finding_count": len(result["findings"]), "verified_message_count": result.get("verified_message_count", 0),
            "continuations": [{"path": f["path"], "sha256": f["sha256"], **f["continuation"]}
                              for f in result.get("files", []) if "continuation" in f]}


def resolve_finding(run_path, finding_id, *, input_root, case_id):
    if not verify(run_path, input_root=input_root)["ok"]:
        raise ValueError("evidence_verification_failed")
    root = Path(run_path)
    manifest = read_json(root / "manifest.json")
    if manifest["case_id"] != case_id:
        raise ValueError("case_scope_mismatch")
    result = read_json(root / "result.json")
    finding = next((f for f in result["findings"] if f["finding_id"] == finding_id), None)
    if finding is None:
        raise ValueError("finding_not_found")
    return {"ok": True, "finding_id": finding_id, "case_id": case_id,
            "mapping_digest": digest(finding), "mapping_precision": finding["mapping_precision"],
            "ranges": [{**s, "path": str(confined(input_root, s["source_path"]))} for s in finding["source_spans"]],
            "transform_chain": finding["transform_chain"]}


def findings_at_offset(run_path, *, source_sha256, offset):
    if not verify(run_path)["ok"]:
        raise ValueError("evidence_verification_failed")
    result = read_json(Path(run_path) / "result.json")
    return {"ok": True, "finding_ids": [f["finding_id"] for f in result["findings"]
            if any(s["source_sha256"] == source_sha256 and s["offset"] <= offset < s["offset"]+s["length"]
                   for s in f["source_spans"])]}


def resolve_field(run_path, field_id, *, input_root, case_id):
    if not verify(run_path, input_root=input_root)["ok"]:
        raise ValueError("evidence_verification_failed")
    manifest = read_json(Path(run_path)/"manifest.json")
    if manifest["case_id"] != case_id:
        raise ValueError("case_scope_mismatch")
    result = read_json(Path(run_path)/"result.json")
    for file in result["files"]:
        for record in file.get("records", []):
            for field in record["fields"]:
                if field["field_id"] == field_id:
                    return {"ok": True, "field_id": field_id, "mapping_digest": digest(field),
                            "mapping_precision": field["mapping_precision"],
                            "ranges": [{**s, "path": str(confined(input_root, s["source_path"]))} for s in field["source_spans"]],
                            "transform_chain": _field_transforms(file, field)}
    raise ValueError("field_not_found")


def fields_at_offset(run_path, *, source_sha256, offset):
    if not verify(run_path)["ok"]:
        raise ValueError("evidence_verification_failed")
    result = read_json(Path(run_path)/"result.json")
    return {"ok": True, "field_ids": [field["field_id"] for file in result["files"]
            for record in file.get("records", []) for field in record["fields"]
            if any(s["source_sha256"] == source_sha256 and s["offset"] <= offset < s["offset"]+s["length"]
                   for s in field["source_spans"])]}


def render_report(result, manifest):
    rows = []
    for finding in result["findings"]:
        # data attributes contain only content identities, never commands or paths.
        rows.append('<tr><td><a href="forensic-finding:'+html.escape(finding["finding_id"], quote=True)+'">'+
                    html.escape(finding["finding_type"])+"</a></td><td>"+
                    html.escape(finding["source_path"])+"</td><td>"+html.escape(finding.get("rule_field", ""))+"</td><td>"+
                    html.escape(finding["mapping_precision"])+"</td><td>"+html.escape(finding["validation_status"])+"</td></tr>")
    files = []
    for source in result["files"]:
        details = source.get("error_code", "")
        if source.get("continuation"):
            details += " record_cursor="+str(source["continuation"]["record_cursor"])
        files.append("<tr><td>"+html.escape(source["path"])+"</td><td>"+
                     html.escape(source["detection"]["format_id"])+"</td><td>"+html.escape(source["status"])+
                     "</td><td>"+str(len(source["records"]))+"</td><td>"+html.escape(details)+"</td></tr>")
    return '<!doctype html><meta charset="utf-8"><title>Forensic evidence</title><h1>Forensic evidence</h1><p>'+html.escape(result["status"])+\
        '</p><p>Case: '+html.escape(manifest["case_id"])+"; capture: "+html.escape(manifest["capture_id"])+\
        '; selection: '+html.escape(manifest["selection"]["rule"])+\
        '</p><p>Source scope: manifest only. Message verification is not inferred from marker counts. Verified messages: '+str(result.get("verified_message_count", 0))+\
        '</p><h2>Source coverage</h2><table border="1"><tr><th>Source</th><th>Format</th><th>Status</th><th>Records</th><th>Limits/errors</th></tr>'+"".join(files)+\
        '</table><h2>Findings</h2><table border="1"><tr><th>Finding</th><th>Source</th><th>Profile field</th><th>Mapping</th><th>Evidence</th></tr>'+"".join(rows)+\
        '</table><p>Open this report in the registered Hex Editor evidence viewer to navigate findings.</p>'
