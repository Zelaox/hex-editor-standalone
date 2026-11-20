"""Synthetic private-message candidate, V8, provenance and sealing tests."""
import copy
import hashlib
import json
import os
from pathlib import Path
import struct
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT))
from src.services.browser_forensics.chromium_values import decode_script_value, decode_idb_record
from src.services.browser_forensics.common import load_policy, canonical, read_json
from src.services.browser_forensics.private_recovery import recovery_policy, protect, recover, open_payload, private_html
from src.services.browser_forensics.message_recovery_worker import Recovery
from src.services.browser_forensics import parsers as p


def vint(n):
    raw = bytearray()
    while n >= 128:
        raw.append((n & 127) | 128)
        n >>= 7
    return bytes(raw)+bytes([n])


def string(value):
    raw = value.encode("utf-8")
    return b"S"+vint(len(raw))+raw


def object_bytes(value):
    return b"o"+b"".join(string(k)+string(v) for k,v in value.items())+b"{"+vint(len(value))


def encoded(value):
    return b"\xff\x15\xfe"+bytes(12)+b"\xff\x0f"+object_bytes(value)


def test_v8_envelope_types_and_whole_document_validation():
    budget, cfg = load_policy()["budgets"], recovery_policy()
    obj = {"text": "Hej åäö 🔒", "messageId": "id", "threadId": "thread", "senderId": "sender"}
    data = encoded(obj)
    node, context = decode_script_value(data, budget, cfg)
    assert node.value == obj and context == {"blink_version": 21, "v8_version": 15}
    assert data[node.children[0][1].start:node.children[0][1].end] == string(obj["text"])
    for bad in [data[:-1], data+b"evil", b"\xff\x7f", b"\xff\x0f\\", b"\xff\x0f^\x00"]:
        with pytest.raises((p.ParseError, UnicodeError)):
            decode_script_value(bad, budget, cfg)


def test_idb_prefix_and_primary_key_not_magic_search():
    budget, cfg = load_policy()["budgets"], recovery_policy()
    key = bytes([0, 1, 2, 1, 1])+vint(1)+"k".encode("utf-16be")
    node, info = decode_idb_record(key, b"\x01"+encoded({"text": "hi"}), budget, cfg)
    assert node.value == {"text": "hi"} and info["object_store_id"] == 2
    with pytest.raises(p.ParseError):
        decode_idb_record(key[:3]+b"\x02"+key[4:], b"\x01"+encoded({"text": "hi"}), budget, cfg)


def test_typed_views_and_array_properties_are_bounded():
    budget, cfg = load_policy()["budgets"], recovery_policy()
    raw = b"\xff\x0fB\x04abcdVB\x01\x02\x00"
    node, _ = decode_script_value(raw, budget, cfg)
    assert node.value == b"bc" and node.kind == "bytes"
    with pytest.raises(p.ParseError):
        decode_script_value(raw[:-3]+b"\xff\x01\x02\x00", budget, cfg)
    array = b"\xff\x0fA\x01"+string("first")+string("extra")+string("metadata")+b"$\x01\x01"
    node, _ = decode_script_value(array, budget, cfg)
    assert node.value == ["first"] and node.children[-1][0] == "extra"


def test_v8_references_shared_objects_cycles_and_buffer_views():
    budget, cfg = load_policy()["budgets"], recovery_policy()
    # Root array gets ID 0, child object ID 1. References allocate no ID.
    data = b"\xff\x0fA\x03"+object_bytes({"text":"same object"})+b"^\x01^\x00$\x00\x03"
    node, _ = decode_script_value(data, budget, cfg)
    assert node.value[0] is node.value[1] and node.value[2] is node.value
    assert node.children[1][1].kind == "reference" and not node.children[1][1].children
    data = b"\xff\x0fA\x03B\x04abcd^\x01VB\x01\x02\x00^\x02$\x00\x03"
    node, _ = decode_script_value(data, budget, cfg)
    assert node.value == [b"abcd", b"bc", b"bc"]
    with pytest.raises(p.ParseError, match="reference_out_of_bounds"):
        decode_script_value(b"\xff\x0fA\x01^\x01$\x00\x01", budget, cfg)


def test_encrypted_object_is_not_promoted_and_spans_are_real():
    budget, cfg = load_policy()["budgets"], recovery_policy()
    key = bytes([0,1,2,1,1,1])+"k".encode("utf-16be")
    obj = {"text": "private synthetics", "messageId": "id", "threadId": "thread", "senderId": "sender"}
    value = b"\x01"+encoded(obj)
    record = {"locator": {"record_ordinal": 0}, "sequence": 7, "fields": [{"source_spans": [{"offset": 100, "length": len(value)}], "mapping_precision": "exact"}]}
    item = {"path": "table", "sha256": "0"*64}
    recovery = Recovery(item, budget, cfg)
    recovery.observe(key, value, record)
    assert len(recovery.rows) == 1 and recovery.rows[0]["status"] == "structured_message_candidate"
    expected = value.index(string(obj["text"]))
    assert recovery.rows[0]["source_spans"][0]["offset"] == 100+expected
    encrypted = {**obj, "_encryptedContent": "not-plaintext"}
    blocked = Recovery(item, budget, cfg)
    blocked.observe(key, b"\x01"+encoded(encrypted), {**record, "fields": [{"source_spans": [{"offset": 100, "length": len(encoded(encrypted))+1}], "mapping_precision": "exact"}]})
    assert not blocked.rows and blocked.statistics["encrypted_object_requires_keys_and_protocol"] == 1


def test_saved_dom_candidates_remain_unverified_and_schema_scoped():
    recovery = Recovery({"path": "saved.json", "sha256": "0"*64}, load_policy()["budgets"], recovery_policy())
    value = {"schema_version":1,"export_kind":"snapchat_live","origin":"https://www.snapchat.com",
             "threads":[{"conversation_id":"thread","display_name":"label","messages":[{"text":"<img src=x onerror=evil>","source":"dom:leaf"}]}]}
    recovery.json_export(canonical(value))
    assert len(recovery.rows) == 1 and recovery.rows[0]["status"] == "saved_dom_text_candidate"
    rendered = private_html({"candidates":recovery.rows})
    assert "<img" not in rendered and "&lt;img" in rendered
    value["origin"] = "https://wrong.invalid"
    other = Recovery(recovery.item, recovery.budget, recovery.config)
    other.json_export(canonical(value))
    assert not other.rows
    value["origin"] = "https://www.snapchat.com"
    value["schema_version"] = 2
    newer = Recovery(recovery.item, recovery.budget, recovery.config)
    newer.json_export(canonical(value))
    assert len(newer.rows) == 1 and newer.rows[0]["profile_id"].endswith("v2")


def test_snappy_script_value_does_not_invent_exact_offsets():
    budget, cfg = load_policy()["budgets"], recovery_policy()
    raw = encoded({"text":"synthetic"})
    compressed = vint(len(raw))+bytes([(len(raw)-1)<<2])+raw
    node, metadata = decode_script_value(b"\xff\x11\x02"+compressed, budget, cfg)
    assert node.value["text"] == "synthetic" and metadata["value_mapping_precision"] == "block-level"
    with pytest.raises(p.ParseError, match="external_blob_required"):
        decode_script_value(b"\xff\x11\x01\x05\x00", budget, cfg)


def test_new_value_harnesses_run_in_isolation(tmp_path):
    from src.services.browser_forensics.sandbox import run_worker
    policy, config = load_policy(), recovery_policy()
    corpus = tmp_path/"corpus"
    corpus.mkdir()
    seeds = [encoded({"text":"synthetic"}), b'\x01\x01\x00x', b"\xff\x0fA\x010$\x00\x01"]
    files = []
    for i,seed in enumerate(seeds):
        path = corpus/(str(i)+".bin")
        path.write_bytes(seed)
        files.append({"path":path.name,"sha256":hashlib.sha256(seed).hexdigest()})
    result = run_worker({"operation":"fuzz","policy":policy,"recovery_policy":config,"files":files,
                         "registry":read_json(ROOT/policy["format_registry"])}, corpus, artifact_output=tmp_path/"campaign")
    assert result["ok"], result
    assert len(result["harnesses"]) == len(policy["fuzz"]["harnesses"])+len(config["fuzz_harnesses"])
    assert all(row["campaign_complete"] and row["branch_arcs"] for row in result["harnesses"])


@pytest.mark.skipif(os.name != "nt", reason="Current-user Windows DPAPI backend")
def test_dpapi_private_payload_authentication():
    sealed = protect(b"private synthetic body")
    assert b"private synthetic body" not in sealed
    assert protect(sealed, decrypt=True) == b"private synthetic body"
    damaged = sealed[:-1]+bytes([sealed[-1]^1])
    with pytest.raises(RuntimeError):
        protect(damaged, decrypt=True)


@pytest.mark.skipif(os.name != "nt", reason="Windows private recovery integration")
def test_isolated_recovery_output_no_plaintext_case_and_tamper(tmp_path, monkeypatch):
    source = tmp_path/"input"
    source.mkdir()
    (source/"saved.json").write_bytes(canonical({"schema_version":1,"export_kind":"snapchat_live","origin":"https://www.snapchat.com",
        "threads":[{"conversation_id":"thread","messages":[{"text":"secret-only-in-sealed-payload","source":"dom:leaf"}]}]}))
    spec = {"schema_version":1,"case_id":"synthetic-private-case","capture_id":"copy","input_root":str(source),
            "snapshot_state":"unknown","files":[{"path":"saved.json"}]}
    spec_path = tmp_path/"spec.json"
    spec_path.write_bytes(canonical(spec))
    result = recover(spec_path, tmp_path/"out", index_learning=False)
    assert result["candidate_count"] == 1 and result["verified_message_count"] == 0
    run = Path(result["run_path"])
    for path in run.iterdir():
        assert b"secret-only-in-sealed-payload" not in path.read_bytes()
    assert open_payload(run, spec["case_id"])["candidates"][0]["text"] == "secret-only-in-sealed-payload"
    # Reuse the real existing Learning DB service, but a test-local database.
    from src.services.learning_db import load_learning_db_bundle
    from src.services.learning_db.core import index_private_message_recovery
    import sqlite3
    lp = read_json(ROOT/"config/learning_db_policy.json")
    db_cfg = tmp_path/"db-config.json"
    db_cfg.write_text(json.dumps({"learning_db_root":str(tmp_path/"test-db")}))
    lp["storage"]["path_source"]["config_file"] = str(db_cfg)
    db_policy = tmp_path/"db-policy.json"
    db_policy.write_text(json.dumps(lp))
    bundle = load_learning_db_bundle(policy_path=db_policy)
    assert index_private_message_recovery(run, bundle=bundle)["indexed"]
    assert index_private_message_recovery(run, bundle=bundle)["indexed"]
    with sqlite3.connect(tmp_path/"test-db"/lp["storage"]["filename"]) as db:
        assert db.execute("SELECT COUNT(*) FROM forensic_runs").fetchone()[0] == 1
    for db_file in (tmp_path/"test-db").iterdir():
        if db_file.is_file():
            assert b"secret-only-in-sealed-payload" not in db_file.read_bytes()
    from PyQt5.QtWidgets import QApplication, QTextBrowser
    from src.private_recovery_viewer import create_private_viewer
    from hexeditor_tools import file_access
    # The GUI still validates roots; grant only the synthetic test directory.
    monkeypatch.setattr(file_access, "get_allowed_roots", lambda: [tmp_path])
    app = QApplication.instance() or QApplication([])
    viewer = create_private_viewer(run, spec["case_id"])
    assert "secret-only-in-sealed-payload" in viewer.findChild(QTextBrowser).toPlainText()
    assert not viewer.findChild(QTextBrowser).openExternalLinks()
    viewer.close()
    with pytest.raises(ValueError, match="case_scope"):
        open_payload(run, "wrong-case")
    target = run/"private.dpapi"
    target.write_bytes(target.read_bytes()+b"changed")
    with pytest.raises(ValueError, match="digest"):
        open_payload(run, spec["case_id"])
