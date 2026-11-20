"""Synthetic parser, evidence, replay, LearnerDB and sandbox acceptance tests."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sqlite3
import struct
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.services.browser_forensics import parsers as p
from src.services.browser_forensics.common import canonical, digest, load_policy, read_json
from src.services.browser_forensics.detection import detect_bytes
from src.services.browser_forensics import engine


@pytest.fixture
def policy():
    return load_policy()


def vint(n):
    result = bytearray()
    while n >= 128:
        result.append((n & 127) | 128)
        n >>= 7
    return bytes(result)+bytes([n])


def log_fragment(value, kind=1):
    return struct.pack("<IHB", p.masked_crc(bytes([kind])+value), len(value), kind)+value


def batch(key=b"opaque-key", value=b"_encryptedContent", sequence=8):
    return struct.pack("<QI", sequence, 1)+b"\1"+vint(len(key))+key+vint(len(value))+value


def make_spec(tmp_path, content, filename="sample.data", hint="", *, state="consistent"):
    root = tmp_path / "input"
    root.mkdir(parents=True)
    file = root / filename
    file.write_bytes(content)
    spec = {"schema_version": 1, "case_id": "synthetic-case", "capture_id": "synthetic-capture",
            "input_root": str(root), "snapshot_state": state, "profiles": ["messaging-markers-v1"],
            "files": [{"path": filename, **({"format_hint": hint} if hint else {})}]}
    path = tmp_path / "spec.json"
    path.write_bytes(canonical(spec))
    return path, root


def test_protobuf_is_schema_less_and_malformed_is_not_plaintext(policy):
    out = p.parse(b'\x0a\x05hello', "protobuf_records", policy["budgets"], [])
    assert out["status"] == "completed"
    assert out["records"][0]["validation_status"] == "protobuf_candidate"
    assert b"hello" not in canonical(out)
    assert p.parse(b'\x0a\xff', "protobuf_records", policy["budgets"], [])["status"] == "partial"
    registry = read_json(ROOT / "config/format_detect_registry.json")
    assert detect_bytes(b'\x0a\x05hello', registry, policy["budgets"])["format_id"] == "unknown"
    assert detect_bytes(b'\x0a\x05hello', registry, policy["budgets"], "protobuf")["format_id"] == "protobuf"


def test_log_checksum_fragment_mapping_and_tombstone(policy):
    raw = batch()
    encoded = log_fragment(raw[:15], 2)+log_fragment(raw[15:], 4)
    out = p.leveldb_log(encoded, policy["budgets"], policy["profiles"][0]["rules"])
    rec = out["records"][0]
    assert rec["sequence"] == 8 and not rec["deleted"]
    assert rec["fields"][0]["findings"][0]["validation_status"] == "carved"
    assert sum(s["length"] for s in rec["fields"][0]["source_spans"]) == len(b"_encryptedContent")
    broken = bytes([encoded[0]^1])+encoded[1:]
    assert p.parse(broken, "leveldb_log", policy["budgets"], [])["status"] == "partial"


def test_snappy_literal_overlap_and_budget(policy):
    assert p.snappy(b'\x05\x10hello', policy["budgets"]) == b"hello"
    # Five-byte output: one literal followed by overlapping COPY_2.
    assert p.snappy(b'\x05\x00x\x0e\x01\x00', policy["budgets"]) == b"xxxxx"
    with pytest.raises(p.ParseError):
        p.snappy(b'\x05\x0e\x00\x00', policy["budgets"])
    budget = {**policy["budgets"], "max_expanded_bytes": 2}
    with pytest.raises(p.BudgetExceeded):
        p.snappy(b'\x05\x10hello', budget)


def test_sqlite_rows_overflow_and_no_raw_values(tmp_path, policy):
    path = tmp_path / "without_suffix"
    with sqlite3.connect(path) as db:
        db.execute("PRAGMA page_size=512")
        db.execute("CREATE TABLE t(id INTEGER PRIMARY KEY, payload TEXT)")
        db.execute("INSERT INTO t(payload) VALUES (?)", ("sensitive-test-value"*400,))
    raw = path.read_bytes()
    out = p.sqlite_records(raw, policy["budgets"], [])
    records = [r for r in out["records"] if r["locator"]["table_root_page"] != 1]
    assert len(records) == 1
    assert len(records[0]["fields"][1]["source_spans"]) > 1
    assert b"sensitive-test-value" not in canonical(out)
    assert sum(s["length"] for s in records[0]["fields"][1]["source_spans"]) == len("sensitive-test-value"*400)


def test_json_fields_classified_without_exposing_values(policy):
    out = p.json_records(b'{"_encryptedContent":"private-body","other":"secret"}', policy["budgets"], policy["profiles"][0]["rules"])
    assert out[0]["fields"][0]["findings"][0]["finding_type"] == "ciphertext_record"
    assert b"private-body" not in canonical(out) and b"secret" not in canonical(out)


def test_sandbox_denies_network_host_input_write_and_fork(policy):
    from src.services.browser_forensics.sandbox import run_worker
    result = run_worker({"operation": "preflight", "policy": policy, "files": []})
    assert result["status"] == "completed", result
    assert result["isolated"] and result["uid"] != 0
    assert all(result["denied"].values()), result


@pytest.mark.parametrize("probe", ["memory", "output"])
def test_sandbox_enforces_resource_limits(policy, probe):
    from src.services.browser_forensics.sandbox import run_worker
    result = run_worker({"operation": "resource_probe", "probe": probe, "policy": policy, "files": []})
    assert result["status"] == "completed" and result["limited"], result


def test_worker_cpu_limit_is_enforced_and_parent_survives(policy):
    from src.services.browser_forensics.sandbox import run_worker
    policy = copy.deepcopy(policy)
    policy["budgets"]["cpu_seconds"] = 1
    result = run_worker({"operation": "resource_probe", "probe": "cpu", "policy": policy, "files": []})
    assert result["status"] == "budget_exhausted" and result["error_code"] == "worker_cpu_limit", result


def test_worker_wall_limit_terminates_group(policy):
    from src.services.browser_forensics.sandbox import run_worker
    policy = copy.deepcopy(policy)
    policy["budgets"].update(wall_seconds=1, cpu_seconds=10)
    result = run_worker({"operation": "resource_probe", "probe": "cpu", "policy": policy, "files": []})
    assert result["status"] == "budget_exhausted" and result["error_code"] == "worker_wall_limit", result


def test_real_sandbox_replay_navigation_and_tamper(tmp_path):
    spec, root = make_spec(tmp_path, b'{"_encryptedContent":"never disclose this message"}')
    first = engine.analyze(spec, tmp_path / "out-one", index_learning=False)
    second = engine.analyze(spec, tmp_path / "out-two", index_learning=False)
    assert first["status"] == "completed", first
    assert first["normalized_result_digest"] == second["normalized_result_digest"]
    repeated = engine.replay(first["run_path"], root, tmp_path/"replayed", index_learning=False)
    assert repeated["ok"] and repeated["replay_matches"], repeated
    import shutil
    relocated = tmp_path/"relocated-input"
    shutil.copytree(root, relocated)
    moved = engine.replay(first["run_path"], relocated, tmp_path/"relocated-output", index_learning=False)
    assert moved["ok"] and moved["replay_matches"], moved
    run = Path(first["run_path"])
    result = read_json(run / "result.json")
    assert b"never disclose" not in (run/"result.json").read_bytes()
    assert engine.verify(run, input_root=root)["ok"]
    finding = result["findings"][0]
    mapped = engine.resolve_finding(run, finding["finding_id"], input_root=root, case_id="synthetic-case")
    assert mapped["mapping_precision"] == "block-level"
    assert finding["finding_id"] in engine.findings_at_offset(run, source_sha256=finding["source_sha256"], offset=1)["finding_ids"]
    with pytest.raises(ValueError):
        engine.resolve_finding(run, finding["finding_id"], input_root=root, case_id="another-case")
    (root/"sample.data").write_bytes(b"changed")
    assert not engine.verify(run, input_root=root)["ok"]
    # Saved artifact integrity remains independently verifiable without sources.
    assert engine.verify(run)["ok"]
    (run/"result.json").write_text('{}')
    assert not engine.verify(run)["ok"]


def test_spec_rejects_escape_and_wrong_hash(tmp_path, policy):
    spec, root = make_spec(tmp_path, b"{}")
    obj = read_json(spec)
    obj["files"][0]["path"] = "../spec.json"
    with pytest.raises(ValueError):
        engine._prepare(obj, policy)
    obj["files"][0] = {"path": "sample.data", "sha256": "0"*64}
    with pytest.raises(ValueError, match="input_changed"):
        engine._prepare(obj, policy)


def test_learning_readonly_never_creates_db_and_index_is_idempotent(tmp_path, policy):
    from src.services.learning_db import load_learning_db_bundle, inspect_learning_db_readonly, index_browser_forensic_run
    lp = read_json(ROOT/"config/learning_db_policy.json")
    cfg = tmp_path / "root-config.json"
    cfg.write_text(json.dumps({"learning_db_root": str(tmp_path/"db")}))
    lp["storage"]["path_source"]["config_file"] = str(cfg)
    config = tmp_path / "policy.json"
    config.write_text(json.dumps(lp))
    bundle = load_learning_db_bundle(policy_path=config)
    assert inspect_learning_db_readonly(bundle=bundle)["status"] == "not_found"
    assert not (tmp_path/"db").exists()
    spec, root = make_spec(tmp_path/"case", b'{"_encryptedContent":"private"}')
    run = engine.analyze(spec, tmp_path/"out", index_learning=False)["run_path"]
    index_browser_forensic_run(run, policy=policy, bundle=bundle)
    index_browser_forensic_run(run, policy=policy, bundle=bundle)
    from src.services.learning_db import learning_db_path
    db = learning_db_path(bundle=bundle)
    # Explicit maintenance is performed by the test only, never read-only inspect.
    with sqlite3.connect(db) as conn:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    before = (db.stat().st_mtime_ns, db.read_bytes())
    summary = inspect_learning_db_readonly(bundle=bundle)
    assert summary["ok"], summary
    assert summary["table_counts"]["forensic_acquisitions"] == 1
    assert summary["table_counts"]["forensic_runs"] == 1
    assert summary["table_counts"]["findings"] == 1
    assert before == (db.stat().st_mtime_ns, db.read_bytes())


def sstable(value=b"_encryptedContent", compressed=False, values=None):
    key = b"record" + ((7 << 8) | 1).to_bytes(8, "little")
    raw = b"".join(b"\0"+vint(len(key))+vint(len(v))+key+v for v in (values or [value]))+struct.pack("<II", 0, 1)
    def block(content, codec=0):
        return content+bytes([codec])+struct.pack("<I", p.masked_crc(content+bytes([codec])))
    if compressed:
        length = len(raw)
        packed = vint(length) + (bytes([(length-1)<<2]) if length <= 60 else bytes([240, length-1])) + raw
        content = block(packed, 1)
    else:
        content = block(raw)
    data_size = len(content)-5
    meta_offset = len(content)
    meta = block(struct.pack("<II", 0, 1))
    index_offset = len(content)+len(meta)
    handle = vint(0)+vint(data_size)
    index_raw = b"\0"+vint(1)+vint(len(handle))+b"z"+handle+struct.pack("<II", 0, 1)
    index = block(index_raw)
    footer = vint(meta_offset)+vint(len(meta)-5)+vint(index_offset)+vint(len(index)-5)
    return content+meta+index+footer.ljust(40,b"\0")+bytes.fromhex("57fb808b247547db")


def test_sstable_snappy_block_mapping_and_falsification(policy):
    raw = sstable(compressed=True)
    out = p.leveldb_sstable(raw, policy["budgets"], policy["profiles"][0]["rules"])
    assert out["records"][0]["fields"][0]["mapping_precision"] == "block-level"
    assert out["transforms"][0]["kind"] == "snappy"
    assert out["records"][0]["sequence"] == 7
    bad = bytearray(raw)
    bad[1] ^= 1
    assert p.parse(bytes(bad), "leveldb_sstable", policy["budgets"], [])["status"] == "partial"


def test_sstable_pagination_can_resume_inside_one_block(policy):
    raw = sstable(values=[b"first", b"second", b"third"])
    budget = {**policy["budgets"], "max_records": 1}
    pages = []
    for cursor in range(3):
        out = p.parse(raw, "leveldb_sstable", {**budget, "record_cursor": cursor}, [])
        assert len(out["records"]) == 1
        pages.extend(r["locator"]["record_ordinal"] for r in out["records"])
        if cursor < 2:
            assert out["continuation"]["record_cursor"] == cursor+1
        else:
            assert out["status"] == "completed" and "continuation" not in out
    assert pages == [0, 1, 2]


def test_profile_key_encoding_never_claims_message_or_value_span(policy):
    key = "e2eeIdentityKey.shared".encode("utf-16le")
    out = p.leveldb_log(log_fragment(batch(key=key, value=b"private-key-material")), policy["budgets"], policy["profiles"][0]["rules"])
    field = out["records"][0]["fields"][1]
    assert field["type"] == "opaque_key" and field["mapping_precision"] == "exact"
    assert field["findings"][0]["finding_type"] == "marker_occurrence"
    assert field["findings"][0]["candidate_type"] == "key_reference"
    assert sum(s["length"] for s in field["source_spans"]) == len(key)
    assert b"private-key-material" not in canonical(out)


def test_wal_commit_overlay_preserves_source_fields(tmp_path, policy):
    db_path = tmp_path/"wal-db"
    db = sqlite3.connect(db_path)
    try:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA wal_autocheckpoint=0")
        db.execute("CREATE TABLE t(payload TEXT)")
        db.commit()
        # Capture only generated synthetic bytes while the test connection holds WAL.
        db.execute("INSERT INTO t VALUES ('synthetic-payload')")
        db.commit()
        raw, wal = db_path.read_bytes(), Path(str(db_path)+"-wal").read_bytes()
        overlay, mapping, page_size = p.sqlite_wal_overlay(raw, wal, policy["budgets"])
        result = p.sqlite_records(overlay, policy["budgets"], [])
        assert any(r["locator"]["table_root_page"] != 1 for r in result["records"])
        assert mapping
        corrupted = wal[:-1]+bytes([wal[-1]^1])
        with pytest.raises(p.ParseError):
            p.sqlite_wal_overlay(raw, corrupted, policy["budgets"])
    finally:
        db.close()


def test_sqlite_without_rowid_is_not_misclassified(tmp_path, policy):
    path = tmp_path/"index-btree"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE t(k TEXT PRIMARY KEY,v BLOB) WITHOUT ROWID")
        db.execute("INSERT INTO t VALUES (?,?)", ("key", b"synthetic"))
    result = p.sqlite_records(path.read_bytes(), policy["budgets"], [])
    assert len(result["records"]) == 2


def test_configured_coverage_guided_campaign(tmp_path, policy):
    from src.services.browser_forensics.fuzz import campaign
    path = tmp_path/"seed.sqlite"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE t(v TEXT)")
        db.execute("INSERT INTO t VALUES ('synthetic')")
    seeds = [b"", b"{}", b'\x0a\x03abc', log_fragment(batch()), sstable(), sstable(compressed=True),
             path.read_bytes(), log_fragment(b'\x02\x08')]
    report = campaign(seeds, tmp_path/"fuzz", policy, read_json(ROOT/policy["format_registry"]))
    assert report["ok"], report["blockers"]
    assert len(report["harnesses"]) == len(policy["fuzz"]["harnesses"])
    assert all(r["campaign_complete"] and r["branch_arcs"] for r in report["harnesses"])


def test_fuzz_campaign_runs_under_isolation(tmp_path, policy):
    from src.services.browser_forensics.sandbox import run_worker
    corpus = tmp_path/"corpus"
    corpus.mkdir()
    files = []
    for ordinal, raw in enumerate([b'{}', b'\x0a\x03abc', sstable(compressed=True), log_fragment(batch())]):
        path = corpus/(str(ordinal)+".bin")
        path.write_bytes(raw)
        files.append({"path": path.name, "sha256": hashlib.sha256(raw).hexdigest()})
    result = run_worker({"operation": "fuzz", "files": files, "policy": policy,
                         "registry": read_json(ROOT/policy["format_registry"])}, corpus, artifact_output=tmp_path/"export")
    assert result["ok"], result
    assert not result["blockers"] and len(result["harnesses"]) == len(policy["fuzz"]["harnesses"])
    assert read_json(tmp_path/"export/campaign.json")["ok"]


def test_current_reference_parser_and_crc_standard(policy):
    assert p.crc32c(b"123456789") == 0xe3069283
    assert p.leveldb_current(b"MANIFEST-000004\n", policy["budgets"], [])["records"]
    assert p.parse(b"MANIFEST-../secret\n", "leveldb_current", policy["budgets"], [])["status"] == "partial"


def test_gui_fields_resolve_and_reverse_lookup(tmp_path, monkeypatch):
    from PyQt5.QtCore import QUrl
    from PyQt5.QtWidgets import QApplication
    from src.forensic_results_widget import ForensicResultsWidget
    from hexeditor_tools import file_access
    monkeypatch.setattr(file_access, "get_allowed_roots", lambda: [tmp_path])
    app = QApplication.instance() or QApplication([])
    spec, source_root = make_spec(tmp_path, b'{"_encryptedContent":"synthetic-private"}')
    saved = engine.analyze(spec, tmp_path/"out", index_learning=False)
    widget = ForensicResultsWidget()
    try:
        widget.load_run(saved["run_path"], source_root)
        selected = []
        widget.selection_resolved.connect(selected.append)
        file_node = widget.tree.topLevelItem(0)
        field_node = file_node.child(0).child(0)
        widget.select_item(field_node)
        assert selected and selected[0]["ranges"][0]["offset"] == 0
        assert selected[0]["mapping_precision"] == "block-level"
        widget.reflect_hex_offset(source_root/"sample.data", 1)
        assert widget.tree.selectedItems()
        result = read_json(Path(saved["run_path"])/"result.json")
        selected.clear()
        widget.select_report_finding(QUrl("forensic-finding:"+result["findings"][0]["finding_id"]))
        assert selected and selected[0]["ok"]
        selected.clear()
        widget.select_report_finding(QUrl("file:///etc/shadow"))
        assert not selected
        (source_root/"sample.data").write_bytes(b"changed")
        selected.clear()
        widget.select_item(field_node)
        assert not selected  # stale bytes must never navigate using old maps
    finally:
        widget.close()


def test_runtime_parser_name_registry_is_the_only_dispatch(policy):
    altered = read_json(ROOT/policy["format_registry"])
    altered["storage_rules"] = [{"id": "new-profile-json", "probe": "probe_json", "parser": "json_records",
                                 "region_class": "structured_data", "confidence": 0.8}]
    detected = detect_bytes(b'{"any":"payload"}', altered, policy["budgets"])
    assert detected["format_id"] == "new-profile-json"


def test_field_transform_chain_excludes_unrelated_blocks():
    transforms = [{"input_spans": [{"offset": n, "length": 20}]} for n in [0, 100, 200]]
    source = {"path": "table", "transforms": transforms}
    field = {"source_spans": [{"offset": 105, "length": 3, "source_path": "table"}]}
    assert engine._field_transforms(source, field) == [transforms[1]]


def test_automatic_indexing_respects_existing_learning_policy(tmp_path, monkeypatch):
    from src.services import learning_db
    monkeypatch.setattr(learning_db, "load_learning_db_bundle", lambda: {"policy": {"sync": {"on_run_complete": False}}})
    spec, _root = make_spec(tmp_path, b"{}")
    result = engine.analyze(spec, tmp_path/"out")
    assert result["index_status"] == {"indexed": False, "reason": "auto_index_disabled"}


def test_missing_companions_never_hide_record_budget(policy):
    source = {"path": "table", "sha256": "0"*64, "size": 1}
    worker = {"status": "completed", "files": [{**source, "status": "budget_exhausted",
              "detection": {"format_id": "leveldb_sstable", "candidates": []},
              "records": [], "transforms": [], "continuation": {"record_cursor": 10}}]}
    result = engine._aggregate(worker, {"snapshot_state": "unknown"}, [source], policy)
    assert result["status"] == "budget_exhausted"
    assert result["files"][0]["missing_companion_patterns"]
    assert result["files"][0]["continuation"]["record_cursor"] == 10


def test_fuzz_blocker_is_minimized_sanitized_and_closes_gate(tmp_path, policy, monkeypatch):
    from src.services.browser_forensics import fuzz
    altered = copy.deepcopy(policy)
    altered["fuzz"].update(harnesses=["mapping"], iterations=1)
    def broken(_harness, _handler, _value, _policy):
        raise AssertionError("private-parser-diagnostic-must-not-leak")
    monkeypatch.setattr(fuzz, "_exercise", broken)
    report = fuzz.campaign([b"approved-synthetic-seed"], tmp_path, altered, read_json(ROOT/policy["format_registry"]))
    assert not report["ok"] and len(report["blockers"]) == 1
    blocker = report["blockers"][0]
    repro = tmp_path/(blocker["input_sha256"]+".bin")
    assert hashlib.sha256(repro.read_bytes()).hexdigest() == blocker["input_sha256"]
    assert blocker["minimized_bytes"] == 0
    assert b"private-parser-diagnostic" not in canonical(report)
