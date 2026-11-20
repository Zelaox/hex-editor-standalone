"""Synthetic plaintext opt-in, media framing, heap graph and input scope tests."""
import copy
import importlib.util
import os
from pathlib import Path
import struct
import sys
import zlib

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT))
from src.services.browser_forensics.common import canonical, digest, load_policy, read_json
from src.services.browser_forensics.private_recovery import recovery_policy, recover, open_payload
from src.services.browser_forensics.live_dom import live_profile, seal_observation
from src.services.browser_forensics.readable_export import export_policy, export_readable, verify_readable
from src.services.browser_forensics.media_carving import carve, framed_length
from src.services.browser_forensics.heap_snapshot import read_snapshot, scan_snapshot
from src.services.browser_forensics.message_recovery_worker import Recovery


def png():
    def chunk(name, raw):
        return struct.pack(">I",len(raw))+name+raw+struct.pack(">I",zlib.crc32(name+raw)&0xffffffff)
    return b"\x89PNG\r\n\x1a\n"+chunk(b"IHDR",struct.pack(">IIBBBBB",1,1,8,2,0,0,0))+chunk(b"IDAT",zlib.compress(b"\0\xff\0\0"))+chunk(b"IEND",b"")


def test_media_framing_crc_bounds_and_not_message_association():
    cfg = export_policy()
    data = b"prefix"+png()+b"suffix"
    result = carve(data,{"path":"copy.bin","sha256":"0"*64},cfg,load_policy()["budgets"])
    assert len(result["candidates"]) == 1
    row = result["candidates"][0]
    assert row["source_spans"] == [{"offset":6,"length":len(png())}]
    assert row["status"] == "framed_media_candidate" and "thread" not in row
    broken = bytearray(png()); broken[30] ^= 1
    assert framed_length(bytes(broken),0,"png",cfg["media"]) is None
    assert framed_length(png()[:-1],0,"png",cfg["media"]) is None
    webp = b"RIFF"+struct.pack("<I",14)+b"WEBPVP8 "+struct.pack("<I",2)+b"xx"
    assert framed_length(webp,0,"webp",cfg["media"]) == len(webp)
    mp4 = struct.pack(">I",16)+b"ftypisom0000"+struct.pack(">I",8)+b"moov"+struct.pack(">I",8)+b"mdat"
    assert framed_length(mp4,0,"mp4",cfg["media"]) == len(mp4)
    assert framed_length(mp4[:-8],0,"mp4",cfg["media"]) is None


def heap_config():
    return {"max_numeric_values":1000,"max_strings":1000,"max_string_chars":1000,"max_nodes":100,"max_edges":100,"max_objects":100}


def heap():
    strings = ["", "Object", "text", "messageId", "threadId", "senderId", "private synthetic heap text", "id", "thread", "sender"]
    nodes = [0,1,1,4]
    for i,name in enumerate(range(6,10)): nodes += [1,name,i+2,0]
    edges = []
    for i,name in enumerate(range(2,6)): edges += [0,name,(i+1)*4]
    return {"snapshot":{"node_count":5,"edge_count":4,"meta":{"node_fields":["type","name","id","edge_count"],"node_types":[["object","string"],"string","number","number"],"edge_fields":["type","name_or_index","to_node"],"edge_types":[["property"],"string_or_number","node"]}},"nodes":nodes,"edges":edges,"strings":strings}


def test_heap_message_fields_need_graph_relations_not_loose_string_hits():
    cfg = recovery_policy(); cfg["heap"] = heap_config()
    value = heap()
    r = Recovery({"path":"copy.heap","sha256":"0"*64},load_policy()["budgets"],cfg)
    raw = canonical(value)
    scan_snapshot(raw,r)
    assert len(r.rows) == 1 and r.rows[0]["text"] == "private synthetic heap text"
    assert r.rows[0]["locator"]["heap_node_ordinal"] == 0 and r.rows[0]["mapping_precision"] == "block-level"
    bad = copy.deepcopy(value); bad["edges"][2] = 3
    blocked = Recovery(r.item,r.budget,cfg)
    with pytest.raises(ValueError): scan_snapshot(canonical(bad),blocked)
    assert not blocked.rows
    # Mere presence in strings cannot associate a body, sender or conversation.
    value["edges"][1] = 0
    no_text = Recovery(r.item,r.budget,cfg)
    scan_snapshot(canonical(value),no_text)
    assert not no_text.rows


def test_heap_opaque_ids_are_labeled_as_graph_references_not_service_ids():
    cfg = recovery_policy(); cfg["heap"] = heap_config()
    value = heap()
    # Identity targets are actual heap objects, but no service ID is decoded.
    for offset in (8,12,16): value["nodes"][offset] = 0
    r = Recovery({"path":"copy.heap","sha256":"0"*64},load_policy()["budgets"],cfg)
    scan_snapshot(canonical(value),r)
    assert len(r.rows) == 1 and r.rows[0]["thread"].startswith("heap-node-reference:")
    assert "not server-verified" in r.rows[0]["locator"]["identity_representation"]


@pytest.mark.parametrize("raw", [b"{}", b'{"nodes":[01]}', b'{"nodes":[1,]}', b'{"nodes":[-1]}', b'{"nodes":[1.1]}', b'{"strings":[123]}', b'{"snapshot":{"x":1,"x":2}}'])
def test_heap_malformed_input_fails(raw):
    with pytest.raises(ValueError): read_snapshot(raw,heap_config())


@pytest.mark.skipif(os.name != "nt",reason="DPAPI current-user integration")
def test_plaintext_export_separates_candidates_and_verifies_media_and_tamper(tmp_path):
    profile = live_profile()
    value = {"schema_version":1,"profile_id":profile["id"],"profile_digest":digest(profile),"url":profile["origins"][0]+"/web/synthetic-thread", "conversation_id":"synthetic-thread", "conversation_label":"synthetic-label","observed_at":"2026-01-01T00:00:00Z", "groups":[[{"text_parts":["private synthetic <script> text"],"sender":None,"timestamp":None}]]}
    run = seal_observation(value,tmp_path/"sealed","synthetic-case",index_learning=False)
    (tmp_path/"media.bin").write_bytes(b"noise"+png())
    media_spec = tmp_path/"media-spec.json"
    media_spec.write_bytes(canonical({"schema_version":1,"case_id":"synthetic-case","capture_id":"copy","input_root":str(tmp_path),"snapshot_state":"unknown","files":[{"path":"media.bin"}]}))
    spec_path = tmp_path/"export.json"
    spec = {"schema_version":1,"case_id":"synthetic-export","runs":[{"run_path":run["run_path"],"case_id":"synthetic-case"}],"include_candidates":False,"media_spec_path":str(media_spec)}
    spec_path.write_bytes(canonical(spec))
    result = export_readable(spec_path,tmp_path/"exports")
    assert result["plaintext"] and result["observation_count"] == 1 and result["media_count"] == 1
    folder = Path(result["export_path"])
    assert "private synthetic <script> text" in (folder/"history.txt").read_text(encoding="utf-8")
    html = (folder/"index.html").read_text(encoding="utf-8")
    assert "<script>" not in html and "&lt;script&gt;" in html and "Content-Security-Policy" in html
    assert not read_json(folder/"candidates.json")["candidates"]
    assert verify_readable(folder)["ok"]
    (folder/"history.txt").write_bytes(b"tampered")
    with pytest.raises(ValueError): verify_readable(folder)
    spec["runs"][0]["case_id"] = "wrong"
    spec_path.write_bytes(canonical(spec))
    with pytest.raises(ValueError): export_readable(spec_path,tmp_path/"exports")


def test_plaintext_tool_requires_confirmation():
    from hexeditor_tools.api import binary_message_export
    with pytest.raises(ValueError,match="confirmation"):
        binary_message_export("not-read","not-written",False)


@pytest.mark.skipif(os.name != "nt",reason="Isolated DPAPI integration")
def test_heap_candidate_through_isolated_worker_and_sealed_run(tmp_path):
    source = tmp_path/"source"
    source.mkdir()
    (source/"copy.heap").write_bytes(canonical(heap()))
    cfg = recovery_policy(); cfg["heap"] = heap_config()
    cfg_path = tmp_path/"recovery-policy.json"
    cfg_path.write_bytes(canonical(cfg))
    spec = {"schema_version":1,"case_id":"synthetic-case","capture_id":"heap-copy","input_root":str(source),
            "snapshot_state":"unknown","files":[{"path":"copy.heap","format_hint":"v8_heap_snapshot"}]}
    spec_path = tmp_path/"spec.json"
    spec_path.write_bytes(canonical(spec))
    result = recover(spec_path,tmp_path/"runs",recovery_policy_path=cfg_path,index_learning=False)
    assert result["structured_candidates"] == 1 and result["verified_message_count"] == 0
    row = open_payload(result["run_path"],spec["case_id"])["candidates"][0]
    assert row["text"] == "private synthetic heap text" and row["locator"]["heap_node_ordinal"] == 0
