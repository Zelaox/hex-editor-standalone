"""Synthetic loaded-DOM observations: truthful scope, privacy, loopback boundary."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import threading
import urllib.error
import urllib.request

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.services.browser_forensics.common import canonical, digest, read_json
from src.services.browser_forensics.live_dom import live_profile, normalize_observation, seal_observation
from src.services.browser_forensics.private_recovery import open_payload, private_html


def observation(profile):
    return {"schema_version": 1, "profile_id": profile["id"], "profile_digest": digest(profile),
            "url": profile["origins"][0]+"/web/synthetic-thread", "conversation_id": "synthetic-thread",
            "conversation_label": "Synthetic friend", "observed_at": "2026-01-01T00:00:00Z",
            "groups": [[{"text_parts": ["private synthetic text <script>"], "sender": "Self",
                         "timestamp": "2025-12-31T23:30:00Z"},
                        {"text_parts": ["Second bubble\nembedded transcript stays one body"], "sender": None, "timestamp": None}]]}


def test_observation_does_not_inherit_or_split_or_deduplicate():
    profile = live_profile()
    value = observation(profile)
    value["groups"][0].append(copy.deepcopy(value["groups"][0][1]))
    rows = normalize_observation(value, profile)
    assert len(rows) == 3 and rows[1]["sender"] is None and rows[1]["timestamp"] is None
    assert rows[1]["text"] == rows[2]["text"] and rows[1]["candidate_id"] != rows[2]["candidate_id"]
    assert all(r["source_spans"] == [] and r["mapping_precision"] == "dom-observation" for r in rows)
    assert "<script>" not in private_html({"observation_kind":"live_dom", "candidates": rows})


@pytest.mark.parametrize("mutation", ["origin", "thread", "profile", "timezone", "extra", "empty", "budget"])
def test_bad_or_out_of_scope_observation_rejected(mutation):
    profile = live_profile()
    value = observation(profile)
    if mutation == "origin": value["url"] = "https://example.invalid/web/synthetic-thread"
    if mutation == "thread": value["conversation_id"] = "another"
    if mutation == "profile": value["profile_digest"] = "0"*64
    if mutation == "timezone": value["groups"][0][0]["timestamp"] = "2026-01-01T12:00:00"
    if mutation == "extra": value["groups"][0][0]["html"] = "not allowed"
    if mutation == "empty": value["groups"] = []
    if mutation == "budget": value["groups"][0][0]["text_parts"] = ["x"*(profile["max_text_chars"]+1)]
    with pytest.raises(ValueError): normalize_observation(value, profile)


@pytest.mark.skipif(os.name != "nt", reason="DPAPI is Windows current user only")
def test_live_sealing_no_plaintext_and_authenticated_profile(tmp_path):
    profile = live_profile()
    value = observation(profile)
    result = seal_observation(value, tmp_path, "synthetic-case", index_learning=False)
    run = Path(result["run_path"])
    assert result["candidate_count"] == 2 and result["verified_message_count"] == 0
    payload = open_payload(run, "synthetic-case")
    assert payload["source_observation"] == value
    assert payload["candidates"][1]["sender"] is None
    for artifact in run.iterdir():
        assert b"private synthetic text" not in artifact.read_bytes()
        assert b"Synthetic friend" not in artifact.read_bytes()
    with pytest.raises(ValueError): open_payload(run, "another-case")
    changed = read_json(run/"live_profile.json")
    changed["revision"] += 1
    (run/"live_profile.json").write_bytes(canonical(changed))
    with pytest.raises(ValueError, match="live_profile_digest_mismatch"):
        open_payload(run, "synthetic-case")


@pytest.mark.skipif(os.name != "nt", reason="DPAPI is Windows current user only")
def test_local_import_rejects_csrf_then_seals_without_plaintext(tmp_path):
    spec = importlib.util.spec_from_file_location("local_live_capture_test", ROOT/"scripts/browser_live_capture.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    ready, result = {}, {}
    signal = threading.Event()
    def on_ready(url):
        ready["url"] = url
        signal.set()
    def run():
        result.update(module.serve(tmp_path, "synthetic-case", index_learning=False, ready=on_ready))
    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    assert signal.wait(5)
    url = ready["url"]
    body = b"observation="+canonical(observation(live_profile()))+b"\r\n"
    origin = url.rsplit("/", 1)[0]
    for bad_origin in ["https://example.invalid", "null"]:
        req = urllib.request.Request(url, data=body, headers={"Content-Type":"text/plain", "Origin":bad_origin})
        with pytest.raises(urllib.error.HTTPError) as exc: urllib.request.urlopen(req)
        assert exc.value.code == 403
    with urllib.request.urlopen(url) as response:
        page = response.read()
        assert response.headers["Cache-Control"] == "no-store" and b"textarea" in page
    req = urllib.request.Request(url, data=body, headers={"Content-Type":"text/plain", "Origin":origin})
    with urllib.request.urlopen(req) as response:
        assert b"Protected import complete" in response.read()
    thread.join(5)
    assert not thread.is_alive() and result["ok"]
    assert open_payload(result["run_path"], "synthetic-case")["observation_kind"] == "live_dom"
