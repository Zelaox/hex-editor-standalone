"""Bounded structural hypotheses, reusing Hex Editor's shared XOR executor."""
import base64
from collections import Counter
import hashlib
import json
import re
import zlib

try:
    from .common import canonical, digest
    from .chromium_values import decode_script_value, decode_idb_record
    from .message_recovery_worker import Recovery, strict_json
    from .media_carving import framed_length
    from .detection import detect_bytes
    from .parsers import parse, ParseError, BudgetExceeded, snappy
except ImportError:
    from common import canonical, digest
    from chromium_values import decode_script_value, decode_idb_record
    from message_recovery_worker import Recovery, strict_json
    from media_carving import framed_length
    from detection import detect_bytes
    from parsers import parse, ParseError, BudgetExceeded, snappy


class Probe:
    def __init__(self, item, policy, config, recovery_config, registry, media_config, executor):
        self.item, self.policy, self.cfg, self.rcfg = item, policy, config, recovery_config
        self.registry, self.media_cfg, self.executor = registry, media_config, executor
        self.stats, self.rows, self.media, self.structures = Counter(), {}, {}, []
        self.target_ids, self.exhausted = set(), False
        self.anchors = [(bytes.fromhex(f["signature_hex"]), f["offset"]) for f in media_config["media"]["formats"]]
        self.anchors += [(bytes.fromhex(f["prefix_hex"]), 0) for f in registry["storage_rules"] if f.get("prefix_hex")]

    def xor(self, data, key):
        return self.executor(data, {"constraints":{"key_hex":key.hex()}, "source_ranges":[{"offset":0,"length":len(data)}]})

    def promising(self, data):
        if data.lstrip().startswith((b"{",b"[")) or data.startswith(b"\xff"):
            return True
        if data.startswith((b"\x1f\x8b",b"\x78")):
            return True
        return any(data[offset:offset+len(sig)] == sig for sig,offset in self.anchors)

    def validate(self, raw, locator, spans, steps, *, publish=False):
        """Only full structure/app-field proofs count; UTF-8/printability never does."""
        recovery = Recovery(self.item, self.policy["budgets"], self.rcfg)
        proof = None
        for fmt in self.media_cfg["media"]["formats"]:
            sig, offset = bytes.fromhex(fmt["signature_hex"]), fmt["offset"]
            if raw[offset:offset+len(sig)] == sig and framed_length(raw,0,fmt["validator"],self.media_cfg["media"]) == len(raw):
                proof = {"kind":"framed_media_candidate", "format_id":fmt["id"], "extension":fmt["extension"], "mime":fmt["mime"]}
                break
        try:
            if raw.lstrip().startswith((b"{",b"[")):
                recovery.json_export(raw)
                if recovery.rows: proof = {"kind":"structured_message_fields"}
            elif raw.startswith(b"\xff"):
                node, _ = decode_script_value(raw,self.policy["budgets"],self.rcfg)
                recovery.scan(node,locator,spans,"block-level",serialized=False)
                if recovery.rows: proof = {"kind":"structured_message_fields"}
            if proof is None:
                found = detect_bytes(raw,self.registry,self.policy["budgets"])
                if found["format_id"] in ("sqlite","leveldb_sstable","leveldb_log"):
                    result = parse(raw,found["candidates"][0]["parser"],self.policy["budgets"],[])
                    if result["status"] == "completed" and len(result["records"]) >= self.cfg["minimum_structure_nodes"]:
                        proof = {"kind":"validated_storage_structure", "format_id":found["format_id"], "records":len(result["records"])}
        except (ParseError, ValueError, UnicodeError, RecursionError, OverflowError):
            return None
        if not proof or not publish: return proof
        transformed_sha = hashlib.sha256(raw).hexdigest()
        trace = {"steps":steps, "derived_sha256":transformed_sha, "hypothesis_only":True,
                 "verified_decryption":False}
        self.structures.append({**proof,"locator":locator,"trace":trace})
        for row in recovery.rows:
            row.update(source_spans=spans,mapping_precision="block-level",locator={**locator,"transform_trace":trace})
            row["candidate_id"] = digest(row)
            self.rows[row["candidate_id"]] = row
        if proof["kind"] == "framed_media_candidate":
            self.media[transformed_sha] = {**proof,"status":"framed_media_candidate", "sha256":transformed_sha,
                "size":len(raw), "data_base64":base64.b64encode(raw).decode("ascii"),
                "source_path":self.item["path"],"source_sha256":self.item["sha256"],"source_spans":spans,
                "mapping_precision":"block-level","locator":locator,"transform_trace":trace}
        self.stats["accepted_structural_hypotheses"] += 1
        return proof

    def decoded(self, raw):
        for encoding in self.cfg["encodings"]:
            try:
                result = None
                if encoding == "hex" and len(raw)%2 == 0 and re.fullmatch(rb"[0-9a-fA-F]+",raw):
                    result = bytes.fromhex(raw.decode("ascii"))
                elif encoding == "base64" and len(raw)%4 == 0 and re.fullmatch(rb"[A-Za-z0-9+/]+={0,2}",raw):
                    result = base64.b64decode(raw,validate=True)
                    if base64.b64encode(result) != raw: result = None
                elif encoding in ("gzip","zlib") and raw.startswith(b"\x1f\x8b" if encoding == "gzip" else b"\x78"):
                    obj = zlib.decompressobj(31 if encoding == "gzip" else 15)
                    result = obj.decompress(raw,self.cfg["max_target_bytes"]+1)
                    if not obj.eof or obj.unused_data or obj.unconsumed_tail: result = None
                if result is not None and self.cfg["min_target_bytes"] <= len(result) <= self.cfg["max_target_bytes"]:
                    yield result,{"algorithm":encoding}
            except (ValueError,zlib.error,UnicodeError):
                continue

    def target(self, raw, locator, spans, *, steps=(), visited=None):
        if len(raw) < self.cfg["min_target_bytes"]:
            self.stats["targets_too_short"] += 1
            return
        if len(raw) > self.cfg["max_target_bytes"]:
            self.stats["targets_too_large"] += 1
            return
        source_sha = hashlib.sha256(raw).hexdigest()
        if visited is None:
            if source_sha in self.target_ids:
                self.stats["duplicate_targets"] += 1
                return
            if len(self.target_ids) >= self.cfg["max_targets_per_file"]:
                self.exhausted = True
                self.stats["target_budget_skips"] += 1
                return
            self.target_ids.add(source_sha)
            self.stats["targets_selected"] += 1
            visited = set()
        if source_sha in visited: return
        visited.add(source_sha)
        if not steps and self.validate(raw,locator,spans,steps):
            self.stats["baseline_supported_targets"] += 1
            return
        if steps and self.validate(raw,locator,spans,steps,publish=True): return
        if len(steps) >= self.cfg["max_chain_depth"]: return
        if len(self.structures) >= self.cfg["max_candidates_per_file"]:
            self.exhausted = True
            return
        for value, step in self.decoded(raw):
            self.stats["encoding_steps"] += 1
            self.target(value,locator,spans,steps=steps+(step,),visited=visited)
        keys = [(bytes([key]),"xor_single_byte") for key in range(self.cfg["single_byte_min"],self.cfg["single_byte_max"]+1) if key]
        for signature, offset in self.anchors:
            for period in range(self.cfg["repeating_period_min"],self.cfg["repeating_period_max"]+1):
                if len(signature) < period*self.cfg["minimum_crib_cycles"] or offset+len(signature) > len(raw): continue
                key, valid = [None]*period, True
                for index, plain in enumerate(signature):
                    lane = (offset+index)%period
                    expected = raw[offset+index]^plain
                    if key[lane] is not None and key[lane] != expected:
                        valid = False
                        break
                    key[lane] = expected
                if valid and all(v is not None for v in key) and any(key):
                    keys.append((bytes(key),"xor_repeating_header_crib"))
        seen = set()
        for key, algorithm in keys:
            if key in seen: continue
            seen.add(key)
            if self.stats["xor_trials"] >= self.cfg["max_trials_per_file"]:
                self.exhausted = True
                self.stats["trial_budget_skips"] += 1
                return
            self.stats["xor_trials"] += 1
            prefix = self.xor(raw[:self.cfg["max_probe_prefix_bytes"]],key)
            if not self.promising(prefix): continue
            value = self.xor(raw,key)
            self.stats["full_candidate_checks"] += 1
            step = {"algorithm":algorithm,"key_length":len(key),"key_sha256":hashlib.sha256(key).hexdigest()}
            self.target(value,locator,spans,steps=steps+(step,),visited=visited)

    def bytes_in_node(self, node, locator, spans):
        stack = [(node,[])]
        while stack:
            current,path = stack.pop()
            if current.kind == "bytes":
                self.target(current.value,{**locator,"child_ordinals":path},spans)
            stack.extend((child,path+[i]) for i,(_,child) in enumerate(current.children))

    def observe(self,key,value,record):
        if record.get("deleted"): return
        field = record["fields"][0]
        locator, spans = record["locator"],field["source_spans"]
        try:
            node, _ = decode_idb_record(key,value,self.policy["budgets"],self.rcfg)
            self.stats["known_idb_values"] += 1
            self.bytes_in_node(node,locator,spans)
        except (ParseError,ValueError,UnicodeError,RecursionError,OverflowError):
            self.target(value,locator,spans)

    def run(self,data):
        if self.item.get("format_hint") == "v8_heap_snapshot":
            self.stats["heap_graph_has_no_raw_backing_bytes"] += 1
        elif self.item.get("role") == "blob":
            try:
                node,_ = decode_script_value(data,self.policy["budgets"],self.rcfg)
                self.stats["known_blob_values"] += 1
                self.bytes_in_node(node,{"blob":True},[{"offset":0,"length":len(data)}])
            except (ParseError,ValueError,UnicodeError,RecursionError,OverflowError):
                self.target(data,{"opaque_blob":True},[{"offset":0,"length":len(data)}])
        else:
            found = detect_bytes(data,self.registry,self.policy["budgets"])
            if found["format_id"] in ("leveldb_sstable","leveldb_log"):
                cursor = 0
                for _ in range(self.cfg["max_pages_per_file"]):
                    result = parse(data,found["candidates"][0]["parser"],{**self.policy["budgets"],"record_cursor":cursor,"_record_observer":self.observe},[])
                    self.stats["storage_pages"] += 1
                    if result["status"] == "partial":
                        self.rows.clear(); self.media.clear(); self.structures.clear()
                        self.exhausted = True
                        break
                    continuation = result.get("continuation",{}).get("record_cursor")
                    if continuation is None: break
                    if continuation <= cursor: raise ParseError("probe_cursor_stalled")
                    cursor = continuation
                else: self.exhausted = True
            elif found["format_id"] != "unknown":
                self.stats["known_container_skipped"] += 1
            else:
                self.target(data,{"whole_copy":True},[{"offset":0,"length":len(data)}])
        return {"path":self.item["path"],"sha256":self.item["sha256"],
                "status":"budget_exhausted" if self.exhausted else "bounded_scan_complete",
                "statistics":dict(self.stats),"private_candidates":list(self.rows.values()),
                "private_media":list(self.media.values()),"structures":self.structures,"verified_decryption":False}
