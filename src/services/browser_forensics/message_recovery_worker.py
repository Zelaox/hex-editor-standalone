"""Transient plaintext inspection in the sandbox; outputs require host sealing."""
from collections import Counter
import hashlib
import json

try:
    from .chromium_values import decode_idb_record, decode_script_value, Node
    from .parsers import ParseError, BudgetExceeded, _slice_spans
except ImportError:
    from chromium_values import decode_idb_record, decode_script_value, Node
    from parsers import ParseError, BudgetExceeded, _slice_spans


def _json_node(value, budget, config, depth=0, counter=None):
    counter = counter if counter is not None else [0]
    counter[0] += 1
    if depth > budget["max_depth"] or counter[0] > config["max_nodes"]:
        raise BudgetExceeded("json_recovery_structure")
    children = []
    if isinstance(value, dict):
        if len(value) > budget["max_fields"]:
            raise BudgetExceeded("json_recovery_fields")
        children = [(k, _json_node(v, budget, config, depth+1, counter)) for k,v in value.items()]
    elif isinstance(value, list):
        if len(value) > budget["max_records"]:
            raise BudgetExceeded("json_recovery_array")
        children = [(k, _json_node(v, budget, config, depth+1, counter)) for k,v in enumerate(value)]
    return Node(value, "object" if isinstance(value, dict) else "array" if isinstance(value, list) else "scalar", 0, 0, children)


def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ParseError("duplicate_json_key")
            result[key] = value
        return result
    def nonfinite(_):
        raise ParseError("nonfinite_json")
    return json.loads(data.decode("utf-8-sig"), object_pairs_hook=pairs, parse_constant=nonfinite)


class Recovery:
    def __init__(self, item, budget, config):
        self.item, self.budget, self.config = item, budget, config
        self.rows, self.statistics, self.known_fields = [], Counter(), Counter()

    def add(self, text, status, profile, locator, spans, precision, **metadata):
        if not isinstance(text, str) or not text.strip():
            return
        try:
            text.encode("utf-8", errors="strict")
        except UnicodeError:
            self.statistics["text_encoding_unsupported"] += 1
            return
        if len(text) > self.config["max_text_chars"]:
            self.statistics["text_length_budget"] += 1
            return
        if len(self.rows) >= self.config["max_candidates"]:
            raise BudgetExceeded("recovery_candidate_budget")
        safe = {key: value for key,value in metadata.items() if value is None or type(value) in (str, int, float)}
        entry = {"text": text, "status": status, "profile_id": profile["id"], "locator": locator,
                 "source_path": self.item["path"], "source_sha256": self.item["sha256"],
                 "source_spans": spans, "mapping_precision": precision, **safe}
        identity = json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()
        entry["candidate_id"] = hashlib.sha256(identity).hexdigest()
        self.rows.append(entry)

    def scan(self, root, locator, spans, precision, serialized=True, status="structured_message_candidate"):
        def pick(mapping, keys):
            return next((mapping[k] for k in keys if k in mapping and mapping[k] is not None), None)
        stack = [(root, [])]
        while stack:
            node, path = stack.pop()
            if node.kind == "object":
                for profile in self.config["profiles"]:
                    if profile["adapter"] != "structured_object":
                        continue
                    obj = node.value
                    known = {key for key, value in profile.items() if key.endswith("_fields") for key in value}
                    self.known_fields.update(k for k in obj if k in known)
                    if any(k in obj for k in profile["encrypted_fields"]):
                        self.statistics["encrypted_object_requires_keys_and_protocol"] += 1
                        continue
                    ident, thread, sender = (pick(obj, profile[k]) for k in ("identity_fields", "thread_fields", "sender_fields"))
                    if not all(type(v) in (str, int) and str(v) for v in (ident, thread, sender)):
                        continue
                    text = pick(obj, profile["text_fields"])
                    child = next((v for k,v in node.children if k in profile["text_fields"] and v.value == text), None)
                    mapped = _slice_spans(spans, child.start, child.end-child.start) if serialized and precision == "exact" and child else spans
                    self.add(text, status, profile, {**locator, "object_path": path}, mapped,
                             precision if serialized else "block-level", message_id=str(ident), thread=str(thread), sender=str(sender),
                             timestamp=pick(obj, profile["timestamp_fields"]))
            stack.extend((child, path+[key]) for key,child in reversed(node.children))

    def observe(self, key, value, record):
        if record.get("deleted"):
            self.statistics["tombstones"] += 1
            return
        try:
            node, context = decode_idb_record(key, value, self.budget, self.config)
        except (ParseError, UnicodeError, OverflowError, RecursionError) as exc:
            code = str(exc) if isinstance(exc, ParseError) else type(exc).__name__
            self.statistics[code] += 1
            return
        self.statistics["decoded_idb_values"] += 1
        locator = {**record["locator"], "sequence": record["sequence"], **context}
        field = record["fields"][0]
        self.scan(node, locator, field["source_spans"], context.get("value_mapping_precision", field["mapping_precision"]))

    def blob_value(self, data):
        try:
            node, context = decode_script_value(data, self.budget, self.config)
        except (ParseError, UnicodeError, OverflowError, RecursionError) as exc:
            code = str(exc) if isinstance(exc, ParseError) else type(exc).__name__
            self.statistics[code] += 1
            return False
        self.statistics["decoded_unbound_blob_values"] += 1
        stack = [node]
        while stack:
            current = stack.pop()
            self.statistics["decoded_kind_"+current.kind] += 1
            if current.kind == "bytes":
                self.statistics["decoded_byte_buffer_bytes"] += len(current.value)
            stack.extend(child for _, child in current.children)
        self.scan(node, {"unbound_external_blob": True, **context}, [{"offset": 0, "length": len(data)}], context.get("value_mapping_precision", "exact"), status="unbound_blob_text_candidate")
        return True

    def json_export(self, data):
        value = strict_json(data)
        root = _json_node(value, self.budget, self.config)
        whole = [{"offset": 0, "length": len(data)}]
        self.scan(root, {"json_export": True}, whole, "block-level", serialized=False)
        if not isinstance(value, dict):
            return
        for profile in self.config["profiles"]:
            if profile["adapter"] != "saved_dom_export":
                continue
            if not all(type(value.get(k)) is type(v) and value.get(k) == v for k,v in profile["required_root"].items()):
                continue
            if value.get(profile["origin_key"]) not in profile["origins"]:
                continue
            threads = value.get(profile["threads_key"], [])
            if not isinstance(threads, list):
                raise ParseError("export_threads_type")
            for i,thread in enumerate(threads):
                if not isinstance(thread, dict):
                    raise ParseError("export_thread_type")
                rows = thread.get(profile["rows_key"], [])
                if not isinstance(rows, list):
                    raise ParseError("export_rows_type")
                for j,row in enumerate(rows):
                    if not isinstance(row, dict):
                        continue
                    self.add(row.get(profile["text_key"]), "saved_dom_text_candidate", profile,
                             {"thread_ordinal": i, "row_ordinal": j}, whole, "block-level",
                             thread=thread.get(profile["thread_key"]), thread_label=thread.get(profile["label_key"]),
                             observation_source=row.get(profile["source_key"]))
