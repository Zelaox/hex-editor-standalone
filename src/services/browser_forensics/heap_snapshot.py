"""Bounded V8 heap graph subset. Never export the raw string/secret table."""
from array import array
from collections import Counter
import json
import re

try:
    from .parsers import ParseError, BudgetExceeded
    from .chromium_values import Node
except ImportError:
    from parsers import ParseError, BudgetExceeded
    from chromium_values import Node


def read_snapshot(data, config):
    text = data.decode("utf-8", errors="strict")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result: raise ParseError("heap_duplicate_key")
            result[key] = value
        return result
    def nonfinite(_): raise ParseError("heap_nonfinite")
    decoder = json.JSONDecoder(object_pairs_hook=pairs, parse_constant=nonfinite)
    whitespace, integer = re.compile(r"[ \t\r\n]*"), re.compile(r"0|[1-9][0-9]*")
    pos, result = 0, {}
    def ws(p): return whitespace.match(text, p).end()
    pos = ws(pos)
    if text[pos:pos+1] != "{": raise ParseError("heap_root")
    pos += 1
    while True:
        pos = ws(pos)
        key, pos = decoder.raw_decode(text, pos)
        if not isinstance(key, str) or key in result: raise ParseError("heap_duplicate_or_invalid_key")
        pos = ws(pos)
        if text[pos:pos+1] != ":": raise ParseError("heap_member_separator")
        pos = ws(pos+1)
        if key in ("nodes", "edges"):
            if text[pos:pos+1] != "[": raise ParseError("heap_numeric_array")
            values, pos = array("Q"), ws(pos+1)
            if text[pos:pos+1] == "]": pos += 1
            else:
                while True:
                    match = integer.match(text, pos)
                    if not match: raise ParseError("heap_numeric_value")
                    n = int(match.group())
                    if n > 0xffffffffffffffff: raise ParseError("heap_numeric_overflow")
                    values.append(n)
                    if len(values) > config["max_numeric_values"]: raise BudgetExceeded("heap_numeric_budget")
                    pos = ws(match.end())
                    if text[pos:pos+1] == "]":
                        pos += 1
                        break
                    if text[pos:pos+1] != ",": raise ParseError("heap_array_separator")
                    pos = ws(pos+1)
            result[key] = values
        elif key == "strings":
            if text[pos:pos+1] != "[": raise ParseError("heap_string_array")
            strings, pos = [], ws(pos+1)
            if text[pos:pos+1] == "]": pos += 1
            else:
                while True:
                    value, pos = decoder.raw_decode(text, pos)
                    if not isinstance(value, str): raise ParseError("heap_string_value")
                    if len(value) > config["max_string_chars"] or len(strings) >= config["max_strings"]:
                        raise BudgetExceeded("heap_string_budget")
                    strings.append(value)
                    pos = ws(pos)
                    if text[pos:pos+1] == "]":
                        pos += 1
                        break
                    if text[pos:pos+1] != ",": raise ParseError("heap_string_separator")
                    pos = ws(pos+1)
            result[key] = strings
        else:
            result[key], pos = decoder.raw_decode(text, pos)
        pos = ws(pos)
        if text[pos:pos+1] == "}":
            pos = ws(pos+1)
            if pos != len(text): raise ParseError("heap_trailing_data")
            break
        if text[pos:pos+1] != ",": raise ParseError("heap_root_separator")
        pos += 1
    if not all(k in result for k in ("snapshot", "nodes", "edges", "strings")):
        raise ParseError("heap_sections_missing")
    return result


def scan_snapshot(data, recovery):
    config = recovery.config.get("heap")
    if not config: raise ParseError("heap_adapter_disabled")
    value = read_snapshot(data, config)
    meta = value["snapshot"]["meta"]
    nf, ef = meta["node_fields"], meta["edge_fields"]
    if len(set(nf)) != len(nf) or len(set(ef)) != len(ef): raise ParseError("heap_duplicate_field")
    ni = {name:nf.index(name) for name in ("type", "name", "id", "edge_count")}
    ei = {name:ef.index(name) for name in ("type", "name_or_index", "to_node")}
    nt, et = meta["node_types"][ni["type"]], meta["edge_types"][ei["type"]]
    nodes, edges, strings, nw, ew = value["nodes"], value["edges"], value["strings"], len(nf), len(ef)
    count, edge_count = value["snapshot"]["node_count"], value["snapshot"]["edge_count"]
    if (type(count) is not int or type(edge_count) is not int or count > config["max_nodes"] or edge_count > config["max_edges"]
            or len(nodes) != count*nw or len(edges) != edge_count*ew):
        raise ParseError("heap_graph_counts")
    known = {field for p in recovery.config["profiles"] if p["adapter"] == "structured_object"
             for key, fields in p.items() if key.endswith("_fields") for field in fields}
    statistics, offset, pending, edge_offsets = Counter(), 0, [], array("Q")
    # Validate the entire graph before publishing any candidate.
    for node_offset in range(0, len(nodes), nw):
        edge_offsets.append(offset)
        kind, name_index = nodes[node_offset+ni["type"]], nodes[node_offset+ni["name"]]
        if kind >= len(nt) or name_index >= len(strings): raise ParseError("heap_node_index")
        n = nodes[node_offset+ni["edge_count"]]
        if offset+n*ew > len(edges): raise ParseError("heap_edge_counts")
        refs, locators = {}, {}
        for edge_offset in range(offset, offset+n*ew, ew):
            edge_kind, name, target = (edges[edge_offset+ei[k]] for k in ("type", "name_or_index", "to_node"))
            if edge_kind >= len(et) or target % nw or target >= len(nodes): raise ParseError("heap_edge_target")
            if et[edge_kind] == "property":
                if name >= len(strings): raise ParseError("heap_property_name")
                field = strings[name]
                if nt[kind] == "object" and field in known:
                    statistics["known_property_"+field] += 1
                    target_kind, target_name = nodes[target+ni["type"]], nodes[target+ni["name"]]
                    if target_kind >= len(nt) or target_name >= len(strings): raise ParseError("heap_target_name")
                    statistics["target_kind_"+field+"_"+nt[target_kind]] += 1
                    refs[field] = target
                    locators[field] = edge_offset//ew
        if refs:
            pending.append((node_offset//nw, nodes[node_offset+ni["id"]], refs, locators))
            if len(pending) > config["max_objects"]: raise BudgetExceeded("heap_object_budget")
        offset += n*ew
    if offset != len(edges): raise ParseError("heap_unused_edges")
    statistics.update(heap_nodes=count, heap_edges=edge_count, heap_strings=len(strings), heap_objects_with_known_fields=len(pending))
    def string_at(target, trail=()):
        if target in trail or len(trail) > recovery.budget["max_depth"]: return None
        kind, name = nt[nodes[target+ni["type"]]], strings[nodes[target+ni["name"]]]
        if kind == "string": return name
        if kind != "concatenated string": return None
        parts = {}
        start = edge_offsets[target//nw]
        end = start+nodes[target+ni["edge_count"]]*ew
        for edge in range(start,end,ew):
            if et[edges[edge+ei["type"]]] != "internal": continue
            name_index = edges[edge+ei["name_or_index"]]
            if name_index >= len(strings): return None
            key = strings[name_index]
            if key in ("first","second"):
                if key in parts: return None
                parts[key] = string_at(edges[edge+ei["to_node"]],trail+(target,))
        if set(parts) != {"first","second"} or any(v is None for v in parts.values()): return None
        if len(parts["first"])+len(parts["second"]) > recovery.config["max_text_chars"]: return None
        return parts["first"]+parts["second"]
    identity_fields = {field for p in recovery.config["profiles"] if p["adapter"] == "structured_object"
                       for key in ("identity_fields","thread_fields","sender_fields") for field in p[key]}
    for ordinal, node_id, refs, locators in pending:
        obj = {}
        for field, target in refs.items():
            obj[field] = string_at(target)
            if obj[field] is None and field in identity_fields and nt[nodes[target+ni["type"]]] in ("object","array","bigint"):
                # Explicit graph identity, NOT a decoded service/account/message ID.
                obj[field] = "heap-node-reference:"+str(nodes[target+ni["id"]])
        for p in recovery.config["profiles"]:
            if p["adapter"] == "structured_object" and all(any(k in refs for k in p[group]) for group in ("identity_fields","thread_fields","sender_fields")):
                statistics["objects_with_identity_thread_sender_fields"] += 1
                if any(isinstance(obj.get(k),str) for k in p["text_fields"]):
                    statistics["objects_with_linked_text"] += 1
        recovery.scan(Node(obj, "object", 0, len(data)),
                      {"heap_node_ordinal":ordinal,"heap_node_id":node_id,"property_edge_ordinals":locators,
                       "identity_representation":"string-or-explicit-heap-node-reference; not server-verified"},
                      [{"offset":0,"length":len(data)}], "block-level", serialized=False)
    recovery.statistics.update(statistics)
