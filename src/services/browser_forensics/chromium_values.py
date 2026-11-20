"""Bounded Chromium IndexedDB/V8 subset, never regex-carved or executed.

Wire grammar references are recorded in docs/BROWSER_STORAGE_FORENSICS.md.
Unsupported tags, trailers and versions fail closed. Nodes/values
are transient inside the sandbox, not part of the ordinary analysis result.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import math
import struct
import hashlib

try:
    from .parsers import ParseError, BudgetExceeded, bounded, varint, snappy
except ImportError:
    from parsers import ParseError, BudgetExceeded, bounded, varint, snappy


@dataclass
class Node:
    value: object
    kind: str
    start: int
    end: int
    children: list = field(default_factory=list)


def key_prefix(key):
    lead = bounded(key, 0, 1)[0]
    widths = ((lead >> 5)+1, ((lead >> 2) & 7)+1, (lead & 3)+1)
    pos, ids = 1, []
    for width in widths:
        ids.append(int.from_bytes(bounded(key, pos, width), "little"))
        pos += width
    return tuple(ids), pos


def idb_key(data, pos, budget, depth=0):
    if depth > budget["max_depth"]:
        raise BudgetExceeded("idb_key_depth")
    kind = bounded(data, pos, 1)[0]
    pos += 1
    if kind in (2, 3):
        value = struct.unpack("<d", bounded(data, pos, 8))[0]
        if not math.isfinite(value):
            raise ParseError("idb_key_nonfinite")
        return value, pos+8
    if kind in (1, 6):
        n, pos = varint(data, pos)
        size = n*2 if kind == 1 else n
        if size > budget["max_expanded_bytes"]:
            raise BudgetExceeded("idb_key_bytes")
        value = bounded(data, pos, size)
        return value.decode("utf-16be", errors="strict") if kind == 1 else value, pos+size
    if kind == 4:
        n, pos = varint(data, pos)
        if n > budget["max_fields"]:
            raise BudgetExceeded("idb_key_fields")
        items = []
        for _ in range(n):
            value, pos = idb_key(data, pos, budget, depth+1)
            items.append(value)
        return items, pos
    raise ParseError("idb_key_unsupported")


class Reader:
    def __init__(self, data, budget, config, offset=0):
        self.data, self.budget, self.config, self.pos = data, budget, config, offset
        self.nodes = 0
        self.objects = []

    def remember(self, node, wire_kind):
        if len(self.objects) >= self.config["max_nodes"]:
            raise BudgetExceeded("v8_reference_budget")
        self.objects.append((wire_kind, node))
        return node

    def byte(self):
        value = bounded(self.data, self.pos, 1)[0]
        self.pos += 1
        return value

    def uint(self):
        value, self.pos = varint(self.data, self.pos)
        return value

    def take(self, n):
        if n > self.budget["max_expanded_bytes"]:
            raise BudgetExceeded("v8_expansion")
        data = bounded(self.data, self.pos, n)
        self.pos += n
        return data

    def peek(self):
        while self.pos < len(self.data) and self.data[self.pos] == 0:
            self.pos += 1
        return bounded(self.data, self.pos, 1)[0]

    def read(self, depth=0):
        self.nodes += 1
        if depth > self.budget["max_depth"] or self.nodes > self.config["max_nodes"]:
            raise BudgetExceeded("v8_structure_budget")
        self.peek()
        start, tag = self.pos, self.byte()
        children = []
        registered, buffer_value = None, None
        if tag in (ord("0"), ord("_"), ord("-")):
            value, kind = None, "null" if tag == ord("0") else "undefined"
        elif tag in (ord("T"), ord("F")):
            value, kind = tag == ord("T"), "boolean"
        elif tag in (ord("I"), ord("U")):
            value = self.uint()
            if value > 0xffffffff:
                raise ParseError("v8_uint32_overflow")
            if tag == ord("I"):
                value = (value >> 1) ^ -(value & 1)
            kind = "number"
        elif tag in (ord("N"), ord("D")):
            value, kind = struct.unpack("<d", self.take(8))[0], "number"
            if not math.isfinite(value):
                raise ParseError("v8_nonfinite")
            if tag == ord("D"):
                registered = self.remember(Node(value, kind, start, self.pos), "date")
        elif tag in (ord('"'), ord("S"), ord("c")):
            n = self.uint()
            raw = self.take(n)
            encoding = {ord('"'): "latin-1", ord("S"): "utf-8", ord("c"): "utf-16le"}[tag]
            value, kind = raw.decode(encoding, errors="strict"), "string"
        elif tag == ord("B"):
            value, kind = self.take(self.uint()), "bytes"
            buffer_value = value
            registered = self.remember(Node(value, kind, start, self.pos), "array_buffer")
        elif tag == ord("^"):
            index = self.uint()
            if index >= len(self.objects):
                raise ParseError("v8_reference_out_of_bounds")
            wire_kind, target = self.objects[index]
            value, kind = target.value, "reference"
            # Reference leaves never recursively expand a cyclic graph.
            if wire_kind == "array_buffer":
                buffer_value = value
        elif tag == ord("o"):
            value, kind = {}, "object"
            registered = self.remember(Node(value, kind, start, self.pos, children), "object")
            while self.peek() != ord("{"):
                if len(children) >= self.budget["max_fields"]:
                    raise BudgetExceeded("v8_property_budget")
                key = self.read(depth+1)
                if key.kind not in ("string", "number"):
                    raise ParseError("v8_property_key")
                name = str(key.value)
                if name in value:
                    raise ParseError("v8_duplicate_property")
                child = self.read(depth+1)
                value[name] = child.value
                children.append((name, child))
            self.byte()
            if self.uint() != len(children):
                raise ParseError("v8_property_count")
        elif tag in (ord("A"), ord("a")):
            n = self.uint()
            if n > self.budget["max_records"]:
                raise BudgetExceeded("v8_array_budget")
            value, kind = [None]*n, "array"
            registered = self.remember(Node(value, kind, start, self.pos, children), "array")
            if tag == ord("A"):
                for i in range(n):
                    child = self.read(depth+1)
                    value[i] = child.value
                    children.append((i, child))
                ending, properties = ord("$"), 0
            else:
                ending, properties = ord("@"), 0
            while self.peek() != ending:
                if properties >= self.budget["max_fields"]:
                    raise BudgetExceeded("v8_array_properties_budget")
                key = self.read(depth+1)
                if key.kind == "number" and type(key.value) is int and 0 <= key.value < n and tag == ord("a"):
                    name = key.value
                elif key.kind == "string" and not key.value.isdigit() and key.value != "length":
                    name = key.value
                else:
                    raise ParseError("v8_array_property_unsupported")
                if any(str(k) == str(name) for k, _ in children):
                    raise ParseError("v8_array_duplicate_property")
                child = self.read(depth+1)
                if isinstance(name, int):
                    value[name] = child.value
                children.append((name, child))
                properties += 1
            self.byte()
            if self.uint() != properties or self.uint() != n:
                raise ParseError("v8_array_count")
        else:
            # No scanning forward after unsupported host/transfer/reference tags.
            raise ParseError("v8_tag_unsupported_"+format(tag, "02x"))
        if buffer_value is not None and self.pos < len(self.data) and self.peek() == ord("V"):
            self.byte()
            subtype, offset, length = self.uint(), self.uint(), self.uint()
            sizes = {ord(c): n for chars,n in (("bBC?",1),("wWh",2),("dDf",4),("FqQ",8)) for c in chars}
            flags = self.uint() if self.version >= 14 else 0
            if subtype not in sizes or flags or offset % sizes[subtype] or length % sizes[subtype]:
                raise ParseError("v8_view_unsupported")
            value, kind = bounded(buffer_value, offset, length), "bytes"
            registered = self.remember(Node(value, kind, start, self.pos), "array_buffer_view")
        if registered is not None:
            registered.end = self.pos
            return registered
        return Node(value, kind, start, self.pos, children)


def decode_script_value(data, budget, config, *, offset=0, layers=0):
    if layers > budget["max_depth"]:
        raise BudgetExceeded("idb_wrapping_depth")
    if data[offset:offset+3] == b"\xff\x11\x02":
        unpacked = snappy(data[offset+3:], budget)
        node, metadata = decode_script_value(unpacked, budget, config, layers=layers+1)
        return node, {**metadata, "value_mapping_precision": "block-level", "derived_sha256": hashlib.sha256(unpacked).hexdigest()}
    if data[offset:offset+3] == b"\xff\x11\x01":
        raise ParseError("indexeddb_external_blob_required")
    reader = Reader(data, budget, config, offset)
    if reader.byte() != 0xff:
        raise ParseError("v8_header_missing")
    version = reader.uint()
    blink = None
    if version >= 17:
        blink = version
        if blink not in config["blink_versions"]:
            raise ParseError("blink_version_unsupported")
        if blink >= 21:
            if reader.byte() != 0xfe:
                raise ParseError("blink_trailer_header")
            trailer_offset = int.from_bytes(reader.take(8), "big")
            trailer_length = int.from_bytes(reader.take(4), "big")
            if trailer_offset or trailer_length:
                raise ParseError("blink_trailer_unsupported")
        if reader.byte() != 0xff:
            raise ParseError("v8_inner_header_missing")
        version = reader.uint()
    if version not in config["v8_versions"]:
        raise ParseError("v8_version_unsupported")
    reader.version = version
    node = reader.read()
    if any(data[reader.pos:]):
        raise ParseError("v8_trailing_data")
    return node, {"v8_version": version, "blink_version": blink}


def decode_idb_record(key, value, budget, config):
    ids, pos = key_prefix(key)
    if ids[0] <= 0 or ids[1] <= 0 or ids[2] != 1:
        raise ParseError("idb_not_object_store_data")
    _primary, end = idb_key(key, pos, budget)
    if end != len(key):
        raise ParseError("idb_primary_key_trailing")
    version, offset = varint(value, 0)
    node, envelope = decode_script_value(value, budget, config, offset=offset)
    return node, {"database_id": ids[0], "object_store_id": ids[1], "record_version": version, **envelope}
