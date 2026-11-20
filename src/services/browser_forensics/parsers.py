"""Bounded storage grammars. Values remain transient; outputs contain structure only.

Numeric constants here are wire-format grammar, never case-specific offsets/keys.
This module is stdlib-only so it can run inside the minimal parser sandbox.
"""
from __future__ import annotations

import hashlib
import json
import math
import struct


class ParseError(ValueError):
    pass


class BudgetExceeded(ParseError):
    pass


def span(offset, length):
    return {"offset": offset, "length": length}


def varint(data, pos, *, sqlite=False):
    start = pos
    value = 0
    for i in range(9 if sqlite else 10):
        if pos >= len(data):
            raise ParseError("truncated_varint")
        b = data[pos]
        pos += 1
        if sqlite:
            value = (value << (8 if i == 8 else 7)) | (b if i == 8 else b & 127)
        else:
            if i == 9 and b > 1:
                raise ParseError("varint_overflow")
            value |= (b & 127) << (7 * i)
        if b < 128 or (sqlite and i == 8):
            return value, pos
    raise ParseError("varint_overflow")


def bounded(data, start, size):
    if start < 0 or size < 0 or start + size > len(data):
        raise ParseError("range_out_of_bounds")
    return data[start:start + size]


def crc32c(data):
    crc = 0xffffffff
    for value in data:
        crc ^= value
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82f63b78 if crc & 1 else 0)
    return crc ^ 0xffffffff


def masked_crc(data):
    v = crc32c(data)
    return (((v >> 15) | ((v << 17) & 0xffffffff)) + 0xa282ead8) & 0xffffffff


def snappy(data, budget):
    size, pos = varint(data, 0)
    if size > budget["max_expanded_bytes"]:
        raise BudgetExceeded("expansion_budget")
    out = bytearray()
    while pos < len(data):
        tag = data[pos]
        pos += 1
        kind = tag & 3
        if kind == 0:
            n = tag >> 2
            if n < 60:
                length = n + 1
            else:
                width = n - 59
                length = int.from_bytes(bounded(data, pos, width), "little") + 1
                pos += width
            if len(out) + length > size:
                raise ParseError("snappy_length")
            out.extend(bounded(data, pos, length))
            pos += length
        else:
            if kind == 1:
                length = 4 + ((tag >> 2) & 7)
                distance = ((tag & 224) << 3) | bounded(data, pos, 1)[0]
                pos += 1
            else:
                width = 2 if kind == 2 else 4
                length = 1 + (tag >> 2)
                distance = int.from_bytes(bounded(data, pos, width), "little")
                pos += width
            if not distance or distance > len(out) or len(out) + length > size:
                raise ParseError("snappy_copy")
            for _ in range(length):
                out.append(out[-distance])
    if len(out) != size:
        raise ParseError("snappy_size")
    return bytes(out)


def _field(data, offset, width, kind, ordinal):
    bounded(data, offset, width)
    return {"ordinal": ordinal, "type": kind, "byte_length": width,
            "source_spans": [span(offset, width)], "mapping_precision": "exact", "findings": []}


def _rules(value, rules):
    """Only profile-declared field names may be emitted; never emit raw values."""
    return [{"rule_field": r["field"], "finding_type": r["finding_type"],
             "validation_status": r["status"]} for r in rules if value == r["field"]]


def json_records(data, budget, rules):
    def no_constant(_):
        raise ParseError("nonfinite_json")
    def object_pairs(pairs):
        result = {}
        for key, child in pairs:
            if key in result:
                raise ParseError("duplicate_json_key")
            result[key] = child
        return result
    value = json.loads(data.decode("utf-8-sig"), parse_constant=no_constant, object_pairs_hook=object_pairs)
    records = []
    def walk(item, depth):
        if depth > budget["max_depth"]:
            raise BudgetExceeded("depth_budget")
        if isinstance(item, dict):
            if len(item) > budget["max_fields"]:
                raise BudgetExceeded("field_budget")
            fields = []
            for ordinal, (name, child) in enumerate(sorted(item.items())):
                fields.append({"ordinal": ordinal, "type": type(child).__name__, "findings": _rules(name, rules),
                               "source_spans": [span(0, len(data))], "mapping_precision": "block-level"})
                walk(child, depth + 1)
            records.append({"locator": {"object_ordinal": len(records)}, "fields": fields})
        elif isinstance(item, list):
            if len(item) > budget["max_records"]:
                raise BudgetExceeded("record_budget")
            for child in item:
                walk(child, depth + 1)
        if len(records) > budget["max_records"]:
            raise BudgetExceeded("record_budget")
    walk(value, 0)
    return records


def protobuf_records(data, budget, rules):
    records = []
    def walk(chunk, base, depth):
        if depth > budget["max_depth"]:
            raise BudgetExceeded("depth_budget")
        fields, pos = [], 0
        while pos < len(chunk):
            if len(fields) >= budget["max_fields"]:
                raise BudgetExceeded("field_budget")
            start = pos
            tag, pos = varint(chunk, pos)
            field_no, wire = tag >> 3, tag & 7
            if not field_no or field_no >= (1 << 29):
                raise ParseError("protobuf_field_number")
            if wire == 0:
                _, end = varint(chunk, pos)
            elif wire == 1:
                end = pos + 8
            elif wire == 5:
                end = pos + 4
            elif wire == 2:
                length, pos = varint(chunk, pos)
                end = pos + length
            else:
                raise ParseError("protobuf_unsupported_wire_type")
            bounded(chunk, pos, end - pos)
            field = _field(data, base + start, end - start, f"wire_{wire}", len(fields))
            field["field_number"] = field_no
            fields.append(field)
            # Schema-less wire 2 stays opaque; strings are never guessed to be messages.
            pos = end
        records.append({"locator": {"wire_object": len(records)}, "fields": fields,
                        "validation_status": "protobuf_candidate"})
    walk(data, 0, 0)
    return records


def _block_entries(block, budget):
    if len(block) < 4:
        raise ParseError("restart_table_missing")
    count = int.from_bytes(block[-4:], "little")
    end = len(block) - 4 - 4 * count
    if end < 0 or not count:
        raise ParseError("restart_table_bounds")
    restarts = [int.from_bytes(block[end+i*4:end+i*4+4], "little") for i in range(count)]
    if restarts != sorted(set(restarts)) or restarts[0] != 0 or any(x > end for x in restarts):
        raise ParseError("restart_offsets")
    pos, previous = 0, b""
    starts = set()
    while pos < end:
        starts.add(pos)
        start = pos
        shared, pos = varint(block, pos)
        nkey, pos = varint(block, pos)
        nval, pos = varint(block, pos)
        if shared > len(previous) or pos + nkey + nval > end or (start in restarts and shared):
            raise ParseError("prefix_entry_bounds")
        key = previous[:shared] + block[pos:pos+nkey]
        pos += nkey
        val_start = pos
        value = block[pos:pos+nval]
        pos += nval
        previous = key
        # Stream entries so a page may end inside a large data/index block.
        # The caller owns record pagination; bytes/CPU/memory remain bounded.
        yield key, value, start, val_start, pos
    if not set(restarts).issubset(starts | ({0} if end == 0 else set())):
        raise ParseError("restart_not_entry")


def _block(data, handle, budget):
    offset, size = handle
    raw = bounded(data, offset, size + 5)
    codec = raw[size]
    if masked_crc(raw[:size+1]) != int.from_bytes(raw[size+1:], "little"):
        raise ParseError("block_checksum")
    if codec == 0:
        return raw[:size], "exact"
    if codec == 1:
        return snappy(raw[:size], budget), "block-level"
    raise ParseError("unsupported_compression")


def _handle(data, pos=0):
    off, pos = varint(data, pos)
    size, pos = varint(data, pos)
    return (off, size), pos


def _level_record(key, value, spans, precision, ordinal, rules, *, key_spans=None, key_precision="unmapped"):
    def markers(content, location):
        findings = []
        # Carving is an observation, not proof of app semantics or encryption.
        for rule in rules:
            if location not in rule.get("locations", ["value"]):
                continue
            count = sum(content.count(rule["field"].encode(encoding)) for encoding in rule.get("encodings", ["utf-8"]))
            if count:
                findings.append({"finding_type": "marker_occurrence", "rule_field": rule["field"],
                                 "candidate_type": rule["finding_type"], "count": count,
                                 "validation_status": "carved"})
        return findings
    fields = [{"ordinal": 0,
            "type": "opaque_value", "byte_length": len(value), "source_spans": spans,
            "mapping_precision": precision, "findings": markers(value, "value")}]
    key_findings = markers(key, "key")
    if key_findings:
        fields.append({"ordinal": 1, "type": "opaque_key", "byte_length": len(key),
                       "source_spans": key_spans or [], "mapping_precision": key_precision, "findings": key_findings})
    return {"locator": {"record_ordinal": ordinal}, "fields": fields,
            "key_digest": hashlib.sha256(key).hexdigest()}


def leveldb_sstable(data, budget, rules):
    if len(data) < 48 or data[-8:] != bytes.fromhex("57fb808b247547db"):
        raise ParseError("sstable_footer")
    meta_handle, pos = _handle(data, len(data)-48)
    meta_content, _ = _block(data, meta_handle, budget)
    for _entry in _block_entries(meta_content, budget):
        pass
    index_handle, _ = _handle(data, pos)
    index, _precision = _block(data, index_handle, budget)
    records, transforms, observed = [], [], 0
    for _key, encoded, *_ in _block_entries(index, budget):
        handle, _ = _handle(encoded)
        content, precision = _block(data, handle, budget)
        transforms.append({"kind": "identity" if precision == "exact" else "snappy",
                           "input_spans": [span(handle[0], handle[1]+5)],
                           "output_sha256": hashlib.sha256(content).hexdigest(), "output_size": len(content),
                           "mapping_precision": precision})
        for key, value, start, value_start, end in _block_entries(content, budget):
            ordinal = observed
            observed += 1
            if ordinal < budget.get("record_cursor", 0):
                continue
            if len(records) >= budget["max_records"]:
                return {"status": "budget_exhausted", "records": records, "transforms": transforms,
                        "continuation": {"record_cursor": ordinal}, "error_code": "record_budget"}
            if len(key) < 8:
                raise ParseError("internal_key_short")
            trailer = int.from_bytes(key[-8:], "little")
            kind, sequence = trailer & 255, trailer >> 8
            if kind not in (0, 1):
                raise ParseError("internal_key_type")
            source_spans = [span(handle[0] + value_start, len(value))] if precision == "exact" else [span(handle[0], handle[1]+5)]
            rec = _level_record(key[:-8], value, source_spans, precision, ordinal, rules,
                                key_spans=[span(handle[0], handle[1]+5)], key_precision="block-level")
            rec["sequence"] = sequence
            rec["deleted"] = kind == 0
            rec["locator"]["block_offset"] = handle[0]
            rec["locator"]["logical_value_offset"] = value_start
            if budget.get("_record_observer"):
                budget["_record_observer"](key[:-8], value, rec)
            records.append(rec)
    return {"records": records, "transforms": transforms}


def log_records(data, budget):
    """LevelDB physical record checksums and FIRST/MIDDLE/LAST assembly."""
    result, fragments, spans, pos = [], bytearray(), [], 0
    while pos < len(data):
        remaining = 32768 - (pos % 32768)
        if remaining < 7:
            if any(data[pos:pos+remaining]):
                raise ParseError("log_trailer")
            pos += remaining
            continue
        if len(data)-pos < 7:
            raise ParseError("log_truncated_header")
        crc, length, kind = struct.unpack_from("<IHB", data, pos)
        if crc == length == kind == 0:
            tail = min(remaining, len(data)-pos)
            if any(data[pos:pos+tail]):
                raise ParseError("log_zero_record")
            pos += tail
            continue
        if length + 7 > remaining:
            raise ParseError("log_fragment_boundary")
        payload = bounded(data, pos+7, length)
        if kind not in (1, 2, 3, 4) or masked_crc(bytes([kind])+payload) != crc:
            raise ParseError("log_checksum_or_type")
        part_span = span(pos+7, length)
        if kind == 1:
            if fragments:
                raise ParseError("log_unfinished_fragment")
            result.append((payload, [part_span]))
        elif kind == 2:
            if fragments:
                raise ParseError("log_nested_first")
            fragments, spans = bytearray(payload), [part_span]
        else:
            if not spans:
                raise ParseError("log_orphan_fragment")
            fragments.extend(payload)
            spans.append(part_span)
            if kind == 4:
                result.append((bytes(fragments), spans))
                fragments, spans = bytearray(), []
        if len(fragments) > budget["max_expanded_bytes"] or len(result) > budget["max_records"]:
            raise BudgetExceeded("record_budget")
        pos += 7 + length
    if spans:
        raise ParseError("log_unfinished_fragment")
    return result


def _slice_spans(spans, offset, length):
    result, cursor = [], 0
    for s in spans:
        left, right = max(offset, cursor), min(offset+length, cursor+s["length"])
        if left < right:
            result.append(span(s["offset"]+left-cursor, right-left))
        cursor += s["length"]
    if sum(s["length"] for s in result) != length:
        raise ParseError("mapping_incomplete")
    return result


def leveldb_log(data, budget, rules):
    records = []
    for batch, spans in log_records(data, budget):
        if len(batch) < 12:
            raise ParseError("writebatch_header")
        seq, count = struct.unpack_from("<QI", batch)
        if count > budget["max_records"]:
            raise BudgetExceeded("record_budget")
        pos = 12
        for index in range(count):
            kind = bounded(batch, pos, 1)[0]
            pos += 1
            if kind not in (0, 1):
                raise ParseError("writebatch_tag")
            n, pos = varint(batch, pos)
            key = bounded(batch, pos, n)
            key_spans = _slice_spans(spans, pos, n)
            pos += n
            value = b""
            if kind == 1:
                n, pos = varint(batch, pos)
                value = bounded(batch, pos, n)
                loc = pos
                pos += n
            else:
                loc, n = pos, 0
            rec = _level_record(key, value, _slice_spans(spans, loc, n), "exact", len(records), rules,
                                key_spans=key_spans, key_precision="exact")
            rec.update(sequence=seq+index, deleted=kind == 0)
            if budget.get("_record_observer"):
                budget["_record_observer"](key, value, rec)
            records.append(rec)
            if len(records) > budget["max_records"]:
                raise BudgetExceeded("record_budget")
        if pos != len(batch):
            raise ParseError("writebatch_trailing_bytes")
    return {"records": records, "transforms": []}


def leveldb_manifest(data, budget, rules):
    records = []
    for edit, spans in log_records(data, budget):
        pos, fields = 0, []
        def string_at(p):
            n, p = varint(edit, p)
            bounded(edit, p, n)
            return p+n
        while pos < len(edit):
            start = pos
            tag, pos = varint(edit, pos)
            if tag in (1,):
                pos = string_at(pos)
            elif tag in (2, 3, 4, 9):
                _, pos = varint(edit, pos)
            elif tag in (5, 6, 7):
                _, pos = varint(edit, pos)  # level
                if tag == 5:
                    pos = string_at(pos)
                else:
                    _, pos = varint(edit, pos)  # file number
                    if tag == 7:
                        _, pos = varint(edit, pos)  # file size
                        pos = string_at(string_at(pos))
            else:
                raise ParseError("manifest_unsupported_tag")
            fields.append({"ordinal": len(fields), "type": "version_edit", "tag": tag,
                           "source_spans": _slice_spans(spans, start, pos-start),
                           "mapping_precision": "exact", "findings": []})
            if len(fields) > budget["max_fields"]:
                raise BudgetExceeded("field_budget")
        records.append({"locator": {"version_edit": len(records)}, "fields": fields})
    return {"records": records, "transforms": []}


def sqlite_records(data, budget, rules):
    """Read SQLite table btrees, overflow chains and serial fields with exact spans.

    SQLite schema rows identify table roots. Index btrees are not treated as tables.
    WAL overlays are deliberately reported as pending by the orchestration layer.
    """
    if len(data) < 100 or data[:16] != b"SQLite format 3\x00":
        raise ParseError("sqlite_header")
    page_size = int.from_bytes(data[16:18], "big")
    page_size = 65536 if page_size == 1 else page_size
    reserved = data[20]
    if page_size < 512 or page_size > 65536 or page_size & (page_size-1) or reserved >= page_size:
        raise ParseError("sqlite_page_size")
    usable = page_size-reserved
    pages = len(data)//page_size
    if not pages or len(data) % page_size:
        raise ParseError("sqlite_truncated_page")
    def integer(off, n):
        return int.from_bytes(bounded(data, off, n), "big")
    def payload(off, size, *, index_page=False):
        if size > budget["max_expanded_bytes"]:
            raise BudgetExceeded("payload_budget")
        maximum = ((usable-12)*64//255)-23 if index_page else usable-35
        if size <= maximum:
            return bounded(data, off, size), [span(off, size)]
        minimum = ((usable-12)*32//255)-23
        local = minimum+(size-minimum) % (usable-4)
        if local > maximum:
            local = minimum
        out, spans = bytearray(bounded(data, off, local)), [span(off, local)]
        next_page = integer(off+local, 4)
        seen = set()
        while len(out) < size:
            if not 1 <= next_page <= pages or next_page in seen:
                raise ParseError("sqlite_overflow_chain")
            seen.add(next_page)
            base = (next_page-1)*page_size
            n = min(usable-4, size-len(out))
            out.extend(bounded(data, base+4, n))
            spans.append(span(base+4, n))
            next_page = integer(base, 4)
        if next_page:
            raise ParseError("sqlite_overflow_tail")
        return bytes(out), spans
    def decode_record(raw, spans):
        header_size, p = varint(raw, 0, sqlite=True)
        if header_size < p or header_size > len(raw):
            raise ParseError("sqlite_record_header")
        serials = []
        while p < header_size:
            serial, p = varint(raw, p, sqlite=True)
            serials.append(serial)
            if len(serials) > budget["max_fields"]:
                raise BudgetExceeded("field_budget")
        if p != header_size:
            raise ParseError("sqlite_serial_header")
        pos, fields, raw_values = header_size, [], []
        sizes = {0: 0, 1: 1, 2: 2, 3: 3, 4: 4, 5: 6, 6: 8, 7: 8, 8: 0, 9: 0}
        for ordinal, serial in enumerate(serials):
            if serial in (10, 11):
                raise ParseError("sqlite_reserved_serial")
            length = sizes[serial] if serial < 10 else (serial-12)//2
            value = bounded(raw, pos, length)
            fields.append({"ordinal": ordinal, "type": "sqlite_serial", "serial_type": serial,
                           "byte_length": length, "source_spans": _slice_spans(spans, pos, length),
                           "mapping_precision": "exact", "findings": []})
            raw_values.append(value)
            pos += length
        if pos != len(raw):
            raise ParseError("sqlite_record_tail")
        return fields, raw_values
    def table(root):
        pending, seen, result = [root], set(), []
        while pending:
            page = pending.pop()
            if not 1 <= page <= pages or page in seen:
                raise ParseError("sqlite_btree_cycle")
            seen.add(page)
            base = (page-1)*page_size
            head = base+(100 if page == 1 else 0)
            kind = bounded(data, head, 1)[0]
            if kind not in (2, 5, 10, 13):
                raise ParseError("sqlite_page_kind")
            count = integer(head+3, 2)
            pointer_base = head+(12 if kind in (2, 5) else 8)
            if pointer_base+count*2 > base+usable:
                raise ParseError("sqlite_cell_pointer_bounds")
            if kind in (2, 5):
                pending.append(integer(head+8, 4))
            for i in range(count):
                cell = base+integer(pointer_base+i*2, 2)
                if not pointer_base+count*2 <= cell < base+usable:
                    raise ParseError("sqlite_cell_offset")
                if kind in (2, 5):
                    pending.append(integer(cell, 4))
                    if kind == 5:
                        continue
                    cell += 4
                size, pos = varint(data, cell, sqlite=True)
                rowid = None
                if kind == 13:
                    rowid, pos = varint(data, pos, sqlite=True)
                    if rowid >= (1 << 63):
                        rowid -= (1 << 64)
                raw, spans = payload(pos, size, index_page=kind in (2, 10))
                fields, values = decode_record(raw, spans)
                result.append((rowid, fields, values))
                if len(result) > budget["max_records"]:
                    raise BudgetExceeded("record_budget")
        return result
    schema = table(1)
    roots = [1]
    for _rid, _fields, values in schema:
        if len(values) == 5 and values[0] == b"table" and values[3]:
            root = int.from_bytes(values[3], "big", signed=True)
            if root > 1:
                roots.append(root)
    records = []
    for root in sorted(set(roots)):
        for rowid, fields, values in table(root):
            # Value carving is labeled, never promoted to structured app semantics.
            for field, value in zip(fields, values):
                for rule in rules:
                    n = value.count(rule["field"].encode("utf-8"))
                    if n:
                        field["findings"].append({"finding_type": "marker_occurrence", "rule_field": rule["field"],
                                                  "candidate_type": rule["finding_type"], "count": n, "validation_status": "carved"})
            records.append({"locator": {"table_root_page": root, "rowid": rowid}, "fields": fields})
            if len(records) > budget["max_records"]:
                raise BudgetExceeded("record_budget")
    return {"records": records, "transforms": []}


def sqlite_wal_overlay(database, wal, budget):
    if len(wal) < 32:
        raise ParseError("wal_header")
    magic = int.from_bytes(wal[:4], "big")
    if magic not in (0x377f0682, 0x377f0683):
        raise ParseError("wal_magic")
    page_size = int.from_bytes(wal[8:12], "big")
    if page_size < 512 or page_size > 65536 or page_size & (page_size-1):
        raise ParseError("wal_page_size")
    db_page_size = int.from_bytes(database[16:18], "big")
    if (65536 if db_page_size == 1 else db_page_size) != page_size:
        raise ParseError("wal_database_page_size")
    order = "little" if magic == 0x377f0682 else "big"
    def checksum(block, seed):
        s1, s2 = seed
        if len(block) % 8:
            raise ParseError("wal_checksum_alignment")
        for off in range(0, len(block), 8):
            s1 = (s1 + int.from_bytes(block[off:off+4], order) + s2) & 0xffffffff
            s2 = (s2 + int.from_bytes(block[off+4:off+8], order) + s1) & 0xffffffff
        return s1, s2
    seed = checksum(wal[:24], (0, 0))
    if seed != struct.unpack(">II", wal[24:32]):
        raise ParseError("wal_header_checksum")
    pos, pending, committed, committed_size = 32, {}, {}, None
    while pos < len(wal):
        frame = bounded(wal, pos, 24+page_size)
        page, db_size = struct.unpack(">II", frame[:8])
        if not page or frame[8:16] != wal[16:24]:
            raise ParseError("wal_frame_identity")
        seed = checksum(frame[:8]+frame[24:], seed)
        if seed != struct.unpack(">II", frame[16:24]):
            raise ParseError("wal_frame_checksum")
        pending[page] = (frame[24:], pos+24)
        if db_size:
            committed.update(pending)
            pending = {}
            committed_size = db_size
        pos += 24+page_size
        if len(committed)+len(pending) > budget["max_records"]:
            raise BudgetExceeded("wal_frame_budget")
    size = committed_size*page_size if committed_size else len(database)
    if size > budget["max_expanded_bytes"]:
        raise BudgetExceeded("wal_expansion_budget")
    out = bytearray(database[:size])
    out.extend(b"\0" * (size-len(out)))
    mapping = {}
    for page, (content, original_offset) in committed.items():
        if (page-1)*page_size < size:
            out[(page-1)*page_size:page*page_size] = content
            mapping[page] = original_offset
    return bytes(out), mapping, page_size


def probe_sqlite(data, budget):
    return len(data) >= 100 and data[:16] == b"SQLite format 3\x00"


def sqlite_wal_records(data, budget, rules):
    if len(data) < 32:
        raise ParseError("wal_header")
    size = int.from_bytes(data[8:12], "big")
    if size < 512 or size > 65536 or size & (size-1):
        raise ParseError("wal_page_size")
    # Reuse the checksum/commit validator with a synthetic empty compatible header.
    header = bytearray(size)
    header[:16] = b"SQLite format 3\x00"
    header[16:18] = (1 if size == 65536 else size).to_bytes(2, "big")
    sqlite_wal_overlay(bytes(header), data, budget)
    records = []
    for offset in range(32, len(data), 24+size):
        records.append({"locator": {"frame_offset": offset}, "fields": [
            {"ordinal": 0, "type": "wal_frame", "source_spans": [span(offset, 24+size)],
             "mapping_precision": "exact", "findings": []}]})
    return {"records": records, "transforms": []}


def probe_wal(data, budget):
    return len(data) >= 32 and int.from_bytes(data[:4], "big") in (0x377f0682, 0x377f0683)


def leveldb_current(data, budget, rules):
    import re
    if re.fullmatch(rb"MANIFEST-[0-9]+\n", data) is None:
        raise ParseError("current_pointer_invalid")
    return {"records": [{"locator": {"pointer_offset": 0}, "fields": [
        {"ordinal": 0, "type": "manifest_reference", "source_spans": [span(0, len(data))],
         "mapping_precision": "exact", "findings": []}]}], "transforms": []}


def probe_current(data, budget):
    return bool(leveldb_current(data, budget, [])["records"])


def probe_sstable(data, budget):
    # Magic checked from registry. Validate the footer's block handles as well.
    if len(data) < 48:
        return False
    meta, pos = _handle(data, len(data)-48)
    index, pos = _handle(data, pos)
    return all(off + n + 5 <= len(data)-48 for off, n in (meta, index))


def probe_writebatch(data, budget):
    items = log_records(data, budget)
    if not items:
        return False
    return all(len(batch) >= 12 and int.from_bytes(batch[8:12], "little") <= budget["max_records"] for batch, _ in items)


def probe_manifest(data, budget):
    return bool(leveldb_manifest(data, budget, [])["records"])


def probe_json(data, budget):
    return data.lstrip().startswith((b"{", b"[")) and bool(json_records(data, budget, []) or data.strip() in (b"[]", b"{}"))


def probe_protobuf(data, budget):
    return bool(data) and bool(protobuf_records(data, budget, []))


def parse(data, parser_name, budget, rules):
    handler = globals().get(parser_name)
    if not callable(handler) or parser_name.startswith("_"):
        return {"status": "unsupported", "records": [], "transforms": [], "error_code": "unsupported_format"}
    try:
        result = handler(data, budget, rules)
        if isinstance(result, list):
            result = {"records": result, "transforms": []}
        return {"status": "completed", **result}
    except BudgetExceeded as exc:
        return {"status": "budget_exhausted", "records": [], "transforms": [], "error_code": str(exc)}
    except (ParseError, UnicodeError, json.JSONDecodeError, RecursionError, OverflowError, struct.error) as exc:
        code = str(exc) if isinstance(exc, ParseError) else type(exc).__name__
        return {"status": "partial", "records": [], "transforms": [], "error_code": code}
