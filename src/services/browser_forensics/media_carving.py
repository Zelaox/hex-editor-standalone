"""Bounded framing checks, not codec decoding or proof of chat association."""
import base64
import hashlib
import struct
import zlib

try:
    from .parsers import snappy, ParseError
except ImportError:
    from parsers import snappy, ParseError


def framed_length(data, start, kind, cfg):
    """Return a bounded complete framing candidate, never execute/decode content."""
    end_limit = min(len(data), start+cfg["max_media_bytes"])
    if kind == "png":
        pos, first, image_data = start+8, True, False
        for _ in range(cfg["max_segments"]):
            if pos+12 > end_limit: return None
            n = int.from_bytes(data[pos:pos+4], "big")
            end = pos+12+n
            if end > end_limit: return None
            name, raw = data[pos+4:pos+8], data[pos+8:pos+8+n]
            if zlib.crc32(name+raw)&0xffffffff != int.from_bytes(data[pos+8+n:end], "big"): return None
            if first:
                if name != b"IHDR" or n != 13: return None
                width, height = struct.unpack(">II", raw[:8])
                if not 0 < width <= cfg["max_dimension"] or not 0 < height <= cfg["max_dimension"]: return None
            first = False
            if name == b"IDAT": image_data = True
            if name == b"IEND": return end-start if n == 0 and image_data else None
            pos = end
    elif kind == "webp":
        if start+12 > end_limit or data[start+8:start+12] != b"WEBP": return None
        end = start+8+int.from_bytes(data[start+4:start+8], "little")
        if end > end_limit: return None
        pos, image = start+12, False
        for _ in range(cfg["max_segments"]):
            if pos == end: return end-start if image else None
            if pos+8 > end: return None
            name, n = data[pos:pos+4], int.from_bytes(data[pos+4:pos+8], "little")
            pos += 8+n+(n&1)
            if pos > end: return None
            image |= name in (b"VP8 ", b"VP8L")
    elif kind == "jpeg":
        pos, scan, sof, entropy = start+2, False, False, False
        for _ in range(cfg["max_segments"]):
            if entropy:
                pos = data.find(b"\xff", pos, end_limit)
                if pos < 0: return None
            if pos+2 > end_limit or data[pos] != 255: return None
            while pos < end_limit and data[pos] == 255: pos += 1
            if pos >= end_limit: return None
            tag = data[pos]
            pos += 1
            if entropy and (tag == 0 or 0xd0 <= tag <= 0xd7): continue
            if tag == 0xd9: return pos-start if scan and sof else None
            if tag in (0, 0xd8) or 0xd0 <= tag <= 0xd7: return None
            if tag == 1: continue
            if pos+2 > end_limit: return None
            n = int.from_bytes(data[pos:pos+2], "big")
            if n < 2 or pos+n > end_limit: return None
            if 0xc0 <= tag <= 0xcf and tag not in (0xc4,0xc8,0xcc):
                if n < 8: return None
                height, width = struct.unpack(">HH", data[pos+3:pos+7])
                if not 0 < width <= cfg["max_dimension"] or not 0 < height <= cfg["max_dimension"]: return None
                sof = True
            if tag == 0xda: scan = True
            entropy = tag == 0xda
            pos += n
    elif kind == "mp4":
        pos, kinds = start, set()
        for _ in range(cfg["max_segments"]):
            if pos+8 > end_limit: break
            size, name = int.from_bytes(data[pos:pos+4], "big"), data[pos+4:pos+8]
            if not all(32 <= c <= 126 for c in name): break
            header = 8
            if size == 1:
                if pos+16 > end_limit: return None
                size, header = int.from_bytes(data[pos+8:pos+16], "big"), 16
            if size == 0: return None  # Unknown end inside a carved stream.
            if size < header or pos+size > end_limit: break
            if pos == start and (name != b"ftyp" or size < 16): return None
            kinds.add(name)
            pos += size
        if b"mdat" in kinds and (b"moov" in kinds or b"moof" in kinds): return pos-start
    return None


def carve(data, item, config, budgets):
    cfg = config["media"]
    streams = [("raw", data)]
    if data.startswith(b"\xff\x11\x02"):
        try:
            streams.append(("chromium_snappy", snappy(data[3:], budgets)))
        except ParseError:
            pass
    rows, examined, exhausted = [], 0, False
    for transform, raw in streams:
        for fmt in cfg["formats"]:
            signature, cursor = bytes.fromhex(fmt["signature_hex"]), 0
            while cursor < len(raw):
                hit = raw.find(signature, cursor)
                if hit < 0: break
                cursor = hit+1
                examined += 1
                if examined > cfg["max_hits_per_file"]:
                    exhausted = True
                    break
                start = hit-fmt["offset"]
                if start < 0: continue
                length = framed_length(raw, start, fmt["validator"], cfg)
                if not length: continue
                value = raw[start:start+length]
                rows.append({"status":"framed_media_candidate", "format_id":fmt["id"],
                             "extension":fmt["extension"], "mime":fmt["mime"], "sha256":hashlib.sha256(value).hexdigest(),
                             "size":len(value), "source_path":item["path"], "source_sha256":item["sha256"],
                             "transform":transform, "derived_sha256":hashlib.sha256(raw).hexdigest(),
                             "derived_offset":start, "mapping_precision":"exact" if transform == "raw" else "block-level",
                             "source_spans":[{"offset":start,"length":length}] if transform == "raw" else [{"offset":0,"length":len(data)}],
                             "data_base64":base64.b64encode(value).decode("ascii")})
                if len(rows) >= cfg["max_items"]:
                    exhausted = True
                    break
            if exhausted: break
        if exhausted: break
    return {"status":"budget_exhausted" if exhausted else "scanned", "signature_hits":examined, "candidates":rows}
