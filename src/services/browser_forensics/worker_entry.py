"""Minimal parser worker: no host imports, values, inherited credentials or DB writes."""
from __future__ import annotations

import hashlib
import ctypes
import json
import os
from pathlib import Path
import resource
import socket
import sys

from detection import detect_bytes
from parsers import parse, sqlite_wal_overlay, ParseError, span


def restrict_syscalls(names):
    lib = ctypes.CDLL("libseccomp.so.2")
    lib.seccomp_init.argtypes = [ctypes.c_uint32]
    lib.seccomp_init.restype = ctypes.c_void_p
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    lib.seccomp_syscall_resolve_name.restype = ctypes.c_int
    lib.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
    lib.seccomp_load.argtypes = [ctypes.c_void_p]
    lib.seccomp_release.argtypes = [ctypes.c_void_p]
    ctx = lib.seccomp_init(0x7fff0000)  # SCMP_ACT_ALLOW; EPERM rules below.
    if not ctx:
        raise RuntimeError("seccomp_init_failed")
    try:
        for name in names:
            syscall = lib.seccomp_syscall_resolve_name(name.encode("ascii"))
            if syscall >= 0 and lib.seccomp_rule_add(ctx, 0x00050001, syscall, 0) != 0:
                raise RuntimeError("seccomp_rule_failed")
        if lib.seccomp_load(ctx) != 0:
            raise RuntimeError("seccomp_load_failed")
    finally:
        lib.seccomp_release(ctx)


def main():
    request = json.loads(Path(sys.argv[1]).read_text())
    budgets = request["policy"]["budgets"]
    resource.setrlimit(resource.RLIMIT_AS, (budgets["memory_bytes"], budgets["memory_bytes"]))
    resource.setrlimit(resource.RLIMIT_CPU, (budgets["cpu_seconds"], budgets["cpu_seconds"]+1))
    resource.setrlimit(resource.RLIMIT_FSIZE, (budgets["max_output_bytes"], budgets["max_output_bytes"]))
    resource.setrlimit(resource.RLIMIT_NPROC, (budgets["max_processes"], budgets["max_processes"]))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    # Pin the actual interpreter binary, not only a marketing version string.
    runtime_binary = hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest()
    if os.geteuid() == 0:
        raise RuntimeError("worker_must_be_unprivileged")
    # Enforce and attest namespace absence of network interfaces other than loopback.
    isolated = not any(name != "lo" for _index, name in socket.if_nameindex())
    if not isolated:
        raise RuntimeError("network_namespace_not_isolated")
    restrict_syscalls(request["policy"]["worker"]["deny_syscalls"])
    if request.get("operation") == "preflight":
        denied = {}
        for name, fn in (("host_root", lambda: Path("/etc/shadow").read_bytes()),
                         ("input_write", lambda: Path(sys.argv[1]).write_text("forbidden")),
                         ("fork", os.fork), ("network_socket", lambda: socket.socket(socket.AF_INET, socket.SOCK_STREAM))):
            try:
                fn()
                denied[name] = False
            except (OSError, PermissionError):
                denied[name] = True
        result = {"status": "completed", "isolated": isolated, "denied": denied,
                  "uid": os.geteuid(), "python": sys.version.split()[0]}
    elif request.get("operation") == "resource_probe":
        probe = request["probe"]
        if probe == "memory":
            try:
                bytearray(budgets["memory_bytes"]+1)
                result = {"status": "failed", "limited": False}
            except MemoryError:
                result = {"status": "completed", "limited": True}
        elif probe == "output":
            try:
                with Path("/output/limit_probe.bin").open("wb") as handle:
                    block = b"\0"*min(budgets["max_output_bytes"], 1024*1024)
                    for _ in range(budgets["max_output_bytes"]//len(block)+2):
                        handle.write(block)
                result = {"status": "failed", "limited": False}
            except OSError:
                result = {"status": "completed", "limited": True}
        elif probe == "cpu":
            while True:
                pass
        else:
            raise ValueError("unknown_resource_probe")
    elif request.get("operation") == "transform_probe":
        from transform_probe import Probe
        import shared_xor_executor
        executor_sha = hashlib.sha256(Path(shared_xor_executor.__file__).read_bytes()).hexdigest()
        if executor_sha != request["build"]["shared_xor_executor_sha256"]:
            raise ValueError("transform_executor_identity")
        outputs = []
        for item in request["files"]:
            path = (Path("/input/data")/item["path"]).resolve()
            if not path.is_relative_to(Path("/input/data")): raise ValueError("worker_path_escape")
            data = path.read_bytes()
            if len(data) > budgets["max_file_bytes"] or hashlib.sha256(data).hexdigest() != item["sha256"]:
                raise ValueError("transform_input_identity")
            probe = Probe(item,request["policy"],request["transform_policy"],request["recovery_policy"],
                          request["registry"],request["export_policy"],shared_xor_executor.apply_xor_descriptor)
            outputs.append(probe.run(data))
        result = {"status":"completed","files":outputs,"python":sys.version.split()[0],
                  "runtime_binary_sha256":runtime_binary,"shared_xor_executor_sha256":executor_sha}
    elif request.get("operation") == "media_scan":
        from media_carving import carve
        files = []
        for item in request["files"]:
            path = (Path("/input/data")/item["path"]).resolve()
            if not path.is_relative_to(Path("/input/data")):
                raise ValueError("worker_path_escape")
            data = path.read_bytes()
            if len(data) > budgets["max_file_bytes"] or hashlib.sha256(data).hexdigest() != item["sha256"]:
                raise ValueError("media_input_identity")
            files.append({"path":item["path"], "sha256":item["sha256"], **carve(data, item, request["export_policy"], budgets)})
        result = {"status":"completed", "files":files}
    elif request.get("operation") == "blob_schema":
        from chromium_values import decode_script_value
        import re
        files = []
        def shape(node, depth=0):
            out = {"kind": node.kind}
            if node.kind in ("string", "bytes"):
                out["length"] = len(node.value)
            if depth < 4:
                out["children"] = [{"key": k if isinstance(k, int) or re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]{0,63}", str(k)) else "masked-key",
                                    "shape": shape(v, depth+1)} for k,v in node.children[:4]]
            return out
        for item in request["files"]:
            data = (Path("/input/data")/item["path"]).read_bytes()
            if len(data) > budgets["max_file_bytes"] or hashlib.sha256(data).hexdigest() != item["sha256"]:
                raise ValueError("schema_probe_input_identity")
            node, context = decode_script_value(data, budgets, request["recovery_policy"])
            files.append({"path": item["path"], "shape": shape(node), "context": context})
            del node, data
            import gc
            gc.collect()
        result = {"status": "completed", "files": files}
    elif request.get("operation") == "fuzz":
        from fuzz import campaign
        corpus = [(Path("/input/data")/item["path"]).read_bytes() for item in request["files"]]
        campaign_policy = request["policy"]
        if request.get("recovery_policy"):
            campaign_policy = {**campaign_policy, "message_recovery": request["recovery_policy"],
                               "fuzz": {**campaign_policy["fuzz"], "harnesses": campaign_policy["fuzz"]["harnesses"]+request["recovery_policy"]["fuzz_harnesses"]}}
        result = campaign(corpus, "/output", campaign_policy, request["registry"])
        result["status"] = "completed" if result["ok"] else "failed"
    else:
        rules = [r for p in request["policy"]["profiles"] if p["id"] in request.get("profiles", []) for r in p["rules"]]
        results = []
        items_by_path = {item["path"]: item for item in request["files"]}
        for item in request["files"]:
            path = Path("/input/data") / item["path"]
            if not path.resolve().is_relative_to(Path("/input/data")):
                raise ValueError("worker_path_escape")
            data = path.read_bytes()
            if len(data) > budgets["max_file_bytes"]:
                raise ValueError("input_budget")
            if hashlib.sha256(data).hexdigest() != item["sha256"]:
                raise ValueError("input_changed")
            detection = detect_bytes(data, request["registry"], budgets, item.get("format_hint", ""))
            wal_name = item["path"] + "-wal"
            wal_mapping, wal_page_size = {}, None
            source_data = data
            overlay_error = None
            if detection["format_id"] == "sqlite" and wal_name in items_by_path and request["operation"] != "detect":
                wal_item = items_by_path[wal_name]
                wal = (Path("/input/data") / wal_name).read_bytes()
                if hashlib.sha256(wal).hexdigest() != wal_item["sha256"]:
                    raise ValueError("input_changed")
                try:
                    data, wal_mapping, wal_page_size = sqlite_wal_overlay(data, wal, budgets)
                except ParseError:
                    overlay_error = "wal_unresolved"
            if request["operation"] == "detect":
                parsed = {"status": "completed", "records": [], "transforms": []}
            elif request["operation"] == "recover":
                from message_recovery_worker import Recovery
                recovery = Recovery(item, budgets, request["recovery_policy"])
                parser = detection["candidates"][0]["parser"] if detection["candidates"] else ""
                if item.get("format_hint") == "v8_heap_snapshot":
                    from heap_snapshot import scan_snapshot
                    try:
                        scan_snapshot(data, recovery)
                        parsed = {"status":"completed", "records":[], "transforms":[]}
                    except (ParseError, ValueError, KeyError, TypeError, IndexError, RecursionError, UnicodeError) as exc:
                        recovery.rows.clear()
                        # Our ParseError messages are fixed grammar codes, never input text.
                        recovery.statistics[str(exc) if isinstance(exc, ParseError) else type(exc).__name__] += 1
                        parsed = {"status":"unsupported", "records":[], "transforms":[], "error_code":"heap_snapshot_incomplete"}
                elif item.get("role") == "blob":
                    parsed = {"status": "completed" if recovery.blob_value(data) else "unsupported", "records": [], "transforms": []}
                elif detection["format_id"] == "json":
                    try:
                        recovery.json_export(data)
                        parsed = {"status": "completed", "records": [], "transforms": []}
                    except (ParseError, UnicodeError, ValueError, RecursionError):
                        recovery.rows.clear()
                        parsed = {"status": "partial", "error_code": "json_recovery_incomplete", "records": [], "transforms": []}
                elif detection["format_id"] in ("leveldb_sstable", "leveldb_log"):
                    parsed = parse(data, parser, {**budgets, "record_cursor": item.get("record_cursor", 0), "_record_observer": recovery.observe}, [])
                    if parsed["status"] == "partial":
                        recovery.rows.clear()
                else:
                    parsed = {"status": "unsupported", "records": [], "transforms": [], "error_code": "recovery_format_unsupported"}
                parsed["records"] = []
                parsed.update(private_candidates=recovery.rows, recovery_statistics=dict(recovery.statistics),
                              known_field_counts=dict(recovery.known_fields))
            else:
                parsed = parse(data, detection["candidates"][0]["parser"], {**budgets, "record_cursor": item.get("record_cursor", 0)}, rules) if detection["candidates"] else {
                    "status": "unsupported", "records": [], "transforms": [], "error_code": "unsupported_format"}
            if overlay_error:
                parsed.update(status="partial", error_code=overlay_error)
            if wal_mapping:
                for record in parsed["records"]:
                    for field in record["fields"]:
                        mapped = []
                        for s in field["source_spans"]:
                            pos, left = s["offset"], s["length"]
                            while left:
                                page = pos // wal_page_size + 1
                                delta = pos % wal_page_size
                                n = min(left, wal_page_size-delta)
                                path = wal_name if page in wal_mapping else item["path"]
                                off = wal_mapping[page]+delta if page in wal_mapping else pos
                                mapped.append({**span(off, n), "source_path": path})
                                pos, left = pos+n, left-n
                        field["source_spans"] = mapped
                parsed["transforms"].append({"kind": "sqlite_wal_overlay", "output_sha256": hashlib.sha256(data).hexdigest(),
                                             "output_size": len(data), "mapping_precision": "exact",
                                             "wal_source_sha256": items_by_path[wal_name]["sha256"]})
            results.append({"path": item["path"], "sha256": item["sha256"], "size": len(source_data), "detection": detection, **parsed})
        result = {"status": "completed", "files": results, "python": sys.version.split()[0],
                  "runtime_binary_sha256": runtime_binary}
    encoded = json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    if len(encoded) > budgets["max_output_bytes"]:
        encoded = json.dumps({"status": "budget_exhausted", "error_code": "output_budget"}).encode()
    Path(sys.argv[2]).write_bytes(encoded)


if __name__ == "__main__":
    try:
        main()
    except BaseException as exc:
        if isinstance(exc, MemoryError):
            # Do not include input-derived exception text, even on memory failure.
            Path(sys.argv[2]).write_text('{"status":"budget_exhausted","error_code":"worker_memory_limit"}')
            sys.exit(0)
        # Exception text may contain secret payloads. Emit only its class.
        print(type(exc).__name__, file=sys.stderr)
        sys.exit(2)
