"""Deterministic coverage-guided campaigns; synthetic corpus only by default.

Coverage feedback retains inputs reaching new Python branch arcs. This is not a
claim of native sanitizer coverage; the shipped storage codecs are Python.
"""
from __future__ import annotations

import random
from pathlib import Path
import sys
import time

try:
    from . import parsers
    from . import chromium_values
    from .common import canonical, digest, file_hash
except ImportError:
    import parsers
    import chromium_values
    from common import canonical, digest, file_hash


def _exercise(harness, handler, value, policy):
    if harness == "v8_value":
        chromium_values.decode_script_value(value, policy["budgets"], policy["message_recovery"])
    elif harness == "indexeddb_key":
        chromium_values.idb_key(value, 0, policy["budgets"])
    elif harness == "snappy":
        parsers.snappy(value, policy["budgets"])
    elif harness == "mapping":
        n = len(value)
        parsers._slice_spans([parsers.span(0, n)], value[0] if n else 0, value[-1] if n else 0)
    else:
        result = parsers.parse(value, handler, policy["budgets"], [])
        for record in result["records"]:
            for field in record["fields"]:
                for s in field["source_spans"]:
                    assert 0 <= s["offset"] <= s["offset"]+s["length"] <= len(value)


def _minimize(harness, handler, value, exception_type, policy):
    width = max(1, len(value)//2)
    for _ in range(policy["fuzz"]["minimize_steps"]):
        changed = False
        for pos in range(0, len(value), width):
            candidate = value[:pos]+value[pos+width:]
            try:
                _exercise(harness, handler, candidate, policy)
            except Exception as exc:
                if type(exc).__name__ == exception_type:
                    value, changed = candidate, True
                    break
        if not changed:
            if width == 1:
                break
            width = max(1, width//2)
    return value


def campaign(corpus, output, policy, registry):
    directory = Path(output)
    directory.mkdir(parents=True, exist_ok=True)
    config = policy["fuzz"]
    rng = random.Random(config["seed"])
    handlers = {r["id"]: r["parser"] for r in registry["storage_rules"]}
    handlers.update({"snappy": "snappy", "mapping": "_slice_spans"})
    handlers.update({name: name for name in policy.get("message_recovery", {}).get("fuzz_harnesses", [])})
    summary, blockers = [], []
    start = time.monotonic()
    for harness in config["harnesses"]:
        if harness not in handlers:
            raise ValueError("unknown_fuzz_harness")
        pool = list(corpus)
        if not pool:
            raise ValueError("empty_fuzz_corpus")
        coverage = set()
        iterations = 0
        for iteration in range(config["iterations"]):
            seed = rng.choice(pool)
            data = bytearray(seed)
            if data:
                index = rng.randrange(len(data))
                mode = rng.randrange(3)
                if mode == 0:
                    data[index] ^= 1 << rng.randrange(8)
                elif mode == 1:
                    del data[index:]
                elif len(data) < config["max_input_bytes"]:
                    data.insert(index, rng.randrange(256))
            else:
                data.append(rng.randrange(256))
            value = bytes(data[:config["max_input_bytes"]])
            arcs, previous = set(), {}
            def trace(frame, event, arg):
                if frame.f_code.co_filename not in (parsers.__file__, chromium_values.__file__):
                    return None
                if event == "line":
                    last = previous.get(id(frame))
                    arcs.add((last, frame.f_lineno))
                    previous[id(frame)] = frame.f_lineno
                elif event == "call":
                    previous[id(frame)] = None
                elif event == "return":
                    previous.pop(id(frame), None)
                return trace
            try:
                sys.settrace(trace)
                _exercise(harness, handlers[harness], value, policy)
            except (parsers.ParseError, ValueError, UnicodeError, RecursionError, OverflowError):
                pass
            except Exception as exc:
                sys.settrace(None)
                value = _minimize(harness, handlers[harness], value, type(exc).__name__, policy)
                h = __import__("hashlib").sha256(value).hexdigest()
                (directory/(h+".bin")).write_bytes(value)
                blockers.append({"harness": harness, "input_sha256": h, "exception_type": type(exc).__name__, "iteration": iteration,
                                 "minimized_bytes": len(value), "seed": config["seed"]})
            finally:
                sys.settrace(None)
            if arcs-coverage:
                coverage.update(arcs)
                pool.append(value)
            iterations += 1
        summary.append({"harness": harness, "iterations": iterations, "branch_arcs": len(coverage),
                        "retained_corpus": len(pool), "campaign_complete": iterations == config["iterations"]})
    report = {"schema_version": 1, "seed": config["seed"], "harnesses": summary,
              "blockers": blockers, "ok": not blockers, "native_sanitizers": "not_run",
              "build_digest": file_hash(parsers.__file__), "elapsed_seconds": time.monotonic()-start,
              "policy_digest": digest(policy), "registry_digest": digest(registry),
              "corpus_sha256": sorted(__import__("hashlib").sha256(seed).hexdigest() for seed in corpus)}
    (directory/"campaign.json").write_bytes(canonical(report))
    return report
