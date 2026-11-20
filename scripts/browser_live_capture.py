"""One-shot loopback UI: accept an operator's DOM observation, seal it locally."""
import argparse
import html
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import secrets
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT))

from src.services.browser_forensics.live_dom import live_profile, seal_observation
from src.services.browser_forensics.message_recovery_worker import strict_json


def serve(output_workspace, case_id, *, profile=None, index_learning=True, ready=None):
    profile = profile or live_profile()
    token, outcome = secrets.token_urlsafe(32), {}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass  # Never log the body, URL capability or recovered text.

        def setup(self):
            super().setup()
            self.connection.settimeout(profile["request_timeout_seconds"])

        def reply(self, status, body):
            data = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Security-Policy", "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
            self.send_header("Referrer-Policy", "same-origin")
            self.end_headers()
            self.wfile.write(data)

        def valid_target(self):
            return self.path == "/"+token and self.headers.get("Host") == host

        def do_GET(self):
            if not self.valid_target():
                self.reply(404, "Not found")
                return
            self.reply(200, '<!doctype html><meta charset="utf-8"><title>Local protected chat import</title>'
                       '<h1>Local protected chat import</h1><p>Only a loaded-DOM observation. No E2EE decryption. '
                       'Text is sealed with current-user Windows DPAPI; LearnerDB gets masked metadata only.</p>'
                       '<form method="post" enctype="text/plain"><label>DOM observation JSON<br>'
                       '<textarea name="observation" rows="16" cols="100" aria-label="DOM observation JSON"></textarea></label>'
                       '<p><button type="submit">Seal locally</button></p></form>')

        def do_POST(self):
            if not self.valid_target() or self.headers.get("Origin") != origin:
                self.reply(403, "Rejected")
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if self.headers.get("Transfer-Encoding") or not 0 < length <= profile["max_input_bytes"]:
                    raise ValueError("live_transport_budget")
                if self.headers.get("Content-Type") != "text/plain":
                    raise ValueError("live_transport_content_type")
                body = self.rfile.read(length)
                if len(body) != length or not body.startswith(b"observation=") or not body.endswith(b"\r\n"):
                    raise ValueError("live_transport_envelope")
                value = strict_json(body[len(b"observation="):-2])
                result = seal_observation(value, output_workspace, case_id, profile=profile, index_learning=index_learning)
            except Exception:
                self.reply(400, "Import rejected. No message text is included in diagnostics.")
                return
            outcome.update(result)
            self.reply(200, '<!doctype html><meta charset="utf-8"><title>Protected import complete</title>'
                       '<h1>Protected import complete</h1><p>Loaded text observations: '+str(result["candidate_count"])+
                       '</p><p>Storage: Windows DPAPI, current user. No E2EE decryption or complete-history claim.</p>'
                       '<p>LearnerDB indexed: '+html.escape(str(result["index_status"].get("indexed", False)))+'</p>')

    with HTTPServer(("127.0.0.1", 0), Handler) as server:
        host = "127.0.0.1:"+str(server.server_port)
        origin = "http://"+host
        url = origin+"/"+token
        server.timeout = 1
        if ready:
            ready(url)
        else:
            print(json.dumps({"local_import_url": url}), flush=True)
        deadline = time.monotonic()+profile["server_timeout_seconds"]
        while not outcome and time.monotonic() < deadline:
            server.handle_request()
    if not outcome:
        return {"ok": False, "error_code": "local_import_expired"}
    return outcome


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--output-workspace", required=True)
    p.add_argument("--case-id", required=True)
    p.add_argument("--profile")
    p.add_argument("--no-index", action="store_true")
    args = p.parse_args()
    output = str(Path(args.output_workspace).resolve())
    profile_path = str(Path(args.profile).resolve()) if args.profile else None
    from hexeditor_tools.cli import bootstrap_lab_runtime
    bootstrap_lab_runtime(ROOT)
    from hexeditor_tools.api import _forensic_root
    try:
        result = serve(_forensic_root(output), args.case_id,
                       profile=live_profile(profile_path), index_learning=not args.no_index)
    except Exception:
        p.exit(2, "Local protected import failed.\n")
    print(json.dumps(result), flush=True)
    return 0 if result["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
