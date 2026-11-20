"""Trusted Linux launcher. Kills the entire sandbox group on wall-time expiry."""
from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys


def main():
    stage, output, code = map(lambda p: Path(p).resolve(), sys.argv[1:4])
    request = json.loads((stage / "request.json").read_text())
    worker = request["policy"]["worker"]
    bwrap = shutil.which(worker["executable"])
    if not bwrap:
        return 78
    output.mkdir(exist_ok=True)
    os.chmod(output, 0o777)
    args = [bwrap, "--unshare-all", "--die-with-parent", "--new-session", "--cap-drop", "ALL",
            "--clearenv", "--uid", str(worker["uid"]), "--gid", str(worker["gid"])]
    for root in worker["runtime_roots"]:
        if Path(root).is_dir():
            args += ["--ro-bind", root, root]
    args += ["--ro-bind", str(code), "/app", "--ro-bind", str(stage), "/input",
             "--bind", str(output), "/output", "--proc", "/proc", "--dev", "/dev",
             "--tmpfs", "/tmp", "--chdir", "/tmp", "--setenv", "PYTHONDONTWRITEBYTECODE", "1",
             worker["linux_python"], "-B", "/app/worker_entry.py", "/input/request.json", "/output/result.json"]
    # Avoid pipe buffering or unbounded stderr from hostile code.
    with (output / "worker.stderr").open("wb") as err:
        proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=err, start_new_session=True, env={"PATH": os.defpath})
        try:
            rc = proc.wait(timeout=request["policy"]["budgets"]["wall_seconds"])
            if rc:
                # bwrap can relay a child's signal as shell-style 128+signal.
                cpu_limit = rc in (-signal.SIGXCPU, 128+signal.SIGXCPU)
                status = "budget_exhausted" if cpu_limit else "failed"
                code = "worker_cpu_limit" if cpu_limit else "worker_terminated"
                (output/"result.json").write_text(json.dumps({"status": status, "error_code": code, "exit_code": rc}))
            else:
                result_path = output/"result.json"
                # Only read bounded worker output; metadata is attested by the launcher.
                if result_path.stat().st_size > request["policy"]["budgets"]["max_output_bytes"]:
                    result = {"status": "budget_exhausted", "error_code": "output_budget"}
                else:
                    result = json.loads(result_path.read_text())
                    result["sandbox_binary_sha256"] = hashlib.sha256(Path(bwrap).read_bytes()).hexdigest()
                result_path.write_text(json.dumps(result, sort_keys=True, separators=(",", ":")))
            return 0
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
            (output/"result.json").write_text(json.dumps({"status": "budget_exhausted", "error_code": "worker_wall_limit"}))
            return 0


if __name__ == "__main__":
    sys.exit(main())
