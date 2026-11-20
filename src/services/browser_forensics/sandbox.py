"""Cross-platform host for the fail-closed Linux namespace backend."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from .common import canonical, file_hash, read_json, confined


def _linux_path(path, policy):
    if os.name != "nt":
        return str(Path(path).resolve())
    p = subprocess.run(["wsl", "-d", policy["worker"]["wsl_distribution"], "--exec", "wslpath", "-a", Path(path).resolve().as_posix()],
                       capture_output=True, timeout=policy["budgets"]["wall_seconds"], check=True)
    return p.stdout.decode("utf-8").strip()


def run_worker(request, input_root=None, artifact_output=None):
    policy = request["policy"]
    if policy["worker"]["backend"] != "bubblewrap":
        return {"status": "isolation_unavailable", "error_code": "unsupported_backend"}
    try:
        with tempfile.TemporaryDirectory(prefix="hex-forensic-") as temp:
            root = Path(temp)
            stage, output = root / "stage", root / "output"
            stage.mkdir()
            output.mkdir()
            (stage / "data").mkdir()
            for item in request.get("files", []):
                src = confined(input_root, item["path"])
                dst = confined(stage / "data", item["path"])
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(src, dst)
                if file_hash(dst) != item["sha256"]:
                    return {"status": "input_changed", "error_code": "staged_hash_mismatch"}
            (stage / "request.json").write_bytes(canonical(request))
            code = root / "code"
            code.mkdir()
            for source in Path(__file__).resolve().parent.glob("*.py"):
                shutil.copyfile(source, code/source.name)
            expected_code = {name: sha for name, sha in request.get("build", {}).items() if name.endswith(".py")}
            if expected_code and {p.name: file_hash(p) for p in sorted(code.glob("*.py"))} != expected_code:
                return {"status": "failed", "error_code": "build_changed"}
            if request.get("operation") == "transform_probe":
                # Reuse the actual Hex Editor executor, without importing PTX scoring/defaults.
                executor = Path(__file__).resolve().parents[1]/"key_hunt_executors.py"
                expected = request.get("build", {}).get("shared_xor_executor_sha256")
                if not expected or file_hash(executor) != expected:
                    return {"status":"failed", "error_code":"shared_executor_changed"}
                shutil.copyfile(executor, code/"shared_xor_executor.py")
                if file_hash(code/"shared_xor_executor.py") != expected:
                    return {"status":"failed", "error_code":"shared_executor_copy_changed"}
            launcher = _linux_path(code / "sandbox_launcher.py", policy)
            args = [policy["worker"]["linux_python"], launcher,
                    _linux_path(stage, policy), _linux_path(output, policy), _linux_path(code, policy)]
            if os.name == "nt":
                args = ["wsl", "-d", policy["worker"]["wsl_distribution"], "--exec", *args]
            proc = subprocess.run(args, capture_output=True, timeout=policy["budgets"]["wall_seconds"]+10)
            target = output / "result.json"
            if proc.returncode or not target.is_file():
                return {"status": "isolation_unavailable" if proc.returncode == 78 else "failed",
                        "error_code": {124: "worker_timeout", -9: "worker_killed"}.get(proc.returncode, "worker_failed"),
                        "exit_code": proc.returncode}
            if target.stat().st_size > policy["budgets"]["max_output_bytes"]:
                return {"status": "budget_exhausted", "error_code": "output_budget"}
            result = read_json(target)
            if artifact_output is not None and request["operation"] == "fuzz":
                import re
                destination = Path(artifact_output)
                destination.mkdir(parents=True, exist_ok=True)
                for artifact in output.glob("*.bin"):
                    if artifact.is_symlink() or not re.fullmatch(r"[0-9a-f]{64}\.bin", artifact.name):
                        raise ValueError("invalid_fuzz_artifact")
                    if artifact.stat().st_size > policy["fuzz"]["max_input_bytes"] or file_hash(artifact) != artifact.stem:
                        raise ValueError("invalid_fuzz_artifact")
                    shutil.copyfile(artifact, destination/artifact.name)
                (destination/"campaign.json").write_bytes(canonical(result))
            return result
    except (OSError, subprocess.SubprocessError) as exc:
        return {"status": "isolation_unavailable", "error_code": "worker_backend_unavailable",
                "exception_type": type(exc).__name__, "errno": getattr(exc, "errno", None)}
