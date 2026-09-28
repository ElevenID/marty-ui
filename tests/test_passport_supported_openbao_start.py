"""Exercise the pinned disposable OpenBao startup without publishing its root token."""

from __future__ import annotations

from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import time
import uuid

import pytest

from scripts.passport_supported_infra_images import qualified_images


ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.skipif(shutil.which("docker") is None, reason="Docker unavailable")
def test_disposable_openbao_root_token_stays_out_of_docker_logs() -> None:
    image = qualified_images(verify_registry=False)["openbao"]
    name = "passport-openbao-probe-" + uuid.uuid4().hex[:12]
    token = secrets.token_hex(32)
    with tempfile.TemporaryDirectory(prefix="passport-openbao-") as directory:
        token_file = Path(directory) / "bao_root_token"
        token_file.write_text(token, encoding="ascii")
        try:
            subprocess.run([
                "docker", "run", "--detach", "--rm", "--network", "none",
                "--name", name, "--entrypoint", "/bin/sh",
                "--mount", "type=bind,src=" + str(ROOT / "scripts/passport_supported_openbao_start.sh")
                + ",dst=/usr/local/bin/passport-supported-openbao-start,readonly",
                "--mount", "type=bind,src=" + str(token_file)
                + ",dst=/run/secrets/bao_root_token,readonly",
                image, "/usr/local/bin/passport-supported-openbao-start",
            ], check=True, capture_output=True, text=True, timeout=180)
            for _ in range(30):
                status = subprocess.run([
                    "docker", "exec", name, "bao", "status",
                    "-address=http://127.0.0.1:8200",
                ], capture_output=True, text=True, timeout=10)
                if status.returncode == 0:
                    break
                time.sleep(0.2)
            else:
                pytest.fail("Disposable OpenBao did not become ready")
            inspection = subprocess.run([
                "docker", "inspect", name, "--format", "{{json .Config.Env}}",
            ], check=True, capture_output=True, text=True, timeout=10).stdout
            logs = subprocess.run([
                "docker", "logs", name,
            ], check=True, capture_output=True, text=True, timeout=10)
            assert token not in inspection
            assert token not in logs.stdout + logs.stderr
        finally:
            subprocess.run(["docker", "stop", name], capture_output=True,
                           text=True, timeout=30, check=False)
