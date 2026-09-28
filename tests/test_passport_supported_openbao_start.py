"""Exercise the pinned disposable OpenBao and scoped callback bootstrap."""

from __future__ import annotations

from pathlib import Path
import secrets
import shutil
import subprocess
import time
import uuid

import pytest

from scripts.passport_supported_infra_images import qualified_images


ROOT = Path(__file__).resolve().parents[1]


def docker(*args: str, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["docker", *args], check=True, capture_output=True,
                          text=True, timeout=timeout)


@pytest.fixture
def disposable_openbao(tmp_path: Path) -> tuple[str, str, Path, str, str]:
    if shutil.which("docker") is None:
        pytest.skip("Docker unavailable")
    image = qualified_images(verify_registry=False)["openbao"]
    suffix = uuid.uuid4().hex[:12]
    name = "passport-openbao-probe-" + suffix
    network = "passport-openbao-probe-" + suffix
    token = secrets.token_hex(32)
    token_file = tmp_path / "bao_root_token"
    token_file.write_text(token, encoding="ascii")
    try:
        docker("network", "create", "--internal", network)
        docker(
            "run", "--detach", "--rm", "--network", network,
            "--network-alias", "openbao", "--name", name,
            "--entrypoint", "/bin/sh",
            "--mount", "type=bind,src=" + str(ROOT / "scripts/passport_supported_openbao_start.sh")
            + ",dst=/usr/local/bin/passport-supported-openbao-start,readonly",
            "--mount", "type=bind,src=" + str(token_file)
            + ",dst=/run/secrets/bao_root_token,readonly",
            image, "/usr/local/bin/passport-supported-openbao-start", timeout=180,
        )
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
        yield name, network, token_file, token, image
    finally:
        subprocess.run(["docker", "stop", name], capture_output=True,
                       text=True, timeout=30, check=False)
        subprocess.run(["docker", "network", "rm", network], capture_output=True,
                       text=True, timeout=30, check=False)


def test_disposable_openbao_root_token_stays_out_of_docker_logs(
    disposable_openbao: tuple[str, str, Path, str, str],
) -> None:
    name, _, _, token, _ = disposable_openbao
    inspection = docker("inspect", name, "--format", "{{json .Config.Env}}").stdout
    logs = docker("logs", name)
    assert token not in inspection
    assert token not in logs.stdout + logs.stderr


def test_disposable_openbao_bootstrap_mints_scoped_tokens(
    disposable_openbao: tuple[str, str, Path, str, str], tmp_path: Path,
) -> None:
    name, network, token_file, root_token, image = disposable_openbao
    for index in range(2):
        output_dir = tmp_path / f"output-{index}"
        output_dir.mkdir()
        result = docker(
            "run", "--rm", "--network", network, "--entrypoint", "/bin/sh",
            "--env", "BAO_ADDR=http://openbao:8200",
            "--mount", "type=bind,src=" + str(ROOT / "scripts/passport_supported_openbao_bootstrap.sh")
            + ",dst=/scripts/passport_supported_openbao_bootstrap.sh,readonly",
            "--mount", "type=bind,src=" + str(ROOT / "docker/openbao-init.sh")
            + ",dst=/scripts/openbao-init.sh,readonly",
            "--mount", "type=bind,src=" + str(token_file)
            + ",dst=/run/secrets/bao_root_token,readonly",
            "--mount", "type=bind,src=" + str(output_dir) + ",dst=/work/secrets",
            image, "/scripts/passport_supported_openbao_bootstrap.sh", timeout=180,
        )
        assert "scoped tokens initialized" in result.stdout
        service = (output_dir / "bao_token").read_text(encoding="ascii")
        callback = (output_dir / "callback_signer_bao_token").read_text(encoding="ascii")
        assert service and callback and service != callback
        assert root_token not in (service, callback, result.stdout, result.stderr)
    inspection = docker("inspect", name, "--format", "{{json .Config.Env}}").stdout
    logs = docker("logs", name)
    assert root_token not in inspection + logs.stdout + logs.stderr
