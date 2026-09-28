"""Exercise the pinned disposable OpenBao and scoped callback bootstrap."""

from __future__ import annotations

from pathlib import Path
import os
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
    if os.name == "posix":
        token_file.chmod(0o600)
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
        # The bootstrap writes mode 0600 secrets. Match the bind-mount owner's
        # UID on Linux so the test runner can verify them without relaxing it.
        host_user = (["--user", f"{os.getuid()}:{os.getgid()}"]
                     if hasattr(os, "getuid") else [])
        result = docker(
            "run", "--rm", *host_user, "--network", network, "--entrypoint", "/bin/sh",
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
        for purpose, expected in (
            ("csca", "cred-dsc-5fc5bffec62456e58552-es256"),
            ("x509_doc_signer", "cred-dsc-86997e8fa454582d8bb5-es256"),
        ):
            source = "|".join(("00000000-0000-0000-0000-000000000001",
                               "did:web:localhost:orgs:marty", purpose,
                               "ICAO_EMRTD", "ES256"))
            assert expected == "cred-dsc-" + uuid.uuid5(
                uuid.NAMESPACE_URL, source).hex[:20] + "-es256"
            probe = docker(
                "run", "--rm", "--network", network, "--entrypoint", "/bin/sh",
                "--env", "BAO_ADDR=http://openbao:8200",
                "--mount", "type=bind,src=" + str(output_dir / "bao_token")
                + ",dst=/run/secrets/bao_token,readonly",
                image, "-c", "BAO_TOKEN=$(cat /run/secrets/bao_token); "
                "export BAO_TOKEN; "
                f"bao read -field=type transit/keys/{expected}; printf '\\n'; "
                f"bao read -field=exportable transit/keys/{expected}; printf '\\n'; "
                f"bao token capabilities transit/keys/{expected}",
            )
            assert probe.stdout.splitlines() == ["ecdsa-p256", "false", "read"]
    inspection = docker("inspect", name, "--format", "{{json .Config.Env}}").stdout
    logs = docker("logs", name)
    assert root_token not in inspection + logs.stdout + logs.stderr
