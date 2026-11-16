"""Exercise the pinned disposable OpenBao and scoped callback bootstrap."""

from __future__ import annotations

from pathlib import Path
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import time
import uuid

import pytest

from scripts.passport_supported_infra_images import qualified_images
from scripts.passport_disposable_identity import managed_key_reference


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
    public_ca_dir = tmp_path / "public-ca"
    public_ca_dir.mkdir()
    if os.name == "posix":
        token_file.chmod(0o600)
    try:
        docker("network", "create", "--internal", network)
        docker(
            "run", "--detach", "--rm", "--network", network,
            "--network-alias", "openbao", "--hostname", "openbao", "--name", name,
            "--tmpfs", "/tmp/bao-tls:rw,mode=1777",
            "--env", "PASSPORT_BAO_TLS_MODE=required",
            "--entrypoint", "/bin/sh",
            "--mount", "type=bind,src=" + str(ROOT / "scripts/passport_supported_openbao_start.sh")
            + ",dst=/usr/local/bin/passport-supported-openbao-start,readonly",
            "--mount", "type=bind,src=" + str(token_file)
            + ",dst=/run/secrets/bao_root_token,readonly",
            "--mount", "type=bind,src=" + str(public_ca_dir)
            + ",dst=/bao/public-ca",
            image, "/usr/local/bin/passport-supported-openbao-start", timeout=180,
        )
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            ca_file = public_ca_dir / "ca.crt"
            if ca_file.is_file() and ca_file.stat().st_size:
                status = subprocess.run([
                    "docker", "run", "--rm", "--network", network,
                    "--mount", f"type=bind,src={ca_file},dst=/ca.crt,readonly",
                    "--entrypoint", "bao", image, "status",
                    "-address=https://openbao:8200", "-ca-cert=/ca.crt",
                ], capture_output=True, text=True, timeout=10)
            else:
                status = None
            if status is not None and status.returncode == 0:
                break
            time.sleep(0.25)
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
    ca_file = tmp_path / "public-ca" / "ca.crt"
    assert b"PRIVATE KEY" not in ca_file.read_bytes()
    for index in range(2):
        output_dir = tmp_path / f"output-{index}"
        output_dir.mkdir()
        # The bootstrap writes service tokens readable by nonroot bind-mount
        # consumers. Its host output directory remains private to this run.
        host_user = (["--user", f"{os.getuid()}:{os.getgid()}"]
                     if hasattr(os, "getuid") else [])
        try:
            result = docker(
                "run", "--rm", *host_user, "--network", network, "--entrypoint", "/bin/sh",
                "--env", "BAO_ADDR=https://openbao:8200",
                "--env", "BAO_CACERT=/bao/public-ca/ca.crt",
                "--env", "PASSPORT_ACCEPTANCE_CSCA_KEY_REFERENCE="
                + managed_key_reference(29876, "csca"),
                "--env", "PASSPORT_ACCEPTANCE_DSC_KEY_REFERENCE="
                + managed_key_reference(29876, "x509_doc_signer"),
                "--mount", "type=bind,src=" + str(ROOT / "scripts/passport_supported_openbao_bootstrap.sh")
                + ",dst=/scripts/passport_supported_openbao_bootstrap.sh,readonly",
                "--mount", "type=bind,src=" + str(ROOT / "docker/openbao-init.sh")
                + ",dst=/scripts/openbao-init.sh,readonly",
                "--mount", "type=bind,src=" + str(token_file)
                + ",dst=/run/secrets/bao_root_token,readonly",
                "--mount", "type=bind,src=" + str(ca_file)
                + ",dst=/bao/public-ca/ca.crt,readonly",
                "--mount", "type=bind,src=" + str(output_dir) + ",dst=/work/secrets",
                image, "/scripts/passport_supported_openbao_bootstrap.sh", timeout=180,
            )
        except subprocess.CalledProcessError as error:
            # Never surface OpenBao CLI output: it may contain issued tokens.
            match = re.search(
                r"Disposable OpenBao bootstrap failed at ([a-z-]+) \(status ([0-9]+)\)",
                error.stderr or "",
            )
            phase = match.group(1) if match else "unknown"
            pytest.fail(f"Disposable OpenBao bootstrap failed at {phase}")
        assert "scoped tokens initialized" in result.stdout
        assert {path.name for path in output_dir.iterdir()} == {
            "bao_token", "callback_signer_bao_token", "notification_openbao_token",
        }
        service = (output_dir / "bao_token").read_text(encoding="ascii")
        callback = (output_dir / "callback_signer_bao_token").read_text(encoding="ascii")
        notification = (output_dir / "notification_openbao_token").read_text(encoding="ascii")
        tokens = {service, callback, notification}
        assert len(tokens) == 3
        assert all(len(token) >= 20 for token in tokens)
        if os.name == "posix":
            assert stat.S_IMODE((output_dir / "bao_token").stat().st_mode) == 0o644
            assert stat.S_IMODE((output_dir / "callback_signer_bao_token").stat().st_mode) == 0o644
            for filename in ("bao_token", "callback_signer_bao_token", "notification_openbao_token"):
                docker(
                    "run", "--rm", "--user", "10001:10001",
                    "--entrypoint", "/bin/sh",
                    "--mount", "type=bind,src=" + str(output_dir / filename)
                    + ",dst=/tmp/" + filename + ",readonly",
                    image, "-c", "test -r /tmp/" + filename,
                )
        assert root_token not in (service, callback, notification, result.stdout, result.stderr)
        for purpose in ("csca", "x509_doc_signer"):
            expected = managed_key_reference(29876, purpose)
            source = "|".join(("00000000-0000-0000-0000-000000000001",
                               "did:web:localhost%3A29876:orgs:marty", purpose,
                               "ICAO_EMRTD", "ES256"))
            assert expected == "cred-dsc-" + uuid.uuid5(
                uuid.NAMESPACE_URL, source).hex[:20] + "-es256"
            probe = docker(
                "run", "--rm", "--network", network, "--entrypoint", "/bin/sh",
                "--env", "BAO_ADDR=https://openbao:8200",
                "--env", "BAO_CACERT=/bao/public-ca/ca.crt",
                "--mount", "type=bind,src=" + str(ca_file)
                + ",dst=/bao/public-ca/ca.crt,readonly",
                "--mount", "type=bind,src=" + str(output_dir / "bao_token")
                + ",dst=/run/secrets/bao_token,readonly",
                image, "-c", "BAO_TOKEN=$(cat /run/secrets/bao_token); "
                "export BAO_TOKEN; "
                f"bao read -field=type transit/keys/{expected}; printf '\\n'; "
                f"bao read -field=exportable transit/keys/{expected}; printf '\\n'; "
                f"bao token capabilities transit/keys/{expected}",
            )
            assert probe.stdout.splitlines() == ["ecdsa-p256", "false", "read"]
        inventory = docker(
            "run", "--rm", "--network", network, "--entrypoint", "/bin/sh",
            "--env", "BAO_ADDR=https://openbao:8200",
            "--env", "BAO_CACERT=/bao/public-ca/ca.crt",
            "--mount", "type=bind,src=" + str(ca_file)
            + ",dst=/bao/public-ca/ca.crt,readonly",
            "--mount", "type=bind,src=" + str(token_file)
            + ",dst=/run/secrets/bao_root_token,readonly",
            image, "-c", "BAO_TOKEN=$(cat /run/secrets/bao_root_token); "
            "export BAO_TOKEN; bao list -format=json transit/keys",
        )
        keys = set(json.loads(inventory.stdout))
        assert not keys.intersection({
            "cred-issuer-marty-es256", "cred-issuer-marty-es384",
            "cred-issuer-marty-rs256", "cred-issuer-marty-eddsa",
            "cred-dsc-marty-primary", "lti-tool-marty-rs256",
            "oid4vp-verifier-marty-es256",
        })
    inspection = docker("inspect", name, "--format", "{{json .Config.Env}}").stdout
    logs = docker("logs", name)
    assert root_token not in inspection + logs.stdout + logs.stderr
