#!/usr/bin/env python3
"""Run native DIDComm authcrypt with disposable HTTPS OpenBao and guarded Redis."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import secrets
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

from probe_didcomm_openbao_ha import docker_host_path


ROOT = Path(__file__).resolve().parents[1]
IMAGE = os.environ.get("MARTY_OPENBAO_PROBE_IMAGE", "marty-openbao-didcomm-tls-local")
REDIS_IMAGE = json.loads(
    (ROOT / "deploy-config/passport-supported-disposable-infra-images.json").read_text(
        encoding="utf-8"
    )
)["images"]["redis"]["reference"]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def docker(*args: str, timeout: int = 60) -> str:
    result = subprocess.run(["docker", *args], capture_output=True, text=True,
                            check=False, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"disposable Docker {args[0]} failed")
    return result.stdout.strip()


def request(base: str, context: ssl.SSLContext, token: str, method: str,
            path: str, body: dict | None = None) -> tuple[int, dict]:
    payload = None if body is None else json.dumps(body).encode("utf-8")
    headers = {"X-Vault-Token": token, "Content-Type": "application/json"}
    req = urllib.request.Request(f"{base}/v1/{path}", data=payload,
                                 headers=headers, method=method)
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context),
        NoRedirect(),
    )
    try:
        with opener.open(req, timeout=10) as response:
            raw = response.read(1024 * 1024 + 1)
            if len(raw) > 1024 * 1024:
                raise RuntimeError("OpenBao response is oversized")
            return response.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as error:
        error.read(1024 * 1024 + 1)
        return error.code, {}


def prepare_redis(container_id: str) -> tuple[str, str]:
    """Initialize the same guarded DB13 contract used by Signing Keys fixtures."""
    binding = docker("port", container_id, "6379/tcp")
    match = re.fullmatch(r"127\.0\.0\.1:([0-9]{2,5})", binding)
    if match is None or not 1024 <= int(match[1]) <= 65535:
        raise RuntimeError("disposable DIDComm Redis port is invalid")
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        try:
            if docker("exec", container_id, "redis-cli", "ping", timeout=2) == "PONG":
                break
        except (RuntimeError, subprocess.TimeoutExpired):
            pass
        time.sleep(0.25)
    else:
        raise RuntimeError("disposable DIDComm Redis did not become ready")
    nonce = secrets.token_hex(32)
    result = docker("exec", container_id, "redis-cli", "-n", "13", "SET",
                    "marty:tests:disposable-guard", nonce, timeout=5)
    if result != "OK":
        raise RuntimeError("disposable DIDComm Redis guard could not be initialized")
    return f"redis://127.0.0.1:{match[1]}/13", nonce


def probe() -> None:
    image_id = docker("image", "inspect", IMAGE, "--format", "{{.Id}}")
    if re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is None:
        raise RuntimeError("disposable plugin image is invalid")
    suffix = secrets.token_hex(6)
    name = f"marty-didcomm-tls-{suffix}"
    token_volume = f"marty-didcomm-tls-token-{suffix}"
    ca_volume = f"marty-didcomm-tls-ca-{suffix}"
    redis_name = f"marty-didcomm-tls-redis-{suffix}"
    redis_id = None
    with tempfile.TemporaryDirectory(prefix="marty-didcomm-tls-") as temporary:
        root = Path(temporary)
        token = secrets.token_hex(32)
        script = ROOT / "scripts/passport_supported_openbao_start.sh"
        try:
            for volume in (token_volume, ca_volume):
                docker("volume", "create", "--label", "marty.disposable=didcomm-tls-probe", volume)
            seeded = subprocess.run([
                "docker", "run", "--rm", "-i", "-v", f"{token_volume}:/run/secrets",
                "--entrypoint", "/bin/sh", IMAGE, "-c",
                "umask 077; cat > /run/secrets/bao_root_token",
            ], input=token, capture_output=True, text=True, check=False, timeout=60)
            if seeded.returncode:
                raise RuntimeError("disposable OpenBao token volume could not be seeded")
            docker(
                "run", "-d", "--name", name, "--hostname", "openbao",
                "--label", "marty.disposable=didcomm-tls-probe",
                "-p", "127.0.0.1::8200", "--tmpfs", "/tmp/bao-tls:rw,mode=1777",
                "--mount", f"type=bind,src={docker_host_path(script)},dst=/usr/local/bin/passport-supported-openbao-start,readonly",
                "-v", f"{token_volume}:/run/secrets:ro",
                "-v", f"{ca_volume}:/bao/public-ca",
                "-e", "PASSPORT_BAO_TLS_MODE=required",
                "-e", 'BAO_LOCAL_CONFIG={"plugin_directory":"/plugins"}',
                "--entrypoint", "/bin/sh", IMAGE,
                "/usr/local/bin/passport-supported-openbao-start",
            )
            port_output = docker("port", name, "8200/tcp")
            port = port_output.splitlines()[0].rsplit(":", 1)[-1]
            if re.fullmatch(r"[0-9]{2,5}", port) is None:
                raise RuntimeError("disposable OpenBao port is invalid")
            base = f"https://localhost:{port}"
            ca = root / "ca.crt"
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                try:
                    public_ca = docker("run", "--rm", "-v", f"{ca_volume}:/pub:ro",
                                       "--entrypoint", "/bin/cat", IMAGE, "/pub/ca.crt")
                    ca.write_text(public_ca + "\n", encoding="ascii")
                except RuntimeError:
                    pass
                if ca.is_file() and ca.stat().st_size:
                    context = ssl.create_default_context(cafile=ca)
                    try:
                        status, _ = request(base, context, token, "GET", "sys/health")
                        if status == 200:
                            break
                    except (OSError, ssl.SSLError, ValueError):
                        pass
                time.sleep(0.25)
            else:
                raise RuntimeError("disposable HTTPS OpenBao did not become ready")
            if b"PRIVATE KEY" in ca.read_bytes():
                raise RuntimeError("OpenBao public CA contains private material")
            digest = docker("exec", name, "sha256sum",
                            "/plugins/openbao-didcomm-authcrypt").split()[0]
            if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
                raise RuntimeError("disposable plugin digest is invalid")
            status, _ = request(
                base, context, token, "PUT",
                "sys/plugins/catalog/secret/openbao-didcomm-authcrypt",
                {"command": "openbao-didcomm-authcrypt", "sha256": digest},
            )
            if status not in (200, 204):
                raise RuntimeError("disposable DIDComm plugin registration failed")
            status, _ = request(base, context, token, "POST", "sys/mounts/didcomm",
                                {"type": "openbao-didcomm-authcrypt"})
            if status not in (200, 204):
                raise RuntimeError("disposable DIDComm plugin mount failed")
            redis_id = docker(
                "run", "-d", "--name", redis_name,
                "--label", "marty.disposable=didcomm-tls-probe",
                "--memory", "128m", "--memory-swap", "128m",
                "--tmpfs", "/data:rw,mode=700", "-p", "127.0.0.1::6379",
                REDIS_IMAGE, "redis-server", "--save", "", "--appendonly", "no",
            )
            if re.fullmatch(r"[0-9a-f]{64}", redis_id) is None:
                raise RuntimeError("disposable DIDComm Redis identity is invalid")
            redis_url, redis_nonce = prepare_redis(redis_id)
            environment = os.environ.copy()
            environment.update({
                "MARTY_TEST_OPENBAO_URL": base,
                "MARTY_TEST_OPENBAO_TOKEN": token,
                "MARTY_TEST_OPENBAO_CA_CERT_FILE": str(ca),
                "MARTY_TEST_REDIS_URL": redis_url,
                "MARTY_TEST_REDIS_DISPOSABLE_NONCE": redis_nonce,
            })
            result = subprocess.run([
                "cargo", "+1.95.0", "test", "--locked", "-p", "marty-issuance-service",
                "--test", "didcomm_remote_kms_live", "--",
                "--ignored", "--test-threads=1",
            ], cwd=ROOT / "rust", env=environment, check=False, timeout=300)
            if result.returncode:
                raise RuntimeError("native DIDComm authcrypt HTTPS contract failed")
            print(f"Native DIDComm authcrypt HTTPS contract passed: {image_id}")
        finally:
            try:
                # Remove only the immutable ID returned for this owned fixture.
                if redis_id is not None and re.fullmatch(r"[0-9a-f]{64}", redis_id):
                    docker("rm", "-f", redis_id, timeout=30)
            finally:
                subprocess.run(["docker", "rm", "-f", name], capture_output=True,
                               check=False, timeout=30)
                for volume in (ca_volume, token_volume):
                    subprocess.run(["docker", "volume", "rm", "-f", volume],
                                   capture_output=True, check=False, timeout=30)


if __name__ == "__main__":
    probe()
