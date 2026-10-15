#!/usr/bin/env python3
"""Run the native DIDComm authcrypt contract against disposable HTTPS OpenBao."""

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


ROOT = Path(__file__).resolve().parents[1]
IMAGE = os.environ.get("MARTY_OPENBAO_PROBE_IMAGE", "marty-openbao-didcomm-tls-local")


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


def probe() -> None:
    image_id = docker("image", "inspect", IMAGE, "--format", "{{.Id}}")
    if re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is None:
        raise RuntimeError("disposable plugin image is invalid")
    suffix = secrets.token_hex(6)
    name = f"marty-didcomm-tls-{suffix}"
    with tempfile.TemporaryDirectory(prefix="marty-didcomm-tls-") as temporary:
        root = Path(temporary)
        token_file = root / "root-token"
        token = secrets.token_hex(32)
        token_file.write_text(token, encoding="ascii")
        public = root / "public-ca"
        public.mkdir()
        script = ROOT / "scripts/passport_supported_openbao_start.sh"
        try:
            docker(
                "run", "-d", "--name", name, "--hostname", "openbao",
                "--label", "marty.disposable=didcomm-tls-probe",
                "-p", "127.0.0.1::8200", "--tmpfs", "/tmp/bao-tls:rw,mode=1777",
                "--mount", f"type=bind,src={script},dst=/usr/local/bin/passport-supported-openbao-start,readonly",
                "--mount", f"type=bind,src={token_file},dst=/run/secrets/bao_root_token,readonly",
                "--mount", f"type=bind,src={public},dst=/bao/public-ca",
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
            ca = public / "ca.crt"
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
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
            environment = os.environ.copy()
            environment.update({
                "MARTY_TEST_OPENBAO_URL": base,
                "MARTY_TEST_OPENBAO_TOKEN": token,
                "MARTY_TEST_OPENBAO_CA_CERT_FILE": str(ca),
            })
            result = subprocess.run([
                "cargo", "+1.95", "test", "--locked", "-p", "marty-issuance-service",
                "--test", "didcomm_remote_kms_live", "--",
                "--ignored", "--test-threads=1",
            ], cwd=ROOT / "rust", env=environment, check=False, timeout=300)
            if result.returncode:
                raise RuntimeError("native DIDComm authcrypt HTTPS contract failed")
            print(f"Native DIDComm authcrypt HTTPS contract passed: {image_id}")
        finally:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True,
                           check=False, timeout=30)


if __name__ == "__main__":
    probe()
