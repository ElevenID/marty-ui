"""Start an owned, disposable OpenBao plugin backend for Canvas process tests.

The root token stays in the runner process. Issuance receives only a per-key
read/pack token file; the synthetic signing peer uses a separate Transit
sign-only token created by the Rust acceptance fixture.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from probe_didcomm_openbao_ha import docker, wait_for  # noqa: E402

DEV_CA = "/tmp/bao-tls/vault-ca.pem"


def start(ca_output: Path, namespace_postgres_id: str | None = None) -> None:
    image = os.environ["MARTY_CANVAS_OPENBAO_IMAGE"]
    if not image or any(character.isspace() for character in image):
        raise ValueError("Canvas OpenBao image is missing or malformed")
    name = f"canvas-kms-{uuid.uuid4().hex[:12]}"
    root_token = secrets.token_hex(32)
    if namespace_postgres_id is not None and (
        len(namespace_postgres_id) != 64
        or any(character not in "0123456789abcdef" for character in namespace_postgres_id)
    ):
        raise ValueError("Canvas OpenBao namespace requires an exact container ID")
    if (not ca_output.is_absolute() or not ca_output.parent.is_dir()
            or ca_output.is_symlink() or ca_output.resolve().is_relative_to(ROOT)):
        raise ValueError("Canvas public CA output must be outside the checkout")
    started = False
    last_status_error = "not checked"
    token_fd, token_name = tempfile.mkstemp(prefix="canvas-kms-root-")
    os.close(token_fd)
    token_file = Path(token_name)
    try:
        token_file.write_text(root_token, encoding="ascii")
        if ca_output.name != "ca.crt" or ca_output.exists():
            raise ValueError("Canvas public CA output must be a new ca.crt file")
        network_args = (
            ["--network", f"container:{namespace_postgres_id}"]
            if namespace_postgres_id
            else ["-p", "127.0.0.1::8200"]
        )
        docker(
            "run",
            "--rm",
            "-d",
            "--name",
            name,
            "--label",
            "marty.disposable=canvas-renewal-kms",
            *network_args,
            "--tmpfs",
            "/tmp/bao-tls:rw,mode=1777",
            "--mount",
            f"type=bind,src={ROOT / 'scripts/passport_supported_openbao_start.sh'},dst=/usr/local/bin/passport-supported-openbao-start,readonly",
            "--mount",
            f"type=bind,src={token_file},dst=/run/secrets/bao_root_token,readonly",
            "--mount",
            f"type=bind,src={ca_output.parent},dst=/bao/public-ca",
            "-e",
            "PASSPORT_BAO_TLS_MODE=required",
            "-e",
            'BAO_LOCAL_CONFIG={"plugin_directory":"/plugins"}',
            "--entrypoint",
            "/bin/sh",
            image,
            "/usr/local/bin/passport-supported-openbao-start",
        )
        started = True
        def listener_ready() -> bool:
            nonlocal last_status_error
            if not ca_output.is_file() or ca_output.stat().st_size == 0:
                last_status_error = "public CA not ready"
                return False
            result = subprocess.run(
                ["docker", "exec", "--env", "BAO_ADDR=https://127.0.0.1:8200",
                 "--env", f"BAO_CACERT={DEV_CA}", name, "bao", "status"],
                capture_output=True, check=False, timeout=5,
                text=True,
            )
            last_status_error = (
                result.stderr.strip()[-300:] or f"bao status exit {result.returncode}"
            ).replace(root_token, "[redacted]")
            return result.returncode == 0

        wait_for("Canvas HTTPS OpenBao listener", listener_ready)
        if namespace_postgres_id:
            base = "https://127.0.0.1:8200"
        else:
            port = int(docker("port", name, "8200/tcp").splitlines()[0].rsplit(":", 1)[1])
            base = f"https://127.0.0.1:{port}"
        public_ca = ca_output.read_text(encoding="ascii")
        if "BEGIN CERTIFICATE" not in public_ca or "PRIVATE KEY" in public_ca:
            raise ValueError("Canvas OpenBao published CA is invalid")
        digest = docker("exec", name, "sha256sum", "/plugins/openbao-didcomm-authcrypt").split()[0]
        cli = (
            "exec", "--env", "BAO_ADDR=https://127.0.0.1:8200",
            "--env", f"BAO_CACERT={DEV_CA}", "--env", f"BAO_TOKEN={root_token}", name, "bao"
        )
        docker(*cli, "plugin", "register", f"-sha256={digest}", "secret", "openbao-didcomm-authcrypt")
        docker(*cli, "secrets", "enable", "-path=didcomm", "openbao-didcomm-authcrypt")
        docker(*cli, "secrets", "enable", "-path=transit", "transit")
        print(json.dumps({"url": base, "root_token": root_token, "container": name,
                          "ca_cert_file": str(ca_output)}))
    except BaseException as error:
        # The caller captures stderr. Report only bounded, token-redacted
        # diagnostics; the dev server's full logs print its root token.
        state = "not started"
        if started:
            inspect = subprocess.run(
                ["docker", "inspect", "--format",
                 "{{.State.Status}} exit={{.State.ExitCode}} error={{.State.Error}}", name],
                capture_output=True, text=True, check=False, timeout=10,
            )
            state = inspect.stdout.strip()[:300] or f"inspect exit {inspect.returncode}"
        print(
            "Canvas OpenBao startup: "
            f"{type(error).__name__}: {str(error).replace(root_token, '[redacted]')[:300]}; "
            f"container={state.replace(root_token, '[redacted]')}; "
            f"last_status={last_status_error}",
            file=sys.stderr,
        )
        if started:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False, timeout=30)
        ca_output.unlink(missing_ok=True)
        raise
    finally:
        token_file.unlink(missing_ok=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--namespace-postgres-id")
    parser.add_argument("--ca-output", type=Path, required=True)
    args = parser.parse_args()
    start(args.ca_output, args.namespace_postgres_id)
