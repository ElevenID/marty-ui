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
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from probe_didcomm_openbao_ha import docker, request, require_status, wait_for  # noqa: E402


def start(namespace_postgres_id: str | None = None) -> None:
    image = os.environ["MARTY_CANVAS_OPENBAO_IMAGE"]
    if not image or any(character.isspace() for character in image):
        raise ValueError("Canvas OpenBao image is missing or malformed")
    name = f"canvas-kms-{uuid.uuid4().hex[:12]}"
    root_token = uuid.uuid4().hex
    if namespace_postgres_id is not None and (
        len(namespace_postgres_id) != 64
        or any(character not in "0123456789abcdef" for character in namespace_postgres_id)
    ):
        raise ValueError("Canvas OpenBao namespace requires an exact container ID")
    started = False
    try:
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
            "-v",
            f"{ROOT / 'docker/openbao-didcomm-dev.hcl'}:/openbao/config/plugin.hcl:ro",
            "-e",
            f"BAO_DEV_ROOT_TOKEN_ID={root_token}",
            image,
            "server",
            "-dev",
            "-dev-listen-address=0.0.0.0:8200",
            "-config=/openbao/config/plugin.hcl",
        )
        started = True
        if namespace_postgres_id:
            base = "http://127.0.0.1:8200"
            wait_for(
                "Canvas namespace OpenBao listener",
                lambda: subprocess.run(
                    ["docker", "exec", "--env", f"BAO_ADDR={base}", name, "bao", "status"],
                    capture_output=True,
                    check=False,
                    timeout=5,
                ).returncode == 0,
            )
        else:
            port = int(docker("port", name, "8200/tcp").splitlines()[0].rsplit(":", 1)[1])
            base = f"http://127.0.0.1:{port}"
            wait_for("Canvas OpenBao listener", lambda: request(base, "GET", "sys/health")[0] == 200)
        digest = docker("exec", name, "sha256sum", "/plugins/openbao-didcomm-authcrypt").split()[0]
        if namespace_postgres_id:
            cli = (
                "exec", "--env", f"BAO_ADDR={base}", "--env", f"BAO_TOKEN={root_token}", name, "bao"
            )
            docker(*cli, "plugin", "register", f"-sha256={digest}", "secret", "openbao-didcomm-authcrypt")
            docker(*cli, "secrets", "enable", "-path=didcomm", "openbao-didcomm-authcrypt")
            docker(*cli, "secrets", "enable", "-path=transit", "transit")
        else:
            require_status(
                base,
                "PUT",
                "sys/plugins/catalog/secret/openbao-didcomm-authcrypt",
                root_token,
                {"command": "openbao-didcomm-authcrypt", "sha256": digest},
            )
            require_status(
                base,
                "POST",
                "sys/mounts/didcomm",
                root_token,
                {"type": "openbao-didcomm-authcrypt"},
            )
            require_status(base, "POST", "sys/mounts/transit", root_token, {"type": "transit"})
        print(json.dumps({"url": base, "root_token": root_token, "container": name}))
    except BaseException:
        if started:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False, timeout=30)
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--namespace-postgres-id")
    start(parser.parse_args().namespace_postgres_id)
