"""Check key writes on disposable file storage and dev storage."""

from __future__ import annotations

import json
import subprocess
import uuid

from probe_didcomm_openbao_ha import (
    IMAGE,
    ROOT,
    docker,
    prepare_image,
    request,
    require_status,
    wait_for,
)


def run() -> None:
    prepare_image()
    name = f"kms-file-{uuid.uuid4().hex[:12]}"
    started = False
    try:
        config = {
            "disable_mlock": True,
            "plugin_directory": "/plugins",
            "storage": {"file": {"path": "/openbao/file/storage"}},
            "listener": [{"tcp": {"address": "0.0.0.0:8200", "tls_disable": True}}],
        }
        docker(
            "run",
            "--rm",
            "-d",
            "--name",
            name,
            "--label",
            "marty.disposable=kms-file-probe",
            "-p",
            "127.0.0.1::8200",
            "-e",
            f"BAO_LOCAL_CONFIG={json.dumps(config)}",
            IMAGE,
            "server",
        )
        started = True
        port = int(docker("port", name, "8200/tcp").splitlines()[0].rsplit(":", 1)[1])
        base = f"http://127.0.0.1:{port}"
        wait_for(
            "file-storage listener",
            lambda: request(base, "GET", "sys/health")[0] == 501,
        )
        initialized = require_status(
            base, "PUT", "sys/init", "", {"secret_shares": 1, "secret_threshold": 1}
        )
        require_status(base, "PUT", "sys/unseal", "", {"key": initialized["keys"][0]})
        root = initialized["root_token"]
        digest = docker(
            "exec", name, "sha256sum", "/plugins/openbao-didcomm-authcrypt"
        ).split()[0]
        require_status(
            base,
            "PUT",
            "sys/plugins/catalog/secret/openbao-didcomm-authcrypt",
            root,
            {"command": "openbao-didcomm-authcrypt", "sha256": digest},
        )
        require_status(
            base,
            "POST",
            "sys/mounts/didcomm",
            root,
            {"type": "openbao-didcomm-authcrypt"},
        )
        for path, body in [
            (
                "didcomm/keys/tenant_a/sender",
                {
                    "sender_did": "did:example:alice",
                    "sender_key_id": "did:example:alice#agreement-1",
                },
            ),
            ("didcomm/haip/keys/tenant_a/flow_a", {}),
        ]:
            status, _ = request(base, "POST", path, body, root)
            if status == 200:
                raise RuntimeError(f"File-backed plugin accepted key creation: {path}")
            status, _ = request(base, "GET", path, token=root)
            if status == 200:
                raise RuntimeError(f"Failed file-backed create left a key: {path}")
        print("Disposable file-backed OpenBao rejected both key lifecycle writes")
    finally:
        if started:
            subprocess.run(
                ["docker", "rm", "-f", name],
                capture_output=True,
                timeout=30,
                check=False,
            )
    run_dev()


def run_dev() -> None:
    name = f"kms-dev-{uuid.uuid4().hex[:12]}"
    started = False
    try:
        docker(
            "run",
            "--rm",
            "-d",
            "--name",
            name,
            "--label",
            "marty.disposable=kms-dev-probe",
            "-p",
            "127.0.0.1::8200",
            "-v",
            f"{ROOT / 'docker/openbao-didcomm-dev.hcl'}:/openbao/config/plugin.hcl:ro",
            "-e",
            f"BAO_DEV_ROOT_TOKEN_ID={uuid.uuid4().hex}",
            IMAGE,
            "server",
            "-dev",
            "-dev-listen-address=0.0.0.0:8200",
            "-config=/openbao/config/plugin.hcl",
        )
        started = True
        port = int(docker("port", name, "8200/tcp").splitlines()[0].rsplit(":", 1)[1])
        base = f"http://127.0.0.1:{port}"
        wait_for("dev listener", lambda: request(base, "GET", "sys/health")[0] == 200)
        root = docker("exec", name, "printenv", "BAO_DEV_ROOT_TOKEN_ID")
        digest = docker(
            "exec", name, "sha256sum", "/plugins/openbao-didcomm-authcrypt"
        ).split()[0]
        require_status(
            base,
            "PUT",
            "sys/plugins/catalog/secret/openbao-didcomm-authcrypt",
            root,
            {"command": "openbao-didcomm-authcrypt", "sha256": digest},
        )
        require_status(
            base,
            "POST",
            "sys/mounts/didcomm",
            root,
            {"type": "openbao-didcomm-authcrypt"},
        )
        for path, body in [
            (
                "didcomm/keys/tenant_a/sender",
                {
                    "sender_did": "did:example:alice",
                    "sender_key_id": "did:example:alice#agreement-1",
                },
            ),
            ("didcomm/haip/keys/tenant_a/flow_a", {}),
        ]:
            require_status(base, "POST", path, root, body)
        print("Disposable dev OpenBao accepted both key lifecycle writes")
    finally:
        if started:
            subprocess.run(
                ["docker", "rm", "-f", name],
                capture_output=True,
                timeout=30,
                check=False,
            )


if __name__ == "__main__":
    run()
