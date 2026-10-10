"""Qualify clean self-host OpenBao Raft bootstrap with disposable Docker volumes."""

from __future__ import annotations

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
    suffix = uuid.uuid4().hex[:12]
    server = f"kms-selfhost-{suffix}"
    state = f"kms-selfhost-state-{suffix}"
    runtime = f"kms-selfhost-runtime-{suffix}"
    volumes: list[str] = []
    started = False
    try:
        for volume in (state, runtime):
            docker(
                "volume",
                "create",
                "--label",
                "marty.disposable=kms-selfhost-probe",
                volume,
            )
            volumes.append(volume)
        docker(
            "run",
            "--rm",
            "-v",
            f"{state}:/bao/data",
            "--entrypoint",
            "/bin/chown",
            IMAGE,
            "-R",
            "openbao:openbao",
            "/bao/data",
        )
        config = ROOT / "docker/openbao-selfhost.hcl"
        docker(
            "run",
            "-d",
            "--name",
            server,
            "--label",
            "marty.disposable=kms-selfhost-probe",
            "-p",
            "127.0.0.1::8200",
            "-v",
            f"{state}:/bao/data",
            "-v",
            f"{config}:/bao/config/openbao.hcl:ro",
            IMAGE,
            "server",
            "-config=/bao/config/openbao.hcl",
        )
        started = True
        try:
            port = int(
                docker("port", server, "8200/tcp").splitlines()[0].rsplit(":", 1)[1]
            )
        except (RuntimeError, IndexError, ValueError) as error:
            logs = subprocess.run(
                ["docker", "logs", "--tail", "20", server],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            raise RuntimeError(
                f"Disposable Raft server exited: {(logs.stdout + logs.stderr)[-2500:]}"
            ) from error
        base = f"http://127.0.0.1:{port}"
        try:
            wait_for(
                "self-host Raft listener",
                lambda: request(base, "GET", "sys/health")[0] == 501,
            )
        except RuntimeError as error:
            logs = subprocess.run(
                ["docker", "logs", "--tail", "20", server],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            raise RuntimeError(
                f"Disposable Raft server did not start: {(logs.stdout + logs.stderr)[-2500:]}"
            ) from error
        result = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--network",
                f"container:{server}",
                "-e",
                "BAO_ADDR=http://127.0.0.1:8200",
                "-e",
                "DIDCOMM_KMS_PLUGIN_REQUIRED=true",
                "-v",
                f"{state}:/bao/data",
                "-v",
                f"{runtime}:/bao/runtime",
                "-v",
                f"{ROOT / 'docker/openbao-init.sh'}:/scripts/openbao-init.sh:ro",
                "-v",
                f"{ROOT / 'docker/openbao-selfhost-init.sh'}:/scripts/openbao-selfhost-init.sh:ro",
                "-v",
                f"{ROOT / 'docker/openbao-haip-workload-policy.hcl'}:/scripts/openbao-haip-workload-policy.hcl:ro",
                "--entrypoint",
                "/bin/sh",
                IMAGE,
                "/scripts/openbao-selfhost-init.sh",
            ],
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
        if result.returncode:
            raise RuntimeError("Disposable self-host Raft bootstrap failed")
        root = docker(
            "run",
            "--rm",
            "-v",
            f"{state}:/bao/data",
            "--entrypoint",
            "/bin/cat",
            IMAGE,
            "/bao/data/root.token",
        )
        if len(root) < 16:
            raise RuntimeError("Disposable bootstrap did not retain its root token")
        leader = require_status(base, "GET", "sys/leader", root)
        if leader.get("is_self") is not True:
            raise RuntimeError("Disposable self-host Raft node is not active")
        did = "did:example:selfhost-probe"
        require_status(
            base,
            "POST",
            "didcomm/keys/tenant_a/sender",
            root,
            {"sender_did": did, "sender_key_id": did + "#agreement-1"},
        )
        require_status(base, "POST", "didcomm/haip/keys/tenant_a/flow_a", root, {})
        key_name = "integration-secret-envelope-marty-aes256"
        metadata = require_status(base, "GET", f"transit/keys/{key_name}", root)["data"]
        if (
            metadata.get("type") != "aes256-gcm96"
            or metadata.get("exportable") is not False
            or metadata.get("allow_plaintext_backup") is not False
        ):
            raise RuntimeError("Disposable integration-secret key has unsafe metadata")
        token = docker(
            "run",
            "--rm",
            "-v",
            f"{runtime}:/bao/runtime",
            "--entrypoint",
            "/bin/cat",
            IMAGE,
            "/bao/runtime/signing_keys_openbao_token",
        )
        encrypted = require_status(
            base,
            "POST",
            f"transit/encrypt/{key_name}",
            token,
            {"plaintext": "cHJvYmU="},
        )["data"]["ciphertext"]
        decrypted = require_status(
            base,
            "POST",
            f"transit/decrypt/{key_name}",
            token,
            {"ciphertext": encrypted},
        )["data"]["plaintext"]
        if decrypted != "cHJvYmU=":
            raise RuntimeError(
                "Scoped token could not decrypt integration-secret proof"
            )
        if (
            request(
                base, "GET", f"transit/export/encryption-key/{key_name}", token=token
            )[0]
            != 403
        ):
            raise RuntimeError(
                "Scoped token unexpectedly exported integration-secret key"
            )
        print("Clean self-host Raft bootstrap, plugin and secret custody passed")
    finally:
        if started:
            subprocess.run(
                ["docker", "rm", "-f", server],
                capture_output=True,
                timeout=30,
                check=False,
            )
        for volume in reversed(volumes):
            subprocess.run(
                ["docker", "volume", "rm", volume],
                capture_output=True,
                timeout=30,
                check=False,
            )


if __name__ == "__main__":
    run()
