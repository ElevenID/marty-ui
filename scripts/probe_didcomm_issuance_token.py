"""Prove the native DIDComm token minted by the packaged OpenBao init script.

All resources are disposable. Only public key metadata and a complete
authcrypt envelope may cross the scoped workload boundary.
"""

from __future__ import annotations

import base64
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
    suffix = uuid.uuid4().hex[:12]
    name = f"kms-issuance-token-{suffix}"
    volume = f"kms-issuance-token-{suffix}"
    root = uuid.uuid4().hex
    volume_created = False
    started = False
    try:
        docker(
            "volume", "create", "--label", "marty.disposable=kms-token-probe", volume
        )
        volume_created = True
        docker(
            "run",
            "--rm",
            "-d",
            "--name",
            name,
            "--label",
            "marty.disposable=kms-token-probe",
            "-p",
            "127.0.0.1::8200",
            "-v",
            f"{ROOT / 'docker/openbao-didcomm-dev.hcl'}:/bao/config/didcomm-plugin.hcl:ro",
            "-e",
            f"BAO_DEV_ROOT_TOKEN_ID={root}",
            IMAGE,
            "server",
            "-dev",
            "-dev-listen-address=0.0.0.0:8200",
            "-config",
            "/bao/config/didcomm-plugin.hcl",
        )
        started = True
        port = int(docker("port", name, "8200/tcp").splitlines()[0].rsplit(":", 1)[1])
        base = f"http://127.0.0.1:{port}"
        wait_for(
            "DIDComm token listener",
            lambda: request(base, "GET", "sys/health")[0] == 200,
        )
        docker(
            "run",
            "--rm",
            "--network",
            f"container:{name}",
            "--entrypoint",
            "/bin/sh",
            "-e",
            "BAO_ADDR=http://127.0.0.1:8200",
            "-e",
            f"BAO_TOKEN={root}",
            "-e",
            "DIDCOMM_KMS_PLUGIN_REQUIRED=true",
            "-e",
            "DIDCOMM_ISSUANCE_TOKEN_FILE=/run/didcomm-token/openbao-token",
            "-v",
            f"{ROOT / 'docker/openbao-init.sh'}:/scripts/openbao-init.sh:ro",
            "-v",
            f"{volume}:/run/didcomm-token",
            IMAGE,
            "/scripts/openbao-init.sh",
            timeout=180,
        )
        scoped = docker(
            "run",
            "--rm",
            "--entrypoint",
            "/bin/sh",
            "-v",
            f"{volume}:/run/didcomm-token:ro",
            IMAGE,
            "-ec",
            'test "$(stat -c %a /run/didcomm-token/openbao-token)" = 444; '
            "cat /run/didcomm-token/openbao-token",
        )
        lookup = require_status(
            base, "POST", "auth/token/lookup", root, {"token": scoped}
        )["data"]
        if (
            lookup["policies"] != ["didcomm-issuance"]
            or lookup.get("orphan") is not True
            or not isinstance(lookup.get("ttl"), int)
            or lookup["ttl"] <= 0
            or lookup.get("renewable") is not True
        ):
            raise RuntimeError("DIDComm workload token has unexpected authority")
        print(
            "Disposable DIDComm token lifetime:",
            lookup.get("ttl"),
            "seconds; renewable:",
            lookup.get("renewable"),
        )

        sender_did = "did:example:scoped-sender"
        recipient_did = "did:example:scoped-recipient"
        sender = require_status(
            base,
            "POST",
            "didcomm/keys/tenant_a/sender",
            root,
            {"sender_did": sender_did, "sender_key_id": sender_did + "#agreement-1"},
        )["data"]
        recipient = require_status(
            base,
            "POST",
            "didcomm/keys/tenant_a/recipient",
            root,
            {
                "sender_did": recipient_did,
                "sender_key_id": recipient_did + "#agreement-1",
            },
        )["data"]
        version = sender["version"]
        key_path = f"didcomm/keys/tenant_a/sender/versions/{version}"
        public = require_status(base, "GET", key_path, scoped)["data"]
        if public["version"] != version or "private_key" in public:
            raise RuntimeError("Scoped DIDComm metadata is not public and versioned")
        plaintext = json.dumps(
            {"id": suffix, "type": "example", "from": sender_did, "to": [recipient_did]}
        ).encode()
        envelope = require_status(
            base,
            "POST",
            f"didcomm/pack/tenant_a/sender/{version}",
            scoped,
            {
                "recipient_did": recipient_did,
                "recipients": json.dumps(
                    [
                        {
                            "kid": recipient["sender_key_id"],
                            "public_key": recipient["public_key"],
                        }
                    ]
                ),
                "plaintext_base64": base64.b64encode(plaintext).decode(),
            },
        )["data"]
        if not envelope.get("jwe") or envelope.get("version") != version:
            raise RuntimeError(
                "Scoped DIDComm pack did not return a versioned envelope"
            )
        for method, path, body in [
            (
                "POST",
                "didcomm/keys/tenant_a/forbidden",
                {"sender_did": sender_did, "sender_key_id": sender_did + "#new"},
            ),
            ("GET", "didcomm/keys/tenant_a/sender", None),
            ("POST", "didcomm/keys/tenant_a/sender/rotate", {}),
            ("GET", "transit/keys/cred-issuer-marty-es256", None),
            ("POST", "auth/token/create", {"policies": ["root"]}),
            ("GET", "sys/mounts", None),
        ]:
            status, _ = request(base, method, path, body, scoped)
            if status != 403:
                raise RuntimeError(
                    f"Scoped DIDComm token unexpectedly reached {path}: {status}"
                )
        print(
            "Disposable DIDComm issuance token: public read and pack allowed; administration denied"
        )
    finally:
        if started:
            subprocess.run(
                ["docker", "rm", "-f", name],
                capture_output=True,
                timeout=30,
                check=False,
            )
        if volume_created:
            subprocess.run(
                ["docker", "volume", "rm", volume],
                capture_output=True,
                timeout=30,
                check=False,
            )


if __name__ == "__main__":
    run()
