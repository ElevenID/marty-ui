"""Probe the pinned OpenBao in a disposable, network-isolated container.

Uses synthetic keys and plaintext only. No host ports, volumes, credentials, or
production services are used. Output is capability evidence, not DIDComm or
application migration acceptance. Requires the pinned image to exist locally.
"""

from __future__ import annotations

import base64
import json
import subprocess
import uuid


IMAGE = (
    "quay.io/openbao/openbao@sha256:"
    "6150c4a6b62067db6141c8da7a6a6b5763f4f47c315343d0c848b40fecdfd452"
)


def docker(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=60, check=False
    )


def probe() -> dict:
    name = f"kms-hardening-capability-{uuid.uuid4().hex}"
    token = "disposable-synthetic-capability-probe"
    created = False

    def bao(*args: str) -> subprocess.CompletedProcess[str]:
        return docker("exec", name, "bao", *args)

    def checked(*args: str) -> str:
        result = bao(*args)
        if result.returncode:
            # Never propagate provider output that could contain secret material.
            raise RuntimeError(f"OpenBao operation failed: {args[0]}")
        return result.stdout.strip()

    def metadata(key: str) -> dict:
        return json.loads(checked("read", "-format=json", f"transit/keys/{key}"))[
            "data"
        ]

    try:
        result = docker(
            "run",
            "-d",
            "--pull=never",
            "--name",
            name,
            "--network",
            "none",
            "--cap-add",
            "IPC_LOCK",
            "-e",
            "BAO_ADDR=http://127.0.0.1:8200",
            "-e",
            f"BAO_TOKEN={token}",
            IMAGE,
            "server",
            "-dev",
            f"-dev-root-token-id={token}",
        )
        if result.returncode:
            raise RuntimeError(
                "Could not start isolated OpenBao; ensure pinned image is local"
            )
        created = True
        # Poll the owned process, rather than assuming startup completed.
        for _ in range(30):
            if bao("status", "-format=json").returncode == 0:
                break
        else:
            raise RuntimeError("Isolated OpenBao did not become ready")
        version = checked("version")
        checked("secrets", "enable", "transit")
        derive_help = checked("path-help", "transit/derive-key/probe")

        curve_results = {}
        for curve in ("x25519", "ecdh-x25519"):
            result = bao(
                "write",
                f"transit/keys/probe-{curve}",
                f"type={curve}",
                "exportable=false",
                "allow_plaintext_backup=false",
            )
            if result.returncode == 0:
                curve_results[curve] = (
                    "key_creation_accepted_requires_protocol_qualification"
                )
            elif f"unknown key type {curve}" in result.stderr:
                curve_results[curve] = "unsupported_key_type"
            else:
                raise RuntimeError("Curve probe failed for an unclassified reason")

        key = "integration-storage-probe"
        checked(
            "write",
            f"transit/keys/{key}",
            "type=aes256-gcm96",
            "exportable=false",
            "allow_plaintext_backup=false",
        )
        initial = metadata(key)
        if initial["exportable"] or initial["allow_plaintext_backup"]:
            raise RuntimeError("Storage key unexpectedly permits key export")
        plaintext = base64.b64encode(b"synthetic integration secret").decode("ascii")
        encrypted = checked(
            "write",
            "-field=ciphertext",
            f"transit/encrypt/{key}",
            f"plaintext={plaintext}",
        )
        checked("write", "-f", f"transit/keys/{key}/rotate")
        decrypted = checked(
            "write",
            "-field=plaintext",
            f"transit/decrypt/{key}",
            f"ciphertext={encrypted}",
        )
        if decrypted != plaintext or metadata(key)["latest_version"] != 2:
            raise RuntimeError("Prior-version ciphertext did not survive rotation")

        prefix, version_marker, encoded = encrypted.split(":", 2)
        damaged = bytearray(base64.b64decode(encoded, validate=True))
        damaged[-1] ^= 1
        tampered = (
            f"{prefix}:{version_marker}:{base64.b64encode(damaged).decode('ascii')}"
        )
        rejected = bao(
            "write",
            "-field=plaintext",
            f"transit/decrypt/{key}",
            f"ciphertext={tampered}",
        )
        if (
            rejected.returncode == 0
            or "cipher: message authentication failed" not in rejected.stderr
        ):
            raise RuntimeError("Tamper rejection was not established")
        exported = bao("read", "-format=json", f"transit/export/encryption-key/{key}")
        if exported.returncode == 0 or "not exportable" not in exported.stderr:
            raise RuntimeError("Non-exportable storage boundary was not established")

        return {
            "schema": "marty.kms-hardening-capability-probe/v1",
            "image": IMAGE,
            "version": version,
            "isolation": "disposable container; no network, ports or host mounts",
            "didcomm_key_creation": curve_results,
            "derive_key_exposes_named_output": "Name of the output derived key"
            in derive_help,
            "storage": {
                "key_export_disabled": True,
                "plaintext_backup_disabled": True,
                "decrypt_prior_version_after_rotation": True,
                "tamper_rejected": True,
                "key_export_rejected": True,
            },
            "acceptance_limits": [
                "No DIDComm authcrypt or independent recipient qualification",
                "No legacy ciphertext import or application repository migration",
                "No deployed provider or tenant authorization qualification",
            ],
        }
    finally:
        if created:
            if docker("rm", "-f", name).returncode:
                raise RuntimeError(f"Could not remove owned probe container {name}")


if __name__ == "__main__":
    print(json.dumps(probe(), indent=2))
