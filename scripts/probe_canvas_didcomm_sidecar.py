"""Prove the Canvas plugin fixture starts inside a borrowed network namespace."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

from probe_didcomm_openbao_ha import IMAGE, docker, prepare_image, require_status

ROOT = Path(__file__).resolve().parents[1]


def run() -> None:
    prepare_image()
    anchor = f"canvas-kms-anchor-{uuid.uuid4().hex[:12]}"
    sidecar: str | None = None
    anchor_started = False
    try:
        docker(
            "run", "--rm", "-d", "--name", anchor,
            "--label", "marty.disposable=canvas-kms-anchor-probe",
            "--entrypoint", "/bin/sh", IMAGE, "-c", "sleep 180",
        )
        anchor_started = True
        anchor_id = docker("inspect", "--format", "{{.Id}}", anchor)
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts/ci/start-canvas-didcomm-openbao.py"),
                "--namespace-postgres-id",
                anchor_id,
            ],
            env={**os.environ, "MARTY_CANVAS_OPENBAO_IMAGE": IMAGE},
            capture_output=True,
            text=True,
            check=False,
            timeout=150,
        )
        if result.returncode:
            raise RuntimeError("Disposable Canvas namespace plugin startup failed")
        response = json.loads(result.stdout)
        sidecar = response["container"]
        if response["url"] != "http://127.0.0.1:8200":
            raise RuntimeError("Canvas sidecar did not bind the borrowed loopback")
        cli = (
            "exec", "--env", f"BAO_ADDR={response['url']}",
            "--env", f"BAO_TOKEN={response['root_token']}", sidecar, "bao",
        )
        mounts = json.loads(docker(*cli, "secrets", "list", "-format=json"))
        if "didcomm/" not in mounts:
            raise RuntimeError("Canvas namespace plugin mount is absent")
        docker(
            *cli, "write", "didcomm/keys/synthetic-org/issuer",
            "sender_did=did:web:issuer.example",
            "sender_key_id=did:web:issuer.example#key-1",
        )
        print("PASS disposable Canvas network-namespace plugin created a sender key")
    finally:
        if sidecar is not None:
            subprocess.run(
                ["docker", "rm", "-f", sidecar],
                capture_output=True, check=False, timeout=30,
            )
        if anchor_started:
            subprocess.run(
                ["docker", "rm", "-f", anchor],
                capture_output=True, check=False, timeout=30,
            )


def run_host() -> None:
    sidecar: str | None = None
    try:
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts/ci/start-canvas-didcomm-openbao.py")],
            env={**os.environ, "MARTY_CANVAS_OPENBAO_IMAGE": IMAGE},
            capture_output=True,
            text=True,
            check=False,
            timeout=150,
        )
        if result.returncode:
            raise RuntimeError("Disposable Canvas host plugin startup failed")
        response = json.loads(result.stdout)
        sidecar = response["container"]
        if not response["url"].startswith("http://127.0.0.1:"):
            raise RuntimeError("Canvas host plugin is not bound to loopback")
        created = require_status(
            response["url"], "POST", "didcomm/keys/synthetic-org/issuer",
            response["root_token"],
            {
                "sender_did": "did:web:issuer.example",
                "sender_key_id": "did:web:issuer.example#key-1",
            },
        )
        if len(created["data"]["version"]) != 32:
            raise RuntimeError("Canvas host plugin did not create a versioned sender")
        print("PASS disposable Canvas host-loopback plugin created a sender key")
        if os.environ.get("MARTY_CANVAS_RUN_PACKAGED_DIRECT") == "1":
            suffix = ".exe" if os.name == "nt" else ""
            binary = ROOT / "rust/target/debug" / f"marty-issuance-service{suffix}"
            if not binary.is_file():
                raise RuntimeError("Packaged direct probe requires built native Issuance binary")
            environment = {
                **os.environ,
                "MARTY_CANVAS_PUBLISHED_SCHEMA_TEST": "1",
                "MARTY_CANVAS_OPENBAO_URL": response["url"],
                "MARTY_CANVAS_OPENBAO_ROOT_TOKEN": response["root_token"],
                "MARTY_ISSUANCE_TEST_BINARY": str(binary),
                "MARTY_DIDCOMM_TEST_PYTHON": sys.executable,
            }
            completed = subprocess.run(
                [
                    "cargo", "+1.95.0", "test", "--locked", "-p", "marty-canvas-acceptance",
                    "--test", "canvas_published_schema_contract",
                    "renewal_fresh_packaged_main_delivers_both_encryption_modes",
                    "--", "--exact", "--nocapture", "--test-threads=1",
                ],
                cwd=ROOT / "rust", env=environment, check=False, timeout=600,
            )
            if completed.returncode:
                raise RuntimeError("Canvas packaged direct KMS renewal failed")
    finally:
        if sidecar is not None:
            subprocess.run(
                ["docker", "rm", "-f", sidecar],
                capture_output=True, check=False, timeout=30,
            )


if __name__ == "__main__":
    run()
    run_host()
