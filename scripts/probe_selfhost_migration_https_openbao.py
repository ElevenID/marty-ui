#!/usr/bin/env python3
"""Start only the disposable migration fixture's OpenBao HTTPS listener."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "docker-compose.selfhost-migrations-disposable.yml"
PIN = json.loads((ROOT / "deploy-config/passport-supported-disposable-infra-images.json")
                 .read_text(encoding="utf-8"))
OPENBAO = PIN["images"]["openbao"]["reference"]
if re.fullmatch(r"quay\.io/openbao/openbao@sha256:[0-9a-f]{64}", OPENBAO) is None:
    raise RuntimeError("disposable OpenBao reference is not pinned")


def run(args: list[str], environment: dict[str, str]) -> bytes:
    result = subprocess.run(args, env=environment, capture_output=True, timeout=120,
                            check=False)
    if result.returncode:
        diagnostic = re.sub(rb"[0-9a-f]{64}", b"[redacted]", result.stderr[-800:])
        raise RuntimeError(
            f"disposable migration OpenBao command failed ({result.returncode}): "
            + diagnostic.decode("utf-8", errors="replace")
        )
    return result.stdout


def probe(*, scoped: bool = False) -> None:
    project = "marty-selfhost-migrate-probe-" + secrets.token_hex(8)
    compose_file = (ROOT / "docker-compose.selfhost-migrations-scoped-disposable.yml"
                    if scoped else COMPOSE)
    with tempfile.TemporaryDirectory(prefix="marty-migration-https-") as temporary:
        secret_dir = Path(temporary)
        (secret_dir / "bao_root_token").write_text(secrets.token_hex(32), encoding="ascii")
        environment = os.environ.copy()
        environment.update({
            "PROBE_SECRET_DIR": str(secret_dir),
            "PROBE_OPENBAO_IMAGE": OPENBAO,
            "PROBE_MIGRATIONS_IMAGE": "ghcr.io/elevenid/marty-ui-oss/migrations@sha256:" + "a" * 64,
            "PROBE_SERVICES_IMAGE": "ghcr.io/elevenid/marty-ui-oss/services@sha256:" + "e" * 64,
            "PROBE_POSTGRES_IMAGE": "docker.io/library/postgres@sha256:" + "b" * 64,
            "PROBE_REDIS_IMAGE": "docker.io/library/redis@sha256:" + "c" * 64,
            "COMPOSE_PROFILES": "",
        })
        if scoped:
            environment.update({
                "PROBE_RUN_USER": "1000:1000" if os.name == "nt" else f"{os.getuid()}:{os.getgid()}",
                "PROBE_OPENBAO_START": str(ROOT / "scripts/passport_supported_openbao_start.sh"),
                "PROBE_OPENBAO_BOOTSTRAP": str(ROOT / "scripts/selfhost_migration_openbao_bootstrap.sh"),
                "PROBE_OPENBAO_INIT": str(ROOT / "docker/openbao-init.sh"),
            })
        compose = ["docker", "compose", "--project-name", project, "-f", str(compose_file)]
        started = False
        try:
            started = True
            run([*compose, "up", "-d", "--wait", "--wait-timeout", "90", "openbao"],
                environment)
            run([*compose, "exec", "-T", "openbao", "sh", "-c",
                 "BAO_CACERT=/bao/public-ca/ca.crt "
                 "bao status -address=https://openbao:8200 >/dev/null"], environment)
            ca = run([*compose, "exec", "-T", "openbao", "cat",
                      "/bao/public-ca/ca.crt"], environment)
            if b"BEGIN CERTIFICATE" not in ca or b"PRIVATE KEY" in ca:
                raise RuntimeError("disposable OpenBao exported non-public CA material")
            if scoped:
                run([*compose, "run", "--no-deps", "--rm", "openbao-bootstrap"],
                    environment)
                outputs = [secret_dir / name for name in (
                    "bao_service_token", "bao_bootstrap_token",
                    "notification_openbao_token", "sign_grant_verify_token",
                    "signing_keys_openbao_token")]
                if not all(path.is_file() and path.stat().st_size for path in outputs):
                    raise RuntimeError("disposable scoped OpenBao token output is incomplete")
            print("Disposable migration OpenBao HTTPS and public CA passed")
        finally:
            if started:
                run([*compose, "down", "--volumes"], environment)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scoped", action="store_true")
    probe(scoped=parser.parse_args().scoped)
