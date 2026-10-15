"""The base and conformance Compose graphs must render KMS-only Keycloak."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from scripts.check_beta_keycloak_kms import validate_model

ROOT = Path(__file__).resolve().parents[1]
FILES = (
    "docker-compose.base.yml",
    "docker-compose.profile.conformance-images.yml",
)


def test_conformance_compose_keeps_keycloak_in_remote_custody(tmp_path: Path) -> None:
    docker = shutil.which("docker")
    if docker is None or subprocess.run(
        [docker, "compose", "version"], capture_output=True, check=False, timeout=10
    ).returncode:
        pytest.skip("Docker Compose is unavailable")

    required = set()
    for name in (*FILES, "docker-compose.profile.issuance-native.yml"):
        required.update(re.findall(r"\$\{([A-Z][A-Z0-9_]*):\?", (ROOT / name).read_text()))
    environment = os.environ.copy()
    for name in required:
        if name.endswith("_FILE"):
            source = tmp_path / name.lower()
            if name == "OPENBAO_TLS_CA_CERT_FILE" or name in {
                "KEYCLOAK_MASTER_RS256_CERT_FILE", "KEYCLOAK_11ID_RS256_CERT_FILE"
            }:
                source.write_text(
                    "-----BEGIN CERTIFICATE-----\ncHVibGlj\n-----END CERTIFICATE-----\n"
                )
            else:
                source.write_text(f"synthetic-scoped-{name}-token-value")
            environment[name] = str(source)
        elif name == "KEYCLOAK_KMS_IMAGE_DIGEST":
            environment[name] = "sha256:" + "a" * 64
        elif name == "KEYCLOAK_KMS_ADDR" or name.endswith("_TLS_KMS_ADDR"):
            environment[name] = "https://openbao:8200"
        elif name == "KEYCLOAK_KMS_KEY_VERSION" or name.endswith("_TLS_KMS_KEY_VERSION"):
            environment[name] = "1"
        else:
            environment[name] = "synthetic-required-value"
    environment["MARTY_OPENBAO_DIDCOMM_IMAGE"] = (
        "example.invalid/openbao@sha256:" + "b" * 64
    )
    command = [docker, "compose"]
    for name in FILES:
        command.extend(("--file", str(ROOT / name)))
    command.extend(("config", "--format", "json"))
    result = subprocess.run(
        command, cwd=ROOT, env=environment, capture_output=True, text=True,
        check=False, timeout=30,
    )
    assert result.returncode == 0, result.stderr
    validate_model(json.loads(result.stdout), check_files=True)
