"""The production operator check rejects plaintext KMS and stock Keycloak."""

from __future__ import annotations

import runpy
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
CHECK = runpy.run_path(str(ROOT / "scripts/check-selfhost-production.py"))
validate = CHECK["validate_kms_transport"]
CheckError = CHECK["CheckError"]


def settings() -> dict[str, str]:
    return {
        "MARTY_KEYCLOAK_KMS_IMAGE": (
            "ghcr.io/elevenid/marty-ui-oss/keycloak@sha256:" + "a" * 64
        ),
        "BAO_ADDR": "https://openbao.example.invalid:8200",
        "KEYCLOAK_KMS_ADDR": "https://openbao.example.invalid:8200",
        "SIGNING_KEYS_TLS_KMS_ADDR": "https://openbao.example.invalid:8200",
    }


def test_accepts_pinned_keycloak_and_https_kms_origins() -> None:
    assert validate(settings()) == "keycloak_image=immutable https_origins=3"


@pytest.mark.parametrize("name,value", [
    ("MARTY_KEYCLOAK_KMS_IMAGE", "quay.io/keycloak/keycloak:25.0"),
    ("MARTY_KEYCLOAK_KMS_IMAGE", "REPLACE_WITH_KEYCLOAK_KMS_IMAGE_DIGEST"),
    ("BAO_ADDR", "http://host.docker.internal:18200"),
    ("KEYCLOAK_KMS_ADDR", "http://openbao:8200"),
    ("SIGNING_KEYS_TLS_KMS_ADDR", "https://user:token@openbao.example.invalid"),
    ("KEYCLOAK_KMS_ADDR", "https://openbao.example.invalid:8200/v1/transit"),
    ("KEYCLOAK_KMS_ADDR", "https://openbao.example.invalid:bad"),
])
def test_rejects_local_custody_and_untrusted_kms_origins(name: str, value: str) -> None:
    configuration = settings()
    configuration[name] = value
    with pytest.raises(CheckError):
        validate(configuration)


def test_requires_both_application_and_keycloak_kms_origins() -> None:
    configuration = settings()
    del configuration["KEYCLOAK_KMS_ADDR"]
    with pytest.raises(CheckError, match="incomplete"):
        validate(configuration)
