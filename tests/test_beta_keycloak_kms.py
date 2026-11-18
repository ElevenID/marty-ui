"""Beta identity-provider render cannot reintroduce local key custody."""

from copy import deepcopy

import pytest

from scripts.check_beta_keycloak_kms import (
    KeycloakKmsError, PUBLIC_CERTS, SECRET_TARGETS, validate_model,
)


IMAGE = "ghcr.io/elevenid/marty-ui-oss/keycloak@sha256:" + "a" * 64


def model(tmp_path):
    declarations = {}
    for index, name in enumerate(SECRET_TARGETS):
        path = tmp_path / name
        if name in PUBLIC_CERTS:
            path.write_text("-----BEGIN CERTIFICATE-----\ncHVibGlj\n-----END CERTIFICATE-----\n")
        else:
            path.write_text(f"synthetic-scoped-token-{index:02d}-never-export-key")
        declarations[name] = {"file": str(path)}
    return {
        "services": {
            "keycloak": {
                "image": IMAGE,
                "environment": {
                    "BAO_ADDR": "https://openbao:8200",
                    "BAO_CACERT": "/run/secrets/openbao_tls_ca_cert",
                    "BAO_TOKEN_FILE": "/run/secrets/keycloak_signing_kms_token",
                    "MARTY_KEYCLOAK_RS256_CERT_DIR": "/run/secrets",
                    "MARTY_KEYCLOAK_JWE_TOKEN_DIR": "/run/secrets",
                    "MARTY_KEYCLOAK_JWE_MOUNT": "didcomm",
                    "MARTY_KEYCLOAK_KMS_KEY_PREFIX": "keycloak",
                    "MARTY_KEYCLOAK_KMS_KEY_VERSION": "1",
                },
                "secrets": [
                    {"source": source, "target": target}
                    for source, target in SECRET_TARGETS.items()
                ],
            },
            "keycloak-configurator": {"image": IMAGE},
        },
        "secrets": declarations,
    }


def test_beta_keycloak_accepts_public_certs_and_distinct_scoped_tokens(tmp_path):
    validate_model(model(tmp_path), check_files=True)


@pytest.mark.parametrize("mutation", [
    "stock_image", "mismatched_configurator", "http_kms", "root_token",
    "missing_signing_token", "private_cert", "duplicate_token",
])
def test_beta_keycloak_rejects_local_or_incomplete_custody(tmp_path, mutation):
    candidate = deepcopy(model(tmp_path))
    keycloak = candidate["services"]["keycloak"]
    if mutation == "stock_image":
        keycloak["image"] = "quay.io/keycloak/keycloak:25.0"
    elif mutation == "mismatched_configurator":
        candidate["services"]["keycloak-configurator"]["image"] = "quay.io/keycloak/keycloak:25.0"
    elif mutation == "http_kms":
        keycloak["environment"]["BAO_ADDR"] = "http://openbao:8200"
    elif mutation == "root_token":
        keycloak["environment"]["BAO_DEV_ROOT_TOKEN_ID"] = "root"
    elif mutation == "missing_signing_token":
        keycloak["secrets"] = [
            item for item in keycloak["secrets"]
            if item["source"] != "keycloak_signing_kms_token"
        ]
    elif mutation == "private_cert":
        (tmp_path / "keycloak_master_rs256_cert").write_text("-----BEGIN PRIVATE KEY-----\nsecret")
    elif mutation == "duplicate_token":
        (tmp_path / "keycloak_11id_cookie_token").write_bytes(
            (tmp_path / "keycloak_master_cookie_token").read_bytes()
        )
    with pytest.raises(KeycloakKmsError):
        validate_model(candidate, check_files=True)
