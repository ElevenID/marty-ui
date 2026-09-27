"""The physical bureau Compose overlays keep callback signing isolated."""

import json
import os
from pathlib import Path
import re
import shutil
import subprocess

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
IMAGE = "example.invalid/marty@sha256:" + "a" * 64
OVERLAYS = {
    "base": ("docker-compose.base.yml", "docker-compose.profile.passport-provider-base.yml"),
    "selfhost": (
        "docker-compose.selfhost.prod.yml",
        "docker-compose.profile.passport-provider-selfhost.yml",
    ),
}


def render(
    base: str,
    overlay: str,
    *,
    provider_ingress_url: str = "",
    provider_ingress_enabled: str = "false",
) -> dict:
    if shutil.which("docker") is None:
        pytest.skip("Docker Compose is unavailable")
    source = (ROOT / base).read_text(encoding="utf-8") + (ROOT / overlay).read_text(
        encoding="utf-8"
    )
    environment = os.environ.copy()
    for name in re.findall(r"\$\{([A-Z][A-Z0-9_]*):\?", source):
        environment.setdefault(name, "synthetic-contract-value")
    environment.update(
        {
            "MARTY_SERVICES_IMAGE": IMAGE,
            "MARTY_ISSUANCE_IMAGE": IMAGE,
            "PERSONALIZATION_BUREAU_PROVIDER_PROFILE_ID": "physical-provider-reference",
            "PASSPORT_PROVIDER_INGRESS_SERVICE_URL": provider_ingress_url,
            "PASSPORT_PROVIDER_INGRESS_GATEWAY_ENABLED": provider_ingress_enabled,
            "PASSPORT_PROVIDER_SECRET_DIR": "/tmp/passport-provider-contract",
            "SELFHOST_SECRET_DIR": "/tmp/passport-provider-contract",
            "SELFHOST_STATE_DIR": "/tmp/passport-provider-state-contract",
            "BAO_ADDR": "https://bao.example.invalid",
            "CORS_ORIGINS": "https://marty.example.invalid",
            "KEYCLOAK_SOCIAL_LOGIN_ENABLED": "false",
        }
    )
    result = subprocess.run(
        ["docker", "compose", "-f", base, "-f", overlay, "config", "--format", "json"],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(result.stdout)


@pytest.mark.parametrize("consumer", OVERLAYS)
def test_supported_compose_signing_boundary(consumer: str) -> None:
    base, overlay = OVERLAYS[consumer]
    model = render(base, overlay)
    services = model["services"]
    signer = services["passport-callback-signer-supported"]
    ingress = services["passport-provider-ingress"]
    signer_env = signer["environment"]
    ingress_env = ingress["environment"]

    assert "ports" not in signer and "ports" not in ingress
    assert signer["networks"] == {"passport-provider-signing": None}
    assert set(ingress["networks"]) == {
        "passport-provider-signing",
        "marty-network" if consumer == "base" else "default",
    }
    assert signer_env["ENVIRONMENT"] == "production"
    assert signer_env["PASSPORT_SUPPORTED_CALLBACK_SIGNER_ENABLED"] == "true"
    assert signer_env["PASSPORT_CALLBACK_SIGNER_API_KEY_FILE"] == ingress_env[
        "PASSPORT_PROVIDER_SIGNER_API_KEY_FILE"
    ]
    assert ingress_env["PASSPORT_PROVIDER_INGRESS_ENABLED"] == "true"
    assert ingress_env["PASSPORT_PROVIDER_SIGNER_URL"] == (
        "http://passport-callback-signer-supported:8018/internal/documents"
    )
    assert ingress_env["PASSPORT_PROVIDER_NATIVE_CALLBACK_URL"] == (
        "http://issuance-native:8005/v1/passport/webhooks/personalization"
    )
    assert ingress_env["PERSONALIZATION_BUREAU_PROVIDER_PROFILE_ID"] == (
        "physical-provider-reference"
    )
    assert "BAO_TOKEN" not in " ".join(ingress_env)
    assert "PASSPORT_PROVIDER_WEBHOOK_SECRET_FILE" not in signer_env
    assert "MARTY_DB_PASSWORD_FILE" not in signer_env
    assert {secret["source"] for secret in signer["secrets"]} == {
        "passport_callback_signer_api_key",
        "passport_callback_signer_bao_token",
    }
    assert {secret["source"] for secret in ingress["secrets"]} == {
        "passport_provider_webhook_secret",
        "passport_callback_signer_api_key",
        "marty_db_password",
    }
    assert services["gateway"]["environment"][
        "PASSPORT_PROVIDER_INGRESS_GATEWAY_ENABLED"
    ] == "false"
    assert services["gateway"]["environment"]["PASSPORT_PROVIDER_INGRESS_SERVICE_URL"] == ""

    if consumer == "base":
        assert "passport-provider-signing" in services["openbao"]["networks"]
        assert model["networks"]["passport-provider-signing"]["internal"] is True
        assert signer_env["BAO_ADDR"] == "http://openbao:8200"
    else:
        assert signer_env["BAO_ADDR"] == "https://bao.example.invalid"
        assert model["networks"]["passport-provider-signing"].get("internal") is not True


@pytest.mark.parametrize("consumer", OVERLAYS)
def test_provider_gateway_target_appears_only_with_selected_overlay(consumer: str) -> None:
    base, overlay = OVERLAYS[consumer]
    target = "http://passport-provider-ingress:8021"
    gateway = render(
        base,
        overlay,
        provider_ingress_url=target,
        provider_ingress_enabled="true",
    )["services"]["gateway"]["environment"]
    assert gateway["PASSPORT_PROVIDER_INGRESS_SERVICE_URL"] == target
    assert gateway["PASSPORT_PROVIDER_INGRESS_GATEWAY_ENABLED"] == "true"


@pytest.mark.parametrize("consumer", OVERLAYS)
def test_supported_compose_requires_explicit_selection_and_secrets(consumer: str) -> None:
    base, overlay = OVERLAYS[consumer]
    base_services = yaml.safe_load((ROOT / base).read_text(encoding="utf-8"))["services"]
    assert "passport-provider-ingress" not in base_services
    assert "passport-callback-signer-supported" not in base_services
    assert "PASSPORT_PROVIDER_INGRESS_SERVICE_URL" not in base_services["gateway"]["environment"]
    overlay_model = yaml.safe_load((ROOT / overlay).read_text(encoding="utf-8"))
    assert overlay_model["services"]["gateway"]["environment"]["PASSPORT_PROVIDER_INGRESS_SERVICE_URL"] == "${PASSPORT_PROVIDER_INGRESS_SERVICE_URL:-}"
    assert set(overlay_model["secrets"]) == {
        "passport_provider_webhook_secret",
        "passport_callback_signer_api_key",
        "passport_callback_signer_bao_token",
        "marty_db_password",
    }
