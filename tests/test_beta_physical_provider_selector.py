"""Physical provider beta mode never selects the simulator or raw-key path."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import runpy

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = runpy.run_path(str(ROOT / "scripts/validate_beta_passport_configuration.py"))
PROFILES = [
    "docker-compose.profile.passport-provider-base.yml",
    "docker-compose.profile.passport-native-physical-beta.yml",
]
IMAGE = "ghcr.io/elevenid/marty-ui-oss/services@sha256:" + "a" * 64
DSC = "physical-beta-dsc-gateway-credential-00001"
CSCA = "physical-beta-csca-gateway-credential-0001"


def model(tmp_path: Path) -> dict:
    secret_root = tmp_path / "elevenid-beta-passport-physical"
    secret_root.mkdir()
    secret_names = (
        "passport_physical_provider_api_key", "passport_provider_webhook_secret",
        "passport_callback_signer_api_key", "passport_callback_signer_bao_token",
        "marty_db_password",
    )
    secrets = {}
    for index, name in enumerate(secret_names):
        path = secret_root / name
        path.write_text("beta-physical-secret-" + str(index) * 40, encoding="utf-8")
        secrets[name] = {"file": str(path)}
    return {"name": "elevenid-beta", "secrets": secrets,
            "networks": {
                "marty-network": {"name": "elevenid-beta-network"},
                "passport-provider-signing": {
                    "name": "elevenid-beta_passport-provider-signing", "internal": True},
            }, "services": {
        "gateway": {"networks": {"marty-network": {}}, "environment": {
            "PASSPORT_NATIVE_GATEWAY_ENABLED": "true",
            "PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED": "true",
            "PASSPORT_PROVIDER_INGRESS_GATEWAY_ENABLED": "true",
            "PASSPORT_PROVIDER_INGRESS_SERVICE_URL": VALIDATOR["PHYSICAL_INGRESS_URL"],
            "SIGNING_KEYS_DSC_ISSUE_GATEWAY_KEY": DSC,
            "SIGNING_KEYS_CSCA_ISSUE_GATEWAY_KEY": CSCA,
        }},
        "flow": {"networks": {"marty-network": {}}, "environment": {
            "PASSPORT_NATIVE_FLOW_ENABLED": "true",
            "PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED": "true",
            "ISSUANCE_NATIVE_SERVICE_URL": "http://issuance-native:8005",
        }},
        "issuance-native": {"networks": {"marty-network": {}}, "environment": {
            "PASSPORT_NATIVE_HTTP_ENABLED": "true",
            "PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED": "true",
            "PASSPORT_MANAGED_ISSUER_SIGNING_ENABLED": "true",
            "PASSPORT_KMS_ARTIFACTS_ENABLED": "true",
            "PASSPORT_KMS_CALLBACKS_ENABLED": "true",
            "PHYSICAL_DOCUMENT_ALLOW_SELF_SIGNED": "false",
            "PERSONALIZATION_BUREAU_URL": "https://bureau.physical-provider.net/jobs",
            "PERSONALIZATION_BUREAU_PROVIDER_PROFILE_ID": "physical-provider-marty-001",
            "PERSONALIZATION_BUREAU_API_KEY": "",
            "PERSONALIZATION_BUREAU_API_KEY_FILE":
                "/run/secrets/passport_physical_provider_api_key",
            "PERSONALIZATION_BUREAU_WEBHOOK_SECRET": "",
            "PERSONALIZATION_BUREAU_WEBHOOK_SECRET_FILE": "",
            "DATABASE_URL": "postgresql+asyncpg://marty:beta-physical-secret-4444444444444444444444444444444444444444@postgres:5432/marty",
        }, "secrets": ["passport_physical_provider_api_key"]},
        "signing-keys": {"networks": {"marty-network": {}}, "environment": {
            "ENVIRONMENT": "beta",
            "SIGNING_KEYS_BETA_CSCA_ISSUANCE_ENABLED": "true",
            "SIGNING_KEYS_DSC_ISSUE_GATEWAY_KEY": DSC,
            "SIGNING_KEYS_CSCA_ISSUE_GATEWAY_KEY": CSCA,
            "SIGNING_KEYS_INTERNAL_API_KEY": "ordinary-signing-secret-00000001",
        }},
        "openbao": {"networks": {"marty-network": {},
                                  "passport-provider-signing": {}}},
        "passport-callback-signer-supported": {"image": IMAGE,
            "networks": {"passport-provider-signing": {}},
            "environment": {
                "SERVICE_NAME": "passport_callback_signer",
                "ENVIRONMENT": "beta",
                "PASSPORT_CALLBACK_SIGNER_ENABLED": "true",
                "SIGNING_KEYS_INTERNAL_API_KEY": "",
                "SIGNING_KEYS_INTERNAL_API_KEY_FILE":
                    "/run/secrets/passport_callback_signer_api_key",
                "BAO_TOKEN": "", "BAO_TOKEN_FILE":
                    "/run/secrets/passport_callback_signer_bao_token",
                "BAO_ADDR": "http://openbao:8200",
            }, "secrets": ["passport_callback_signer_api_key",
                            "passport_callback_signer_bao_token"]},
        "passport-provider-ingress": {"image": IMAGE,
            "networks": {"marty-network": {}, "passport-provider-signing": {}},
            "environment": {
                "SERVICE_NAME": "passport_provider_ingress",
                "PASSPORT_PROVIDER_INGRESS_ENABLED": "true",
                "PERSONALIZATION_BUREAU_PROVIDER_PROFILE_ID":
                    "physical-provider-marty-001",
                "PASSPORT_PROVIDER_SIGNER_URL": VALIDATOR["PHYSICAL_SIGNER_URL"],
                "PASSPORT_PROVIDER_NATIVE_CALLBACK_URL": VALIDATOR["PRIVATE_CALLBACK_URL"],
                "PASSPORT_PROVIDER_SIGNER_API_KEY_FILE":
                    "/run/secrets/passport_callback_signer_api_key",
                "PASSPORT_PROVIDER_WEBHOOK_SECRET_FILE":
                    "/run/secrets/passport_provider_webhook_secret",
            }, "secrets": ["passport_callback_signer_api_key",
                            "passport_provider_webhook_secret", "marty_db_password"]},
    }}


def validate(candidate: dict) -> None:
    registry = {"schema": "marty.passport-beta-physical-provider-allowlist/v1",
                "status": "approved", "providers": [{
                    "endpoint": "https://bureau.physical-provider.net/jobs",
                    "profile_id": "physical-provider-marty-001",
                    "provider_kind": "physical", "environment": "beta"}]}
    VALIDATOR["validate_model"](candidate, passport_enabled=True,
                                files=PROFILES, physical_provider=True,
                                provider_registry=registry)


def test_physical_mode_is_separate_and_default_off(tmp_path: Path) -> None:
    candidate = model(tmp_path)
    validate(candidate)
    physical = yaml.safe_load((ROOT / PROFILES[1]).read_text(encoding="utf-8"))
    assert "passport-beta-bureau" not in physical["services"]
    assert physical["services"]["passport-callback-signer-supported"]["environment"][
        "SERVICE_NAME"] == "passport_callback_signer"
    with pytest.raises(VALIDATOR["PassportConfigurationError"]):
        VALIDATOR["validate_model"](candidate, passport_enabled=False,
                                    files=PROFILES, physical_provider=True)
    with pytest.raises(VALIDATOR["PassportConfigurationError"],
                       match="governed approval"):
        VALIDATOR["validate_model"](candidate, passport_enabled=True,
                                    files=PROFILES, physical_provider=True)


def test_physical_mode_plan_only_blocks_live_deploy_and_restore() -> None:
    selector = (ROOT / "scripts/beta-passport-configuration.ps1").read_text(
        encoding="utf-8")
    deploy = (ROOT / "scripts/deploy-local-beta-release.ps1").read_text(
        encoding="utf-8")
    restore = (ROOT / "scripts/restore-local-beta-release.ps1").read_text(
        encoding="utf-8")
    assert '"docker-compose.profile.passport-native-beta.yml"' in selector
    assert '"docker-compose.profile.passport-native-physical-beta.yml"' in selector
    assert '"docker-compose.profile.passport-provider-base.yml"' in selector
    assert "if ($EnablePassportPhysicalProvider -and -not $PlanOnly)" in deploy
    assert deploy.index("if ($EnablePassportPhysicalProvider -and -not $PlanOnly)") < (
        deploy.index("$script:RepoRoot =")
    )
    assert 'passport_mode = if ($EnablePassportPhysicalProvider)' in deploy
    assert 'passport_physical_provider_enabled = [bool]$EnablePassportPhysicalProvider' in deploy
    assert '"passport-callback-signer-supported"' in deploy
    assert '"passport-provider-ingress"' in deploy
    assert "if ($PhysicalProviderSnapshot -and -not $PlanOnly)" in restore
    assert restore.index("if ($PlanOnly) {") < restore.index("$stackLock =")
    assert 'status = "blocked"' in restore
    assert '"passport-beta-bureau"' not in restore[
        restore.index("if ($PlanOnly) {"):restore.index("$stackLock =")
    ]


@pytest.mark.parametrize("change", [
    lambda candidate: candidate["services"].update({"passport-beta-bureau": {}}),
    lambda candidate: candidate["services"]["issuance-native"]["environment"].update(
        PERSONALIZATION_BUREAU_URL="http://passport-beta-bureau:8020"),
    lambda candidate: candidate["services"]["issuance-native"]["environment"].update(
        PERSONALIZATION_BUREAU_URL="https://bureau.example.test/jobs"),
    lambda candidate: candidate["services"]["issuance-native"]["environment"].update(
        PASSPORT_KMS_CALLBACKS_ENABLED="false"),
    lambda candidate: candidate["services"]["issuance-native"]["environment"].update(
        PERSONALIZATION_BUREAU_API_KEY="raw-secret"),
    lambda candidate: candidate["services"]["passport-callback-signer-supported"][
        "environment"].update(BAO_TOKEN="dev-root-token"),
    lambda candidate: candidate["services"]["passport-provider-ingress"]["environment"].update(
        PERSONALIZATION_BUREAU_PROVIDER_PROFILE_ID="other-profile"),
    lambda candidate: candidate["services"]["passport-provider-ingress"].update(
        ports=["0.0.0.0:8021:8021"]),
    lambda candidate: candidate["services"]["passport-callback-signer-supported"][
        "secrets"].remove("passport_callback_signer_bao_token"),
    lambda candidate: candidate["services"]["passport-provider-ingress"][
        "secrets"].remove("passport_provider_webhook_secret"),
    lambda candidate: candidate.update(name="marty-selfhost-prod"),
    lambda candidate: candidate["networks"]["passport-provider-signing"].update(
        internal=False),
    lambda candidate: candidate["services"]["gateway"].update(
        networks={"host": {}}),
    lambda candidate: candidate["services"]["flow"].update(
        volumes=["/srv/marty-selfhost-prod:/app/data"]),
    lambda candidate: candidate["services"]["issuance-native"].update(
        secrets=["passport_physical_provider_api_key", "production_database_password"]),
    lambda candidate: candidate["services"]["signing-keys"].update(
        network_mode="host"),
    lambda candidate: candidate["services"]["passport-callback-signer-supported"].update(
        container_name="marty-selfhost-prod-signer"),
    lambda candidate: candidate["services"]["passport-provider-ingress"].update(
        volumes_from=["marty-selfhost-prod-postgres"]),
])
def test_physical_mode_rejects_regression(tmp_path: Path, change) -> None:
    candidate = deepcopy(model(tmp_path))
    change(candidate)
    with pytest.raises(VALIDATOR["PassportConfigurationError"]):
        validate(candidate)


def test_physical_mode_rejects_secret_under_production_parent(tmp_path: Path) -> None:
    candidate = model(tmp_path)
    old = Path(candidate["secrets"]["passport_physical_provider_api_key"]["file"])
    nested = tmp_path / "marty-selfhost-prod" / "elevenid-beta-passport-physical"
    nested.mkdir(parents=True)
    new = nested / old.name
    new.write_bytes(old.read_bytes())
    candidate["secrets"]["passport_physical_provider_api_key"]["file"] = str(new)
    with pytest.raises(VALIDATOR["PassportConfigurationError"],
                       match="secret root"):
        validate(candidate)
