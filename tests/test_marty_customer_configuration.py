"""Render customer configuration combinations that can fail after installation."""

from pathlib import Path
import subprocess

import pytest
import yaml

from tests.test_marty_helm_chart import (
    HELM,
    UniqueLoader,
    helm_command,
    installation_values,
    render,
    resources,
)


pytestmark = pytest.mark.skipif(HELM is None, reason="Helm 3 is required to render this chart")


def rejected(tmp_path: Path, overrides: dict[str, str], message: str) -> None:
    values = installation_values()
    values["config"] = overrides
    values_file = tmp_path / "installation.yaml"
    values_file.write_text(yaml.safe_dump(values), encoding="utf-8")
    result = subprocess.run(helm_command(values_file), capture_output=True, text=True)
    assert result.returncode != 0, "Helm accepted inconsistent customer configuration"
    assert message in result.stderr


def smtp_settings(prefix: str = "KEYCLOAK_") -> dict[str, str]:
    return {
        f"{prefix}SMTP_HOST": "smtp.canyon-skills.example",
        f"{prefix}SMTP_PORT": "587",
        f"{prefix}SMTP_FROM": "credentials@canyon-skills.example",
        f"{prefix}SMTP_STARTTLS": "true",
        f"{prefix}SMTP_SSL": "false",
    }


@pytest.mark.parametrize("key,value,source", [
    ("MARTY_ORG_ID", "750e8400-e29b-41d4-a716-446655440001", "organization.id"),
    ("MARTY_ORG_SLUG", "canyon-skills", "organization.slug"),
])
def test_organization_alias_cannot_split_seed_identity_from_callbacks_and_did(
    tmp_path: Path, key: str, value: str, source: str,
) -> None:
    rejected(tmp_path, {key: value}, f"config.{key} must match {source}")


def test_matching_organization_aliases_keep_a_custom_tenant_coherent(tmp_path: Path) -> None:
    values = installation_values()
    organization_id = "750e8400-e29b-41d4-a716-446655440001"
    values["organization"].update(id=organization_id, slug="canyon-skills")
    values["config"] = {
        "MARTY_ORG_ID": organization_id,
        "MARTY_ORG_SLUG": "canyon-skills",
    }
    config = resources(render(tmp_path, values), "ConfigMap")["marty-config"]["data"]
    assert config["MARTY_ORG_ID"] == organization_id
    assert config["FLOW_CALLBACK_DESTINATIONS"].split("|", 1)[0] == organization_id
    assert config["MARTY_ISSUER_DID"].endswith(":orgs:canyon-skills")


@pytest.mark.parametrize("uppercase_canonical,matching_alias", [
    (False, False), (True, False), (True, True),
])
def test_uuid_case_cannot_split_string_keyed_tenant_records(
    tmp_path: Path, uppercase_canonical: bool, matching_alias: bool,
) -> None:
    values = installation_values()
    organization_id = "750e8400-e29b-41d4-a716-446655440001"
    values["organization"]["id"] = organization_id.upper() if uppercase_canonical else organization_id
    values["config"] = {"MARTY_ORG_ID": organization_id.upper()}
    if uppercase_canonical and not matching_alias:
        values["config"] = {}
    values_file = tmp_path / "installation.yaml"
    values_file.write_text(yaml.safe_dump(values), encoding="utf-8")
    result = subprocess.run(helm_command(values_file), capture_output=True, text=True)
    assert result.returncode != 0
    message = "organization.id must use the lowercase canonical UUID spelling" if uppercase_canonical else "config.MARTY_ORG_ID must match organization.id"
    assert message in result.stderr


def test_custom_realm_cannot_diverge_from_imported_realm_and_oidc_routes(tmp_path: Path) -> None:
    rejected(tmp_path, {"KEYCLOAK_REALM": "canyon-skills"}, "config.KEYCLOAK_REALM must be 11id")


@pytest.mark.parametrize("key", [
    "KEYCLOAK_USER_REGISTRATION_ENABLED",
    "KEYCLOAK_VERIFY_EMAIL",
    "KEYCLOAK_RESET_PASSWORD_ENABLED",
    "KEYCLOAK_SOCIAL_LOGIN_ENABLED",
    "KEYCLOAK_ORGANIZATION_IDENTITY_FIRST_ENABLED",
])
def test_login_policy_typo_cannot_fall_back_to_a_different_policy(tmp_path: Path, key: str) -> None:
    rejected(tmp_path, {key: "flase"}, f"config.{key} must be a supported boolean")


@pytest.mark.parametrize("value", ["TRUE", "1", "yes", "y", "ON", "false", "0", "NO", "n", "off"])
def test_existing_setup_boolean_spellings_remain_supported(tmp_path: Path, value: str) -> None:
    values = installation_values()
    values["config"] = {"KEYCLOAK_USER_REGISTRATION_ENABLED": value}
    values_file = tmp_path / "installation.yaml"
    # Helm's YAML parser recognizes unquoted y/n as booleans; config is a string map.
    values_file.write_text(yaml.safe_dump(values, default_style='"'), encoding="utf-8")
    result = subprocess.run(helm_command(values_file), capture_output=True, text=True, check=True)
    documents = [doc for doc in yaml.load_all(result.stdout, Loader=UniqueLoader) if doc]
    config = resources(documents, "ConfigMap")["marty-config"]["data"]
    assert config["KEYCLOAK_USER_REGISTRATION_ENABLED"] == value


@pytest.mark.parametrize("key", ["KEYCLOAK_VERIFY_EMAIL", "KEYCLOAK_RESET_PASSWORD_ENABLED"])
def test_new_installation_cannot_enable_mail_login_without_smtp(tmp_path: Path, key: str) -> None:
    rejected(tmp_path, {key: "true"}, "new installations enabling email verification or password reset require")


def test_upgrade_can_preserve_preconfigured_realm_smtp(tmp_path: Path) -> None:
    values = installation_values()
    values["config"] = {"KEYCLOAK_VERIFY_EMAIL": "true", "KEYCLOAK_RESET_PASSWORD_ENABLED": "true"}
    values_file = tmp_path / "installation.yaml"
    values_file.write_text(yaml.safe_dump(values), encoding="utf-8")
    result = subprocess.run(helm_command(values_file) + ["--is-upgrade"], capture_output=True, text=True, check=True)
    documents = [doc for doc in yaml.load_all(result.stdout, Loader=UniqueLoader) if doc]
    config = resources(documents, "ConfigMap")["marty-config"]["data"]
    assert config["KEYCLOAK_VERIFY_EMAIL"] == "true"
    assert config["KEYCLOAK_RESET_PASSWORD_ENABLED"] == "true"
    assert config["SMTP_HOST"] == ""


def test_replay_without_configurator_does_not_reconfigure_realm_mail(tmp_path: Path) -> None:
    values = installation_values()
    values["keycloak"] = {"configurator": {"enabled": False}}
    values["config"] = {"KEYCLOAK_VERIFY_EMAIL": "true", "KEYCLOAK_RESET_PASSWORD_ENABLED": "true"}
    documents = render(tmp_path, values)
    assert not any(
        job["metadata"]["labels"].get("app.kubernetes.io/component") == "keycloak-configurator"
        for job in resources(documents, "Job").values()
    )


@pytest.mark.parametrize("prefix", ["KEYCLOAK_", ""])
def test_mail_login_accepts_keycloak_settings_and_shared_smtp_fallbacks(
    tmp_path: Path, prefix: str,
) -> None:
    values = installation_values()
    values["config"] = smtp_settings(prefix) | {
        "KEYCLOAK_VERIFY_EMAIL": "yes", "KEYCLOAK_RESET_PASSWORD_ENABLED": "1",
    }
    config = resources(render(tmp_path, values), "ConfigMap")["marty-config"]["data"]
    assert all(config[name] == value for name, value in values["config"].items())


def test_mail_aliases_follow_setup_script_nonempty_precedence(tmp_path: Path) -> None:
    values = installation_values()
    values["config"] = smtp_settings("") | {
        "KEYCLOAK_SMTP_HOST": "", "KEYCLOAK_SMTP_PORT": "", "KEYCLOAK_SMTP_FROM": "",
        "KEYCLOAK_SMTP_SSL": "false", "SMTP_SSL": "true",
        "KEYCLOAK_VERIFY_EMAIL": "true", "KEYCLOAK_RESET_PASSWORD_ENABLED": "true",
    }
    config = resources(render(tmp_path, values), "ConfigMap")["marty-config"]["data"]
    assert config["KEYCLOAK_SMTP_SSL"] == "false"
    assert config["SMTP_SSL"] == "true"


@pytest.mark.parametrize("value", ["0", "65536", "submission", "587.0", "-1"])
def test_configured_smtp_port_must_be_usable(tmp_path: Path, value: str) -> None:
    rejected(tmp_path, smtp_settings() | {"KEYCLOAK_SMTP_PORT": value}, "SMTP port must be between 1 and 65535")


@pytest.mark.parametrize("sender", ["", "credentials", "credentials@canyon-skills.example\n"])
def test_configured_smtp_requires_an_explicit_sender(tmp_path: Path, sender: str) -> None:
    rejected(tmp_path, smtp_settings() | {"KEYCLOAK_SMTP_FROM": sender}, "SMTP requires an explicit sender email")


def test_smtp_transport_flags_cannot_select_conflicting_modes(tmp_path: Path) -> None:
    rejected(tmp_path, smtp_settings() | {"KEYCLOAK_SMTP_SSL": "true"}, "SMTP cannot enable SSL and STARTTLS together")


@pytest.mark.parametrize("key", ["KEYCLOAK_SMTP_SSL", "KEYCLOAK_SMTP_STARTTLS"])
def test_smtp_transport_typo_does_not_disable_requested_encryption(tmp_path: Path, key: str) -> None:
    rejected(tmp_path, smtp_settings() | {key: "treu"}, f"config.{key} must be a supported boolean")


def test_unauthenticated_private_smtp_relay_remains_supported(tmp_path: Path) -> None:
    values = installation_values()
    values["config"] = smtp_settings() | {"KEYCLOAK_SMTP_PORT": "25", "KEYCLOAK_SMTP_STARTTLS": "false"}
    documents = render(tmp_path, values)
    assert resources(documents, "ConfigMap")["marty-config"]["data"]["KEYCLOAK_SMTP_STARTTLS"] == "false"


@pytest.mark.parametrize("key", ["KEYCLOAK_SMTP_USERNAME", "SMTP_USERNAME"])
def test_authenticated_smtp_requires_an_encrypted_transport(tmp_path: Path, key: str) -> None:
    rejected(tmp_path, smtp_settings() | {key: "identity-mailer", "KEYCLOAK_SMTP_STARTTLS": "false"},
             "authenticated SMTP requires SSL or STARTTLS")


@pytest.mark.parametrize("transport", ["SSL", "STARTTLS"])
def test_authenticated_smtp_accepts_either_provider_transport(tmp_path: Path, transport: str) -> None:
    values = installation_values()
    values["config"] = smtp_settings() | {
        "KEYCLOAK_SMTP_USERNAME": "identity-mailer",
        "KEYCLOAK_SMTP_SSL": str(transport == "SSL").lower(),
        "KEYCLOAK_SMTP_STARTTLS": str(transport == "STARTTLS").lower(),
    }
    config = resources(render(tmp_path, values), "ConfigMap")["marty-config"]["data"]
    assert config[f"KEYCLOAK_SMTP_{transport}"] == "true"


def test_advanced_endpoints_and_retained_issuer_identity_remain_customizable(tmp_path: Path) -> None:
    values = installation_values()
    values["config"] = {
        "ISSUER_BASE_URL": "https://issuer.canyon-skills.example:9443",
        "CANVAS_OAUTH_COMPLETION_REDIRECT_URL": "https://learning.canyon-skills.example/complete",
        "MARTY_ISSUER_DID": "did:web:previous.canyon-skills.example:orgs:academy",
        "OID4VP_ISSUER_DID": "did:web:previous.canyon-skills.example:orgs:academy",
        "CREDENTIAL_LOGIN_ISSUER_DID": "did:web:previous.canyon-skills.example:orgs:academy",
        "MARTY_ORG_DOMAIN": "canyon-skills.example",
        "MARTY_ORG_ADMIN_EMAIL": "identity-admin@canyon-skills.example",
        "CORS_ORIGINS": "https://marty.example.test,https://learning.canyon-skills.example",
        "UI_ADDITIONAL_BASE_URLS": "https://learning.canyon-skills.example",
        "FLOW_CALLBACK_DESTINATIONS": "750e8400-e29b-41d4-a716-446655440001|https://learning.canyon-skills.example/callback?nonce=__MARTY_TOKEN__",
        "AUTH_TLS_KMS_ADDR": "https://customer-kms.example:8200",
    }
    config = resources(render(tmp_path, values), "ConfigMap")["marty-config"]["data"]
    assert all(config[name] == value for name, value in values["config"].items())
