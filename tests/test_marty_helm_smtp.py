"""Keep Keycloak mail credentials in Secrets and mail-dependent login opt-in."""

from pathlib import Path
import subprocess

import pytest
import yaml

from tests.test_marty_helm_chart import HELM, helm_command, installation_values, render, resources


pytestmark = pytest.mark.skipif(HELM is None, reason="Helm 3 is required to render this chart")


def configurator_environment(documents: list[dict]) -> dict[str, dict]:
    job = next(
        job for job in resources(documents, "Job").values()
        if job["metadata"]["labels"].get("app.kubernetes.io/component") == "keycloak-configurator"
    )
    container = job["spec"]["template"]["spec"]["containers"][0]
    return {entry["name"]: entry for entry in container["env"]}


def test_default_installation_does_not_require_smtp_or_offer_password_reset(tmp_path: Path) -> None:
    documents = render(tmp_path)
    config = resources(documents, "ConfigMap")["marty-config"]["data"]
    assert config["KEYCLOAK_RESET_PASSWORD_ENABLED"] == "false"
    assert config["SMTP_HOST"] == ""
    assert "SMTP_PASSWORD" not in config
    assert "KEYCLOAK_SMTP_PASSWORD" not in config
    smtp = configurator_environment(documents)["SMTP_PASSWORD"]
    assert "value" not in smtp
    assert smtp["valueFrom"]["secretKeyRef"] == {
        "name": "marty-secrets", "key": "SMTP_PASSWORD", "optional": True,
    }


@pytest.mark.parametrize("secret_name", ["marty-secrets", "installation-private-config"])
def test_configured_keycloak_smtp_uses_existing_secret_and_explicit_login_policy(
    tmp_path: Path, secret_name: str,
) -> None:
    values = installation_values()
    values["existingSecrets"] = {"marty-secrets": secret_name}
    values["config"] = {
        "KEYCLOAK_SMTP_HOST": "smtp.example.test",
        "KEYCLOAK_SMTP_PORT": "587",
        "KEYCLOAK_SMTP_FROM": "identity@example.test",
        "KEYCLOAK_SMTP_USERNAME": "identity-mailer",
        "KEYCLOAK_SMTP_STARTTLS": "true",
        "KEYCLOAK_SMTP_SSL": "false",
        "KEYCLOAK_VERIFY_EMAIL": "true",
        "KEYCLOAK_RESET_PASSWORD_ENABLED": "true",
    }
    documents = render(tmp_path, values)
    config = resources(documents, "ConfigMap")["marty-config"]["data"]
    assert all(config[name] == value for name, value in values["config"].items())
    assert "SMTP_PASSWORD" not in config
    assert "KEYCLOAK_SMTP_PASSWORD" not in config
    assert not resources(documents, "Secret")
    smtp = configurator_environment(documents)["SMTP_PASSWORD"]
    assert "value" not in smtp
    assert smtp["valueFrom"]["secretKeyRef"] == {
        "name": secret_name, "key": "SMTP_PASSWORD", "optional": False,
    }


@pytest.mark.parametrize("overrides,required", [
    ({}, False),
    ({"KEYCLOAK_SMTP_USERNAME": "identity-mailer"}, False),
    ({"SMTP_USERNAME": "identity-mailer"}, False),
    ({"KEYCLOAK_SMTP_HOST": "relay.example.test", "KEYCLOAK_SMTP_FROM": "identity@example.test"}, False),
    ({"SMTP_HOST": "relay.example.test", "SMTP_FROM": "identity@example.test"}, False),
    ({"KEYCLOAK_SMTP_HOST": "smtp.example.test", "KEYCLOAK_SMTP_FROM": "identity@example.test",
      "KEYCLOAK_SMTP_USERNAME": "identity-mailer", "KEYCLOAK_SMTP_STARTTLS": "true"}, True),
    ({"SMTP_HOST": "smtp.example.test", "SMTP_FROM": "identity@example.test",
      "SMTP_USERNAME": "identity-mailer", "SMTP_STARTTLS": "true"}, True),
    ({"SMTP_HOST": "smtp.example.test", "SMTP_FROM": "identity@example.test",
      "SMTP_USERNAME": "identity-mailer", "SMTP_STARTTLS": "true",
      "KEYCLOAK_SMTP_HOST": "", "KEYCLOAK_SMTP_USERNAME": ""}, True),
    ({"KEYCLOAK_SMTP_HOST": "smtp.example.test", "SMTP_FROM": "identity@example.test",
      "SMTP_USERNAME": "identity-mailer", "SMTP_STARTTLS": "true"}, True),
])
def test_smtp_password_is_required_only_when_setup_will_configure_authentication(
    tmp_path: Path, overrides: dict[str, str], required: bool,
) -> None:
    values = installation_values()
    values["config"] = overrides
    documents = render(tmp_path, values)
    smtp = configurator_environment(documents)["SMTP_PASSWORD"]
    host = overrides.get("KEYCLOAK_SMTP_HOST") or overrides.get("SMTP_HOST")
    if host and not required:
        assert smtp == {"name": "SMTP_PASSWORD", "value": ""}
    else:
        assert smtp["valueFrom"]["secretKeyRef"] == {
            "name": "marty-secrets", "key": "SMTP_PASSWORD", "optional": not required,
        }
        assert "value" not in smtp
    assert not resources(documents, "Secret")


def test_selected_unauthenticated_relay_does_not_receive_a_retained_password(tmp_path: Path) -> None:
    from tests.test_keycloak_login_configuration import run_setup

    values = installation_values()
    settings = {
        "KEYCLOAK_SMTP_HOST": "relay.example.test",
        "KEYCLOAK_SMTP_PORT": "25",
        "KEYCLOAK_SMTP_FROM": "identity@example.test",
        "KEYCLOAK_SMTP_USERNAME": "",
        "KEYCLOAK_SMTP_SSL": "false",
        "KEYCLOAK_SMTP_STARTTLS": "false",
    }
    values["config"] = settings
    smtp = configurator_environment(render(tmp_path, values))["SMTP_PASSWORD"]
    # Model Kubernetes env delivery even when the selected Secret retains a key
    # from an earlier authenticated provider.
    retained_secret = {"SMTP_PASSWORD": "retained-provider-password-not-for-relay"}
    delivered = smtp["value"] if "value" in smtp else retained_secret[smtp["valueFrom"]["secretKeyRef"]["key"]]
    result, calls = run_setup(
        tmp_path, "configure_realm_smtp_settings", SMTP_PASSWORD=delivered, **settings,
    )
    assert result.returncode == 0, result.stderr
    assert len(calls) == 1
    mail = calls[0]["payload"]["smtpServer"]
    assert mail["auth"] == "false"
    assert not mail.get("password") and not mail.get("user")
    assert retained_secret["SMTP_PASSWORD"] not in result.stdout + result.stderr


def test_disabled_configurator_does_not_create_a_mail_setup_job(tmp_path: Path) -> None:
    values = installation_values()
    values["keycloak"] = {"configurator": {"enabled": False}}
    documents = render(tmp_path, values)
    assert not any(
        job["metadata"]["labels"].get("app.kubernetes.io/component") == "keycloak-configurator"
        for job in resources(documents, "Job").values()
    )


@pytest.mark.parametrize("key", ["SMTP_PASSWORD", "KEYCLOAK_SMTP_PASSWORD"])
@pytest.mark.parametrize("configurator_enabled", [True, False])
def test_smtp_password_in_config_is_refused_without_disclosing_it(
    tmp_path: Path, key: str, configurator_enabled: bool,
) -> None:
    values = installation_values()
    sentinel = "private-smtp-test-password-never-log"
    values["config"] = {key: sentinel}
    values["keycloak"] = {"configurator": {"enabled": configurator_enabled}}
    values_file = tmp_path / "installation.yaml"
    values_file.write_text(yaml.safe_dump(values), encoding="utf-8")
    result = subprocess.run(helm_command(values_file), capture_output=True, text=True)
    assert result.returncode != 0
    assert f"config.{key}" in result.stderr
    assert "existingSecrets.marty-secrets" in result.stderr
    assert sentinel not in result.stdout + result.stderr
