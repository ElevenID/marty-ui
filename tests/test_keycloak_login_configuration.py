"""Exercise effective login policy and secret delivery through the real setup script."""

import json
import os
from pathlib import Path
import subprocess

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
MATCHING = '{"registrationAllowed":true,"verifyEmail":false,"resetPasswordAllowed":false}'

PASSKEY_POLICY = {
    "RpId": "login.example.test", "RpEntityName": "ElevenID",
    "SignatureAlgorithms": ["ES256", "RS256"],
    "UserVerificationRequirement": "required", "ResidentKey": "required",
    "AttestationConveyancePreference": "none", "AuthenticatorAttachment": "not specified",
    "Mediation": "conditional",
}


def passkey_readbacks():
    return [json.dumps({"systemInfo": {"version": "26.8.0"}}),
            '{"webAuthnPolicyPasswordlessRpId":""}',
            *[json.dumps({"webAuthnPolicyPasswordless" + key: value})
              for key, value in PASSKEY_POLICY.items()],
            '{"enabled":true}', '{"defaultAction":false}',
            '{"webAuthnPolicyPasswordlessPasskeysEnabled":true}']


def run_setup(tmp_path, function, *, readback=MATCHING, readbacks=None, update_exit=0, **settings):
    source = (ROOT / "scripts/setup-keycloak.sh").read_text(encoding="utf-8")
    assert source.rstrip().endswith('main "$@"')
    script = tmp_path / "setup.sh"
    script.write_text(source.rsplit('main "$@"', 1)[0] + function + "\n", encoding="utf-8")
    stub = tmp_path / "kcadm"
    stub.write_text(
        """#!/usr/bin/env python3
import json, os, pathlib, stat, sys
args = sys.argv[1:]
record = {"args": args}
if '-f' in args:
    path = pathlib.Path(args[args.index('-f') + 1])
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    record.update(payload=json.loads(path.read_text()), payload_path=str(path))
    # A noisy admin client must not disclose credential-bearing responses.
    print(path.read_text())
    print(path.read_text(), file=sys.stderr)
with open(os.environ['TEST_CALLS'], 'a', encoding='utf-8') as handle:
    handle.write(json.dumps(record) + '\\n')
if args[0] == 'get':
    sequence = json.loads(os.environ['TEST_READBACK_SEQUENCE'])
    count = sum(json.loads(line)['args'][0] == 'get' for line in pathlib.Path(os.environ['TEST_CALLS']).read_text().splitlines())
    value = sequence[count - 1] if sequence else os.environ['TEST_READBACK']
    if value == '__unavailable__':
        sys.exit(1)
    print(value)
    sys.exit(0)
sys.exit(int(os.environ['TEST_UPDATE_EXIT']))
""",
        encoding="utf-8",
    )
    stub.chmod(0o700)
    calls_path = tmp_path / "calls.jsonl"
    result = subprocess.run(
        ["bash", "-x", str(script)],
        env={
            "PATH": os.environ["PATH"],
            "KCADM_PATH": str(stub),
            "KEYCLOAK_SETUP_STRICT": "true",
            "KEYCLOAK_USER_REGISTRATION_ENABLED": "true",
            "KEYCLOAK_VERIFY_EMAIL": "false",
            "KEYCLOAK_RESET_PASSWORD_ENABLED": "false",
            "TEST_READBACK": readback,
            "TEST_READBACK_SEQUENCE": json.dumps(readbacks or []),
            "TEST_UPDATE_EXIT": str(update_exit),
            "TEST_CALLS": str(calls_path),
            **settings,
        },
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    calls = [json.loads(line) for line in calls_path.read_text().splitlines()] if calls_path.exists() else []
    return result, calls


def test_passkeys_enable_only_after_policy_and_optional_enrollment_are_verified(tmp_path):
    result, calls = run_setup(
        tmp_path, "configure_passkey_login", readbacks=passkey_readbacks(),
        KEYCLOAK_PASSKEYS_ENABLED="true", KEYCLOAK_PASSKEY_RP_ID="login.example.test",
    )
    assert result.returncode == 0, result.stderr
    updates = [call["args"] for call in calls if call["args"][0] == "update"]
    assert len(updates) == 3
    assert 'webAuthnPolicyPasswordlessResidentKey=required' in updates[0]
    assert 'webAuthnPolicyPasswordlessUserVerificationRequirement=required' in updates[0]
    assert 'webAuthnPolicyPasswordlessSignatureAlgorithms=["ES256","RS256"]' in updates[0]
    assert updates[1][1] == 'authentication/required-actions/webauthn-register-passwordless'
    assert 'defaultAction=false' in updates[1]
    assert 'enabled=true' in updates[1]
    assert 'webAuthnPolicyPasswordlessPasskeysEnabled=true' in updates[2]
    assert all('delete' not in call['args'] for call in calls)
    assert all('browserFlow=' not in ' '.join(call['args']) for call in calls)


@pytest.mark.parametrize("index", range(2, 13))
def test_passkeys_never_claim_success_on_incomplete_or_ignored_readback(tmp_path, index):
    readbacks = passkey_readbacks()
    readbacks[index] = '{}'
    result, _ = run_setup(
        tmp_path, "configure_passkey_login", readbacks=readbacks,
        KEYCLOAK_PASSKEYS_ENABLED="true", KEYCLOAK_PASSKEY_RP_ID="login.example.test",
    )
    assert result.returncode != 0
    assert 'configured and verified' not in result.stdout


def test_passkey_rollback_only_disables_login_and_retains_policy_and_credentials(tmp_path):
    result, calls = run_setup(
        tmp_path, "configure_passkey_login",
        readbacks=[passkey_readbacks()[0], '{"webAuthnPolicyPasswordlessPasskeysEnabled":false}'],
        KEYCLOAK_PASSKEYS_ENABLED="false",
    )
    assert result.returncode == 0, result.stderr
    assert [call['args'][0] for call in calls] == ['get', 'update', 'get']
    assert calls[1]['args'] == ['update', 'realms/11id', '-s',
                              'webAuthnPolicyPasswordlessPasskeysEnabled=false']


def test_passkey_policy_readback_preserves_whitespace_inside_string_values(tmp_path):
    readbacks = passkey_readbacks()
    readbacks[8] = '{"webAuthnPolicyPasswordlessAuthenticatorAttachment":"notspecified"}'
    result, _ = run_setup(tmp_path, "configure_passkey_login", readbacks=readbacks,
                          KEYCLOAK_PASSKEYS_ENABLED="true", KEYCLOAK_PASSKEY_RP_ID="login.example.test")
    assert result.returncode != 0
    assert 'AuthenticatorAttachment' in result.stderr


def test_unselected_passkey_configuration_preserves_legacy_realms(tmp_path):
    result, calls = run_setup(tmp_path, "configure_passkey_login")
    assert result.returncode == 0
    assert calls == []


@pytest.mark.parametrize("rp", ['', 'https://login.example.test', 'login.example.test:443',
                                    'LOGIN.example.test', 'login..example.test', 'login.example.test.',
                                    '-login.example.test', 'a' * 64 + '.test'])
def test_invalid_passkey_rp_cannot_mutate_realm(tmp_path, rp):
    result, calls = run_setup(tmp_path, "configure_passkey_login",
                              KEYCLOAK_PASSKEYS_ENABLED="true", KEYCLOAK_PASSKEY_RP_ID=rp)
    assert result.returncode != 0
    assert calls == []


def test_passkey_rp_change_is_refused_before_mutation(tmp_path):
    result, calls = run_setup(
        tmp_path, "configure_passkey_login",
        readbacks=[passkey_readbacks()[0], '{"webAuthnPolicyPasswordlessRpId":"old.example.test"}',
                   '{"webAuthnPolicyPasswordlessRpId":"old.example.test"}'],
        KEYCLOAK_PASSKEYS_ENABLED="true", KEYCLOAK_PASSKEY_RP_ID="login.example.test",
    )
    assert result.returncode != 0
    assert all(call['args'][0] == 'get' for call in calls)


@pytest.mark.parametrize("version", ["25.0.0", "26.8.1", "26.9.0"])
def test_unqualified_keycloak_version_cannot_silently_ignore_passkey_fields(tmp_path, version):
    result, calls = run_setup(tmp_path, "configure_passkey_login",
                              readback=json.dumps({"systemInfo": {"version": version}}),
                              KEYCLOAK_PASSKEYS_ENABLED="false")
    assert result.returncode != 0
    assert len(calls) == 1


@pytest.mark.parametrize("update_exit", [0, 1])
def test_login_success_requires_matching_readback_without_repeating_update(tmp_path, update_exit):
    result, calls = run_setup(tmp_path, "configure_realm_login_settings", update_exit=update_exit)
    assert result.returncode == 0, result.stderr
    assert [call["args"][0] for call in calls] == ["update", "get"]
    assert calls[1]["args"][-1] == "registrationAllowed,verifyEmail,resetPasswordAllowed"
    assert "registrationAllowed=true" in calls[0]["args"]
    assert "verifyEmail=false" in calls[0]["args"]
    assert "resetPasswordAllowed=false" in calls[0]["args"]
    assert "configured and verified" in result.stdout


@pytest.mark.parametrize("update_exit", [0, 1])
@pytest.mark.parametrize("readback", [
    "__unavailable__",
    "",
    "{}",
    '{"registrationAllowed":false,"verifyEmail":false,"resetPasswordAllowed":false}',
    '{"registrationAllowed":true,"verifyEmail":false}',
    '{"registrationAllowed":"true","verifyEmail":false,"resetPasswordAllowed":false}',
    '{"registrationAllowed":true,"registrationAllowed":true,"resetPasswordAllowed":false}',
    '{"registrationAllowed":trueish,"verifyEmail":false,"resetPasswordAllowed":false}',
])
def test_unknown_incomplete_or_mismatching_login_policy_fails(tmp_path, update_exit, readback):
    result, calls = run_setup(tmp_path, "configure_realm_login_settings", readback=readback, update_exit=update_exit)
    assert result.returncode != 0
    assert [call["args"][0] for call in calls] == ["update", "get"]
    assert "configured and verified" not in result.stdout


def test_explicit_closed_registration_and_email_policy_are_preserved(tmp_path):
    result, calls = run_setup(
        tmp_path,
        "configure_realm_login_settings",
        readback='{ "resetPasswordAllowed": true, "registrationAllowed": false, "verifyEmail": true }',
        KEYCLOAK_USER_REGISTRATION_ENABLED="false",
        KEYCLOAK_VERIFY_EMAIL="true",
        KEYCLOAK_RESET_PASSWORD_ENABLED="true",
    )
    assert result.returncode == 0, result.stderr
    assert "registrationAllowed=false" in calls[0]["args"]
    assert "verifyEmail=true" in calls[0]["args"]
    assert "resetPasswordAllowed=true" in calls[0]["args"]


@pytest.mark.parametrize("update_exit", [0, 1])
@pytest.mark.parametrize("provider", ["google", "smtp", "api"])
def test_provider_credentials_use_private_removed_payload_and_never_logs_or_argv(tmp_path, provider, update_exit):
    credential = 'fixture-private-credential-"quoted"-\\literal'
    if provider == "google":
        function = "configure_google_idp"
        settings = {"KEYCLOAK_SOCIAL_LOGIN_ENABLED": "true", "GOOGLE_CLIENT_ID": "fixture-private-client-id", "GOOGLE_CLIENT_SECRET": credential}
        expected = {"enabled": True, "config": {"clientId": settings["GOOGLE_CLIENT_ID"], "clientSecret": credential}}
    elif provider == "smtp":
        function = "configure_realm_smtp_settings"
        settings = {"KEYCLOAK_SMTP_HOST": "mail.example.test", "KEYCLOAK_SMTP_PORT": "587", "KEYCLOAK_SMTP_FROM": "accounts@example.test", "KEYCLOAK_SMTP_FROM_DISPLAY_NAME": 'Account "Support"', "KEYCLOAK_SMTP_USERNAME": "fixture-private-smtp-user", "KEYCLOAK_SMTP_PASSWORD": credential, "KEYCLOAK_SMTP_STARTTLS": "true", "KEYCLOAK_SMTP_SSL": "false"}
        expected = {"smtpServer": {"host": settings["KEYCLOAK_SMTP_HOST"], "port": "587", "from": settings["KEYCLOAK_SMTP_FROM"], "fromDisplayName": settings["KEYCLOAK_SMTP_FROM_DISPLAY_NAME"], "auth": "true", "ssl": "false", "starttls": "true", "user": settings["KEYCLOAK_SMTP_USERNAME"], "password": credential}}
    else:
        function = "get_client_uuid() { echo retained-api-client; }; configure_marty_api_secret"
        settings = {"MARTY_API_CLIENT_SECRET": credential}
        expected = {"secret": credential}
    readbacks = [json.dumps({"config": {"prompt": "consent", "clientSecret": credential}}),
                 '{"enabled":true}'] if provider == "google" else None
    result, calls = run_setup(tmp_path, function, readback='{"enabled":true}', readbacks=readbacks, update_exit=update_exit, **settings)
    assert (result.returncode == 0) == (update_exit == 0), result.stderr
    expected_count = (3 if update_exit == 0 else 2) if provider == "google" else 1
    assert len(calls) == expected_count
    mutation = next(call for call in calls if "payload" in call)
    assert mutation["payload"] == expected
    assert "--merge" in mutation["args"]
    assert not Path(mutation["payload_path"]).exists()
    combined = result.stdout + result.stderr + json.dumps(mutation["args"])
    assert "fixture-private" not in combined


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("readback", ['{"enabled":true}', '{"enabled":false}', '{}', '__unavailable__'])
def test_google_enablement_requires_effective_readback(tmp_path, enabled, readback):
    result, calls = run_setup(
        tmp_path,
        "configure_google_idp",
        readback=readback,
        readbacks=['{"config":{"prompt":"consent"}}', readback] if enabled else None,
        KEYCLOAK_SOCIAL_LOGIN_ENABLED=str(enabled).lower(),
        GOOGLE_CLIENT_ID="fixture-private-client-id" if enabled else "",
        GOOGLE_CLIENT_SECRET="fixture-private-secret" if enabled else "",
    )
    assert (result.returncode == 0) == (readback == json.dumps({"enabled": enabled}, separators=(",", ":")))
    assert [call["args"][0] for call in calls] == (["get", "update", "get"] if enabled else ["update", "get"])
    assert "fixture-private" not in result.stdout + result.stderr


def test_google_disable_failure_is_not_reported_as_success(tmp_path):
    result, calls = run_setup(tmp_path, "configure_google_idp", update_exit=1, KEYCLOAK_SOCIAL_LOGIN_ENABLED="false")
    assert result.returncode != 0
    assert len(calls) == 1


@pytest.mark.parametrize("config", [{}, {"prompt": ""}, {"prompt": None}])
@pytest.mark.parametrize("final", ['{"config":{"prompt":"select_account"}}', '{"config":{}}', '__unavailable__'])
def test_google_default_prompt_requires_verified_supported_value(tmp_path, config, final):
    result, calls = run_setup(tmp_path, "configure_google_idp",
        readbacks=[json.dumps({"config": config}), '{"enabled":true}', final],
        GOOGLE_CLIENT_ID="synthetic", GOOGLE_CLIENT_SECRET="fixture-private-secret")
    assert (result.returncode == 0) == (final == '{"config":{"prompt":"select_account"}}')
    assert calls[1]["payload"]["config"]["prompt"] == "select_account"
    assert "fixture-private" not in result.stdout + result.stderr


@pytest.mark.parametrize("config", ['{}', '__unavailable__'])
def test_google_does_not_write_when_existing_config_cannot_be_read(tmp_path, config):
    result, calls = run_setup(tmp_path, "configure_google_idp", readback=config,
        GOOGLE_CLIENT_ID="synthetic", GOOGLE_CLIENT_SECRET="fixture-private-secret")
    assert result.returncode != 0
    assert [call["args"][0] for call in calls] == ["get"]


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("final", ["matching", "mismatching", "__unavailable__"])
def test_browser_flow_alignment_requires_its_realm_dependency_and_effective_readback(tmp_path, enabled, final):
    desired = "ALTERNATIVE" if enabled else "DISABLED"
    prior = "DISABLED" if enabled else "ALTERNATIVE"
    readbacks = ['{"organizationsEnabled":true}'] if enabled else []
    readbacks += [json.dumps({"requirement": prior}),
                  json.dumps({"requirement": desired if final == "matching" else prior})
                  if final != "__unavailable__" else final]
    result, calls = run_setup(
        tmp_path,
        'get_browser_execution_id_by_display_name() { echo retained-organization-execution; }; configure_browser_flow_alignment',
        readbacks=readbacks,
        KEYCLOAK_ORGANIZATION_IDENTITY_FIRST_ENABLED=str(enabled).lower(),
    )
    assert (result.returncode == 0) == (final == "matching"), result.stderr
    if enabled:
        assert "organizationsEnabled=true" in calls[0]["args"]
        assert calls[1]["args"][-1] == "organizationsEnabled"
    assert sum("requirement=" + desired in call["args"] for call in calls) == 1


def test_identity_first_login_cannot_succeed_with_disabled_realm_organizations(tmp_path):
    result, calls = run_setup(tmp_path, "configure_browser_flow_alignment",
                              readback='{"organizationsEnabled":false}',
                              KEYCLOAK_ORGANIZATION_IDENTITY_FIRST_ENABLED="true")
    assert result.returncode != 0
    assert len(calls) == 2


@pytest.mark.parametrize("enabled", [False, True])
def test_absent_browser_execution_only_allows_disabled_identity_first_login(tmp_path, enabled):
    result, _ = run_setup(
        tmp_path,
        'get_browser_execution_id_by_display_name() { :; }; configure_browser_flow_alignment',
        readback='{"organizationsEnabled":true}',
        KEYCLOAK_ORGANIZATION_IDENTITY_FIRST_ENABLED=str(enabled).lower(),
    )
    assert (result.returncode == 0) == (not enabled)


@pytest.mark.parametrize("client", ["ui", "api"])
def test_required_client_missing_fails_configuration(tmp_path, client):
    function = "configure_marty_ui_redirect_uris" if client == "ui" else "configure_marty_api_secret"
    result, calls = run_setup(tmp_path, "get_client_uuid() { :; }; " + function,
                              MARTY_API_CLIENT_SECRET="fixture-private-api-secret", UI_BASE_URL="https://identity.example.test")
    assert result.returncode != 0
    assert calls == []
    assert "fixture-private" not in result.stdout + result.stderr


@pytest.mark.parametrize("readback", ["matching", "[]", "__unavailable__"])
def test_identity_first_organization_uses_literal_name_and_verified_creation(tmp_path, readback):
    name = 'Acme [Europe] "Accounts"'
    final = json.dumps([{"name": name}]) if readback == "matching" else readback
    result, calls = run_setup(
        tmp_path, "ensure_marty_org_exists", readbacks=["[]", final],
        MARTY_ORG_NAME=name, MARTY_ORG_DOMAIN="identity.example.test",
        KEYCLOAK_ORGANIZATION_IDENTITY_FIRST_ENABLED="true",
    )
    assert (result.returncode == 0) == (readback == "matching"), result.stderr
    assert [call["args"][0] for call in calls] == ["get", "create", "get"]
    assert calls[1]["payload"]["name"] == name
    assert not Path(calls[1]["payload_path"]).exists()


def test_identity_first_cannot_ignore_organization_creation_failure(tmp_path):
    result, calls = run_setup(tmp_path, "ensure_marty_org_exists", readback="[]", update_exit=1,
                              KEYCLOAK_ORGANIZATION_IDENTITY_FIRST_ENABLED="true")
    assert result.returncode != 0
    assert [call["args"][0] for call in calls] == ["get", "create"]
    assert not Path(calls[1]["payload_path"]).exists()


def test_production_compose_propagates_configuration_failure_through_real_wrapper(tmp_path):
    model = yaml.safe_load((ROOT / "docker-compose.selfhost.prod.yml").read_text())
    configured = model["services"]["keycloak-configurator"]["environment"]
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    setup = scripts / "setup-keycloak.sh"
    setup.write_text("#!/bin/sh\nexit 1\n")
    setup.chmod(0o700)
    (scripts / "load-secrets-env.sh").write_bytes((ROOT / "scripts/load-secrets-env.sh").read_bytes())
    wrapper = scripts / "wrapper.sh"
    wrapper.write_text((ROOT / "scripts/setup-keycloak-selfhost-production.sh").read_text().replace("/scripts/", str(scripts) + "/"))
    result = subprocess.run(
        ["bash", str(wrapper)],
        env={"PATH": os.environ["PATH"], "KEYCLOAK_SETUP_STRICT": configured.get("KEYCLOAK_SETUP_STRICT", "false"),
             "KEYCLOAK_ADMIN_PASSWORD": "fixture-private-admin", "MARTY_API_CLIENT_SECRET": "fixture-private-api",
             "KEYCLOAK_REMOVE_DEMO_USERS": "false"},
        capture_output=True, text=True, check=False, timeout=10,
    )
    assert result.returncode == 1
    assert "Keycloak setup failed and KEYCLOAK_SETUP_STRICT=true" in result.stderr
    assert "fixture-private" not in result.stdout + result.stderr
