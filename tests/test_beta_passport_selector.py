"""The beta passport selector is opt-in and rejects raw-key or partial KMS modes."""

import json
import os
from pathlib import Path
import re
import runpy
import shutil
import sqlite3
import subprocess
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = runpy.run_path(
    str(ROOT / "scripts/validate_beta_passport_configuration.py")
)
PROFILE = "docker-compose.profile.passport-native-beta.yml"
IMAGE = "ghcr.io/elevenid/marty-ui-oss/services@sha256:" + "a" * 64
TOKEN = "synthetic-internal-passport-token-00000001"
RECONCILIATION_TOKEN = "synthetic-beta-reconciliation-operator-token-00000001"
DSC_GATEWAY_KEY = "synthetic-dsc-gateway-only-credential-000001"
CSCA_GATEWAY_KEY = "synthetic-csca-gateway-only-credential-00001"


def model(tmp_path, enabled=True):
    services = {
        name: {"environment": {}, "secrets": []}
        for name in ("gateway", "flow", "issuance-native")
    }
    for service, flag in (
        ("gateway", "PASSPORT_NATIVE_GATEWAY_ENABLED"),
        ("flow", "PASSPORT_NATIVE_FLOW_ENABLED"),
        ("issuance-native", "PASSPORT_NATIVE_HTTP_ENABLED"),
    ):
        services[service]["environment"][flag] = str(enabled).lower()
    result = {"services": services, "secrets": {}}
    if not enabled:
        return result
    for service in services.values():
        service["environment"].update(
            {
                "PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED": "true",
                "PASSPORT_TENANT_API_KEYS": "",
                "PASSPORT_TENANT_API_KEYS_FILE": "",
                "GRPC_SERVICE_TOKEN": TOKEN,
            }
        )
    services["flow"]["environment"]["ISSUANCE_NATIVE_SERVICE_URL"] = (
        "http://issuance-native:8005"
    )
    services["issuance-native"]["environment"].update(
        {
            "ENVIRONMENT": "beta",
            "PASSPORT_BETA_RECONCILIATION_ENABLED": "true",
            "PASSPORT_BETA_RECONCILIATION_OPERATOR_TOKEN": RECONCILIATION_TOKEN,
            "PASSPORT_MANAGED_ISSUER_SIGNING_ENABLED": "true",
            "PASSPORT_KMS_ARTIFACTS_ENABLED": "true",
            "PASSPORT_KMS_CALLBACKS_ENABLED": "true",
            "PHYSICAL_DOCUMENT_ALLOW_SELF_SIGNED": "false",
            "ICAO_DOCUMENT_SIGNER_URL": "",
            "PERSONALIZATION_BUREAU_URL": VALIDATOR["PRIVATE_BUREAU_URL"],
            "PERSONALIZATION_BUREAU_API_KEY": TOKEN,
            "SIGNING_KEYS_INTERNAL_API_KEY": "synthetic-signing-credential",
            "DATABASE_URL": "postgresql://marty:synthetic@postgres:5432/marty",
        }
    )
    services["gateway"]["environment"]["SIGNING_KEYS_INTERNAL_API_KEY"] = (
        "synthetic-signing-credential"
    )
    services["gateway"]["environment"]["PASSPORT_PROVIDER_INGRESS_GATEWAY_ENABLED"] = "false"
    services["signing-keys"] = {
        "environment": {
            "ENVIRONMENT": "beta",
            "SIGNING_KEYS_INTERNAL_API_KEY": "synthetic-signing-credential",
            "SIGNING_KEYS_BETA_CSCA_ISSUANCE_ENABLED": "true",
            "BAO_TOKEN": "synthetic-existing-openbao-token",
        }
    }
    services["openbao"] = {
        "environment": {},
        "networks": {"marty-network": None, "passport-callback-signing": None},
    }
    services["passport-callback-signer"] = {
        "image": IMAGE,
        "environment": {
            "SERVICE_NAME": "passport_callback_signer",
            "ENVIRONMENT": "beta",
            "PASSPORT_CALLBACK_SIGNER_ENABLED": "true",
            "SIGNING_KEYS_SERVICE_PORT": "8018",
            "SIGNING_KEYS_INTERNAL_API_KEY": "synthetic-signing-credential",
            "BAO_ADDR": "http://openbao:8200",
            "BAO_TOKEN": "synthetic-existing-openbao-token",
        },
        "networks": {"passport-callback-signing": None},
    }
    services["passport-beta-bureau"] = {
        "image": IMAGE,
        "environment": {
            "SERVICE_NAME": "passport_beta_bureau",
            "ENVIRONMENT": "beta",
            "PASSPORT_BETA_BUREAU_ENABLED": "true",
            "DATABASE_URL": "postgresql://marty:synthetic@postgres:5432/marty",
            "GRPC_SERVICE_TOKEN": TOKEN,
            "SIGNING_KEYS_INTERNAL_API_KEY": "synthetic-signing-credential",
            "SIGNING_KEYS_INTERNAL_URL": VALIDATOR["PRIVATE_SIGNING_URL"],
            "PASSPORT_BETA_BUREAU_GATEWAY_CALLBACK_ENABLED": "true",
            "PASSPORT_BUREAU_CALLBACK_URL": VALIDATOR["PRIVATE_GATEWAY_CALLBACK_URL"],
        },
        "networks": {"marty-network": None, "passport-callback-signing": None},
    }
    result["networks"] = {"passport-callback-signing": {"internal": True}}
    root = tmp_path / "elevenid-beta-passport-ceremony"
    root.mkdir(exist_ok=True)
    for purpose, value in (("dsc", DSC_GATEWAY_KEY),
                           ("csca", CSCA_GATEWAY_KEY)):
        name = f"{purpose}_issue_gateway_key"
        source = root / name
        source.write_text(value, encoding="ascii")
        result["secrets"][name] = {"file": str(source)}
        key = f"SIGNING_KEYS_{purpose.upper()}_ISSUE_GATEWAY_KEY"
        for holder in ("gateway", "signing-keys"):
            service = result["services"][holder]
            service["environment"][f"{key}_FILE"] = f"/run/secrets/{name}"
            service.setdefault("secrets", []).append(
                {"source": name, "target": name})
    return result


def validate(candidate, enabled=True):
    VALIDATOR["validate_model"](
        candidate,
        passport_enabled=enabled,
        files=[PROFILE] if enabled else ["base.yml"],
    )


@pytest.mark.parametrize("mutation", [
    "wrong_target", "other_holder", "inline_key", "same_key", "missing_file",
    "other_setting", "line_ending", "wrong_root", "wrong_source",
    "wrong_mount_target", "inline_only", "secret_alias",
])
def test_file_operator_credentials_are_holder_scoped(tmp_path, mutation):
    candidate = model(tmp_path)
    validate(candidate)
    services = candidate["services"]
    secrets = candidate["secrets"]
    csca = secrets["csca_issue_gateway_key"]["file"]
    if mutation == "wrong_target":
        services["gateway"]["environment"][
            "SIGNING_KEYS_CSCA_ISSUE_GATEWAY_KEY_FILE"] = "/run/secrets/other"
    elif mutation == "other_holder":
        services["flow"]["secrets"].append({"source": "csca_issue_gateway_key"})
    elif mutation == "inline_key":
        services["gateway"]["environment"][
            "SIGNING_KEYS_CSCA_ISSUE_GATEWAY_KEY"] = CSCA_GATEWAY_KEY
    elif mutation == "same_key":
        Path(csca).write_text(DSC_GATEWAY_KEY, encoding="ascii")
    elif mutation == "missing_file":
        Path(csca).unlink()
    elif mutation == "other_setting":
        services["flow"]["environment"]["OTHER_SECRET"] = CSCA_GATEWAY_KEY
    elif mutation == "line_ending":
        Path(csca).write_text(CSCA_GATEWAY_KEY + "\n", encoding="ascii")
    elif mutation == "wrong_root":
        source = tmp_path / "csca_issue_gateway_key"
        source.write_text(CSCA_GATEWAY_KEY, encoding="ascii")
        secrets["csca_issue_gateway_key"]["file"] = str(source)
    elif mutation == "wrong_source":
        secrets["csca_issue_gateway_key"]["file"] = secrets[
            "dsc_issue_gateway_key"]["file"]
    elif mutation == "wrong_mount_target":
        services["gateway"]["secrets"][1]["target"] = "other"
    elif mutation == "inline_only":
        for holder in ("gateway", "signing-keys"):
            env = services[holder]["environment"]
            env.pop("SIGNING_KEYS_DSC_ISSUE_GATEWAY_KEY_FILE")
            env.pop("SIGNING_KEYS_CSCA_ISSUE_GATEWAY_KEY_FILE")
            env["SIGNING_KEYS_DSC_ISSUE_GATEWAY_KEY"] = DSC_GATEWAY_KEY
            env["SIGNING_KEYS_CSCA_ISSUE_GATEWAY_KEY"] = CSCA_GATEWAY_KEY
    elif mutation == "secret_alias":
        secrets["csca_alias"] = {"file": csca}
        services["flow"]["secrets"].append({"source": "csca_alias"})
    with pytest.raises(VALIDATOR["PassportConfigurationError"]):
        validate(candidate)


def test_opt_in_kms_only_and_bureau_is_absent_when_disabled(tmp_path):
    validate(model(tmp_path))
    validate(model(tmp_path, False), False)
    with pytest.raises(VALIDATOR["PassportConfigurationError"]):
        VALIDATOR["validate_model"](model(tmp_path), passport_enabled=False, files=[PROFILE])


@pytest.mark.parametrize("operator_token", [None, "short", TOKEN, "synthetic-signing-credential"])
def test_beta_reconciliation_requires_a_distinct_operator_token(tmp_path, operator_token):
    candidate = model(tmp_path)
    native = candidate["services"]["issuance-native"]["environment"]
    if operator_token is None:
        native.pop("PASSPORT_BETA_RECONCILIATION_OPERATOR_TOKEN")
    else:
        native["PASSPORT_BETA_RECONCILIATION_OPERATOR_TOKEN"] = operator_token
    with pytest.raises(VALIDATOR["PassportConfigurationError"]):
        validate(candidate)


def test_beta_reconciliation_operator_token_stays_in_issuance_native(tmp_path):
    candidate = model(tmp_path)
    candidate["services"]["flow"]["environment"]["OTHER_KEY"] = RECONCILIATION_TOKEN
    with pytest.raises(VALIDATOR["PassportConfigurationError"]):
        validate(candidate)


def test_beta_csca_credential_contract_and_default_off(tmp_path):
    contract = json.loads(
        (ROOT / "contracts/passport-beta-csca-credential-isolation.json").read_text(
            encoding="utf-8"
        )
    )
    assert contract["schema"] == "marty.passport-beta-csca-credential-isolation/v1"
    assert contract["enabled"]["holders"] == ["gateway", "signing-keys"]
    profile = (ROOT / PROFILE).read_text(encoding="utf-8")
    assert (
        len(re.findall(r"^\s+SIGNING_KEYS_CSCA_ISSUE_GATEWAY_KEY_FILE:", profile, re.M)) == 2
    )
    assert 'SIGNING_KEYS_BETA_CSCA_ISSUANCE_ENABLED: "true"' in profile
    disabled = model(tmp_path, False)
    validate(disabled, False)
    disabled["services"]["gateway"]["environment"][
        "SIGNING_KEYS_CSCA_ISSUE_GATEWAY_KEY"
    ] = CSCA_GATEWAY_KEY
    with pytest.raises(VALIDATOR["PassportConfigurationError"]):
        validate(disabled, False)


def test_csca_beta_preflight_is_gated_and_precedes_mutation():
    source = (ROOT / "scripts/deploy-local-beta-release.ps1").read_text(
        encoding="utf-8"
    )
    required = source.index("$requiredFlowSecrets += @(")
    collision = source.index('foreach ($purpose in @("DSC", "CSCA"))')
    mounted = source.index(
        "foreach ($path in $workloadIdentityPaths.Values)", collision
    )
    mutate = source.index('Invoke-Checked -FilePath docker -Arguments @("pull",')
    assert source.rfind("if ($EnablePassportNative) {", 0, required) < required
    assert source.rfind("if ($EnablePassportNative) {", 0, collision) < collision
    assert source.rfind("if ($EnablePassportNative) {", 0, mounted) < mounted
    assert required < collision < mounted < mutate
    assert '"SIGNING_KEYS_CSCA_ISSUE_GATEWAY_KEY"' in source[required:collision]
    assert '"PASSPORT_BETA_CEREMONY_SECRET_DIR"' in source[required:collision]
    assert '"SIGNING_KEYS_${purpose}_ISSUE_GATEWAY_KEY"' in source[collision:mounted]


def test_rendered_compose_environment_list_is_supported(tmp_path):
    candidate = model(tmp_path)
    for service in candidate["services"].values():
        service["environment"] = [
            f"{key}={value}" for key, value in service["environment"].items()
        ]
    validate(candidate)


@pytest.mark.parametrize(
    "mutation",
    (
        "owner",
        "target",
        "internal",
        "signer_mode",
        "artifact_mode",
        "callback_mode",
        "self_signed",
        "remote_signer",
        "bureau_target",
        "tenant_key",
        "tenant_key_file",
        "artifact_key",
        "artifact_key_file",
        "callback_key",
        "callback_key_file",
        "missing_bureau",
        "token_mismatch",
        "signing_key_mismatch",
        "gateway_signing_key_mismatch",
        "service_signing_key_mismatch",
        "signing_environment_missing",
        "signing_environment_production",
        "missing_dsc_gateway_key",
        "missing_csca_gateway_key",
        "short_csca_gateway_key",
        "placeholder_csca_gateway_key",
        "mismatched_csca_gateway_key",
        "csca_flag_disabled",
        "csca_flag_on_gateway",
        "shared_csca_gateway_key",
        "csca_equals_dsc_gateway_key",
        "leaked_csca_gateway_key",
        "csca_gateway_key_file",
        "csca_key_embedded_in_connection_string",
        "shared_dsc_gateway_key",
        "leaked_dsc_gateway_key",
        "dsc_gateway_key_file",
        "dsc_key_as_issuance_credential",
        "dsc_key_as_unrelated_credential",
        "dsc_key_embedded_in_connection_string",
        "dsc_key_as_bao_token",
        "dsc_key_embedded_in_database_password",
        "dsc_key_embedded_in_redis_url",
        "dsc_key_in_service_command",
        "bureau_database_target",
        "native_database_target",
        "native_database_driver",
        "signing_route",
        "callback_route",
        "callback_direct_native",
        "callback_gateway_disabled",
        "callback_provider_ingress_selected",
        "image",
        "exposed_port",
        "network",
        "legacy_mount",
        "bureau_key_file",
        "local_build",
        "entrypoint_override",
        "missing_callback_signer",
        "callback_signer_public_network",
        "callback_signer_shared_network",
        "callback_signer_disabled",
        "callback_signer_image",
        "callback_signer_key_mismatch",
        "callback_signer_extra_member",
    ),
)
def test_partial_or_unsafe_selection_fails_closed(tmp_path, mutation):
    candidate = model(tmp_path)
    services = candidate["services"]
    native = services["issuance-native"]["environment"]
    bureau = services["passport-beta-bureau"]
    if mutation == "owner":
        services["gateway"]["environment"]["PASSPORT_NATIVE_GATEWAY_ENABLED"] = "false"
    elif mutation == "target":
        services["flow"]["environment"]["ISSUANCE_NATIVE_SERVICE_URL"] = (
            "http://issuance:8005"
        )
    elif mutation == "internal":
        services["flow"]["environment"]["PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED"] = (
            "false"
        )
    elif mutation in ("signer_mode", "artifact_mode", "callback_mode"):
        name = {
            "signer_mode": "PASSPORT_MANAGED_ISSUER_SIGNING_ENABLED",
            "artifact_mode": "PASSPORT_KMS_ARTIFACTS_ENABLED",
            "callback_mode": "PASSPORT_KMS_CALLBACKS_ENABLED",
        }[mutation]
        native[name] = "false"
    elif mutation == "self_signed":
        native["PHYSICAL_DOCUMENT_ALLOW_SELF_SIGNED"] = "true"
    elif mutation == "remote_signer":
        native["ICAO_DOCUMENT_SIGNER_URL"] = "https://signer.example.test"
    elif mutation == "bureau_target":
        native["PERSONALIZATION_BUREAU_URL"] = "https://bureau.example.test"
    elif mutation == "tenant_key":
        services["gateway"]["environment"]["PASSPORT_TENANT_API_KEYS"] = (
            "synthetic-private-value"
        )
    elif mutation == "tenant_key_file":
        services["flow"]["environment"]["PASSPORT_TENANT_API_KEYS_FILE"] = (
            "/tmp/keyring"
        )
    elif mutation == "artifact_key":
        native["PHYSICAL_DOCUMENT_ARTIFACT_KEY"] = "synthetic-private-value"
    elif mutation == "artifact_key_file":
        native["PHYSICAL_DOCUMENT_ARTIFACT_KEY_FILE"] = "/tmp/artifact"
    elif mutation == "callback_key":
        native["PERSONALIZATION_BUREAU_WEBHOOK_SECRET"] = "synthetic-private-value"
    elif mutation == "callback_key_file":
        native["PERSONALIZATION_BUREAU_WEBHOOK_SECRET_FILE"] = "/tmp/callback"
    elif mutation == "missing_bureau":
        del services["passport-beta-bureau"]
    elif mutation == "token_mismatch":
        native["PERSONALIZATION_BUREAU_API_KEY"] = "synthetic-private-value"
    elif mutation == "signing_key_mismatch":
        native["SIGNING_KEYS_INTERNAL_API_KEY"] = "synthetic-other-credential"
    elif mutation == "gateway_signing_key_mismatch":
        services["gateway"]["environment"]["SIGNING_KEYS_INTERNAL_API_KEY"] = (
            "synthetic-other-credential"
        )
    elif mutation == "service_signing_key_mismatch":
        services["signing-keys"]["environment"]["SIGNING_KEYS_INTERNAL_API_KEY"] = (
            "synthetic-other-credential"
        )
    elif mutation == "signing_environment_missing":
        del services["signing-keys"]["environment"]["ENVIRONMENT"]
    elif mutation == "signing_environment_production":
        services["signing-keys"]["environment"]["ENVIRONMENT"] = "production"
    elif mutation == "missing_dsc_gateway_key":
        del services["gateway"]["environment"]["SIGNING_KEYS_DSC_ISSUE_GATEWAY_KEY_FILE"]
    elif mutation == "missing_csca_gateway_key":
        del services["gateway"]["environment"]["SIGNING_KEYS_CSCA_ISSUE_GATEWAY_KEY_FILE"]
    elif mutation == "short_csca_gateway_key":
        Path(candidate["secrets"]["csca_issue_gateway_key"]["file"]).write_text(
            "short", encoding="ascii")
    elif mutation == "placeholder_csca_gateway_key":
        Path(candidate["secrets"]["csca_issue_gateway_key"]["file"]).write_text(
            "change-me-csca-operator-credential-00001", encoding="ascii")
    elif mutation == "mismatched_csca_gateway_key":
        services["signing-keys"]["environment"][
            "SIGNING_KEYS_CSCA_ISSUE_GATEWAY_KEY_FILE"
        ] = "/run/secrets/other"
    elif mutation == "csca_flag_disabled":
        services["signing-keys"]["environment"][
            "SIGNING_KEYS_BETA_CSCA_ISSUANCE_ENABLED"
        ] = "false"
    elif mutation == "csca_flag_on_gateway":
        services["gateway"]["environment"][
            "SIGNING_KEYS_BETA_CSCA_ISSUANCE_ENABLED"
        ] = "true"
    elif mutation == "shared_csca_gateway_key":
        Path(candidate["secrets"]["csca_issue_gateway_key"]["file"]).write_text(
            "synthetic-signing-credential", encoding="ascii")
    elif mutation == "csca_equals_dsc_gateway_key":
        Path(candidate["secrets"]["csca_issue_gateway_key"]["file"]).write_text(
            DSC_GATEWAY_KEY, encoding="ascii")
    elif mutation == "leaked_csca_gateway_key":
        services["flow"]["environment"]["SIGNING_KEYS_CSCA_ISSUE_GATEWAY_KEY"] = (
            CSCA_GATEWAY_KEY
        )
    elif mutation == "csca_gateway_key_file":
        services["issuance-native"]["environment"][
            "SIGNING_KEYS_CSCA_ISSUE_GATEWAY_KEY_FILE"
        ] = "/tmp/csca-gateway-key"
    elif mutation == "csca_key_embedded_in_connection_string":
        services["flow"]["environment"]["OTHER_SERVICE_URL"] = (
            f"https://service.example/?token={CSCA_GATEWAY_KEY}"
        )
    elif mutation == "shared_dsc_gateway_key":
        Path(candidate["secrets"]["dsc_issue_gateway_key"]["file"]).write_text(
            "synthetic-signing-credential", encoding="ascii")
    elif mutation == "leaked_dsc_gateway_key":
        services["flow"]["environment"]["SIGNING_KEYS_DSC_ISSUE_GATEWAY_KEY"] = (
            DSC_GATEWAY_KEY
        )
    elif mutation == "dsc_gateway_key_file":
        services["issuance-native"]["environment"][
            "SIGNING_KEYS_DSC_ISSUE_GATEWAY_KEY_FILE"
        ] = "/tmp/dsc-gateway-key"
    elif mutation == "dsc_key_as_issuance_credential":
        services["issuance-native"]["environment"]["ISSUANCE_API_KEY"] = DSC_GATEWAY_KEY
    elif mutation == "dsc_key_as_unrelated_credential":
        services["flow"]["environment"]["OTHER_SERVICE_CREDENTIAL"] = DSC_GATEWAY_KEY
    elif mutation == "dsc_key_embedded_in_connection_string":
        services["flow"]["environment"]["OTHER_SERVICE_URL"] = (
            f"https://service.example/?token={DSC_GATEWAY_KEY}"
        )
    elif mutation == "dsc_key_as_bao_token":
        services["signing-keys"]["environment"]["BAO_TOKEN"] = DSC_GATEWAY_KEY
        services["passport-callback-signer"]["environment"]["BAO_TOKEN"] = (
            DSC_GATEWAY_KEY
        )
    elif mutation == "dsc_key_embedded_in_database_password":
        for name in ("issuance-native", "passport-beta-bureau"):
            database_url = services[name]["environment"]["DATABASE_URL"]
            services[name]["environment"]["DATABASE_URL"] = database_url.replace(
                ":synthetic@", f":{DSC_GATEWAY_KEY}@"
            )
    elif mutation == "dsc_key_embedded_in_redis_url":
        services["signing-keys"]["environment"]["SIGNING_KEYS_REDIS_URL"] = (
            f"redis://:{DSC_GATEWAY_KEY}@redis:6379/2"
        )
    elif mutation == "dsc_key_in_service_command":
        services["openbao"]["command"] = ["server", f"--token={DSC_GATEWAY_KEY}"]
    elif mutation == "bureau_database_target":
        bureau["environment"]["DATABASE_URL"] = (
            "postgresql://marty:synthetic@production.example:5432/marty"
        )
    elif mutation == "native_database_target":
        native["DATABASE_URL"] = "postgresql://marty:other@postgres:5432/marty"
    elif mutation == "native_database_driver":
        native["DATABASE_URL"] = "postgresql+asyncpg://marty:synthetic@postgres:5432/marty"
    elif mutation == "signing_route":
        bureau["environment"]["SIGNING_KEYS_INTERNAL_URL"] = (
            "https://public.example.test"
        )
    elif mutation == "callback_route":
        bureau["environment"]["PASSPORT_BUREAU_CALLBACK_URL"] = (
            "https://public.example.test"
        )
    elif mutation == "callback_direct_native":
        bureau["environment"]["PASSPORT_BUREAU_CALLBACK_URL"] = (
            VALIDATOR["PRIVATE_CALLBACK_URL"]
        )
    elif mutation == "callback_gateway_disabled":
        bureau["environment"]["PASSPORT_BETA_BUREAU_GATEWAY_CALLBACK_ENABLED"] = "false"
    elif mutation == "callback_provider_ingress_selected":
        services["gateway"]["environment"]["PASSPORT_PROVIDER_INGRESS_GATEWAY_ENABLED"] = "true"
    elif mutation == "image":
        bureau["image"] = "services:latest"
    elif mutation == "exposed_port":
        bureau["ports"] = ["8020:8020"]
    elif mutation == "network":
        bureau["networks"] = {"default": None}
    elif mutation == "legacy_mount":
        candidate["secrets"]["passport_tenant_api_keys"] = {"file": "/tmp/keyring"}
    elif mutation == "bureau_key_file":
        native["PERSONALIZATION_BUREAU_API_KEY_FILE"] = "/tmp/bureau"
    elif mutation == "local_build":
        bureau["build"] = "."
    elif mutation == "entrypoint_override":
        bureau["entrypoint"] = ["sh", "-c", "true"]
    elif mutation == "missing_callback_signer":
        del services["passport-callback-signer"]
    elif mutation == "callback_signer_public_network":
        candidate["networks"]["passport-callback-signing"]["internal"] = False
    elif mutation == "callback_signer_shared_network":
        services["passport-callback-signer"]["networks"]["marty-network"] = None
    elif mutation == "callback_signer_disabled":
        services["passport-callback-signer"]["environment"][
            "PASSPORT_CALLBACK_SIGNER_ENABLED"
        ] = "false"
    elif mutation == "callback_signer_image":
        services["passport-callback-signer"]["image"] = "services:latest"
    elif mutation == "callback_signer_key_mismatch":
        services["passport-callback-signer"]["environment"][
            "SIGNING_KEYS_INTERNAL_API_KEY"
        ] = "another-key"
    elif mutation == "callback_signer_extra_member":
        services["gateway"]["networks"] = {"passport-callback-signing": None}
    with pytest.raises(VALIDATOR["PassportConfigurationError"]) as error:
        validate(candidate)
    if mutation in {
        "dsc_key_as_issuance_credential",
        "dsc_key_as_unrelated_credential",
        "dsc_key_embedded_in_connection_string",
        "dsc_key_as_bao_token",
        "dsc_key_embedded_in_database_password",
        "dsc_key_embedded_in_redis_url",
        "dsc_key_in_service_command",
        "csca_key_embedded_in_connection_string",
    }:
        purpose = (
            "CSCA" if mutation == "csca_key_embedded_in_connection_string" else "DSC"
        )
        assert (
            str(error.value)
            == f"Beta {purpose} operator credential isolation is invalid"
        )
    assert "synthetic-private-value" not in str(error.value)


def test_mounted_secret_cannot_reuse_dsc_gateway_credential(tmp_path):
    candidate = model(tmp_path)
    mounted = tmp_path / "flow-secret"
    mounted.write_text(f"prefix:{DSC_GATEWAY_KEY}:suffix", encoding="utf-8")
    candidate["secrets"]["flow-secret"] = {"file": str(mounted)}
    candidate["services"]["flow"]["secrets"].append({"source": "flow-secret"})
    with pytest.raises(
        VALIDATOR["PassportConfigurationError"],
        match="Beta DSC operator credential isolation is invalid",
    ):
        validate(candidate)
    mounted.unlink()
    with pytest.raises(
        VALIDATOR["PassportConfigurationError"],
        match="cannot verify mounted files",
    ):
        validate(candidate)


@pytest.mark.parametrize("service_name", ["gateway", "signing-keys", "flow"])
def test_mounted_secret_cannot_reuse_csca_gateway_credential(tmp_path, service_name):
    candidate = model(tmp_path)
    mounted = tmp_path / "csca-credential"
    mounted.write_text(f"prefix:{CSCA_GATEWAY_KEY}:suffix", encoding="utf-8")
    candidate["secrets"]["csca-credential"] = {"file": str(mounted)}
    candidate["services"][service_name].setdefault("secrets", []).append(
        {"source": "csca-credential"})
    with pytest.raises(
        VALIDATOR["PassportConfigurationError"],
        match="Beta CSCA operator credential isolation is invalid",
    ):
        validate(candidate)


@pytest.mark.parametrize("source_kind", ["file", "external", "missing", "oversize"])
def test_non_owner_compose_config_is_scanned_or_rejected(tmp_path, source_kind):
    candidate = model(tmp_path)
    mounted = tmp_path / "flow-config"
    if source_kind == "file":
        mounted.write_text(f"credential={DSC_GATEWAY_KEY}", encoding="utf-8")
    elif source_kind == "oversize":
        mounted.write_bytes(b"x" * (VALIDATOR["MAX_MOUNT_FILE_BYTES"] + 1))
    candidate["configs"] = {
        "flow-config": (
            {"external": True} if source_kind == "external" else {"file": str(mounted)}
        )
    }
    candidate["services"]["flow"]["configs"] = [
        {"source": "flow-config", "target": "/run/config/flow"}
    ]
    expected = "is invalid" if source_kind == "file" else "cannot verify mounted files"
    with pytest.raises(VALIDATOR["PassportConfigurationError"], match=expected):
        validate(candidate)


def test_non_owner_compose_config_unknown_source_fails_closed(tmp_path):
    candidate = model(tmp_path)
    candidate["services"]["flow"]["configs"] = [{"source": "unknown"}]
    with pytest.raises(
        VALIDATOR["PassportConfigurationError"], match="cannot verify mounted files"
    ):
        validate(candidate)


def test_file_backed_compose_config_without_credential_is_allowed(tmp_path):
    candidate = model(tmp_path)
    mounted = tmp_path / "flow-config"
    mounted.write_text("ordinary configuration", encoding="utf-8")
    candidate["configs"] = {"flow-config": {"file": str(mounted)}}
    candidate["services"]["flow"]["configs"] = ["flow-config"]
    validate(candidate)


def test_csca_credential_in_owner_bind_mount_is_rejected(tmp_path):
    candidate = model(tmp_path)
    mounted = tmp_path / "gateway-config"
    mounted.write_text(f"credential={CSCA_GATEWAY_KEY}", encoding="utf-8")
    candidate["services"]["gateway"]["volumes"] = [
        {"type": "bind", "source": str(mounted), "target": "/config"}
    ]
    with pytest.raises(
        VALIDATOR["PassportConfigurationError"],
        match="Beta CSCA operator credential isolation is invalid",
    ):
        validate(candidate)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("healthcheck", {"test": ["CMD", "check", DSC_GATEWAY_KEY]}),
        ("labels", {"operator-credential": DSC_GATEWAY_KEY}),
        ("labels", {DSC_GATEWAY_KEY: "enabled"}),
        ("logging", {"options": {"token": DSC_GATEWAY_KEY}}),
    ],
)
def test_non_owner_rendered_metadata_cannot_reuse_dsc_credential(tmp_path, field, value):
    candidate = model(tmp_path)
    candidate["services"]["flow"][field] = value
    with pytest.raises(
        VALIDATOR["PassportConfigurationError"],
        match="Beta DSC operator credential isolation is invalid",
    ):
        validate(candidate)


@pytest.mark.parametrize("kind", ["file", "directory"])
def test_bind_mount_cannot_reuse_dsc_gateway_credential(tmp_path, kind):
    candidate = model(tmp_path)
    source = tmp_path / "non-owner-config"
    if kind == "directory":
        source.mkdir()
        mounted = source / "credentials.json"
    else:
        mounted = source
    mounted.write_text(f'{{"token":"{DSC_GATEWAY_KEY}"}}', encoding="utf-8")
    candidate["services"]["flow"]["volumes"] = [
        {"type": "bind", "source": str(source), "target": "/config"}
    ]
    with pytest.raises(
        VALIDATOR["PassportConfigurationError"],
        match="Beta DSC operator credential isolation is invalid",
    ):
        validate(candidate)


@pytest.mark.parametrize("failure", ["missing", "oversize", "too_many"])
def test_bind_mount_scan_fails_closed_with_fixed_error(tmp_path, failure):
    candidate = model(tmp_path)
    source = tmp_path / "non-owner-config"
    if failure == "oversize":
        source.write_bytes(b"x" * (VALIDATOR["MAX_MOUNT_FILE_BYTES"] + 1))
    elif failure == "too_many":
        source.mkdir()
        for index in range(VALIDATOR["MAX_MOUNT_FILES"] + 1):
            (source / f"file-{index}").write_bytes(b"x")
    candidate["services"]["flow"]["volumes"] = [
        {"type": "bind", "source": str(source), "target": "/config"}
    ]
    with pytest.raises(
        VALIDATOR["PassportConfigurationError"],
        match="cannot verify mounted files",
    ) as error:
        validate(candidate)
    assert DSC_GATEWAY_KEY not in str(error.value)


def test_named_volume_is_not_treated_as_a_host_bind(tmp_path):
    candidate = model(tmp_path)
    candidate["services"]["flow"]["volumes"] = [
        {"type": "volume", "source": "flow-data", "target": "/data"}
    ]
    validate(candidate)


@pytest.mark.parametrize("link_location", ["source", "child"])
def test_bind_mount_symlink_fails_closed(tmp_path, link_location):
    candidate = model(tmp_path)
    target = tmp_path / "safe-config"
    target.write_text("public fixture", encoding="utf-8")
    source = tmp_path / "mounted"
    try:
        if link_location == "source":
            source.symlink_to(target)
        else:
            source.mkdir()
            (source / "linked-config").symlink_to(target)
    except OSError:
        pytest.skip("host does not permit test symlinks")
    candidate["services"]["flow"]["volumes"] = [
        {"type": "bind", "source": str(source), "target": "/config"}
    ]
    with pytest.raises(
        VALIDATOR["PassportConfigurationError"],
        match="cannot verify mounted files",
    ):
        validate(candidate)


def test_compose_call_is_read_only_and_closed(tmp_path):
    candidate = model(tmp_path)
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=0, stdout=json.dumps(candidate).encode())

    VALIDATOR["validate_compose"](
        project="elevenid-beta",
        env_files=["synthetic.env"],
        files=[PROFILE],
        passport_enabled=True,
        runner=run,
    )
    command, kwargs = calls[0]
    assert command[-3:] == ["config", "--format", "json"]
    assert kwargs["stdin"] is not None and kwargs["stderr"] is not None


@pytest.mark.parametrize("failure", ("exit", "json", "oversize", "timeout"))
def test_compose_failures_do_not_expose_rendered_credential_values(failure):
    def run(*args, **kwargs):
        if failure == "timeout":
            raise subprocess.TimeoutExpired(["synthetic-private-value"], 30)
        output = (
            b"x" * (VALIDATOR["MAX_MODEL_BYTES"] + 1)
            if failure == "oversize"
            else b"synthetic-private-value"
        )
        return SimpleNamespace(returncode=1 if failure == "exit" else 0, stdout=output)

    with pytest.raises(VALIDATOR["PassportConfigurationError"]) as error:
        VALIDATOR["validate_compose"](
            project="elevenid-beta",
            env_files=["synthetic.env"],
            files=[PROFILE],
            passport_enabled=True,
            runner=run,
        )
    assert str(error.value) == "Beta passport Compose validation failed"


def test_runner_validates_twice_before_mutation():
    source = (ROOT / "scripts/deploy-local-beta-release.ps1").read_text(
        encoding="utf-8"
    )
    assert "[switch]$EnablePassportNative" in source
    assert "[switch]$EnablePassportPhysicalProvider" in source
    assert (
        "$passportProfiles = @(Get-BetaPassportProfiles -Enabled ([bool]$EnablePassportNative)"
        in source
    )
    assert "-PhysicalProvider ([bool]$EnablePassportPhysicalProvider))" in source
    assert "passport_configuration_validated = $false" in source
    assert '$script:SelectedApplicationServices += "passport-beta-bureau"' in source
    assert '$script:SelectedApplicationServices += "passport-callback-signer"' in source
    assert (
        "retire them explicitly before deploying without the passport profile" in source
    )
    marker = "Assert-BetaPassportConfiguration -RepoRoot $script:RepoRoot"
    assert source.count(marker) == 2
    assert source.index(marker) < source.index(
        'Invoke-Checked -FilePath docker -Arguments @("pull",'
    )
    assert source.rindex(marker) < source.index(
        'Invoke-Checked -FilePath docker -Arguments (@("stop")'
    )
    assert source.index("Assert-NoInFlightPassportJobs") < source.index(
        'Write-Step "Capture quiesced maintenance snapshot"'
    )
    assert "WHERE status NOT IN ('ACTIVE', 'FAILED', 'CANCELLED')" in source
    assert "Assert-BetaCallbackSignerNetwork -AttachOpenBao" in source
    assert source.index(
        "Assert-BetaCallbackSignerNetwork -AttachOpenBao"
    ) < source.index(
        'Invoke-Compose -Arguments (@("up", "--detach", "--no-build", "--no-deps", "--force-recreate") + $remainingServices)'
    )
    assert "Unexpected container joined the beta callback network" in source
    assert '"openbao" -notin @($openbaoEndpoint.Value.Aliases)' in source


def test_beta_cutover_drain_query_catches_submission_before_bureau_id_is_saved():
    contract = json.loads(
        (ROOT / "contracts/passport-beta-cutover-drain-behavior.json").read_text(
            encoding="utf-8"
        )
    )
    source = (ROOT / "scripts/deploy-local-beta-release.ps1").read_text(
        encoding="utf-8"
    )
    match = re.search(
        r'-c "(SELECT count\(\*\) FROM issuance_service\.physical_document_jobs WHERE [^"]+)"',
        source,
    )
    assert match, "beta drain SQL is missing"
    with sqlite3.connect(":memory:") as database:
        database.execute("ATTACH DATABASE ':memory:' AS issuance_service")
        database.execute(
            "CREATE TABLE issuance_service.physical_document_jobs "
            "(status TEXT NOT NULL, bureau_job_id TEXT)"
        )
        for case in contract["cases"]:
            database.execute("DELETE FROM issuance_service.physical_document_jobs")
            database.execute(
                "INSERT INTO issuance_service.physical_document_jobs "
                "(status, bureau_job_id) VALUES (?, ?)",
                (case["status"], case["bureau_job_id"]),
            )
            count = database.execute(match.group(1)).fetchone()[0]
            assert bool(count) is case["blocks"], case["name"]


def test_restore_reconstitutes_isolated_signer_before_applications():
    source = (ROOT / "scripts/restore-local-beta-release.ps1").read_text(
        encoding="utf-8"
    )
    assert '"passport-callback-signer"' in source
    assert source.count("Assert-RestoredPassportCallbackNetwork") >= 3
    assert (
        "Unexpected container joined the restored passport callback network" in source
    )
    assert '"openbao" -notin @($openbaoEndpoint.Value.Aliases)' in source


def test_selected_bureau_has_a_packaged_rust_entrypoint():
    dockerfile = (ROOT / "services/Dockerfile").read_text(encoding="utf-8")
    entrypoint = (ROOT / "services/entrypoint.sh").read_text(encoding="utf-8")
    assert (
        "COPY --from=rust-service-builder /build/rust/target/release/marty-passport-beta-bureau /usr/local/bin/marty-passport-beta-bureau"
        in dockerfile
    )
    assert 'if [ "$MODULE_NAME" = "passport_beta_bureau" ]; then' in entrypoint
    assert "exec /usr/local/bin/marty-passport-beta-bureau" in entrypoint
    assert "exec /usr/local/bin/marty-passport-callback-signer" in entrypoint
    assert "target/release/marty-passport-callback-signer" in dockerfile


def test_passport_transit_keys_are_verified_non_exportable_at_bootstrap():
    source = (ROOT / "docker/openbao-init.sh").read_text(encoding="utf-8")
    for key, kind in (
        ("passport-artifact-marty-aes256", "aes256-gcm96"),
        ("passport-bureau-callback-marty-hmac", "hmac"),
    ):
        assert f"transit/keys/{key}" in source
        creation = source.split(f"transit/keys/{key} \\\n", 1)[1].split("2>/dev/null", 1)[0]
        assert f"type={kind}" in creation
        assert "exportable=false" in creation
        if kind == "hmac":
            assert "key_size=32" in creation
        assert f"-field=type transit/keys/{key}" in source
        assert f"-field=exportable transit/keys/{key}" in source


def synthetic_beta_compose_env(tmp_path):
    required = set()
    for file in ROOT.glob("docker-compose*.yml"):
        required.update(re.findall(r"\$\{([A-Z][A-Z0-9_]*):\?", file.read_text()))
    values = {name: "synthetic-value" for name in required}
    for name in required:
        if name.endswith("_FILE"):
            fixture = tmp_path / name.lower()
            fixture.write_text("synthetic-workload-material", encoding="utf-8")
            values[name] = str(fixture)
    values["GRPC_SERVICE_TOKEN"] = TOKEN
    values["PASSPORT_BETA_RECONCILIATION_OPERATOR_TOKEN"] = RECONCILIATION_TOKEN
    values["MARTY_SERVICES_IMAGE"] = IMAGE
    ceremony = tmp_path / "elevenid-beta-passport-ceremony"
    ceremony.mkdir()
    (ceremony / "dsc_issue_gateway_key").write_text(DSC_GATEWAY_KEY, encoding="ascii")
    (ceremony / "csca_issue_gateway_key").write_text(CSCA_GATEWAY_KEY, encoding="ascii")
    values["PASSPORT_BETA_CEREMONY_SECRET_DIR"] = str(ceremony)
    env_file = tmp_path / "synthetic-beta.env"
    env_file.write_text(
        "\n".join(f"{name}={value}" for name, value in sorted(values.items())) + "\n",
        encoding="utf-8",
    )
    passthrough = (
        "PATH",
        "SYSTEMROOT",
        "WINDIR",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "HOME",
        "HOMEDRIVE",
        "HOMEPATH",
        "PROGRAMFILES",
        "PROGRAMFILES(X86)",
        "DOCKER_HOST",
        "DOCKER_CONTEXT",
        "DOCKER_CONFIG",
    )
    environment = {name: os.environ[name] for name in passthrough if name in os.environ}
    return env_file, environment


def test_actual_beta_compose_merge_preserves_default_off_and_kms_selection(tmp_path):
    if not shutil.which("docker"):
        pytest.skip("Docker Compose is not installed")
    base = [
        str(ROOT / name)
        for name in (
            "docker-compose.base.yml",
            "docker-compose.beta.yml",
            "docker-compose.profile.dev.yml",
        )
    ]
    env_file, environment = synthetic_beta_compose_env(tmp_path)

    def render(files):
        command = ["docker", "compose", "--env-file", str(env_file)]
        for file in files:
            command.extend(["-f", file])
        command.extend(["config", "--format", "json"])
        return json.loads(
            subprocess.run(
                command,
                cwd=ROOT,
                capture_output=True,
                env=environment,
                check=True,
                timeout=30,
            ).stdout
        )

    disabled = render(base)
    enabled = render([*base, str(ROOT / PROFILE)])
    assert "passport-beta-bureau" not in disabled["services"]
    assert "passport-beta-bureau" in enabled["services"]
    assert "passport-callback-signer" not in disabled["services"]
    assert "passport-callback-signer" in enabled["services"]
    disabled_signing = VALIDATOR["environment"](disabled["services"]["signing-keys"])
    enabled_signing = VALIDATOR["environment"](enabled["services"]["signing-keys"])
    assert "SIGNING_KEYS_BETA_CSCA_ISSUANCE_ENABLED" not in disabled_signing
    assert enabled_signing["SIGNING_KEYS_BETA_CSCA_ISSUANCE_ENABLED"] == "true"
    assert enabled_signing["ENVIRONMENT"] == "beta"
    for name in ("gateway", "signing-keys"):
        env = VALIDATOR["environment"](enabled["services"][name])
        assert env["SIGNING_KEYS_CSCA_ISSUE_GATEWAY_KEY_FILE"] == (
            "/run/secrets/csca_issue_gateway_key"
        )
        assert "SIGNING_KEYS_CSCA_ISSUE_GATEWAY_KEY" not in env
    for name, flag in (
        ("gateway", "PASSPORT_NATIVE_GATEWAY_ENABLED"),
        ("flow", "PASSPORT_NATIVE_FLOW_ENABLED"),
        ("issuance-native", "PASSPORT_NATIVE_HTTP_ENABLED"),
    ):
        before = VALIDATOR["environment"](disabled["services"][name])
        after = VALIDATOR["environment"](enabled["services"][name])
        assert before.get(flag, "false") != "true"
        assert after[flag] == "true"
        assert after["PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED"] == "true"
    native = VALIDATOR["environment"](enabled["services"]["issuance-native"])
    assert native["PASSPORT_KMS_ARTIFACTS_ENABLED"] == "true"
    assert native["PASSPORT_KMS_CALLBACKS_ENABLED"] == "true"
    assert native["PASSPORT_MANAGED_ISSUER_SIGNING_ENABLED"] == "true"
    assert not set(VALIDATOR["PASSPORT_RAW_KEY_NAMES"]).intersection(
        name for name, value in native.items() if value
    )
    validate(enabled)


def test_actual_interpolated_beta_compose_passes_selector(tmp_path):
    if not shutil.which("docker"):
        pytest.skip("Docker Compose is not installed")
    files = [
        str(ROOT / name)
        for name in (
            "docker-compose.base.yml",
            "docker-compose.beta.yml",
            "docker-compose.profile.dev.yml",
            PROFILE,
        )
    ]
    env_file, environment = synthetic_beta_compose_env(tmp_path)

    def run(command, **kwargs):
        kwargs["stderr"] = subprocess.PIPE
        result = subprocess.run(command, env=environment, cwd=ROOT, **kwargs)
        assert result.returncode == 0, result.stderr.decode(errors="replace")
        return result

    VALIDATOR["validate_compose"](
        project="elevenid-beta",
        env_files=[str(env_file)],
        files=files,
        passport_enabled=True,
        runner=run,
    )
