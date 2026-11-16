"""Validate native-only remote DIDComm custody without reading secret contents."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import PurePosixPath, PureWindowsPath
import subprocess
import sys

POLICY_TARGET = "/run/secrets/didcomm-authcrypt"
POLICY_FILE = POLICY_TARGET + "/didcomm-encryption-policy.json"
NATIVE_URL = "http://issuance-native:8005"
MAX_MODEL_BYTES = 8 * 1024 * 1024


class DidcommConfigurationError(ValueError):
    pass


def environment_mapping(value):
    if isinstance(value, dict):
        return value
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return dict(item.split("=", 1) for item in value if "=" in item)
    raise DidcommConfigurationError("Invalid DIDComm environment model")


def bind_does_not_create_host_path(mount):
    """Interpret Compose's typed bind model, including 2.38's omitted false."""
    options = mount.get("bind")
    return (
        mount.get("type") == "bind"
        and isinstance(options, dict)
        and options.get("create_host_path", False) is False
    )


def assert_native_kms_policy(model):
    # Retain the existing guard entrypoint; the retired HTTP development owner
    # is not an alternative to the current HTTPS Signing Keys route.
    assert_base_https_native_kms(model)


def assert_base_https_native_kms(model):
    try:
        services = model["services"]
        native, signing = services["issuance-native"], services["signing-keys"]
        environment = environment_mapping(native["environment"])
        signing_environment = environment_mapping(signing["environment"])
        direct_fields = {"DIDCOMM_KMS_ADDR", "DIDCOMM_KMS_CA_CERT_FILE", "DIDCOMM_KMS_TOKEN_FILE"}
        for name in ("issuance", "issuance-native"):
            if direct_fields & set(environment_mapping(services[name]["environment"])):
                raise DidcommConfigurationError("Direct Issuance DIDComm key custody is forbidden")
        expected = {
            "INTEGRATION_SECRET_KMS_URL": "https://signing-keys:8018/internal",
            "INTEGRATION_SECRET_KMS_CA_FILE": "/run/secrets/dev_integration_secret_ca",
            "ISSUANCE_CREDENTIAL_SIGN_GRANT_MINT_TOKEN_FILE": "/bao/issuance-credential-grant/token",
            "BAO_ADDR": "https://openbao:8200",
            "BAO_CACERT": "/bao/public-ca/ca.crt",
        }
        signing_expected = {
            "DIDCOMM_KMS_TOKEN_FILE": "/bao/didcomm-issuance-token/token",
            "SIGNING_KEYS_GRANT_VERIFY_TOKEN_FILE": "/bao/verify-grant/token",
            "SIGNING_KEYS_INTEGRATION_SECRET_TLS_CERT_FILE": "/run/secrets/dev_integration_secret_server_cert",
            "BAO_ADDR": "https://openbao:8200",
        }
        issuer_key = environment.get("SIGNING_KEYS_ISSUER_SIGN_KEY")
        verifier_key = signing_environment.get("SIGNING_KEYS_ISSUER_SIGN_KEY")
        same_issuer_key = bool(issuer_key) and issuer_key == verifier_key
        if not same_issuer_key:
            # The source-only merge gate keeps Compose interpolation intact;
            # required/default forms must still select this exact one input.
            selector = r"\$\{SIGNING_KEYS_ISSUER_SIGN_KEY:(?:-|\?)[^{}]*\}"
            same_issuer_key = all(isinstance(value, str) and re.fullmatch(selector, value)
                                  for value in (issuer_key, verifier_key))
        if (
            any(environment.get(key) != value for key, value in expected.items())
            or any(signing_environment.get(key) != value for key, value in signing_expected.items())
            or not same_issuer_key
            or {"DIDCOMM_KMS_ADDR", "DIDCOMM_KMS_CA_CERT_FILE"} & set(signing_environment)
        ):
            raise DidcommConfigurationError("Registered DIDComm HTTPS authority is incomplete")
        signing_ca = signing_environment.get("BAO_CACERT")
        if signing_ca not in {"/bao/public-ca/ca.crt", "/run/secrets/openbao_tls_ca_cert"}:
            raise DidcommConfigurationError("Registered DIDComm public trust is incomplete")
        if signing_ca == "/run/secrets/openbao_tls_ca_cert" and not any(
            isinstance(item, dict) and item.get("source") == "openbao_tls_ca_cert"
            and item.get("target") == signing_ca for item in signing.get("secrets", [])
        ):
            raise DidcommConfigurationError("Registered DIDComm public trust mount is incomplete")

        def readonly_volume(service, source, target):
            matches = [item for item in service.get("volumes", [])
                       if isinstance(item, dict) and item.get("target") == target]
            if len(matches) != 1 or any(matches[0].get(key) != value for key, value in (
                ("type", "volume"), ("source", source), ("read_only", True)
            )):
                raise DidcommConfigurationError("DIDComm scoped authority mount is incomplete")

        for service, source, target in (
            (native, "openbao_public_ca", "/bao/public-ca"),
            (native, "openbao_issuance_credential_grant", "/bao/issuance-credential-grant"),
            (signing, "openbao_public_ca", "/bao/public-ca"),
            (signing, "openbao_verify_grant", "/bao/verify-grant"),
            (signing, "openbao_didcomm_issuance_token", "/bao/didcomm-issuance-token"),
        ):
            readonly_volume(service, source, target)
        token_resource = model.get("volumes", {}).get("openbao_didcomm_issuance_token")
        if (
            not isinstance(token_resource, dict)
            or set(token_resource) - {"name"}
            or (model.get("name") and token_resource.get("name")
                != model["name"] + "_openbao_didcomm_issuance_token")
        ):
            raise DidcommConfigurationError("DIDComm scoped token volume is missing")
        bootstrap = services["openbao-init"]
        bootstrap_environment = environment_mapping(bootstrap["environment"])
        openbao = services["openbao"]
        image = openbao.get("image")
        if (
            not isinstance(image, str)
            or (not re.fullmatch(r"[^\s]+@sha256:[0-9a-f]{64}", image)
                and not (image in {"marty-openbao-didcomm:dev", "${MARTY_OPENBAO_DIDCOMM_IMAGE:-marty-openbao-didcomm:dev}"}
                         and openbao.get("build", {}).get("dockerfile") == "openbao/didcomm-authcrypt/Dockerfile"))
            or bootstrap.get("image") != image
            or bootstrap_environment.get("DIDCOMM_KMS_PLUGIN_REQUIRED") != "true"
            or bootstrap_environment.get("BAO_DIDCOMM_ISSUANCE_TOKEN_FILE") != "/bao/didcomm-issuance-token/token"
            or signing.get("depends_on", {}).get("openbao-init", {}).get("condition") != "service_completed_successfully"
            or not any(isinstance(item, dict) and item.get("type") == "volume"
                       and item.get("source") == "openbao_didcomm_issuance_token"
                       and item.get("target") == "/bao/didcomm-issuance-token"
                       and item.get("read_only") is not True
                       for item in bootstrap.get("volumes", []))
        ):
            raise DidcommConfigurationError("DIDComm OpenBao plugin backend is incomplete")

        policy_file = environment.get("DIDCOMM_ENCRYPTION_POLICY_FILE")
        policy_mounts = [item for item in native.get("volumes", [])
                         if isinstance(item, dict) and item.get("target") == POLICY_FILE]
        if policy_file is None and policy_mounts:
            raise DidcommConfigurationError("Native DIDComm policy mount lacks a selector")
        policy_source = None
        if policy_file is not None:
            if policy_file != POLICY_FILE or len(policy_mounts) != 1:
                raise DidcommConfigurationError("Native DIDComm reference policy path is invalid")
            policy_mount = policy_mounts[0]
            policy_source = policy_mount.get("source")
            if (
                policy_mount.get("type") != "bind"
                or policy_mount.get("read_only") is not True
                or not bind_does_not_create_host_path(policy_mount)
                or not isinstance(policy_source, str)
                or not policy_source.replace("\\", "/").endswith("/didcomm-encryption-policy.json")
            ):
                raise DidcommConfigurationError("Native DIDComm reference policy mount is incomplete")
            directory = policy_source.replace("\\", "/").rsplit("/", 1)[0]
            if not directory or any(str(path) == path.anchor
                                    for path in (PurePosixPath(directory), PureWindowsPath(directory))):
                raise DidcommConfigurationError("DIDComm policy source cannot be a filesystem root")
        for name, service in services.items():
            for item in service.get("volumes", []):
                if not isinstance(item, dict):
                    continue
                if (item.get("source") == "openbao_didcomm_issuance_token"
                    and name not in {"signing-keys", "openbao-init"}):
                    raise DidcommConfigurationError("DIDComm token is mounted outside Signing Keys")
                if name != "issuance-native" and (
                    item.get("target") == POLICY_FILE
                    or (policy_source is not None and item.get("source") == policy_source)
                ):
                    raise DidcommConfigurationError("DIDComm policy is mounted outside native issuance")
    except (KeyError, TypeError, AttributeError):
        raise DidcommConfigurationError("Invalid DIDComm owner model") from None


def validate_model(model, *, authcrypt_enabled, base_https=False):
    try:
        legacy_environment = environment_mapping(
            model["services"]["issuance"]["environment"]
        )
        if any(key in legacy_environment for key in (
            "DIDCOMM_ENCRYPTION_POLICY_FILE", "DIDCOMM_KMS_ADDR", "DIDCOMM_KMS_TOKEN_FILE"
        )):
            raise DidcommConfigurationError("Legacy DIDComm key custody is forbidden")
        if legacy_environment.get("DIDCOMM_DELIVERY_OWNER") != "native":
            raise DidcommConfigurationError("Beta DIDComm delivery owner is not native")
        if legacy_environment.get("ISSUANCE_NATIVE_SERVICE_URL") != NATIVE_URL:
            raise DidcommConfigurationError(
                "Beta DIDComm native service URL is not selected"
            )
        dependency = model["services"]["issuance"]["depends_on"]["issuance-native"]
        if dependency != {"condition": "service_healthy", "required": True}:
            raise DidcommConfigurationError(
                "Beta DIDComm native readiness dependency is not enforced"
            )
        if model["services"]["issuance"]["healthcheck"]["test"] != [
            "CMD",
            "curl",
            "--fail",
            "http://localhost:8005/ready",
        ]:
            raise DidcommConfigurationError(
                "Beta DIDComm retained consumer readiness is not enforced"
            )
        native_policy = environment_mapping(
            model["services"]["issuance-native"]["environment"]
        ).get("DIDCOMM_ENCRYPTION_POLICY_FILE")
        if authcrypt_enabled and not native_policy:
            raise DidcommConfigurationError(
                "Selected native DIDComm policy is not configured"
            )
        if not authcrypt_enabled and native_policy:
            raise DidcommConfigurationError(
                "Configured DIDComm policy requires explicit beta opt-in"
            )
        if base_https:
            assert_base_https_native_kms(model)
        else:
            assert_native_kms_policy(model)
    except (KeyError, TypeError):
        raise DidcommConfigurationError("Invalid DIDComm owner model") from None


def validate_compose(
    *, project, env_files, files, authcrypt_enabled, runner=subprocess.run
):
    command = ["docker", "compose", "--project-name", project]
    for path in env_files:
        command.extend(["--env-file", path])
    for path in files:
        command.extend(["--file", path])
    command.extend(["config", "--format", "json"])
    try:
        result = runner(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=False,
        )
        if result.returncode or len(result.stdout) > MAX_MODEL_BYTES:
            raise DidcommConfigurationError("DIDComm Compose validation failed")
        model = json.loads(result.stdout)
        # The default native profile now always uses the TLS/Raft OpenBao
        # custody contract. The old dev-plugin contract is not a beta mode.
        validate_model(model, authcrypt_enabled=authcrypt_enabled, base_https=True)
    except (OSError, subprocess.SubprocessError, UnicodeError, json.JSONDecodeError):
        raise DidcommConfigurationError("DIDComm Compose validation failed") from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True, choices=["elevenid-beta"])
    parser.add_argument("--env-file", action="append", required=True)
    parser.add_argument("--file", action="append", required=True)
    parser.add_argument("--authcrypt-enabled", action="store_true")
    args = parser.parse_args()
    try:
        validate_compose(
            project=args.project,
            env_files=args.env_file,
            files=args.file,
            authcrypt_enabled=args.authcrypt_enabled,
        )
    except DidcommConfigurationError as error:
        print(str(error), file=sys.stderr)
        return 1
    print("Beta DIDComm configuration validated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
