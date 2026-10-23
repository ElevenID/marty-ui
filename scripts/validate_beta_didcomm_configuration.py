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
TOKEN_TARGET = "/run/secrets/didcomm-kms"
TOKEN_FILE = TOKEN_TARGET + "/openbao-token"
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
    try:
        services = model["services"]
        if "issuance-native" not in services:
            return
        legacy, native = services["issuance"], services["issuance-native"]
        legacy_env = environment_mapping(legacy["environment"])
        native_env = environment_mapping(native["environment"])
        if "DIDCOMM_ENCRYPTION_POLICY_FILE" in legacy_env or any(
            key in legacy_env for key in ("DIDCOMM_KMS_ADDR", "DIDCOMM_KMS_TOKEN_FILE")
        ):
            raise DidcommConfigurationError("Legacy DIDComm key custody is forbidden")
        policy = native_env.get("DIDCOMM_ENCRYPTION_POLICY_FILE")
        if policy is None:
            if any(
                key in native_env
                for key in ("DIDCOMM_KMS_ADDR", "DIDCOMM_KMS_TOKEN_FILE")
            ):
                raise DidcommConfigurationError(
                    "DIDComm KMS requires an explicit native policy"
                )
            return
        if (
            policy != POLICY_FILE
            or native_env.get("DIDCOMM_KMS_ADDR") != "http://openbao:8200"
            or native_env.get("DIDCOMM_KMS_TOKEN_FILE") != TOKEN_FILE
        ):
            raise DidcommConfigurationError(
                "Native DIDComm remote custody is incomplete"
            )
        selected = [
            item
            for item in native.get("volumes", [])
            if item.get("target") in {POLICY_FILE, TOKEN_TARGET}
        ]
        mounts = {
            item["target"]: item
            for item in native.get("volumes", [])
            if item.get("target") in {POLICY_FILE, TOKEN_TARGET}
        }
        if len(selected) != 2 or set(mounts) != {POLICY_FILE, TOKEN_TARGET}:
            raise DidcommConfigurationError(
                "Native DIDComm policy and token mounts are incomplete"
            )
        policy_mount = mounts[POLICY_FILE]
        policy_source = policy_mount["source"]
        if (
            policy_mount["type"] != "bind"
            or policy_mount["read_only"] is not True
            or not bind_does_not_create_host_path(policy_mount)
            or not isinstance(policy_source, str)
            or not policy_source.endswith("/didcomm-encryption-policy.json")
        ):
            raise DidcommConfigurationError(
                "Native DIDComm reference policy mount is incomplete"
            )
        directory = policy_source.rsplit("/", 1)[0]
        if not directory or any(
            str(path) == path.anchor
            for path in (PurePosixPath(directory), PureWindowsPath(directory))
        ):
            raise DidcommConfigurationError(
                "DIDComm policy source cannot be a filesystem root"
            )
        token_mount = mounts[TOKEN_TARGET]
        if (
            token_mount["type"] != "volume"
            or token_mount["source"] != "didcomm_issuance_token"
            or token_mount["read_only"] is not True
        ):
            raise DidcommConfigurationError("Native DIDComm token volume is incomplete")
        token_resource = model.get("volumes", {}).get("didcomm_issuance_token")
        if (
            not isinstance(token_resource, dict)
            or set(token_resource) - {"name"}
            or (
                model.get("name")
                and token_resource.get("name")
                != model["name"] + "_didcomm_issuance_token"
            )
        ):
            raise DidcommConfigurationError(
                "Native DIDComm scoped token volume is missing"
            )
        openbao, bootstrap = services["openbao"], services["openbao-init"]
        image = openbao.get("image")
        unresolved_image = "${MARTY_OPENBAO_DIDCOMM_IMAGE:?set MARTY_OPENBAO_DIDCOMM_IMAGE to the reviewed plugin image digest}"
        if (
            not isinstance(image, str)
            or (
                not re.fullmatch(r"[^\s]+@sha256:[0-9a-f]{64}", image)
                and image != unresolved_image
            )
            or bootstrap.get("image") != image
            or environment_mapping(bootstrap["environment"]).get(
                "DIDCOMM_KMS_PLUGIN_REQUIRED"
            )
            != "true"
            or environment_mapping(bootstrap["environment"]).get(
                "DIDCOMM_ISSUANCE_TOKEN_FILE"
            )
            != "/run/didcomm-token/openbao-token"
            or openbao.get("command")
            != ["server", "-dev", "-config", "/bao/config/didcomm-plugin.hcl"]
            or not any(
                isinstance(mount, dict)
                and mount.get("type") == "volume"
                and mount.get("source") == "didcomm_issuance_token"
                and mount.get("target") == "/run/didcomm-token"
                and mount.get("read_only") is not True
                for mount in bootstrap.get("volumes", [])
            )
            or native.get("depends_on", {}).get("openbao-init", {}).get("condition")
            != "service_completed_successfully"
            or not any(
                isinstance(mount, dict)
                and mount.get("target") == "/bao/config/didcomm-plugin.hcl"
                and mount.get("type") == "bind"
                and mount.get("read_only") is True
                and bind_does_not_create_host_path(mount)
                and str(mount.get("source", ""))
                .replace("\\", "/")
                .endswith("/docker/openbao-didcomm-dev.hcl")
                for mount in openbao.get("volumes", [])
            )
        ):
            raise DidcommConfigurationError(
                "DIDComm OpenBao plugin backend is incomplete"
            )
        for name, service in services.items():
            if name == "issuance-native":
                continue
            if any(
                isinstance(item, dict)
                and (
                    item.get("source") == policy_source
                    or (
                        item.get("source") == "didcomm_issuance_token"
                        and name != "openbao-init"
                    )
                )
                for item in service.get("volumes", [])
            ):
                raise DidcommConfigurationError(
                    "DIDComm policy or token is mounted outside native issuance"
                )
    except (KeyError, TypeError, StopIteration, AttributeError):
        raise DidcommConfigurationError("Invalid DIDComm owner model") from None


def assert_base_https_native_kms(model):
    services = model["services"]
    native = services["issuance-native"]
    environment = environment_mapping(native["environment"])
    expected = {
        "DIDCOMM_KMS_ADDR": "https://openbao:8200",
        "DIDCOMM_KMS_CA_CERT_FILE": "/bao/public-ca/ca.crt",
        "DIDCOMM_KMS_TOKEN_FILE": "/bao/didcomm-issuance-token/token",
    }
    if any(environment.get(key) != value for key, value in expected.items()):
        raise DidcommConfigurationError("Native HTTPS DIDComm custody is incomplete")
    mounts = {item.get("target"): item for item in native.get("volumes", [])}
    for source, target in (
        ("openbao_public_ca", "/bao/public-ca"),
        ("openbao_didcomm_issuance_token", "/bao/didcomm-issuance-token"),
    ):
        mount = mounts.get(target)
        if not isinstance(mount, dict) or any(
            mount.get(key) != value
            for key, value in (
                ("type", "volume"),
                ("source", source),
                ("read_only", True),
            )
        ):
            raise DidcommConfigurationError(
                "Native HTTPS DIDComm CA or token mount is incomplete"
            )
    policy_file = environment.get("DIDCOMM_ENCRYPTION_POLICY_FILE")
    if policy_file is None and POLICY_FILE in mounts:
        raise DidcommConfigurationError("Native DIDComm policy mount lacks a selector")
    if policy_file is not None:
        if policy_file != POLICY_FILE:
            raise DidcommConfigurationError(
                "Native DIDComm reference policy path is invalid"
            )
        policy_mount = mounts.get(POLICY_FILE)
        if (
            not isinstance(policy_mount, dict)
            or policy_mount.get("type") != "bind"
            or policy_mount.get("read_only") is not True
            or not bind_does_not_create_host_path(policy_mount)
            or not str(policy_mount.get("source", ""))
            .replace("\\", "/")
            .endswith("/didcomm-encryption-policy.json")
        ):
            raise DidcommConfigurationError(
                "Native DIDComm reference policy mount is incomplete"
            )
        for name, service in services.items():
            if name != "issuance-native" and any(
                isinstance(item, dict) and item.get("target") == POLICY_FILE
                for item in service.get("volumes", [])
            ):
                raise DidcommConfigurationError(
                    "DIDComm policy is mounted outside native issuance"
                )


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
