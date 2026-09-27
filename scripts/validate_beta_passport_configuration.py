"""Validate the opt-in beta passport Compose model without exposing secret data."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import urlsplit

MAX_MODEL_BYTES = 8 * 1024 * 1024
MAX_MOUNT_ENTRIES = 1024
MAX_MOUNT_FILES = 512
MAX_MOUNT_FILE_BYTES = 1024 * 1024
MAX_MOUNT_TOTAL_BYTES = 8 * 1024 * 1024
PROFILE = "docker-compose.profile.passport-native-beta.yml"
PASSPORT_RAW_KEY_NAMES = (
    "PASSPORT_TENANT_API_KEYS",
    "PHYSICAL_DOCUMENT_ARTIFACT_KEY",
    "ICAO_DOCUMENT_SIGNER_API_KEY",
    "PERSONALIZATION_BUREAU_WEBHOOK_SECRET",
)
PRIVATE_BUREAU_URL = "http://passport-beta-bureau:8020"
PRIVATE_SIGNING_URL = "http://passport-callback-signer:8018/internal/documents"
PRIVATE_SIGNING_NETWORK = "passport-callback-signing"
PRIVATE_CALLBACK_URL = (
    "http://issuance-native:8005/v1/passport/webhooks/personalization"
)


class PassportConfigurationError(ValueError):
    pass


def environment(service):
    value = service.get("environment")
    if isinstance(value, dict):
        return value
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return dict(item.split("=", 1) for item in value if "=" in item)
    raise PassportConfigurationError("Invalid beta passport service environment")


def contains_credential(value, credential):
    if isinstance(value, str):
        return credential in value
    if isinstance(value, (list, tuple)):
        return any(contains_credential(item, credential) for item in value)
    if isinstance(value, dict):
        return any(
            contains_credential(item, credential)
            for pair in value.items()
            for item in pair
        )
    return False


def service_reuses_credential(service_name, service, credential, dedicated_name):
    for field, value in service.items():
        if field == "environment" and service_name in {"gateway", "signing-keys"}:
            value = {
                name: entry
                for name, entry in environment(service).items()
                if name != dedicated_name
            }
        if contains_credential(value, credential):
            return True
    return False


def validate_mounted_sources(model, services, credential):
    sources = []
    for secret in model.get("secrets", {}).values():
        path = secret.get("file") if isinstance(secret, dict) else None
        if not isinstance(path, str):
            raise PassportConfigurationError(
                "Beta DSC operator credential isolation cannot verify mounted files"
            )
        sources.append(path)
    for service_name, service in services.items():
        if service_name in {"gateway", "signing-keys"}:
            continue
        configs = service.get("configs", [])
        if not isinstance(configs, list):
            raise PassportConfigurationError(
                "Beta DSC operator credential isolation cannot verify mounted files"
            )
        definitions = model.get("configs", {})
        if not isinstance(definitions, dict):
            raise PassportConfigurationError(
                "Beta DSC operator credential isolation cannot verify mounted files"
            )
        for config in configs:
            name = (
                config
                if isinstance(config, str)
                else (config.get("source") if isinstance(config, dict) else None)
            )
            definition = definitions.get(name) if isinstance(name, str) else None
            path = definition.get("file") if isinstance(definition, dict) else None
            if not isinstance(path, str) or definition.get("external"):
                raise PassportConfigurationError(
                    "Beta DSC operator credential isolation cannot verify mounted files"
                )
            sources.append(path)
        volumes = service.get("volumes", [])
        if not isinstance(volumes, list):
            raise PassportConfigurationError(
                "Beta DSC operator credential isolation cannot verify mounted files"
            )
        for volume in volumes:
            if not isinstance(volume, dict):
                raise PassportConfigurationError(
                    "Beta DSC operator credential isolation cannot verify mounted files"
                )
            kind = volume.get("type")
            if kind in {"volume", "tmpfs"}:
                continue
            if kind != "bind" or not isinstance(volume.get("source"), str):
                raise PassportConfigurationError(
                    "Beta DSC operator credential isolation cannot verify mounted files"
                )
            sources.append(volume["source"])

    pending = [Path(source).absolute() for source in sources]
    visited = set()
    file_count = 0
    total_bytes = 0
    marker = credential.encode()
    try:
        while pending:
            path = pending.pop()
            if path in visited:
                continue
            visited.add(path)
            if len(visited) > MAX_MOUNT_ENTRIES or path.is_symlink():
                raise PassportConfigurationError(
                    "Beta DSC operator credential isolation cannot verify mounted files"
                )
            if path.is_dir():
                with os.scandir(path) as entries:
                    for entry in entries:
                        if len(visited) + len(pending) >= MAX_MOUNT_ENTRIES:
                            raise PassportConfigurationError(
                                "Beta DSC operator credential isolation cannot verify mounted files"
                            )
                        pending.append(Path(entry.path))
            elif path.is_file():
                file_count += 1
                size = path.stat().st_size
                total_bytes += size
                if (
                    file_count > MAX_MOUNT_FILES
                    or size > MAX_MOUNT_FILE_BYTES
                    or total_bytes > MAX_MOUNT_TOTAL_BYTES
                ):
                    raise PassportConfigurationError(
                        "Beta DSC operator credential isolation cannot verify mounted files"
                    )
                with path.open("rb") as mounted:
                    if marker in mounted.read(MAX_MOUNT_FILE_BYTES + 1):
                        raise PassportConfigurationError(
                            "Beta DSC operator credential isolation is invalid"
                        )
            else:
                raise PassportConfigurationError(
                    "Beta DSC operator credential isolation cannot verify mounted files"
                )
    except OSError:
        raise PassportConfigurationError(
            "Beta DSC operator credential isolation cannot verify mounted files"
        ) from None


def validate_model(model, *, passport_enabled, files):
    selected = sum(Path(path).name == PROFILE for path in files)
    if selected != int(passport_enabled):
        raise PassportConfigurationError(
            "Beta passport profile selection is inconsistent"
        )
    try:
        services = model["services"]
        targets = {
            name: services[name] for name in ("gateway", "flow", "issuance-native")
        }
        selectors = (
            ("gateway", "PASSPORT_NATIVE_GATEWAY_ENABLED"),
            ("flow", "PASSPORT_NATIVE_FLOW_ENABLED"),
            ("issuance-native", "PASSPORT_NATIVE_HTTP_ENABLED"),
        )
        for service_name, flag in selectors:
            actual = str(environment(targets[service_name]).get(flag, "false")).lower()
            if actual != ("true" if passport_enabled else "false"):
                raise PassportConfigurationError(
                    "Beta passport owner selection is inconsistent"
                )
        if not passport_enabled:
            if (
                "passport-beta-bureau" in services
                or "passport-callback-signer" in services
            ):
                raise PassportConfigurationError(
                    "Beta passport callback services selected without profile"
                )
            return
        bureau = services["passport-beta-bureau"]
        callback_signer = services["passport-callback-signer"]
        signing = environment(services["signing-keys"])
        gateway = environment(targets["gateway"])
        flow = environment(targets["flow"])
        if flow.get("ISSUANCE_NATIVE_SERVICE_URL") != "http://issuance-native:8005":
            raise PassportConfigurationError("Beta passport Flow target is not native")
        for owner in targets.values():
            env = environment(owner)
            if (
                str(env.get("PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED", "false")).lower()
                != "true"
            ):
                raise PassportConfigurationError(
                    "Beta passport internal handoff is incomplete"
                )
            if env.get("PASSPORT_TENANT_API_KEYS") or env.get(
                "PASSPORT_TENANT_API_KEYS_FILE"
            ):
                raise PassportConfigurationError(
                    "Beta passport tenant keyring is forbidden"
                )
        native = environment(targets["issuance-native"])
        for name in (
            "PASSPORT_MANAGED_ISSUER_SIGNING_ENABLED",
            "PASSPORT_KMS_ARTIFACTS_ENABLED",
            "PASSPORT_KMS_CALLBACKS_ENABLED",
        ):
            if str(native.get(name, "false")).lower() != "true":
                raise PassportConfigurationError("Beta passport KMS mode is incomplete")
        if (
            str(native.get("PHYSICAL_DOCUMENT_ALLOW_SELF_SIGNED", "false")).lower()
            != "false"
        ):
            raise PassportConfigurationError(
                "Beta passport self-signed mode is forbidden"
            )
        if native.get("ICAO_DOCUMENT_SIGNER_URL"):
            raise PassportConfigurationError("Beta passport remote signer is forbidden")
        if native.get("PERSONALIZATION_BUREAU_URL") != PRIVATE_BUREAU_URL:
            raise PassportConfigurationError("Beta passport bureau target is invalid")
        for name in PASSPORT_RAW_KEY_NAMES:
            if native.get(name) or native.get(f"{name}_FILE"):
                raise PassportConfigurationError(
                    "Beta passport raw key binding is forbidden"
                )
        if native.get("PERSONALIZATION_BUREAU_API_KEY_FILE"):
            raise PassportConfigurationError(
                "Beta passport bureau key file is forbidden"
            )
        bureau_env = environment(bureau)
        database_url = bureau_env.get("DATABASE_URL")
        native_database_url = native.get("DATABASE_URL")
        if not (
            isinstance(database_url, str)
            and isinstance(native_database_url, str)
            and native_database_url.startswith("postgresql+asyncpg://")
            and database_url
            == native_database_url.replace("postgresql+asyncpg://", "postgresql://", 1)
        ):
            raise PassportConfigurationError("Beta passport database target is invalid")
        database_target = urlsplit(database_url)
        if not (
            database_target.scheme == "postgresql"
            and database_target.hostname == "postgres"
            and database_target.port == 5432
            and database_target.path == "/marty"
            and database_target.username == "marty"
            and database_target.password
            and not database_target.query
            and not database_target.fragment
        ):
            raise PassportConfigurationError("Beta passport database target is invalid")
        signing_key = bureau_env.get("SIGNING_KEYS_INTERNAL_API_KEY")
        dsc_gateway_key_name = "SIGNING_KEYS_DSC_ISSUE_GATEWAY_KEY"
        dsc_gateway_key = gateway.get(dsc_gateway_key_name)
        dsc_key_holders = {
            name
            for name, service in services.items()
            if service.get("environment") is not None
            and environment(service).get(dsc_gateway_key_name)
        }
        dsc_value_reused = isinstance(dsc_gateway_key, str) and any(
            service_reuses_credential(
                service_name, service, dsc_gateway_key, dsc_gateway_key_name
            )
            for service_name, service in services.items()
        )
        if not (
            isinstance(dsc_gateway_key, str)
            and len(dsc_gateway_key) >= 32
            and dsc_gateway_key == signing.get(dsc_gateway_key_name)
            and dsc_gateway_key != signing_key
            and dsc_key_holders == {"gateway", "signing-keys"}
            and not dsc_value_reused
            and all(
                not environment(service).get(f"{dsc_gateway_key_name}_FILE")
                for service in services.values()
                if service.get("environment") is not None
            )
        ):
            raise PassportConfigurationError(
                "Beta DSC operator credential isolation is invalid"
            )
        validate_mounted_sources(model, services, dsc_gateway_key)
        callback_signer_env = environment(callback_signer)
        if not (
            bureau_env.get("SERVICE_NAME") == "passport_beta_bureau"
            and bureau_env.get("ENVIRONMENT") == "beta"
            and str(bureau_env.get("PASSPORT_BETA_BUREAU_ENABLED", "false")).lower()
            == "true"
            and bureau_env.get("GRPC_SERVICE_TOKEN")
            and bureau_env.get("GRPC_SERVICE_TOKEN")
            == native.get("PERSONALIZATION_BUREAU_API_KEY")
            and bureau_env.get("GRPC_SERVICE_TOKEN")
            == gateway.get("GRPC_SERVICE_TOKEN")
            and bureau_env.get("GRPC_SERVICE_TOKEN") == flow.get("GRPC_SERVICE_TOKEN")
            and bureau_env.get("GRPC_SERVICE_TOKEN") == native.get("GRPC_SERVICE_TOKEN")
            and signing_key
            and all(
                signing_key == owner.get("SIGNING_KEYS_INTERNAL_API_KEY")
                for owner in (native, gateway, signing)
            )
            and bureau_env.get("SIGNING_KEYS_INTERNAL_URL") == PRIVATE_SIGNING_URL
            and bureau_env.get("PASSPORT_BUREAU_CALLBACK_URL") == PRIVATE_CALLBACK_URL
        ):
            raise PassportConfigurationError(
                "Beta passport bureau identity or route is invalid"
            )
        if not (
            callback_signer_env.get("SERVICE_NAME") == "passport_callback_signer"
            and callback_signer_env.get("ENVIRONMENT") == "beta"
            and str(
                callback_signer_env.get("PASSPORT_CALLBACK_SIGNER_ENABLED", "false")
            ).lower()
            == "true"
            and str(callback_signer_env.get("SIGNING_KEYS_SERVICE_PORT")) == "8018"
            and callback_signer_env.get("SIGNING_KEYS_INTERNAL_API_KEY") == signing_key
            and callback_signer_env.get("BAO_ADDR") == "http://openbao:8200"
            and callback_signer_env.get("BAO_TOKEN")
            and callback_signer_env.get("BAO_TOKEN") == signing.get("BAO_TOKEN")
        ):
            raise PassportConfigurationError(
                "Beta callback signer configuration is invalid"
            )
        if not re.fullmatch(
            r"ghcr\.io/elevenid/marty-ui-oss/services@sha256:[0-9a-f]{64}",
            str(bureau.get("image", "")),
        ):
            raise PassportConfigurationError(
                "Beta passport bureau image must be immutable"
            )
        if callback_signer.get("image") != bureau.get("image"):
            raise PassportConfigurationError(
                "Beta callback signer image must be immutable"
            )
        if (
            bureau.get("ports")
            or bureau.get("secrets")
            or bureau.get("volumes")
            or bureau.get("build")
            or bureau.get("entrypoint")
            or bureau.get("command")
            or bureau.get("privileged")
            or bureau.get("network_mode")
        ):
            raise PassportConfigurationError(
                "Beta passport bureau exposure is forbidden"
            )
        if any(
            callback_signer.get(name)
            for name in (
                "ports",
                "secrets",
                "volumes",
                "build",
                "entrypoint",
                "command",
                "privileged",
                "network_mode",
            )
        ):
            raise PassportConfigurationError(
                "Beta callback signer exposure is forbidden"
            )
        networks = bureau.get("networks", {})
        if not isinstance(networks, dict) or set(networks) != {
            "marty-network",
            PRIVATE_SIGNING_NETWORK,
        }:
            raise PassportConfigurationError("Beta passport bureau network is invalid")
        isolated = model.get("networks", {}).get(PRIVATE_SIGNING_NETWORK, {})
        if isolated.get("internal") is not True:
            raise PassportConfigurationError(
                "Beta callback signer network is not internal"
            )
        members = {
            name
            for name, service in services.items()
            if PRIVATE_SIGNING_NETWORK in service.get("networks", {})
        }
        if members != {"openbao", "passport-beta-bureau", "passport-callback-signer"}:
            raise PassportConfigurationError(
                "Beta callback signer network membership is invalid"
            )
        if set(callback_signer.get("networks", {})) != {PRIVATE_SIGNING_NETWORK}:
            raise PassportConfigurationError("Beta callback signer network is invalid")
        forbidden = {
            "passport_tenant_api_keys",
            "physical_document_artifact_key",
            "icao_document_signer_api_key",
            "personalization_bureau_api_key",
            "personalization_bureau_webhook_secret",
        }
        if forbidden.intersection(model.get("secrets", {})):
            raise PassportConfigurationError(
                "Legacy passport secret mounts are forbidden"
            )
        for owner in (*targets.values(), bureau, callback_signer):
            if any(
                item.get("source") in forbidden
                for item in owner.get("secrets", [])
                if isinstance(item, dict)
            ):
                raise PassportConfigurationError(
                    "Legacy passport secret mounts are forbidden"
                )
    except PassportConfigurationError:
        raise
    except (KeyError, TypeError, AttributeError, OSError, ValueError):
        raise PassportConfigurationError(
            "Invalid beta passport Compose model"
        ) from None


def validate_compose(
    *, project, env_files, files, passport_enabled, runner=subprocess.run
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
            raise PassportConfigurationError("Beta passport Compose validation failed")
        validate_model(
            json.loads(result.stdout), passport_enabled=passport_enabled, files=files
        )
    except (OSError, subprocess.SubprocessError, UnicodeError, json.JSONDecodeError):
        raise PassportConfigurationError(
            "Beta passport Compose validation failed"
        ) from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True, choices=["elevenid-beta"])
    parser.add_argument("--env-file", action="append", required=True)
    parser.add_argument("--file", action="append", required=True)
    parser.add_argument("--passport-enabled", action="store_true")
    args = parser.parse_args()
    try:
        validate_compose(
            project=args.project,
            env_files=args.env_file,
            files=args.file,
            passport_enabled=args.passport_enabled,
        )
    except PassportConfigurationError as error:
        print(str(error), file=sys.stderr)
        return 1
    print("Beta passport configuration validated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
