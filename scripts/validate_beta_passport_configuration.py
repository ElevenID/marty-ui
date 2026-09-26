"""Validate the opt-in beta passport Compose model without exposing secret data."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

MAX_MODEL_BYTES = 8 * 1024 * 1024
PROFILE = "docker-compose.profile.passport-native-beta.yml"
PASSPORT_RAW_KEY_NAMES = (
    "PASSPORT_TENANT_API_KEYS",
    "PHYSICAL_DOCUMENT_ARTIFACT_KEY",
    "ICAO_DOCUMENT_SIGNER_API_KEY",
    "PERSONALIZATION_BUREAU_WEBHOOK_SECRET",
)
PRIVATE_BUREAU_URL = "http://passport-beta-bureau:8020"
PRIVATE_SIGNING_URL = "http://gateway:8000/internal/signing-keys"
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
            if "passport-beta-bureau" in services:
                raise PassportConfigurationError(
                    "Beta passport bureau selected without profile"
                )
            return
        bureau = services["passport-beta-bureau"]
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
        if not (
            bureau_env.get("SERVICE_NAME") == "passport_beta_bureau"
            and bureau_env.get("ENVIRONMENT") == "beta"
            and str(bureau_env.get("PASSPORT_BETA_BUREAU_ENABLED", "false")).lower()
            == "true"
            and bureau_env.get("GRPC_SERVICE_TOKEN")
            and bureau_env.get("GRPC_SERVICE_TOKEN")
            == native.get("PERSONALIZATION_BUREAU_API_KEY")
            and bureau_env.get("GRPC_SERVICE_TOKEN")
            == environment(targets["gateway"]).get("GRPC_SERVICE_TOKEN")
            and bureau_env.get("GRPC_SERVICE_TOKEN") == flow.get("GRPC_SERVICE_TOKEN")
            and bureau_env.get("GRPC_SERVICE_TOKEN") == native.get("GRPC_SERVICE_TOKEN")
            and bureau_env.get("SIGNING_KEYS_INTERNAL_API_KEY")
            and bureau_env.get("SIGNING_KEYS_INTERNAL_URL") == PRIVATE_SIGNING_URL
            and bureau_env.get("PASSPORT_BUREAU_CALLBACK_URL") == PRIVATE_CALLBACK_URL
        ):
            raise PassportConfigurationError(
                "Beta passport bureau identity or route is invalid"
            )
        if not re.fullmatch(
            r"ghcr\.io/elevenid/marty-ui-oss/services@sha256:[0-9a-f]{64}",
            str(bureau.get("image", "")),
        ):
            raise PassportConfigurationError(
                "Beta passport bureau image must be immutable"
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
        networks = bureau.get("networks", {})
        if not isinstance(networks, dict) or set(networks) != {"marty-network"}:
            raise PassportConfigurationError("Beta passport bureau network is invalid")
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
        for owner in (*targets.values(), bureau):
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
