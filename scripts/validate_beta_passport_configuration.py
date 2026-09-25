"""Validate the opt-in beta passport Compose model without exposing secret data."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
from urllib.parse import urlparse

MAX_MODEL_BYTES = 8 * 1024 * 1024
PROFILE = "docker-compose.profile.passport-native-beta.yml"
SECRET_MOUNTS = {
    "passport_tenant_api_keys": ("gateway", "flow", "issuance-native"),
    "physical_document_artifact_key": ("issuance-native",),
    "icao_document_signer_api_key": ("issuance-native",),
    "personalization_bureau_api_key": ("issuance-native",),
    "personalization_bureau_webhook_secret": ("issuance-native",),
}
ENV_NAMES = {
    "passport_tenant_api_keys": "PASSPORT_TENANT_API_KEYS",
    "physical_document_artifact_key": "PHYSICAL_DOCUMENT_ARTIFACT_KEY",
    "icao_document_signer_api_key": "ICAO_DOCUMENT_SIGNER_API_KEY",
    "personalization_bureau_api_key": "PERSONALIZATION_BUREAU_API_KEY",
    "personalization_bureau_webhook_secret": "PERSONALIZATION_BUREAU_WEBHOOK_SECRET",
}


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
            return
        flow = environment(targets["flow"])
        if flow.get("ISSUANCE_NATIVE_SERVICE_URL") != "http://issuance-native:8005":
            raise PassportConfigurationError("Beta passport Flow target is not native")
        native = environment(targets["issuance-native"])
        if (
            str(native.get("PHYSICAL_DOCUMENT_ALLOW_SELF_SIGNED", "false")).lower()
            != "false"
        ):
            raise PassportConfigurationError(
                "Beta passport self-signed mode is forbidden"
            )
        for name in ("ICAO_DOCUMENT_SIGNER_URL", "PERSONALIZATION_BUREAU_URL"):
            url = urlparse(str(native.get(name, "")))
            if (
                url.scheme != "https"
                or not url.hostname
                or url.username
                or url.password
                or url.port == 0
                or url.query
                or url.fragment
            ):
                raise PassportConfigurationError(
                    f"{name} must be a credential-free HTTPS URL"
                )
        secrets = model["secrets"]
        for secret_name, owners in SECRET_MOUNTS.items():
            source = secrets[secret_name]["file"]
            if not isinstance(source, str) or not Path(source).is_file():
                raise PassportConfigurationError(
                    "Beta passport secret source is not a file"
                )
            with Path(source).open("rb") as secret_file:
                has_content = bool(secret_file.read(1))
            if not has_content:
                raise PassportConfigurationError("Beta passport secret source is empty")
            for owner in owners:
                service = targets[owner]
                mounts = service.get("secrets", [])
                if not any(
                    isinstance(item, dict)
                    and item.get("source") == secret_name
                    and item.get("target") == f"/run/secrets/{secret_name}"
                    for item in mounts
                ):
                    raise PassportConfigurationError(
                        "Beta passport secret mount is missing"
                    )
                env = environment(service)
                name = ENV_NAMES[secret_name]
                if (
                    env.get(name)
                    or env.get(f"{name}_FILE") != f"/run/secrets/{secret_name}"
                ):
                    raise PassportConfigurationError(
                        "Beta passport secret file binding is invalid"
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
