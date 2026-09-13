"""Validate beta DIDComm owner pairing without reading policy contents or logging models."""

from __future__ import annotations

import argparse
import json
from pathlib import PurePosixPath, PureWindowsPath
import subprocess
import sys

POLICY_TARGET = "/run/secrets/didcomm-authcrypt"
MAX_MODEL_BYTES = 8 * 1024 * 1024


class DidcommConfigurationError(ValueError):
    pass


def environment_mapping(value):
    if isinstance(value, dict):
        return value
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return dict(item.split("=", 1) for item in value if "=" in item)
    raise DidcommConfigurationError("Invalid DIDComm environment model")


def assert_native_policy_pairing(model):
    try:
        services = model["services"]
        if "issuance-native" not in services:
            return
        legacy, native = services["issuance"], services["issuance-native"]
        policy = environment_mapping(legacy["environment"]).get(
            "DIDCOMM_ENCRYPTION_POLICY_FILE"
        )
        if not policy:
            return
        if (
            environment_mapping(native["environment"]).get(
                "DIDCOMM_ENCRYPTION_POLICY_FILE"
            )
            != policy
        ):
            raise DidcommConfigurationError("Native DIDComm policy is not paired")
        previous = next(
            item
            for item in legacy.get("volumes", [])
            if item["target"] == POLICY_TARGET
        )
        candidate = next(
            item
            for item in native.get("volumes", [])
            if item["target"] == POLICY_TARGET
        )
        if (
            policy != POLICY_TARGET + "/didcomm-encryption-policy.json"
            or candidate["source"] != previous["source"]
            or candidate["type"] != "bind"
            or candidate["read_only"] is not True
            or candidate["bind"]["create_host_path"] is not False
            or previous["read_only"] is not True
        ):
            raise DidcommConfigurationError("Native DIDComm policy mount is not paired")
        source = candidate["source"]
        if (
            not isinstance(source, str)
            or not source
            or any(
                str(path) == path.anchor
                for path in (PurePosixPath(source), PureWindowsPath(source))
            )
        ):
            raise DidcommConfigurationError(
                "DIDComm policy directory cannot be a filesystem root"
            )
        for name, service in services.items():
            if name in {"issuance", "issuance-native"}:
                continue
            if any(
                item.get("source") == candidate["source"]
                for item in service.get("volumes", [])
            ):
                raise DidcommConfigurationError(
                    "DIDComm policy is mounted outside its delivery owners"
                )
    except (KeyError, TypeError, StopIteration, AttributeError):
        raise DidcommConfigurationError("Invalid DIDComm owner model") from None


def validate_model(model, *, authcrypt_enabled):
    try:
        policies = [
            environment_mapping(model["services"][name]["environment"]).get(
                "DIDCOMM_ENCRYPTION_POLICY_FILE"
            )
            for name in ("issuance", "issuance-native")
        ]
        if authcrypt_enabled and not all(policies):
            raise DidcommConfigurationError(
                "Selected DIDComm policy is not configured for both owners"
            )
        if not authcrypt_enabled and any(policies):
            raise DidcommConfigurationError(
                "Configured DIDComm policy requires explicit beta opt-in"
            )
        assert_native_policy_pairing(model)
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
        validate_model(model, authcrypt_enabled=authcrypt_enabled)
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
