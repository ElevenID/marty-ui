#!/usr/bin/env python3
"""Refuse image-only Keycloak updates before the full remote-KMS cutover."""

from __future__ import annotations

import argparse
import json
import re
import sys


IMAGE = re.compile(r"ghcr\.io/elevenid/marty-ui-oss/keycloak@sha256:[0-9a-f]{64}\Z")
EXPECTED_ENV = {
    "BAO_ADDR": {"valueFrom": {"configMapKeyRef": {"name": "marty-config", "key": "KEYCLOAK_KMS_ADDR"}}},
    "BAO_CACERT": {"value": "/run/secrets/openbao_tls_ca_cert"},
    "BAO_TOKEN_FILE": {"value": "/run/secrets/keycloak_signing_kms_token"},
    "MARTY_KEYCLOAK_RS256_CERT_DIR": {"value": "/run/secrets"},
    "MARTY_KEYCLOAK_JWE_TOKEN_DIR": {"value": "/run/secrets"},
    "MARTY_KEYCLOAK_JWE_MOUNT": {"value": "didcomm"},
    "MARTY_KEYCLOAK_KMS_KEY_PREFIX": {"value": "keycloak"},
    "MARTY_KEYCLOAK_KMS_KEY_VERSION": {
        "valueFrom": {"configMapKeyRef": {"name": "marty-config", "key": "KEYCLOAK_KMS_KEY_VERSION"}}
    },
}


def validate(deployment: object, namespace: str) -> None:
    if not isinstance(deployment, dict):
        raise ValueError("Keycloak deployment is missing")
    metadata = deployment.get("metadata") or {}
    if metadata.get("name") != "keycloak" or metadata.get("namespace") != namespace:
        raise ValueError("Keycloak deployment identity differs")
    pod = deployment.get("spec", {}).get("template", {}).get("spec", {})
    containers = pod.get("containers", [])
    if not isinstance(containers, list) or len(containers) != 1 or containers[0].get("name") != "keycloak":
        raise ValueError("Keycloak deployment container differs")
    container = containers[0]
    if not isinstance(container.get("image"), str) or IMAGE.fullmatch(container["image"]) is None:
        raise ValueError("Keycloak deployment is not on the remote-key image")
    env = container.get("env", [])
    if not isinstance(env, list) or len({item.get("name") for item in env if isinstance(item, dict)}) != len(env):
        raise ValueError("Keycloak environment is invalid")
    by_name = {item["name"]: item for item in env}
    if any(by_name.get(name) != {"name": name, **expected}
           for name, expected in EXPECTED_ENV.items()):
        raise ValueError("Keycloak remote-key environment differs")
    mounts = container.get("volumeMounts", [])
    volumes = pod.get("volumes", [])
    if (not isinstance(mounts, list) or not isinstance(volumes, list)
            or not any(item.get("name") == "keycloak-kms" and item.get("mountPath") == "/run/secrets"
                       and item.get("readOnly") is True for item in mounts)
            or not any(item.get("name") == "keycloak-kms"
                       and item.get("secret", {}).get("secretName") == "keycloak-kms"
                       for item in volumes)):
        raise ValueError("Keycloak KMS secret mount differs")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--namespace", required=True)
    args = parser.parse_args()
    try:
        validate(json.load(sys.stdin), args.namespace)
    except (ValueError, TypeError, KeyError, AttributeError):
        parser.exit(1, "Keycloak image-only update requires the full KMS manifest cutover.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
