#!/usr/bin/env python3
"""Check whether a rendered server candidate has inputs for a runtime attempt.

This checks local files and image references only. It does not start containers,
validate credentials, contact an external KMS, or qualify a product release.
"""

from __future__ import annotations

import argparse
import json
import re
import runpy
from pathlib import Path

from product_evidence_intake import read_json, require

COMPOSE = runpy.run_path(str(Path(__file__).with_name("compose_product_packages.py")))
REQUIRED_SERVICES = {"edge", "gateway", "auth", "keycloak", "flow", "postgres", "redis"}
OWNED_ROLES = {
    **{name: "services" for name in COMPOSE["SHARED_SERVICES"]},
    "db-migrate": "migrations",
    "kms-initialize": "migrations",
    "keycloak": "keycloak",
    "keycloak-configurator": "keycloak",
    "openbao": "openbao-didcomm",
}
PINNED = COMPOSE["PINNED_IMAGE"]
HEX_DIGEST = re.compile(r"sha256:([0-9a-f]{64})\Z")
SECRET_WHITESPACE = b" \t\r\n\v\f"
SECRET_PLACEHOLDER_PREFIXES = (
    b"change-me", b"change_me", b"changeme", b"replace-me", b"replace_me"
)


def available_file(value: object) -> tuple[bool, bool]:
    if not isinstance(value, str) or not value:
        return False, False
    path = Path(value)
    if not path.is_absolute() or path.is_symlink():
        return False, path.is_symlink()
    if not path.is_file():
        return False, False
    try:
        prefix = bytearray()
        last_nonspace = -1
        position = 0
        started = False
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(65536), b""):
                for byte in chunk:
                    if not started and byte in SECRET_WHITESPACE:
                        continue
                    started = True
                    if len(prefix) < len(b"placeholder") + 1:
                        prefix.append(byte)
                    if byte not in SECRET_WHITESPACE:
                        last_nonspace = position
                    position += 1
        normalized_prefix = bytes(prefix).lower()
        placeholder = any(
            normalized_prefix.startswith(value) for value in SECRET_PLACEHOLDER_PREFIXES
        ) or (
            last_nonspace == len(b"placeholder") - 1
            and normalized_prefix.startswith(b"placeholder")
        )
        return last_nonspace >= 0 and not placeholder, False
    except OSError:
        return False, False


def available_bind(value: object) -> tuple[bool, bool]:
    if not isinstance(value, str) or not value:
        return False, False
    path = Path(value)
    if not path.is_absolute() or path.is_symlink():
        return False, path.is_symlink()
    return path.exists(), False


def assess(model: dict, package: dict) -> dict:
    images = COMPOSE["package_images"](package)
    require(package["product"] == "marty-server", "runtime input check needs server package")
    require(model.get("x-marty-product") == COMPOSE["metadata"](package),
            "rendered model differs from the server package")
    services = model.get("services")
    require(isinstance(services, dict) and REQUIRED_SERVICES <= set(services),
            "rendered server model lacks required services")
    require(not set(services) & COMPOSE["REMOVED_SERVICES"],
            "rendered server model retains console or tunnel services")
    edge = services["edge"]
    require(edge.get("environment", {}).get("SELFHOST_CONSOLE_ENABLED") == "false",
            "server edge has not disabled the console")
    require("ui" not in edge.get("depends_on", {}),
            "server edge still depends on UI")

    missing_secrets = 0
    linked_inputs = 0
    declarations = model.get("secrets", {})
    require(isinstance(declarations, dict), "server secret declarations are invalid")
    for entry in declarations.values():
        require(isinstance(entry, dict), "server secret declaration is invalid")
        available, linked = available_file(entry.get("file"))
        missing_secrets += not available
        linked_inputs += linked

    missing_binds = 0
    unpinned_images = 0
    placeholder_images = 0
    wrong_owned_images = 0
    external_image_refs = set()
    for name, service in services.items():
        require(isinstance(service, dict), "server service is invalid")
        image = service.get("image")
        if not isinstance(image, str) or PINNED.fullmatch(image) is None:
            unpinned_images += 1
        elif name in OWNED_ROLES:
            wrong_owned_images += image != images[OWNED_ROLES[name]]
        else:
            external_image_refs.add(image)
            match = HEX_DIGEST.search(image)
            placeholder_images += bool(match and len(set(match.group(1))) == 1)
        for mount in service.get("volumes", []):
            require(isinstance(mount, dict), "server volume declaration is invalid")
            if mount.get("type") == "bind":
                available, linked = available_bind(mount.get("source"))
                missing_binds += not available
                linked_inputs += linked

    checks = {
        "missing_secret_files": int(missing_secrets),
        "missing_bind_sources": int(missing_binds),
        "linked_inputs": int(linked_inputs),
        "unpinned_images": int(unpinned_images),
        "placeholder_external_images": int(placeholder_images),
        "wrong_product_images": int(wrong_owned_images),
    }
    return {
        "schema": "marty.product-runtime-input-preflight/v1",
        "product": "marty-server",
        "version": package["version"],
        "source_sha": package["source"]["commit"],
        "service_count": len(services),
        "declared_secret_count": len(declarations),
        "external_image_count": len(external_image_refs),
        "checks": checks,
        "result": (
            "ready_for_runtime_attempt" if all(value == 0 for value in checks.values())
            else "blocked_missing_runtime_inputs"
        ),
        "external_kms_runtime_proven": False,
        "business_journey_proven": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compose", type=Path, required=True)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = assess(read_json(args.compose), read_json(args.package))
    with args.output.open("x", encoding="utf-8", newline="\n") as output:
        json.dump(result, output, sort_keys=True, indent=2)
        output.write("\n")
    if result["result"] != "ready_for_runtime_attempt":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
