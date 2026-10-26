#!/usr/bin/env python3
"""Render digest-bound product composition; never install or start services."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import runpy
from copy import deepcopy
from pathlib import Path
from urllib.parse import urlsplit

PLAN = runpy.run_path(str(Path(__file__).with_name("product_package_plan.py")))
SHARED_SERVICES = {
    "revocation-profile-migrate": "revocation_profile",
    "issuance-migrations": "issuance_native",
    "gateway": "gateway",
    "auth": "auth",
    "organization": "organization",
    "credential-template": "credential_template",
    "trust-profile": "trust_profile",
    "issuance": "issuance_native",
    "issuance-native": "issuance_native",
    "canvas-sync-worker": "canvas_sync_worker",
    "applicant": "applicant",
    "notification": "notification",
    "compliance-profile": "compliance_profile",
    "presentation-policy": "presentation_policy",
    "deployment-profile": "deployment_profile",
    "signing-keys": "signing_keys",
    "flow": "flow",
    "verification": "verification",
    "revocation-profile": "revocation_profile",
    "device-registration": "device_registration",
    "event-stream": "event_stream",
}
REMOVED_SERVICES = {
    "ui",
    "console",
    "cloudflared",
    "cloudflared-beta",
    "tunnel-nginx-proxy",
}
PINNED_IMAGE = re.compile(r"[a-z0-9][a-z0-9:._/-]*@sha256:[0-9a-f]{64}")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def package_images(package: dict) -> dict[str, str]:
    require(
        package.get("schema") == "marty.product-package/v1",
        "product package schema is invalid",
    )
    product = package.get("product")
    require(product in PLAN["PRODUCTS"], "product package identity is invalid")
    require(
        PLAN["VERSION"].fullmatch(str(package.get("version"))) is not None,
        "product version is invalid",
    )
    prefix, roles = PLAN["PRODUCTS"][product]
    require(
        package.get("tag") == prefix + package["version"],
        "product tag differs from its version",
    )
    source = package.get("source", {})
    require(
        source.get("repository") == "ElevenID/marty-ui"
        and PLAN["SHA"].fullmatch(str(source.get("commit"))) is not None,
        "product source is invalid",
    )
    require(
        package.get("api") == {"http": "v1", "mip": "0.5.0"},
        "product API contract is incompatible",
    )
    images = package.get("images", [])
    require(
        len(images) == len(roles) and {image.get("role") for image in images} == roles,
        "product image role set differs",
    )
    refs = {}
    for image in images:
        uri = "ghcr.io/elevenid/" + product + "/" + image["role"]
        require(
            image.get("uri") == uri and image.get("platform") == "linux/amd64",
            "product image identity differs",
        )
        ref = uri + "@" + str(image.get("digest"))
        require(
            PINNED_IMAGE.fullmatch(ref) is not None,
            "product image must be digest-pinned",
        )
        refs[image["role"]] = ref
    return refs


def metadata(package: dict) -> dict:
    canonical = json.dumps(package, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return {
        "product": package["product"],
        "version": package["version"],
        "source": package["source"],
        "api": package["api"],
        "package_sha256": "sha256:" + hashlib.sha256(canonical).hexdigest(),
    }


def server_composition(base: dict, package: dict, runtime_dir: Path | None = None) -> dict:
    images = package_images(package)
    require(
        package["product"] == "marty-server",
        "server composition requires the server package",
    )
    require("include" not in base, "base must resolve source includes")
    result = deepcopy(base)
    services = result.get("services", {})
    require(
        {"edge", "gateway", "auth", "keycloak", "flow"} <= set(services),
        "server base lacks required backend services",
    )
    for name in REMOVED_SERVICES:
        services.pop(name, None)
    edge = services["edge"]
    require(
        isinstance(edge.get("depends_on", {}), dict),
        "base must be a normalized Compose model",
    )
    edge.get("depends_on", {}).pop("ui", None)
    edge.setdefault("environment", {})["SELFHOST_CONSOLE_ENABLED"] = "false"
    edge["environment"].pop("UI_UPSTREAM", None)
    for name, service in services.items():
        require(
            "extends" not in service and "include" not in service,
            "base must resolve source includes and extensions",
        )
        dependencies = service.get("depends_on", {})
        require(
            not set(dependencies) & REMOVED_SERVICES,
            "backend depends on removed console/tunnel services",
        )
        for field in ("network_mode", "pid", "ipc"):
            require(
                service.get(field)
                not in {"service:" + item for item in REMOVED_SERVICES},
                "backend shares a removed service namespace",
            )
        for field in ("links", "volumes_from"):
            require(
                not any(
                    item.split(":", 1)[0] in REMOVED_SERVICES
                    for item in service.get(field, [])
                ),
                "backend references a removed service",
            )
        environment = service.setdefault("environment", {})
        require(
            isinstance(environment, dict),
            "base environments must be normalized mappings",
        )
        role = None
        if name in SHARED_SERVICES:
            role = "services"
            environment["SERVICE_NAME"] = SHARED_SERVICES[name]
        elif name in {"db-migrate", "kms-initialize"}:
            role = "migrations"
        elif name in {"keycloak", "keycloak-configurator"}:
            role = "keycloak"
        elif name == "openbao":
            role = "openbao-didcomm"
        if role:
            service.pop("build", None)
            service["image"] = images[role]
            service["pull_policy"] = "missing"
            environment["MARTY_RELEASE_VERSION"] = package["version"]
            environment["MARTY_UI_SHA"] = package["source"]["commit"]
        else:
            require("build" not in service, "unbound service retains a source build")
            image = str(service.get("image", ""))
            require(
                PINNED_IMAGE.fullmatch(image) is not None,
                "external runtime images must be digest-pinned",
            )
            require(
                not image.startswith("ghcr.io/elevenid/marty-"),
                "unmapped Marty service depends on another product image",
            )
        for mount in service.get("volumes", []):
            require(isinstance(mount, dict), "base mounts must be normalized")
            if mount.get("type") == "bind":
                require(
                    "ui"
                    not in str(mount.get("source", "")).replace("\\", "/").split("/"),
                    "backend retains frontend source assets",
                )
    if runtime_dir is not None:
        for relative in PLAN["SERVER_RUNTIME_FILES"]:
            PLAN["source_file"](runtime_dir, relative)
        for name, service in services.items():
            targets = PLAN["SERVER_RUNTIME_MOUNTS"].get(name, {})
            for mount in service.get("volumes", []):
                if mount.get("type") == "bind" and mount.get("target") in targets:
                    mount["source"] = str((runtime_dir / targets[mount["target"]]).resolve())
    for kind in ("secrets", "configs"):
        used = {
            ref["source"] if isinstance(ref, dict) else ref
            for service in services.values()
            for ref in service.get(kind, [])
        }
        if kind in result:
            result[kind] = {
                name: value for name, value in result[kind].items() if name in used
            }
    result["name"] = "marty-server"
    result["x-marty-product"] = metadata(package)
    return result


def console_composition(package: dict, origin: str, port: int = 3002) -> dict:
    images = package_images(package)
    require(
        package["product"] == "marty-console",
        "console composition requires the console package",
    )
    require(
        isinstance(origin, str)
        and len(origin) <= 2048
        and re.fullmatch(
            r"https?://(?:[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?|\[[0-9A-Fa-f:]+\])(?::[0-9]+)?",
            origin,
        )
        is not None,
        "server origin must not contain credentials, path, query or fragment",
    )
    parts = urlsplit(origin)
    require(
        parts.port is None or 1 <= parts.port <= 65535, "server origin port is invalid"
    )
    require(type(port) is int and 1 <= port <= 65535, "console port is invalid")
    return {
        "name": "marty-console",
        "x-marty-product": metadata(package),
        "services": {
            "console": {
                "image": images["ui"],
                "pull_policy": "missing",
                "environment": {"MARTY_SERVER_ORIGIN": origin},
                "ports": [f"127.0.0.1:{port}:80"],
                "restart": "unless-stopped",
            }
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--base", type=Path)
    parser.add_argument("--runtime-dir", type=Path)
    parser.add_argument("--server-origin")
    parser.add_argument("--console-port", type=int, default=3002)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    package = json.loads(args.package.read_bytes())
    if package.get("product") == "marty-server":
        require(
            args.base is not None and args.server_origin is None,
            "server composition needs only a normalized base model",
        )
        result = server_composition(json.loads(args.base.read_bytes()), package, args.runtime_dir)
    else:
        require(
            args.base is None and args.runtime_dir is None and args.server_origin is not None,
            "console composition needs only a public server origin",
        )
        result = console_composition(package, args.server_origin, args.console_port)
    args.output.write_text(
        json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
