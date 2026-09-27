#!/usr/bin/env python3
"""Validate an already rendered disposable Compose model before rollback.

This module has no mutation command. Passing its model check is necessary,
but never sufficient, for a later protected rollback rehearsal.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit


PROJECT = re.compile(r"marty-passport-acceptance-(base|selfhost)-[a-z0-9]{6,32}\Z")
SELECTED = frozenset({
    "gateway", "flow", "issuance-native", "passport-callback-signer-supported",
    "passport-provider-ingress",
})
ISOLATED_DEPENDENCIES = frozenset({"postgres", "openbao", "redis"})
ALLOWED_SERVICES = frozenset({
    "applicant", "auth", "canvas-sync-worker", "compliance-profile",
    "credential-template", "db-migrate", "deployment-profile",
    "device-registration", "event-stream", "flow", "gateway", "issuance",
    "issuance-migrations", "issuance-native", "keycloak",
    "keycloak-configurator", "mailpit", "notification", "openbao",
    "openbao-init", "organization", "passport-callback-signer-supported",
    "passport-provider-ingress", "postgres", "presentation-policy", "redis",
    "revocation-profile", "revocation-profile-migrate", "signing-keys",
    "trust-profile", "ui", "verification", "verification-migrations",
})
REMOTE_KEYS = re.compile(r".*(?:URL|URI|ADDR|ENDPOINT|HOST|TARGET|TEMPLATE)\Z")
URLS = re.compile(r"[a-z][a-z0-9+.-]*://[^\s,]+", re.IGNORECASE)
IMMUTABLE_IMAGE = re.compile(r"[^\s]+@sha256:[0-9a-f]{64}\Z")
ROOT = Path(__file__).resolve().parents[1]


class ModelPreflightError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ModelPreflightError(message)


def _within(path: str, root: Path) -> bool:
    candidate = Path(path)
    return candidate.is_absolute() and candidate.resolve().is_relative_to(root.resolve())


def _endpoint_host(value: str) -> str | None:
    return urlsplit(value).hostname


def _run_config(args: list[str], environment: dict[str, str]) -> str:
    try:
        result = subprocess.run(args, env=environment, capture_output=True,
                                text=True, encoding="utf-8", check=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ModelPreflightError("Disposable Compose model rendering failed") from exc
    require(len(result.stdout) <= 4 * 1024 * 1024,
            "Disposable Compose model is oversized")
    return result.stdout


def render_model(
    surface: str, project: str, env_file: Path, disposable_root: Path,
    services_reference: str,
    runner: Callable[[list[str], dict[str, str]], str] = _run_config,
    *, phase: str = "rust",
) -> dict:
    """Read Docker's resolved model using only fixed repo-owned Compose files."""
    match = PROJECT.fullmatch(project)
    require(match is not None and match.group(1) == surface,
            "Disposable project name is required")
    require(disposable_root.is_absolute() and disposable_root.is_dir(),
            "Disposable resource root is missing")
    require(env_file.is_file() and _within(str(env_file), disposable_root),
            "Compose env file is outside the disposable root")
    require(re.fullmatch(r"ghcr\.io/elevenid/marty-ui-oss/services@sha256:[0-9a-f]{64}",
                         services_reference) is not None,
            "Signed services image reference is invalid")
    require(phase in {"rust", "python"}, "Disposable owner phase is invalid")
    compose = ROOT / "docker-compose.passport-supported-disposable.yml"
    surface_overlay = ROOT / f"docker-compose.passport-supported-disposable-{surface}.yml"
    owner_overlay = ROOT / "docker-compose.passport-supported-disposable-python-owner.yml"
    files = [compose, surface_overlay]
    if phase == "python":
        files.append(owner_overlay)
    require(all(path.is_file() for path in files),
            "Protected Compose source is missing")
    args = ["docker", "compose", "--project-name", project, "--env-file", str(env_file),
            *(arg for path in files for arg in ("-f", str(path))),
            "config", "--format", "json"]
    environment = os.environ.copy()
    environment["MARTY_SERVICES_IMAGE"] = services_reference
    try:
        model = json.loads(runner(args, environment))
    except ValueError as exc:
        raise ModelPreflightError("Disposable Compose model JSON is invalid") from exc
    require(isinstance(model, dict), "Disposable Compose model is not an object")
    return model


def preflight_read_only(
    surface: str, project: str, env_file: Path, disposable_root: Path,
    services_reference: str,
    runner: Callable[[list[str], dict[str, str]], str] = _run_config,
) -> dict:
    model = render_model(surface, project, env_file, disposable_root,
                         services_reference, runner)
    result = validate_model(model, project, services_reference, disposable_root)
    return {"schema": "marty.passport-supported-rollback-preflight/v1",
            "status": "blocked", "model": result,
            "blocker": "protected provisioning and live ownership proof are absent"}


def validate_model(
    model: dict, project: str, services_reference: str, disposable_root: Path,
) -> dict[str, object]:
    """Reject resolved configurations that can touch shared production resources."""
    require(PROJECT.fullmatch(project) is not None, "Disposable project name is required")
    require(disposable_root.is_absolute() and disposable_root.is_dir(),
            "Disposable resource root is missing")
    require(isinstance(model, dict) and model.get("name") == project,
            "Resolved Compose model has a different project")
    services = model.get("services")
    require(isinstance(services, dict)
            and SELECTED | ISOLATED_DEPENDENCIES <= set(services),
            "Resolved Compose model lacks isolated passport dependencies")
    require(set(services) <= ALLOWED_SERVICES,
            "Resolved Compose model has an unexpected service")
    networks = model.get("networks")
    require(isinstance(networks, dict) and bool(networks),
            "Disposable Compose networks are missing")
    for network in networks.values():
        require(isinstance(network, dict)
                and network.get("external") not in (True, "true")
                and network.get("driver", "bridge") == "bridge"
                and not network.get("driver_opts")
                and network.get("internal") is True
                and isinstance(network.get("name"), str)
                and network["name"].startswith(project + "_"),
                "Compose network is external or shared")
    volumes = model.get("volumes", {})
    require(isinstance(volumes, dict), "Compose volumes are invalid")
    for volume in volumes.values():
        require(isinstance(volume, dict)
                and volume.get("external") not in (True, "true")
                and volume.get("driver", "local") == "local"
                and not volume.get("driver_opts")
                and isinstance(volume.get("name"), str)
                and volume["name"].startswith(project + "_"),
                "Compose volume is external or shared")
    secrets = model.get("secrets", {})
    require(isinstance(secrets, dict), "Compose secrets are invalid")
    for secret in secrets.values():
        require(isinstance(secret, dict)
                and secret.get("external") not in (True, "true")
                and isinstance(secret.get("file"), str)
                and _within(secret["file"], disposable_root),
                "Compose secret is outside the disposable root")
    configs = model.get("configs", {})
    require(isinstance(configs, dict), "Compose configs are invalid")
    for config in configs.values():
        require(isinstance(config, dict)
                and config.get("external") not in (True, "true")
                and isinstance(config.get("file"), str)
                and _within(config["file"], disposable_root),
                "Compose config is outside the disposable root")
    for name, service in services.items():
        require(isinstance(service, dict), "Compose service is invalid")
        for forbidden in ("container_name", "network_mode", "pid", "ipc",
                          "privileged", "devices", "extra_hosts", "volumes_from",
                          "build", "command", "entrypoint"):
            require(not service.get(forbidden),
                    f"Compose {name} has a shared-host or fixed-name setting")
        require(service.get("pull_policy") != "build"
                and isinstance(service.get("image"), str)
                and IMMUTABLE_IMAGE.fullmatch(service["image"]) is not None,
                f"Compose {name} image is not immutable")
        if name in SELECTED:
            require(service.get("image") == services_reference,
                    f"Compose {name} is not pinned to the signed services image")
        mounts = service.get("volumes", [])
        require(isinstance(mounts, list), f"Compose {name} mounts are invalid")
        for mount in mounts:
            require(isinstance(mount, dict), f"Compose {name} mount is invalid")
            if mount.get("type") == "bind":
                require(isinstance(mount.get("source"), str)
                        and _within(mount["source"], disposable_root),
                        f"Compose {name} bind mount escapes the disposable root")
            else:
                require(mount.get("type") == "volume"
                        and mount.get("source") in volumes,
                        f"Compose {name} uses an unknown mount")
        for kind, available in (("secrets", secrets), ("configs", configs)):
            references = service.get(kind, [])
            require(isinstance(references, list),
                    f"Compose {name} {kind} are invalid")
            for reference in references:
                require(isinstance(reference, dict)
                        and reference.get("source") in available,
                        f"Compose {name} uses an unknown {kind} source")
        ports = service.get("ports", [])
        require(isinstance(ports, list), f"Compose {name} ports are invalid")
        for port in ports:
            require(isinstance(port, dict) and port.get("host_ip") == "127.0.0.1",
                    f"Compose {name} publishes outside loopback")
        environment = service.get("environment", {})
        require(isinstance(environment, dict), f"Compose {name} environment is invalid")
        for key, value in environment.items():
            require(isinstance(key, str), f"Compose {name} environment key is invalid")
            if not isinstance(value, str):
                continue
            for url in URLS.findall(value):
                require(_endpoint_host(url) in services,
                        f"Compose {name} endpoint leaves disposable services")
            if REMOTE_KEYS.fullmatch(key) and value and not URLS.search(value):
                require(value.split(":", 1)[0] in services,
                        f"Compose {name} endpoint leaves disposable services")
            if key.endswith(("DOMAIN", "HOSTNAME")) and value:
                require(value in {"localhost", "127.0.0.1"}
                        | set(services),
                        f"Compose {name} domain leaves disposable services")
    return {"project": project, "services": sorted(SELECTED),
            "model_safe": True, "rollback_accepted": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--surface", choices=("base", "selfhost"), required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument("--disposable-root", type=Path, required=True)
    parser.add_argument("--services-reference", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = preflight_read_only(args.surface, args.project, args.env_file,
                                     args.disposable_root, args.services_reference)
    except ModelPreflightError as exc:
        report = {"schema": "marty.passport-supported-rollback-preflight/v1",
                  "status": "blocked", "blocker": str(exc)}
        args.output.write_text(json.dumps(report, sort_keys=True) + "\n",
                               encoding="utf-8")
        parser.exit(1, f"Supported rollback preflight blocked: {exc}\n")
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    parser.exit(1, "Supported rollback preflight blocked pending protected provisioning\n")


if __name__ == "__main__":
    raise SystemExit(main())
