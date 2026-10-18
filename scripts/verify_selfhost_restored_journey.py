#!/usr/bin/env python3
"""Verify an already restored, isolated KMS-only self-host installation.

This runner owns no state and never starts or tears down containers. The
operator must first restore a coordinated, quiesced recovery point into fresh
project names and run the exact Compose closure. A passing report is a
post-restore check, not proof of backup provenance or release qualification.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

from check_selfhost_recovery_scope import has_symlink_component, recovery_scope
from run_selfhost_business_journey import (
    JOURNEY,
    JOURNEY_INPUTS,
    LOCAL_SERVICES,
    PROJECT,
    command,
    exercise_installed_keycloak_keys,
    live_services,
    parse_status,
    pinned_integration_checkout,
    verify_keycloak_database_custody,
    verify_marty_database_custody,
)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    for name in ("recovery_root", "source_checkout", "integration_checkout", "install_root",
                 "state_root", "openbao_state_root", "secret_root", "env_file",
                 "openbao_compose", "output"):
        result.add_argument("--" + name.replace("_", "-"), type=Path, required=True)
    for name in ("source_sha", "integration_sha", "project_name", "openbao_project"):
        result.add_argument("--" + name.replace("_", "-"), required=True)
    result.add_argument("--compose-override", type=Path)
    return result


def checked_root(path: Path, label: str) -> Path:
    if (not path.is_absolute() or path == Path(path.anchor) or has_symlink_component(path)
            or not path.is_dir()):
        raise ValueError(f"{label} must be an existing absolute non-linked directory")
    return path.resolve(strict=True)


def runtime_bindings(compose: list[str], model: dict, environment: dict[str, str],
                     services: set[str], install_root: Path) -> dict[str, dict[str, str]]:
    """Bind rendered service settings to the actual project containers."""
    status = parse_status(command([*compose, "ps", "--all", "--format", "json"],
                                  cwd=install_root, env=environment))
    by_service = {item.get("Service"): item for item in status}
    if len(status) != len(services) or set(by_service) != services:
        raise ValueError("running project differs from reviewed service closure")
    ids = [by_service[name].get("ID") for name in sorted(services)]
    if any(not isinstance(value, str) or not value for value in ids) or len(set(ids)) != len(ids):
        raise ValueError("running project has missing or duplicate container identities")
    running = json.loads(command(["docker", "inspect", *ids], env=environment))
    if not isinstance(running, list) or len(running) != len(ids):
        raise ValueError("running container inspection is incomplete")
    image_references = {model["services"][name].get("image") for name in services}
    if any(not isinstance(image, str) or not image for image in image_references):
        raise ValueError("rendered service has no pinned image reference")
    images = sorted(image_references)
    image_metadata = json.loads(command(["docker", "image", "inspect", *images],
                                        env=environment))
    if len(image_metadata) != len(images):
        raise ValueError("rendered image inspection is incomplete")
    image_ids = dict(zip(images, (item.get("Id") for item in image_metadata)))
    hashes = {}
    for name in sorted(services):
        fields = command([*compose, "config", "--hash", name],
                         cwd=install_root, env=environment).split()
        if len(fields) != 2 or fields[0] != name or len(fields[1]) != 64:
            raise ValueError(f"rendered Compose hash for {name} is invalid")
        hashes[name] = fields[1]

    result = {}
    for name, container in zip(sorted(services), running):
        service = model["services"][name]
        labels = container.get("Config", {}).get("Labels") or {}
        if (not isinstance(container.get("Id"), str)
                or not container["Id"].startswith(by_service[name]["ID"])
                or labels.get("com.docker.compose.project") != model.get("name")
                or labels.get("com.docker.compose.service") != name
                or labels.get("com.docker.compose.config-hash") != hashes[name]
                or container.get("Image") != image_ids[service["image"]]):
            raise ValueError(f"running {name} image or Compose configuration differs")
        expected_mounts: set[tuple[str, str, str, bool]] = set()
        for mount in service.get("volumes", []):
            kind = mount.get("type")
            source = mount.get("source")
            if kind == "volume":
                source = model.get("volumes", {}).get(source, {}).get("name")
            if kind not in ("bind", "volume") or not isinstance(source, str):
                raise ValueError(f"rendered {name} mount is not supported")
            expected_mounts.add((kind, source, mount["target"],
                                 not mount.get("read_only", False)))
        for secret in service.get("secrets", []):
            source = model.get("secrets", {}).get(secret.get("source"), {}).get("file")
            if not isinstance(source, str):
                raise TypeError(f"rendered {name} secret has no file source")
            expected_mounts.add(("bind", source, secret["target"], False))
        # The pinned OpenBao image declares two unused anonymous Docker
        # volumes. Its reviewed Raft configuration uses /bao/data instead.
        image_volumes = (container.get("Config", {}).get("Volumes") or {})
        anonymous_openbao = {"/openbao/file", "/openbao/logs"}
        actual_mounts = {
            (mount.get("Type"), mount.get("Name") if mount.get("Type") == "volume"
             else mount.get("Source"), mount.get("Destination"), mount.get("RW"))
            for mount in container.get("Mounts", [])
            if not (model.get("name", "").startswith("marty-preview-")
                    and mount.get("Type") == "volume"
                    and mount.get("Destination") in anonymous_openbao
                    and mount.get("Destination") in image_volumes
                    and mount.get("RW") is True and mount.get("Name"))
        }
        if actual_mounts != expected_mounts:
            raise ValueError(f"running {name} mounts differ from restored model")
        result[name] = {"config_hash": hashes[name], "image_id": container["Image"]}
    return result


def main() -> int:
    args = parser().parse_args()
    if sys.platform != "linux" or PROJECT.fullmatch(args.project_name) is None:
        raise ValueError("restored journey requires Linux and an isolated qualification project")
    if re.fullmatch(r"marty-preview-[a-z0-9]{16}", args.openbao_project) is None:
        raise ValueError("OpenBao project must be an isolated preview")
    for name in ("recovery_root", "source_checkout", "integration_checkout", "install_root",
                 "state_root", "openbao_state_root", "secret_root"):
        setattr(args, name, checked_root(getattr(args, name), name))
    if (not args.recovery_root.name.startswith("recovery-")
            or args.state_root != args.recovery_root / "state"
            or args.openbao_state_root != args.recovery_root / "openbao-state"
            or args.secret_root != args.recovery_root / "secrets"
            or args.install_root != args.recovery_root / "install" / "selfhost-prepared"
            or args.source_checkout.is_relative_to(args.recovery_root)
            or args.integration_checkout.is_relative_to(args.recovery_root)):
        raise ValueError("restore inputs must stay inside one isolated recovery root")
    if (not args.env_file.is_absolute() or args.env_file.is_symlink()
            or not args.env_file.is_file() or args.env_file != args.recovery_root / "selfhost.env"
            or args.openbao_compose != args.install_root / "docker-compose.selfhost.openbao.yml"
            or not args.openbao_compose.is_file() or args.openbao_compose.is_symlink()
            or not args.output.is_absolute() or args.output.parent != args.recovery_root
            or args.output.exists() or args.output.is_symlink()):
        raise ValueError("restore input or new report path is unsafe")
    if any(args.output.is_relative_to(path) for path in
           (args.source_checkout, args.integration_checkout, args.install_root)):
        raise ValueError("report must be outside source and installation")
    if args.compose_override is not None and (
            not args.compose_override.is_absolute() or args.compose_override.is_symlink()
            or not args.compose_override.is_file()):
        raise ValueError("Compose override must be an absolute regular file")
    tool_path = Path(__file__).resolve(strict=True)
    tool_from_release_source = tool_path == args.source_checkout / "scripts" / tool_path.name
    if args.compose_override is None and not tool_from_release_source:
        raise ValueError("signed-image verification requires the exact release-source tool")
    if (re.fullmatch(r"[0-9a-f]{40}", args.source_sha) is None
            or re.fullmatch(r"[0-9a-f]{40}", args.integration_sha) is None):
        raise ValueError("source identities must be commit SHA-1 values")
    if command(["git", "rev-parse", "HEAD^{commit}"],
               cwd=args.source_checkout).strip() != args.source_sha:
        raise ValueError("source checkout differs from claimed release source")
    if command(["git", "status", "--porcelain", "--untracked-files=all"],
               cwd=args.source_checkout).strip():
        raise ValueError("release source checkout has local changes")
    pinned_integration_checkout(args.integration_checkout, args.integration_sha)
    missing = [name for name in JOURNEY_INPUTS if not os.environ.get(name)]
    if missing:
        raise ValueError("restored journey fixture inputs are absent: " + ", ".join(missing))

    environment = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    compose = ["docker", "compose", "--project-name", args.project_name,
               "--env-file", str(args.env_file),
               "-f", str(args.install_root / "docker-compose.yml")]
    if args.compose_override is not None:
        compose.extend(["-f", str(args.compose_override)])
    compose.extend(["--profile", "*"])
    model_raw = command([*compose, "config", "--format", "json"],
                        cwd=args.install_root, env=environment)
    model = json.loads(model_raw)
    recovery_scope(model, args.state_root,
                   hashlib.sha256(model_raw.encode()).hexdigest())
    secrets = model.get("secrets")
    if not isinstance(secrets, dict) or not secrets:
        raise ValueError("restored application has no operator secret inventory")
    required_secrets = {
        secret["source"] for name, service in model["services"].items()
        if name in LOCAL_SERVICES
        for secret in service.get("secrets", [])
    }
    for name, secret in secrets.items():
        source = secret.get("file") if isinstance(secret, dict) else None
        if not isinstance(source, str) or Path(source).parent != args.secret_root:
            raise ValueError(f"rendered secret {name} escaped the recovery root")
        if name in required_secrets and (not Path(source).is_file() or Path(source).is_symlink()):
            raise ValueError(f"rendered secret {name} is missing or linked")
    for env_name, service_name in (("SELFHOST_GATEWAY_URL", "edge"),
                                   ("SELFHOST_KEYCLOAK_URL", "keycloak")):
        ports = model["services"][service_name].get("ports", [])
        origin = urlsplit(environment[env_name])
        if (len(ports) != 1 or ports[0].get("host_ip") != "127.0.0.1"
                or origin.scheme != "http" or origin.hostname not in ("localhost", "127.0.0.1")
                or origin.port != int(ports[0]["published"]) or origin.username
                or origin.password or origin.path not in ("", "/")
                or origin.query or origin.fragment):
            raise ValueError(f"{env_name} does not target the restored loopback service")
    states = live_services(command([*compose, "ps", "--all", "--format", "json"],
                                   cwd=args.install_root, env=environment), model)

    bao_compose = ["docker", "compose", "--project-name", args.openbao_project,
                   "--env-file", str(args.env_file), "-f", str(args.openbao_compose)]
    bao_model = json.loads(command([*bao_compose, "config", "--format", "json"],
                                   cwd=args.install_root, env=environment))
    mounts = bao_model.get("services", {}).get("openbao", {}).get("volumes", [])
    if len([mount for mount in mounts if mount.get("target") == "/bao/data"
            and mount.get("type") == "bind"
            and mount.get("source") == str(args.openbao_state_root)]) != 1:
        raise ValueError("restored OpenBao Raft mount does not match the isolated state root")
    for name, service in bao_model.get("services", {}).items():
        for mount in service.get("volumes", []):
            if mount.get("target") == "/bao/data":
                if mount.get("source") != str(args.openbao_state_root):
                    raise ValueError(f"{name} uses foreign OpenBao state")
            elif (mount.get("target") == "/bao/runtime"
                  and (name != "openbao-bootstrap"
                       or mount.get("source") != str(args.secret_root))):
                raise ValueError("OpenBao bootstrap uses foreign operator secrets")
        if name == "openbao-bootstrap" and not any(
                mount.get("target") == "/bao/runtime" for mount in service.get("volumes", [])):
            raise ValueError("OpenBao bootstrap lacks restored operator secrets")
    ports = bao_model["services"]["openbao"].get("ports", [])
    if (len(ports) != 1 or ports[0].get("host_ip") != "127.0.0.1"
            or ports[0].get("target") != 8200):
        raise ValueError("restored OpenBao listener is not isolated on loopback")
    expected_bao_addr = f"https://host.docker.internal:{ports[0]['published']}"
    configured_bao_addresses = {
        service.get("environment", {}).get("BAO_ADDR")
        for service in model["services"].values()
        if "BAO_ADDR" in service.get("environment", {})
    }
    if configured_bao_addresses != {expected_bao_addr}:
        raise ValueError("restored application is not bound to its own OpenBao listener")
    app_bindings = runtime_bindings(compose, model, environment, set(states), args.install_root)
    bao_bindings = runtime_bindings(bao_compose, bao_model, environment,
                                    set(bao_model["services"]), args.install_root)
    bao_status = json.loads(command([
        *bao_compose, "exec", "-T", "-e", "BAO_CACERT=/bao/data/tls/ca.crt",
        "openbao", "bao", "status", "-format=json"],
        cwd=args.install_root, env=environment))
    if (bao_status.get("storage_type") != "raft" or bao_status.get("sealed") is not False
            or bao_status.get("ha_enabled") is not True):
        raise ValueError("restored OpenBao is not an unsealed Raft KMS")

    journey = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", JOURNEY],
        cwd=args.integration_checkout, env=environment, capture_output=True,
        text=True, timeout=900, check=False,
    )
    if journey.returncode != 0:
        raise ValueError("restored public issue/present/verify/revoke journey failed")
    exercise_installed_keycloak_keys(environment, args.secret_root)
    verify_keycloak_database_custody(compose, args.install_root,
                                      args.source_checkout, args.source_sha, environment)
    verify_marty_database_custody(compose, args.install_root, environment)
    if (runtime_bindings(compose, model, environment, set(states), args.install_root)
            != app_bindings or runtime_bindings(bao_compose, bao_model, environment,
                                                set(bao_model["services"]), args.install_root)
            != bao_bindings):
        raise ValueError("running restore bindings changed during the public journey")
    report = {
        "schema": "marty.selfhost-restored-journey/v1",
        "qualification": "unqualified",
        "source_sha": args.source_sha,
        "integration_sha": args.integration_sha,
        "verifier_sha256": hashlib.sha256(tool_path.read_bytes()).hexdigest(),
        "verifier_from_release_source": tool_from_release_source,
        "compose_model_sha256": hashlib.sha256(model_raw.encode()).hexdigest(),
        "configured_migration_image": model["services"]["db-migrate"].get("image"),
        "candidate_override_used": args.compose_override is not None,
        "app_project": args.project_name,
        "openbao_project": args.openbao_project,
        "raft_applied_index": bao_status.get("raft_applied_index"),
        "service_states": states,
        "application_runtime_bindings": app_bindings,
        "openbao_runtime_bindings": bao_bindings,
        "public_journey": "passed",
        "keycloak_refresh": "passed",
        "keycloak_database_custody": "passed",
        "marty_database_custody": "passed",
        "limits": ["backup provenance and consistency are external inputs",
                   "this report does not qualify a release or cutover"],
    }
    descriptor = os.open(args.output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as sink:
        json.dump(report, sink, indent=2, sort_keys=True)
        sink.write("\n")
    print("restored KMS-only journey passed; report remains unqualified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
