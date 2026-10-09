#!/usr/bin/env python3
"""Validate an already rendered disposable Rust Compose model.

This module has no mutation command. Passing its model check is necessary,
but never sufficient, for protected Rust acceptance.
"""

from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timezone
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

if __package__:
    from .passport_supported_infra_images import qualified_images
else:
    from passport_supported_infra_images import qualified_images


PROJECT = re.compile(r"marty-passport-acceptance-(base|selfhost)-[a-z0-9]{6,32}\Z")
SELECTED = frozenset({
    "gateway", "flow", "issuance-native", "passport-callback-signer",
    "passport-beta-bureau",
})
ISOLATED_DEPENDENCIES = frozenset({"postgres", "openbao", "redis"})
RUST_DEPENDENCIES = frozenset({
    "organization", "event-stream", "revocation-profile", "revocation-profile-migrate",
    "credential-template", "compliance-profile", "trust-profile",
    "presentation-policy", "deployment-profile",
})
DISPOSABLE_SERVICES = SELECTED | ISOLATED_DEPENDENCIES | RUST_DEPENDENCIES | frozenset({
    "db-migrate", "issuance-migrations", "signing-keys", "edge",
})
DISPOSABLE_NETWORKS = frozenset({"private", "callback_signing", "ingress"})
INGRESS_NETWORK = "ingress"
ALLOWED_SERVICES = frozenset({
    "applicant", "auth", "canvas-sync-worker", "compliance-profile",
    "credential-template", "db-migrate", "deployment-profile",
    "device-registration", "edge", "event-stream", "flow", "gateway",
    "issuance-migrations", "issuance-native", "keycloak",
    "keycloak-configurator", "mailpit", "notification", "openbao",
    "openbao-init", "organization", "passport-callback-signer",
    "passport-beta-bureau", "postgres", "presentation-policy", "redis",
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


def _aware_datetime(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return datetime.fromisoformat(value).tzinfo is not None
    except ValueError:
        return False


def _run_config(args: list[str], environment: dict[str, str]) -> str:
    try:
        result = subprocess.run(args, env=environment, capture_output=True,
                                text=True, encoding="utf-8", check=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ModelPreflightError("Disposable Compose model rendering failed") from exc
    require(len(result.stdout) <= 4 * 1024 * 1024,
            "Disposable Compose model is oversized")
    return result.stdout


def source_identity() -> tuple[str, bool]:
    """Read the exact checked-out commit and all tracked/untracked source drift."""
    try:
        head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                              check=True, capture_output=True, text=True,
                              encoding="utf-8", timeout=10).stdout.strip()
        status = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=all"],
            cwd=ROOT, check=True, capture_output=True,
            text=True, encoding="utf-8", timeout=10,
        ).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise ModelPreflightError("Protected source checkout cannot be verified") from exc
    return head, bool(status.strip())


def render_model(
    surface: str, project: str, env_file: Path, disposable_root: Path,
    services_reference: str,
    runner: Callable[[list[str], dict[str, str]], str] = _run_config,
    *, phase: str = "rust", owner_labels: dict[str, str] | None = None,
    plan_expires_at: str | None = None,
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
    require(phase in {"rust", "selfhost_ceremony"},
            "Disposable owner phase is invalid")
    require(phase != "selfhost_ceremony" or surface == "selfhost",
            "Disposable certificate ceremony requires the selfhost surface")
    compose = ROOT / "docker-compose.passport-supported-disposable.yml"
    surface_overlay = ROOT / f"docker-compose.passport-supported-disposable-{surface}.yml"
    ceremony_overlay = (ROOT / "docker-compose.passport-supported-disposable-selfhost-ceremony.yml")
    files = [compose, surface_overlay]
    if phase == "selfhost_ceremony":
        files.append(ceremony_overlay)
    require(all(path.is_file() for path in files),
            "Protected Compose source is missing")
    args = ["docker", "compose", "--project-name", project, "--env-file", str(env_file),
            *(arg for path in files for arg in ("-f", str(path))),
            "config", "--format", "json"]
    environment = os.environ.copy()
    environment["MARTY_SERVICES_IMAGE"] = services_reference
    environment["PASSPORT_ACCEPTANCE_PROJECT"] = project
    if plan_expires_at is not None:
        environment["PASSPORT_ACCEPTANCE_EXPIRES_AT"] = plan_expires_at
    if owner_labels is not None:
        environment["PASSPORT_ACCEPTANCE_PLAN_RUN_ID"] = owner_labels[
            "com.marty.passport.acceptance.run-id"]
        environment["PASSPORT_ACCEPTANCE_SOURCE_COMMIT"] = owner_labels[
            "com.marty.passport.acceptance.source-commit"]
    for role, reference in qualified_images(verify_registry=False).items():
        environment[f"PASSPORT_ACCEPTANCE_{role.upper()}_IMAGE"] = reference
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
    result["static_isolation_verified"] = result.pop("model_safe")
    result["model_safe"] = False
    return {"schema": "marty.passport-supported-rust-model-preflight/v1",
            "status": "blocked", "model": result,
            "blocker": "protected plan attestation and live ownership proof are absent"}


def preflight_attested_plan(
    surface: str, project: str, env_file: Path, disposable_root: Path,
    services_reference: str, plan_path: Path,
    runner: Callable[[list[str], dict[str, str]], str] = _run_config,
    *, attest: Callable[[str, str, str, str, str], bool] | None = None,
    now: datetime | None = None,
    checkout: Callable[[], tuple[str, bool]] = source_identity,
) -> dict:
    """Verify plan provenance before a read-only model render; never authorize up/down."""
    if __package__:
        from .passport_supported_provisioning_plan import (
            COMMIT, PLAN_WORKFLOW, _attest,
        )
    else:
        from passport_supported_provisioning_plan import (
            COMMIT, PLAN_WORKFLOW, _attest,
        )
    try:
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ModelPreflightError("Protected plan artifact is invalid") from exc
    require(isinstance(plan, dict)
            and isinstance(plan.get("source_commit"), str)
            and COMMIT.fullmatch(plan["source_commit"]) is not None
            and plan.get("project") == project
            and plan.get("surface") == surface
            and plan.get("services_reference") == services_reference,
            "Protected plan source/project/reference mismatch")
    attestor = attest or _attest
    try:
        verified = attestor(str(plan_path), "ElevenID/marty-ui", PLAN_WORKFLOW,
                            plan["source_commit"], "refs/heads/main")
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        raise ModelPreflightError("Protected plan attestation failed") from exc
    require(verified is True, "Protected plan attestation failed")
    head, dirty = checkout()
    require(head == plan["source_commit"] and not dirty,
            "Protected source checkout differs from attested plan")
    try:
        created = datetime.fromisoformat(plan["created_at"])
        expires = datetime.fromisoformat(plan["expires_at"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ModelPreflightError("Protected plan lease is invalid") from exc
    current = now or datetime.now(timezone.utc)
    require(current.tzinfo is not None and created.tzinfo is not None
            and expires.tzinfo is not None and created <= current < expires,
            "Protected plan lease has expired")
    require(isinstance(plan.get("owner_labels"), dict),
            "Protected plan owner labels are missing")
    model = render_model(surface, project, env_file, disposable_root,
                         services_reference, runner,
                         owner_labels=plan["owner_labels"],
                         plan_expires_at=plan["expires_at"])
    result = validate_planned_model(model, plan, disposable_root)
    ceremony_result = None
    if surface == "selfhost":
        ceremony = render_model(surface, project, env_file, disposable_root,
                                services_reference, runner,
                                phase="selfhost_ceremony",
                                owner_labels=plan["owner_labels"],
                                plan_expires_at=plan["expires_at"])
        ceremony_result = validate_selfhost_ceremony_model(
            ceremony, model, project, services_reference, disposable_root)
    return {"schema": "marty.passport-supported-rust-model-preflight/v1",
            "status": "blocked", "model": result,
            "ceremony_model": ceremony_result,
            "blocker": "live ownership and Rust route proof are absent"}


def validate_model(
    model: dict, project: str, services_reference: str, disposable_root: Path,
    *, migrations_reference: str | None = None,
) -> dict[str, object]:
    """Reject resolved configurations that can touch shared production resources."""
    project_match = PROJECT.fullmatch(project)
    require(project_match is not None, "Disposable project name is required")
    surface = project_match.group(1)
    require(disposable_root.is_absolute() and disposable_root.is_dir(),
            "Disposable resource root is missing")
    require(isinstance(model, dict) and model.get("name") == project,
            "Resolved Compose model has a different project")
    services = model.get("services")
    require(isinstance(services, dict) and set(services) == DISPOSABLE_SERVICES,
            "Resolved Compose model has an unexpected or missing service")
    infra_images = qualified_images(verify_registry=False)
    networks = model.get("networks")
    require(isinstance(networks, dict) and set(networks) == DISPOSABLE_NETWORKS,
            "Disposable Compose networks are missing")
    for name, network in networks.items():
        require(isinstance(network, dict)
                and network.get("external") not in (True, "true")
                and network.get("driver", "bridge") == "bridge"
                and not network.get("driver_opts")
                and network.get("internal", False) is (name != INGRESS_NETWORK)
                and network.get("name") == f"{project}_{name}",
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
    for name, secret in secrets.items():
        expected_file = disposable_root / "secrets" / name
        require(isinstance(name, str) and re.fullmatch(r"[a-z][a-z0-9_]*", name)
                and isinstance(secret, dict)
                and secret.get("external") not in (True, "true")
                and isinstance(secret.get("file"), str)
                and Path(secret["file"]) == expected_file
                and Path(secret["file"]).resolve() == expected_file
                and _within(secret["file"], disposable_root),
                "Compose secret does not match its private project file")
    configs = model.get("configs", {})
    require(isinstance(configs, dict)
            and set(configs) == {"passport_supported_openbao_start", "passport_supported_edge"},
            "Compose configs are invalid")
    start_config = configs["passport_supported_openbao_start"]
    require(isinstance(start_config, dict)
            and start_config.get("external") not in (True, "true")
            and isinstance(start_config.get("file"), str)
            and Path(start_config["file"]).resolve()
            == (ROOT / "scripts/passport_supported_openbao_start.sh").resolve()
            and (ROOT / "scripts/passport_supported_openbao_start.sh").is_file(),
            "Compose OpenBao start config differs from protected source")
    edge_config = configs["passport_supported_edge"]
    require(isinstance(edge_config, dict)
            and edge_config.get("external") not in (True, "true")
            and isinstance(edge_config.get("file"), str)
            and Path(edge_config["file"]).resolve()
            == (ROOT / "scripts/passport_supported_edge.conf").resolve()
            and (ROOT / "scripts/passport_supported_edge.conf").is_file(),
            "Compose HTTPS edge config differs from protected source")
    edge_candidate = services.get("edge")
    edge_candidate_ports = (edge_candidate.get("ports")
                            if isinstance(edge_candidate, dict) else None)
    edge_candidate_port = (edge_candidate_ports[0].get("published")
                           if isinstance(edge_candidate_ports, list)
                           and len(edge_candidate_ports) == 1
                           and isinstance(edge_candidate_ports[0], dict) else None)
    public_origin = (f"https://localhost:{edge_candidate_port}"
                     if isinstance(edge_candidate_port, str)
                     and edge_candidate_port.isdigit() else None)
    public_domain = (f"localhost:{edge_candidate_port}"
                     if public_origin is not None else None)
    for name, service in services.items():
        require(isinstance(service, dict), "Compose service is invalid")
        for forbidden in ("container_name", "network_mode", "pid", "ipc",
                          "privileged", "devices", "extra_hosts", "dns", "dns_search",
                          "dns_opt", "links", "hostname", "domainname", "volumes_from",
                          "build", *(() if name == "issuance-migrations" else ("command",))):
            require(not service.get(forbidden),
                    f"Compose {name} has a shared-host or fixed-name setting")
        if name == "openbao":
            require(service.get("entrypoint") == [
                "/bin/sh", "/usr/local/bin/passport-supported-openbao-start"],
                "Compose OpenBao start command differs from protected source")
        elif name == "issuance-migrations":
            require(service.get("entrypoint") == ["/bin/sh", "-c"],
                    "Compose Rust issuance migrator entrypoint differs")
        else:
            require(not service.get("entrypoint"),
                    f"Compose {name} has an unexpected entrypoint")
        require(service.get("pull_policy") != "build"
                and isinstance(service.get("image"), str)
                and IMMUTABLE_IMAGE.fullmatch(service["image"]) is not None,
                f"Compose {name} image is not immutable")
        if name in SELECTED | RUST_DEPENDENCIES:
            require(service.get("image") == services_reference,
                    f"Compose {name} is not pinned to the signed services image")
        expected_image = (infra_images.get(name)
                          or (services_reference if name in RUST_DEPENDENCIES | {"signing-keys"}
                              else None)
                          or (migrations_reference if name == "db-migrate" else None)
                          or (services_reference if name == "issuance-migrations" else None))
        if expected_image is not None:
            require(service.get("image") == expected_image,
                    f"Compose {name} differs from the protected image reference")
        mounts = service.get("volumes", [])
        expected_mounts = {
            "postgres": {("postgres_data", "/var/lib/postgresql/data")},
            "redis": {("redis_data", "/data")},
            "openbao": {
                ("openbao_data", "/bao/data"),
                ("openbao_file", "/openbao/file"),
                ("openbao_logs", "/openbao/logs"),
            },
        }
        require(isinstance(mounts, list), f"Compose {name} mounts are invalid")
        if name in expected_mounts:
            require(len(mounts) == len(expected_mounts[name])
                    and all(isinstance(mount, dict)
                            and mount.get("type") == "volume"
                            and (mount.get("source"), mount.get("target"))
                            in expected_mounts[name]
                            and mount.get("source") in volumes
                            for mount in mounts)
                    and {(mount["source"], mount["target"]) for mount in mounts}
                    == expected_mounts[name],
                    f"Compose {name} has an unexpected bind mount or volume")
        else:
            require(not mounts, f"Compose {name} has an unexpected bind mount or volume")
        for kind, available in (("secrets", secrets), ("configs", configs)):
            references = service.get(kind, [])
            require(isinstance(references, list),
                    f"Compose {name} {kind} are invalid")
            for reference in references:
                require(isinstance(reference, dict)
                        and reference.get("source") in available
                        and (kind != "secrets" or (
                            set(reference) <= {"source", "target"}
                            and reference.get("target", f"/run/secrets/{reference['source']}")
                            == f"/run/secrets/{reference['source']}")),
                        f"Compose {name} uses an unknown {kind} source")
            require(len({reference["source"] for reference in references}) == len(references),
                    f"Compose {name} has duplicate {kind} sources")
        if name == "openbao":
            require(service.get("configs") == [{
                "source": "passport_supported_openbao_start",
                "target": "/usr/local/bin/passport-supported-openbao-start",
            }] and {secret.get("source") for secret in service.get("secrets", [])}
            == {"bao_root_token"},
            "Compose OpenBao start secrets or config differ from protected source")
            require(not any(key in service.get("environment", {}) for key in (
                "BAO_DEV_ROOT_TOKEN_ID", "BAO_TOKEN", "VAULT_TOKEN")),
                "Compose OpenBao root token is exposed in the resolved environment")
        elif name == "edge":
            require(service.get("configs") == [{
                "source": "passport_supported_edge",
                "target": "/etc/nginx/conf.d/default.conf",
            }] and {secret.get("source") for secret in service.get("secrets", [])}
            == {"passport_edge_tls_cert", "passport_edge_tls_key"},
            "Compose HTTPS edge config or TLS secrets differ from protected source")
        else:
            require(not service.get("configs"),
                    f"Compose {name} has an unexpected config")
            require(all(secret.get("source") != "bao_root_token"
                        for secret in service.get("secrets", [])),
                    f"Compose {name} mounts the OpenBao root token")
        ports = service.get("ports", [])
        require(isinstance(ports, list), f"Compose {name} ports are invalid")
        for port in ports:
            require(isinstance(port, dict) and port.get("host_ip") == "127.0.0.1",
                    f"Compose {name} publishes outside loopback")
        environment = service.get("environment", {})
        require(isinstance(environment, dict), f"Compose {name} environment is invalid")
        if name == "signing-keys":
            dependencies = service.get("depends_on")
            require(environment.get("SIGNING_KEYS_REDIS_URL") == "redis://redis:6379/2"
                    and isinstance(dependencies, dict)
                    and isinstance(dependencies.get("redis"), dict)
                    and dependencies["redis"].get("condition") == "service_healthy",
                    "Compose signing-keys lacks isolated Redis readiness")
        for key, value in environment.items():
            require(isinstance(key, str), f"Compose {name} environment key is invalid")
            if not isinstance(value, str):
                continue
            if (name in {"revocation-profile", "revocation-profile-migrate"}
                    and key == "STATUS_LIST_BASE_URL"):
                continue
            if (name in {"credential-template", "trust-profile",
                         "presentation-policy", "flow"}
                    and key in {"PUBLIC_API_URL", "MARTY_ISSUER_BASE_URL",
                                "PUBLIC_BASE_URL", "ISSUER_BASE_URL"}
                    and value == public_origin):
                continue
            if ((name, key) in {("db-migrate", "MARTY_ISSUER_BASE_URL"),
                                ("gateway", "ISSUER_BASE_URL"),
                                ("issuance-native", "ISSUER_BASE_URL")}
                    and value == public_origin):
                continue
            for url in URLS.findall(value):
                require(_endpoint_host(url) in services,
                        f"Compose {name} endpoint leaves disposable services")
            if REMOTE_KEYS.fullmatch(key) and value and not URLS.search(value):
                require(value.split(":", 1)[0] in services,
                        f"Compose {name} endpoint leaves disposable services")
            if key.endswith(("DOMAIN", "HOSTNAME")) and value:
                require(value in {"localhost", "127.0.0.1", public_domain}
                        | set(services),
                        f"Compose {name} domain leaves disposable services")
    callback_networks = {
        "passport-callback-signer": {"callback_signing"},
        "passport-beta-bureau": {"private", "callback_signing"},
        "openbao": {"private", "callback_signing"},
        "edge": {"private", INGRESS_NETWORK},
    }
    for name in services:
        expected = callback_networks.get(name, {"private"})
        joined = services[name].get("networks")
        require(isinstance(joined, (list, dict)) and set(joined) == expected
                and (not isinstance(joined, dict)
                     or all(value in (None, {}) for value in joined.values())),
                f"Compose {name} leaves the dedicated callback signing boundary")
    signer = services["passport-callback-signer"]["environment"]
    bureau = services["passport-beta-bureau"]["environment"]
    require(all(key.lower() not in {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}
                for key in bureau),
            "Disposable bureau proxy environment is forbidden")
    native = services["issuance-native"]["environment"]
    gateway = services["gateway"]["environment"]
    flow = services["flow"]["environment"]
    organization = services["organization"]
    organization_env = organization["environment"]
    event_stream_env = services["event-stream"]["environment"]
    require(
        event_stream_env.get("SERVICE_NAME") == "event_stream"
        and event_stream_env.get("EVENT_STREAM_SERVICE_PORT") == "8015"
        and event_stream_env.get("EVENT_STREAM_GRPC_ENABLED") == "true"
        and event_stream_env.get("EVENT_STREAM_GRPC_PORT") == "9015"
        and organization_env.get("SERVICE_NAME") == "organization"
        and organization_env.get("ORGANIZATION_SERVICE_PORT") == "8002"
        and organization_env.get("ORG_GRPC_PORT") == "9002"
        and organization_env.get("DATABASE_URL_TEMPLATE")
        == flow.get("DATABASE_URL_TEMPLATE")
        == native.get("DATABASE_URL_TEMPLATE")
        and organization_env.get("DATABASE_URL_TEMPLATE", "").startswith(
            "postgresql+asyncpg://marty:")
        and organization_env.get("DATABASE_URL_TEMPLATE", "").endswith(
            "@postgres:5432/marty")
        and organization_env.get("MARTY_DB_PASSWORD_FILE")
        == "/run/secrets/marty_db_password"
        and organization_env.get("GRPC_SERVICE_TOKEN_FILE")
        == "/run/secrets/grpc_service_token"
        and organization_env.get("REDIS_URL") == "redis://redis:6379"
        and organization_env.get("ES_GRPC_TARGET") == "event-stream:9015"
        and isinstance(organization_env.get("MARTY_ORG_ADMIN_EMAIL"), str)
        and "@" in organization_env["MARTY_ORG_ADMIN_EMAIL"]
        and organization_env["MARTY_ORG_ADMIN_EMAIL"]
        == services["db-migrate"]["environment"].get("MARTY_ORG_ADMIN_EMAIL")
        and isinstance(organization.get("labels"), dict)
        and organization_env.get("PASSPORT_ACCEPTANCE_PROJECT") == project
        and organization_env.get("PASSPORT_ACCEPTANCE_RUN_ID")
        == organization["labels"].get("com.marty.passport.acceptance.run-id")
        and organization_env.get("PASSPORT_ACCEPTANCE_SOURCE_COMMIT")
        == organization["labels"].get("com.marty.passport.acceptance.source-commit")
        and _aware_datetime(organization_env.get("PASSPORT_ACCEPTANCE_EXPIRES_AT"))
        and all(key not in organization_env for key in (
            "MARTY_DB_PASSWORD", "GRPC_SERVICE_TOKEN"))
        and {secret.get("source") for secret in organization.get("secrets", [])}
        == {"marty_db_password", "grpc_service_token"}
        and isinstance(organization.get("depends_on"), dict)
        and all(isinstance(organization["depends_on"].get(name), dict)
                and organization["depends_on"][name].get("condition") == condition
                for name, condition in (
                    ("db-migrate", "service_completed_successfully"),
                    ("redis", "service_healthy"),
                    ("event-stream", "service_healthy")))
        and gateway.get("ORGANIZATION_SERVICE_URL") == "http://organization:8002"
        and gateway.get("ORG_GRPC_TARGET") == "organization:9002"
        and gateway.get("ES_GRPC_TARGET") == "event-stream:9015"
        and gateway.get("GRPC_SERVICE_TOKEN_FILE") == "/run/secrets/grpc_service_token",
        "Disposable Organization API-key authority is not isolated and ready",
    )
    require(
        isinstance(services["gateway"].get("depends_on"), dict)
        and isinstance(services["gateway"]["depends_on"].get("organization"), dict)
        and services["gateway"]["depends_on"]["organization"].get("condition")
        == "service_healthy"
        and flow.get("ORG_GRPC_TARGET") == "organization:9002",
        "Disposable passport services do not use the Organization authority",
    )
    edge_ports = services["edge"].get("ports")
    require(not services["gateway"].get("ports")
            and isinstance(edge_ports, list) and len(edge_ports) == 1
            and isinstance(edge_ports[0], dict)
            and edge_ports[0].get("host_ip") == "127.0.0.1"
            and edge_ports[0].get("target") == 8443
            and isinstance(edge_ports[0].get("published"), str)
            and edge_ports[0]["published"].isdigit()
            and 1024 <= int(edge_ports[0]["published"]) <= 65535
            and services["edge"].get("depends_on", {}).get("gateway", {}).get("condition")
            == "service_started",
            "Disposable HTTPS edge lacks a reserved loopback port or Gateway peer")
    status_origin = f"https://localhost:{edge_ports[0]['published']}"
    public_origin = status_origin
    shared_rust = {
        "ENVIRONMENT": "development",
        "DATABASE_URL_TEMPLATE": organization_env["DATABASE_URL_TEMPLATE"],
        "MARTY_DB_PASSWORD_FILE": "/run/secrets/marty_db_password",
        "GRPC_SERVICE_TOKEN_FILE": "/run/secrets/grpc_service_token",
        "ORG_GRPC_TARGET": "organization:9002",
    }
    rust_requirements = {
        "compliance-profile": ({
            **shared_rust, "SERVICE_NAME": "compliance_profile",
            "COMPLIANCE_PROFILE_SERVICE_PORT": "8008",
        }, {"marty_db_password", "grpc_service_token"},
         {"db-migrate": "service_completed_successfully", "organization": "service_healthy"},
         8008),
        "trust-profile": ({
            **shared_rust, "SERVICE_NAME": "trust_profile",
            "TRUST_PROFILE_SERVICE_PORT": "8004",
            "SIGNING_KEYS_INTERNAL_API_KEY_FILE":
                "/run/secrets/signing_keys_internal_api_key",
            "MARTY_ORG_ID": organization_env["MARTY_ORG_ID"],
            "MARTY_ORG_SLUG": "marty", "MARTY_ISSUER_DID":
                f"did:web:localhost%3A{edge_ports[0]['published']}:orgs:marty",
            "MARTY_ISSUER_BASE_URL": public_origin, "PUBLIC_DOMAIN": public_domain,
            "DID_RESOLUTION_BASE_URL": "http://gateway:8000",
        }, {"marty_db_password", "grpc_service_token", "signing_keys_internal_api_key"},
         {"db-migrate": "service_completed_successfully", "organization": "service_healthy"},
         8004),
        "credential-template": ({
            **shared_rust, "SERVICE_NAME": "credential_template",
            "CREDENTIAL_TEMPLATE_SERVICE_PORT": "8003", "CT_GRPC_PORT": "9003",
            "RP_GRPC_TARGET": "revocation-profile:9013",
            "SIGNING_KEYS_INTERNAL_URL": "http://gateway:8000/internal/signing-keys",
            "SIGNING_KEYS_INTERNAL_API_KEY_FILE":
                "/run/secrets/signing_keys_internal_api_key",
            "TRUST_PROFILE_SERVICE_URL": "http://trust-profile:8004",
            "PUBLIC_API_URL": public_origin,
            "MARTY_ORG_ID": organization_env["MARTY_ORG_ID"],
            "MARTY_MIGRATION_PROFILE": "dev",
        }, {"marty_db_password", "grpc_service_token", "signing_keys_internal_api_key"},
         {"db-migrate": "service_completed_successfully", "organization": "service_healthy",
          "revocation-profile": "service_healthy", "trust-profile": "service_healthy",
          "signing-keys": "service_healthy"}, 8003),
        "presentation-policy": ({
            **shared_rust, "SERVICE_NAME": "presentation_policy",
            **({
                "ENVIRONMENT": "production",
                "GRPC_WORKLOAD_TLS_SERVER_CERT": "/run/secrets/pp_workload_server_cert",
                "GRPC_WORKLOAD_TLS_SERVER_KEY": "/run/secrets/pp_workload_server_key",
                "GRPC_WORKLOAD_TLS_CA_CERT": "/run/secrets/workload_identity_ca_cert",
            } if surface == "selfhost" else {}),
            "PRESENTATION_POLICY_SERVICE_PORT": "8009", "PP_GRPC_PORT": "9009",
            "ISSUANCE_API_KEY_FILE": "/run/secrets/issuance_api_key",
            "DID_RESOLUTION_BASE_URL": "http://gateway:8000",
            "TRUST_PROFILE_SERVICE_URL": "http://trust-profile:8004",
            "ISSUANCE_NATIVE_SERVICE_URL": "http://issuance-native:8005",
            "PUBLIC_DOMAIN": public_domain, "PUBLIC_BASE_URL": public_origin,
            "ISSUER_BASE_URL": public_origin, "MARTY_ORG_SLUG": "marty",
        }, {"marty_db_password", "grpc_service_token", "issuance_api_key"}
        | ({"pp_workload_server_cert", "pp_workload_server_key",
            "workload_identity_ca_cert"} if surface == "selfhost" else set()),
         {"db-migrate": "service_completed_successfully", "organization": "service_healthy",
          "trust-profile": "service_healthy", "issuance-native": "service_healthy"}, 8009),
        "deployment-profile": ({
            **shared_rust, "SERVICE_NAME": "deployment_profile",
            "DEPLOYMENT_PROFILE_SERVICE_PORT": "8010",
        }, {"marty_db_password", "grpc_service_token"},
         {"db-migrate": "service_completed_successfully", "organization": "service_healthy"},
         8010),
    }
    for name, (expected_env, expected_secrets, expected_dependencies, port) in rust_requirements.items():
        service = services[name]
        environment = service.get("environment")
        references = service.get("secrets")
        depends_on = service.get("depends_on")
        require(isinstance(environment, dict)
                and all(environment.get(key) == value for key, value in expected_env.items())
                and all(key not in environment for key in (
                    "MARTY_DB_PASSWORD", "GRPC_SERVICE_TOKEN", "ISSUANCE_API_KEY",
                    "SIGNING_KEYS_INTERNAL_API_KEY"))
                and isinstance(references, list)
                and {secret.get("source") for secret in references} == expected_secrets
                and isinstance(depends_on, dict)
                and set(depends_on) == set(expected_dependencies)
                and all(isinstance(depends_on[dependency], dict)
                        and depends_on[dependency].get("condition") == condition
                        for dependency, condition in expected_dependencies.items())
                and service.get("healthcheck", {}).get("test")
                == ["CMD", "curl", "--fail", f"http://localhost:{port}/health"],
                f"Disposable {name} runtime is not isolated and ready")
    require(all(flow.get(key) == value for key, value in {
        "PUBLIC_BASE_URL": public_origin,
        "CT_GRPC_TARGET": "credential-template:9003",
        "PP_GRPC_TARGET": "presentation-policy:9009",
        "ISSUANCE_GRPC_TARGET": "issuance-native:9005",
        "CREDENTIAL_TEMPLATE_SERVICE_URL": "http://credential-template:8003",
        "TRUST_PROFILE_SERVICE_URL": "http://trust-profile:8004",
        "DEPLOYMENT_PROFILE_SERVICE_URL": "http://deployment-profile:8010",
    }.items())
            and isinstance(services["flow"].get("depends_on"), dict)
            and all(services["flow"]["depends_on"].get(name, {}).get("condition")
                    == "service_healthy" for name in (
                        "credential-template", "trust-profile", "presentation-policy",
                        "deployment-profile", "issuance-native", "signing-keys"))
            and all(services[name].get("healthcheck", {}).get("test")
                    == ["CMD", "curl", "--fail", f"http://localhost:{port}/health"]
                    for name, port in (("issuance-native", 8005), ("signing-keys", 8017))),
            "Disposable Flow startup dependencies are incomplete")
    flow_selfhost = {
        "FLOW_CALLBACK_DESTINATIONS": (
            "00000000-0000-0000-0000-000000000001|"
            "https://edge:8443/__disposable/flow-callback?nonce=__MARTY_TOKEN__"),
        "FLOW_WEBHOOK_SECRET_FILE": "/run/secrets/flow_webhook_secret",
        "FLOW_CALLBACK_CA_CERT_FILE": "/run/secrets/workload_identity_ca_cert",
        "GRPC_WORKLOAD_TLS_CLIENT_CERT": "/run/secrets/flow_workload_client_cert",
        "GRPC_WORKLOAD_TLS_CLIENT_KEY": "/run/secrets/flow_workload_client_key",
        "GRPC_WORKLOAD_TLS_SERVER_CERT": "/run/secrets/flow_workload_server_cert",
        "GRPC_WORKLOAD_TLS_SERVER_KEY": "/run/secrets/flow_workload_server_key",
        "GRPC_WORKLOAD_TLS_CA_CERT": "/run/secrets/workload_identity_ca_cert",
    }
    flow_secret_names = {
        "flow_webhook_secret",
        "flow_workload_client_cert", "flow_workload_client_key",
        "flow_workload_server_cert", "flow_workload_server_key",
        "workload_identity_ca_cert",
    }
    actual_flow_secrets = {item.get("source") for item in services["flow"].get("secrets", [])}
    require(flow.get("FLOW_APPLICATION_EVENT_HMAC_KEY_FILE")
            == "/run/secrets/flow_application_event_hmac_key"
            and "flow_application_event_hmac_key" in actual_flow_secrets,
            "Disposable Flow application event authentication is missing")
    require((surface == "selfhost"
             and all(flow.get(key) == value for key, value in flow_selfhost.items())
             and flow_secret_names <= actual_flow_secrets)
            or (surface == "base"
                and not any(key in flow for key in flow_selfhost)
                and not (flow_secret_names & actual_flow_secrets)),
            "Disposable Flow callback or workload TLS configuration differs from surface")
    require(native.get("ISSUANCE_GRPC_ENABLED") == "true"
            and native.get("ISSUANCE_GRPC_PORT") == "9005"
            and native.get("CT_GRPC_TARGET") == "credential-template:9003"
            and native.get("CREDENTIAL_TEMPLATE_SERVICE_URL")
            == "http://credential-template:8003"
            and services["issuance-native"].get("depends_on", {}).get(
                "credential-template", {}).get("condition") == "service_healthy"
            and all(gateway.get(key) == f"http://{name}:{port}"
                    and services["gateway"].get("depends_on", {}).get(
                        name, {}).get("condition") == "service_healthy"
                    for key, name, port in (
                        ("CREDENTIAL_TEMPLATE_SERVICE_URL", "credential-template", 8003),
                        ("COMPLIANCE_PROFILE_SERVICE_URL", "compliance-profile", 8008),
                        ("TRUST_PROFILE_SERVICE_URL", "trust-profile", 8004),
                        ("PRESENTATION_POLICY_SERVICE_URL", "presentation-policy", 8009),
                        ("DEPLOYMENT_PROFILE_SERVICE_URL", "deployment-profile", 8010))),
            "Disposable passport routing lacks the Rust support services")
    migration = services["db-migrate"]
    issuance_migration = services["issuance-migrations"]
    require(
        issuance_migration.get("command") == [
            ". /app/load-secrets-env.sh\nexec /usr/local/bin/marty-issuance-service migrate\n",
        ]
        and issuance_migration.get("environment", {}) == {
            "SERVICE_NAME": "issuance_native",
            "DATABASE_URL_TEMPLATE": "postgresql://marty:$${MARTY_DB_PASSWORD}@postgres:5432/marty",
            "MARTY_DB_PASSWORD_FILE": "/run/secrets/marty_db_password",
        }
        and {secret.get("source") for secret in issuance_migration.get("secrets", [])}
        == {"marty_db_password"}
        and issuance_migration.get("depends_on", {}).get("db-migrate", {}).get("condition")
        == "service_completed_successfully"
        and issuance_migration.get("depends_on", {}).get("organization", {}).get("condition")
        == "service_healthy"
        and issuance_migration.get("healthcheck") == {"disable": True}
        and issuance_migration.get("restart") == "no"
        and services["issuance-native"].get("depends_on", {}).get(
            "issuance-migrations", {}).get("condition") == "service_completed_successfully",
        "Disposable Rust issuance schema is not ordered before runtime",
    )
    migration_env = migration.get("environment")
    dependencies = migration.get("depends_on")
    migration_secrets = migration.get("secrets")
    revocation_migration = services["revocation-profile-migrate"]
    revocation_env = revocation_migration.get("environment")
    revocation_dependencies = revocation_migration.get("depends_on")
    require(
        isinstance(revocation_env, dict)
        and revocation_env.get("SERVICE_NAME") == "revocation_profile"
        and revocation_env.get("RP_MIGRATE_ONLY") == "true"
        and revocation_env.get("ENVIRONMENT") == "development"
        and revocation_env.get("DATABASE_URL_TEMPLATE")
        in {
            "postgresql://marty:${MARTY_DB_PASSWORD}@postgres:5432/marty",
            "postgresql://marty:$${MARTY_DB_PASSWORD}@postgres:5432/marty",
        }
        and revocation_env.get("MARTY_DB_PASSWORD_FILE")
        == "/run/secrets/marty_db_password"
        and revocation_env.get("PUBLIC_API_URL") == "http://gateway:8000"
        and revocation_env.get("STATUS_LIST_BASE_URL") == status_origin
        and revocation_env.get("MARTY_ORG_ID")
        == "00000000-0000-0000-0000-000000000001"
        and {secret.get("source") for secret in revocation_migration.get("secrets", [])}
        == {"marty_db_password"}
        and isinstance(revocation_dependencies, dict)
        and isinstance(revocation_dependencies.get("postgres"), dict)
        and revocation_dependencies["postgres"].get("condition") == "service_healthy"
        and revocation_migration.get("healthcheck") == {"disable": True}
        and revocation_migration.get("restart") == "no"
        and isinstance(dependencies, dict)
        and isinstance(dependencies.get("revocation-profile-migrate"), dict)
        and dependencies["revocation-profile-migrate"].get("condition")
        == "service_completed_successfully",
        "Disposable revocation schema migration is not ordered before shared migrations",
    )
    revocation = services["revocation-profile"]
    revocation_runtime = revocation.get("environment")
    require(
        isinstance(revocation_runtime, dict)
        and revocation_runtime.get("SERVICE_NAME") == "revocation_profile"
        and "RP_MIGRATE_ONLY" not in revocation_runtime
        and revocation_runtime.get("ENVIRONMENT") == "development"
        and revocation_runtime.get("REVOCATION_PROFILE_SERVICE_PORT") == "8013"
        and revocation_runtime.get("RP_GRPC_ENABLED") == "true"
        and revocation_runtime.get("RP_GRPC_PORT") == "9013"
        and revocation_runtime.get("DATABASE_URL_TEMPLATE")
        == revocation_env.get("DATABASE_URL_TEMPLATE")
        and revocation_runtime.get("MARTY_DB_PASSWORD_FILE")
        == "/run/secrets/marty_db_password"
        and revocation_runtime.get("GRPC_SERVICE_TOKEN_FILE")
        == "/run/secrets/grpc_service_token"
        and revocation_runtime.get("REDIS_URL") == "redis://redis:6379/4"
        and revocation_runtime.get("ORG_GRPC_TARGET") == "organization:9002"
        and revocation_runtime.get("PUBLIC_API_URL") == "http://gateway:8000"
        and revocation_runtime.get("STATUS_LIST_BASE_URL") == status_origin
        and revocation_runtime.get("MARTY_ORG_ID") == revocation_env.get("MARTY_ORG_ID")
        and {secret.get("source") for secret in revocation.get("secrets", [])}
        == {"marty_db_password", "grpc_service_token"}
        and isinstance(revocation.get("depends_on"), dict)
        and all(isinstance(revocation["depends_on"].get(name), dict)
                and revocation["depends_on"][name].get("condition") == condition
                for name, condition in (
                    ("db-migrate", "service_completed_successfully"),
                    ("organization", "service_healthy"),
                    ("redis", "service_healthy")))
        and isinstance(revocation.get("healthcheck"), dict)
        and revocation["healthcheck"].get("test")
        == ["CMD", "curl", "--fail", "http://localhost:8013/health"],
        "Disposable revocation runtime is not isolated and ready",
    )
    require(
        native.get("REVOCATION_PROFILE_SERVICE_URL")
        == gateway.get("REVOCATION_PROFILE_SERVICE_URL")
        == "http://revocation-profile:8013"
        and native.get("RP_GRPC_TARGET") == "revocation-profile:9013"
        and all(isinstance(services[name].get("depends_on"), dict)
                and isinstance(services[name]["depends_on"].get("revocation-profile"), dict)
                and services[name]["depends_on"]["revocation-profile"].get("condition")
                == "service_healthy" for name in ("issuance-native", "gateway")),
        "Disposable passport services do not use the revocation runtime",
    )
    require(
        native.get("SIGNING_KEYS_INTERNAL_URL")
        == "http://gateway:8000/internal/signing-keys"
        and native.get("SIGNING_KEYS_INTERNAL_API_KEY_FILE")
        == "/run/secrets/signing_keys_internal_api_key"
        and "signing_keys_internal_api_key" in {
            secret.get("source") for secret in services["issuance-native"].get("secrets", [])
            if isinstance(secret, dict)
        },
        "Disposable native managed issuer signer bypasses the Gateway compatibility API",
    )
    require(
        isinstance(migration_env, dict)
        and migration_env.get("REDIS_URL") == services["signing-keys"]["environment"].get(
            "SIGNING_KEYS_REDIS_URL") == "redis://redis:6379/2"
        and migration_env.get("BAO_ADDR") == "http://openbao:8200"
        and migration_env.get("BAO_TOKEN_FILE") == "/run/secrets/bao_token"
        and migration_env.get("MARTY_KMS_BOOTSTRAP_ENABLED") == "true"
        and migration_env.get("PASSPORT_DISPOSABLE_ICAO_BOOTSTRAP") == "true"
        and migration_env.get("PASSPORT_ACCEPTANCE_PROJECT") == project
        and migration_env.get("PASSPORT_ACCEPTANCE_GATEWAY_PORT") == edge_ports[0]["published"]
        and migration_env.get("PUBLIC_DOMAIN") == public_domain
        and migration_env.get("MARTY_ORG_ID") == revocation_env.get("MARTY_ORG_ID")
        == organization_env.get("MARTY_ORG_ID")
        and migration_env.get("MARTY_ISSUER_BASE_URL") == public_origin
        and isinstance(dependencies, dict)
        and all(isinstance(dependencies.get(role), dict)
                and dependencies[role].get("condition") == "service_healthy"
                for role in ("postgres", "redis", "openbao"))
        and isinstance(migration_secrets, list)
        and any(isinstance(secret, dict) and secret.get("source") == "bao_token"
                for secret in migration_secrets),
        "Disposable migrations could skip managed issuer profile bootstrap",
    )
    issuer_did = f"did:web:localhost%3A{edge_ports[0]['published']}:orgs:marty"
    require(
        migration_env.get("MARTY_ISSUER_DID") == issuer_did
        and migration_env.get("PUBLIC_DOMAIN") == gateway.get("PUBLIC_DOMAIN")
        == services["signing-keys"]["environment"].get("PUBLIC_DOMAIN")
        == public_domain
        and migration_env.get("MARTY_ISSUER_BASE_URL")
        == gateway.get("ISSUER_BASE_URL") == native.get("ISSUER_BASE_URL")
        == public_origin
        and flow.get("MARTY_ISSUER_DID") == issuer_did,
        "Disposable managed issuer DID differs across profile and runtime services",
    )
    require(
        gateway.get("PASSPORT_NATIVE_GATEWAY_ENABLED") == "true"
        and flow.get("PASSPORT_NATIVE_FLOW_ENABLED") == "true"
        and native.get("PASSPORT_NATIVE_HTTP_ENABLED") == "true"
        and native.get("PASSPORT_MANAGED_ISSUER_SIGNING_ENABLED") == "true"
        and native.get("PASSPORT_KMS_ARTIFACTS_ENABLED") == "true"
        and native.get("PASSPORT_KMS_CALLBACKS_ENABLED") == "true"
        and native.get("PASSPORT_BETA_RECONCILIATION_ENABLED") == "true"
        and native.get("PASSPORT_BETA_RECONCILIATION_OPERATOR_TOKEN_FILE")
        == "/run/secrets/passport_beta_reconciliation_operator_token"
        and gateway.get("ISSUANCE_SERVICE_URL")
        == gateway.get("ISSUANCE_NATIVE_SERVICE_URL")
        == "http://issuance-native:8005"
        and flow.get("ISSUANCE_NATIVE_SERVICE_URL")
        == "http://issuance-native:8005"
        and "ISSUANCE_SERVICE_URL" not in flow,
        "Disposable passport routes do not have one Rust owner",
    )
    require(
        all(settings.get("PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED") == "true"
            and "PASSPORT_TENANT_API_KEYS" not in settings
            and "PASSPORT_TENANT_API_KEYS_FILE" not in settings
            for settings in (gateway, flow, native))
        and "passport_tenant_api_keys" not in secrets,
        "Disposable internal passport authentication conflicts with tenant keyring",
    )
    require(
        all(settings.get("ISSUANCE_API_KEY_FILE") == "/run/secrets/issuance_api_key"
            and settings.get("SIGNING_KEYS_INTERNAL_API_KEY_FILE")
            == "/run/secrets/signing_keys_internal_api_key"
            for settings in (gateway, flow, native))
        and services["signing-keys"]["environment"].get(
            "SIGNING_KEYS_INTERNAL_API_KEY_FILE")
        == "/run/secrets/signing_keys_internal_api_key"
        and all({"issuance_api_key", "signing_keys_internal_api_key"}
                <= {secret.get("source") for secret in services[name].get("secrets", [])
                    if isinstance(secret, dict)}
                for name in ("gateway", "flow", "issuance-native"))
        and any(secret.get("source") == "signing_keys_internal_api_key"
                for secret in services["signing-keys"].get("secrets", [])
                if isinstance(secret, dict)),
        "Disposable Gateway and signing services do not share project credentials",
    )
    require(
        native.get("TOKEN_HMAC_KEY_FILE") == "/run/secrets/token_hmac_key"
        and native.get("INTEGRATION_SECRET_MASTER_KEY_FILE")
        == "/run/secrets/integration_secret_master_key"
        and "PASSPORT_BETA_RECONCILIATION_OPERATOR_TOKEN" not in native
        and "TOKEN_HMAC_KEY" not in native
        and "INTEGRATION_SECRET_MASTER_KEY" not in native
        and {"token_hmac_key", "integration_secret_master_key",
             "passport_beta_reconciliation_operator_token"}
        <= {secret.get("source") for secret in services["issuance-native"].get("secrets", [])
            if isinstance(secret, dict)},
        "Disposable native issuance startup secrets are missing",
    )
    operator_token_holders = {
        name for name, service in services.items()
        if any(item.get("source") == "passport_beta_reconciliation_operator_token"
               for item in service.get("secrets", []) if isinstance(item, dict))
    }
    require(operator_token_holders == {"issuance-native"},
            "Disposable native batch operator token escaped its owner")
    require(gateway.get("GRPC_INSECURE_ALLOWED") == "true"
            and native.get("GRPC_INSECURE_ALLOWED") == "true"
            and native.get("ENVIRONMENT") == "beta"
            and gateway.get("ENVIRONMENT") == ("production" if surface == "selfhost" else "beta")
            and flow.get("ENVIRONMENT") == ("production" if surface == "selfhost" else "development"),
            "Disposable surface environment selectors are incompatible with the beta simulator")
    ceremony_secrets = {
        "SIGNING_KEYS_DSC_ISSUE_GATEWAY_KEY": "dsc_issue_gateway_key",
        "SIGNING_KEYS_CSCA_ISSUE_GATEWAY_KEY": "csca_issue_gateway_key",
    }
    signing = services["signing-keys"]
    signing_env = signing.get("environment")
    require(isinstance(signing_env, dict)
            and all(key not in service.get("environment", {})
                    for service in services.values()
                    for key in ceremony_secrets),
            "Disposable certificate operator key is exposed in Compose environment")
    for key, secret in ceremony_secrets.items():
        file_key = key + "_FILE"
        holders = {name for name, service in services.items()
                   if file_key in service.get("environment", {})}
        mounts = {name for name, service in services.items()
                  if secret in {item.get("source") for item in service.get("secrets", [])}}
        expected = {"gateway", "signing-keys"} if surface == "base" else set()
        require(holders == mounts == expected
                and all(services[name]["environment"].get(file_key)
                        == f"/run/secrets/{secret}" for name in holders),
                "Disposable certificate operator key holders are invalid")
    require((surface == "base"
             and signing_env.get("ENVIRONMENT") == "beta"
             and signing_env.get("SIGNING_KEYS_BETA_CSCA_ISSUANCE_ENABLED") == "true"
             and gateway.get("GRPC_INSECURE_ALLOWED") == "true")
            or (surface == "selfhost"
                and "SIGNING_KEYS_BETA_CSCA_ISSUANCE_ENABLED" not in signing_env
                and gateway.get("GRPC_INSECURE_ALLOWED") == "true"),
            "Disposable certificate ceremony mode differs from surface")
    require(signer.get("ENVIRONMENT") == "beta"
            and signer.get("PASSPORT_CALLBACK_SIGNER_ENABLED") == "true"
            and signer.get("SIGNING_KEYS_INTERNAL_API_KEY_FILE") == "/run/secrets/callback_signer_api_key"
            and signer.get("BAO_TOKEN_FILE") == "/run/secrets/callback_signer_bao_token"
            and "SIGNING_KEYS_INTERNAL_API_KEY" not in signer
            and "BAO_TOKEN" not in signer,
            "Disposable callback signer is not isolated beta KMS mode")
    require(bureau.get("ENVIRONMENT") == "beta"
            and bureau.get("PASSPORT_BETA_BUREAU_ENABLED") == "true"
            and bureau.get("DATABASE_URL_FILE") == "/run/secrets/bureau_database_url"
            and bureau.get("GRPC_SERVICE_TOKEN_FILE") == "/run/secrets/grpc_service_token"
            and bureau.get("SIGNING_KEYS_INTERNAL_API_KEY_FILE") == "/run/secrets/callback_signer_api_key"
            and bureau.get("SIGNING_KEYS_INTERNAL_URL")
            == "http://passport-callback-signer:8018/internal/documents"
            and bureau.get("PASSPORT_BETA_BUREAU_GATEWAY_CALLBACK_ENABLED") == "true"
            and bureau.get("PASSPORT_BUREAU_CALLBACK_URL")
            == "http://gateway:8000/v1/passport/webhooks/personalization"
            and all(key not in bureau for key in (
                "DATABASE_URL", "GRPC_SERVICE_TOKEN", "SIGNING_KEYS_INTERNAL_API_KEY")),
            "Disposable bureau is not the private Marty simulator")
    require(native.get("PERSONALIZATION_BUREAU_URL") == "http://passport-beta-bureau:8020"
            and native.get("PERSONALIZATION_BUREAU_API_KEY_FILE") == "/run/secrets/grpc_service_token"
            and native.get("PERSONALIZATION_BUREAU_PROVIDER_PROFILE_ID") == "passport-beta-bureau"
            and gateway.get("PASSPORT_PROVIDER_INGRESS_GATEWAY_ENABLED") == "false"
            and "PASSPORT_PROVIDER_INGRESS_SERVICE_URL" not in gateway,
            "Disposable passport owner selects an external provider")
    require("provider_webhook_secret" not in secrets,
            "Disposable simulator model includes a physical provider secret")
    return {"project": project, "services": sorted(SELECTED),
            "model_safe": True}


def validate_selfhost_ceremony_model(
    ceremony: dict, final: dict, project: str, services_reference: str,
    disposable_root: Path,
) -> dict:
    """Permit only a temporary beta certificate phase before selfhost runtime.

    The protected producer must replace both affected containers using the
    normal final model and inspect their new identities before acceptance.
    """
    require(PROJECT.fullmatch(project) is not None
            and project.startswith("marty-passport-acceptance-selfhost-"),
            "Disposable ceremony requires a selfhost project")
    validated = validate_model(final, project, services_reference, disposable_root)
    require(validated.get("model_safe") is True,
            "Disposable final selfhost model is unsafe")
    expected = deepcopy(final)
    additions = {
        "gateway": {
            "ENVIRONMENT": "beta",
            "SIGNING_KEYS_DSC_ISSUE_GATEWAY_KEY_FILE": "/run/secrets/dsc_issue_gateway_key",
            "SIGNING_KEYS_CSCA_ISSUE_GATEWAY_KEY_FILE": "/run/secrets/csca_issue_gateway_key",
        },
        "signing-keys": {
            "ENVIRONMENT": "beta",
            "SIGNING_KEYS_BETA_CSCA_ISSUANCE_ENABLED": "true",
            "SIGNING_KEYS_DSC_ISSUE_GATEWAY_KEY_FILE": "/run/secrets/dsc_issue_gateway_key",
            "SIGNING_KEYS_CSCA_ISSUE_GATEWAY_KEY_FILE": "/run/secrets/csca_issue_gateway_key",
        },
    }
    for service, environment in additions.items():
        expected["services"][service]["environment"].update(environment)
        expected["services"][service]["secrets"].extend(
            {"source": name, "target": f"/run/secrets/{name}"}
            for name in ("dsc_issue_gateway_key", "csca_issue_gateway_key")
        )
    for name in ("dsc_issue_gateway_key", "csca_issue_gateway_key"):
        expected["secrets"][name] = {
            "file": (disposable_root / "secrets" / name).as_posix(),
            "name": f"{project}_{name}",
        }
    require(ceremony == expected,
            "Disposable certificate ceremony changes more than the isolated beta phase")
    return {"project": project, "model_safe": True,
            "ceremony_only": True}


def validate_planned_model(model: dict, plan: dict, disposable_root: Path) -> dict:
    """Compare a rendered model to a plan whose provenance caller already verified.

    This helper does not verify attestations or authorize resource mutation.
    """
    require(isinstance(plan, dict)
            and plan.get("schema") == "marty.passport-supported-provisioning-plan/v1"
            and plan.get("status") == "blocked"
            and isinstance(plan.get("project"), str)
            and isinstance(plan.get("services_reference"), str)
            and isinstance(plan.get("migrations_reference"), str)
            and plan.get("infra_images") == qualified_images(verify_registry=False),
            "Protected plan image bindings are invalid")
    match = PROJECT.fullmatch(plan["project"])
    require(match is not None and match.group(1) == plan.get("surface"),
            "Protected plan surface/project mismatch")
    labels = plan.get("owner_labels")
    require(isinstance(labels, dict)
            and labels == {
                "com.marty.passport.acceptance.owner": "supported-consumer",
                "com.marty.passport.acceptance.run-id": plan.get("run_id"),
                "com.marty.passport.acceptance.source-commit": plan.get("source_commit"),
                "com.marty.passport.acceptance.services-image": plan.get("services_reference"),
            }, "Protected plan owner labels are invalid")
    require(all(isinstance(model.get(section), dict)
                and all(isinstance(item, dict) and item.get("labels") == labels
                        for item in model[section].values())
                for section in ("services", "networks", "volumes")),
            "Resolved Compose resource labels differ from protected plan")
    organization = model["services"].get("organization")
    require(_aware_datetime(plan.get("expires_at"))
            and isinstance(organization, dict)
            and isinstance(organization.get("environment"), dict)
            and organization["environment"].get(
                "PASSPORT_ACCEPTANCE_EXPIRES_AT") == plan["expires_at"],
            "Disposable API key lease differs from protected plan")
    return validate_model(model, plan["project"], plan["services_reference"],
                          disposable_root,
                          migrations_reference=plan["migrations_reference"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--surface", choices=("base", "selfhost"), required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument("--disposable-root", type=Path, required=True)
    parser.add_argument("--services-reference", required=True)
    parser.add_argument("--plan", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.plan:
            report = preflight_attested_plan(
                args.surface, args.project, args.env_file,
                args.disposable_root, args.services_reference, args.plan)
        else:
            report = preflight_read_only(args.surface, args.project, args.env_file,
                                         args.disposable_root, args.services_reference)
    except ModelPreflightError as exc:
        report = {"schema": "marty.passport-supported-rust-model-preflight/v1",
                  "status": "blocked", "blocker": str(exc)}
        args.output.write_text(json.dumps(report, sort_keys=True) + "\n",
                               encoding="utf-8")
        parser.exit(1, f"Supported Rust model preflight blocked: {exc}\n")
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    parser.exit(1, "Supported Rust model preflight blocked pending protected provisioning\n")


if __name__ == "__main__":
    raise SystemExit(main())
