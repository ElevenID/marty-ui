#!/usr/bin/env python3
"""Validate an already rendered disposable Compose model before rollback.

This module has no mutation command. Passing its model check is necessary,
but never sufficient, for a later protected rollback rehearsal.
"""

from __future__ import annotations

import argparse
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
DISPOSABLE_SERVICES = SELECTED | ISOLATED_DEPENDENCIES | frozenset({
    "db-migrate", "issuance", "signing-keys",
})
ALLOWED_SERVICES = frozenset({
    "applicant", "auth", "canvas-sync-worker", "compliance-profile",
    "credential-template", "db-migrate", "deployment-profile",
    "device-registration", "event-stream", "flow", "gateway", "issuance",
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
    return {"schema": "marty.passport-supported-rollback-preflight/v1",
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
                         owner_labels=plan["owner_labels"])
    result = validate_planned_model(model, plan, disposable_root)
    return {"schema": "marty.passport-supported-rollback-preflight/v1",
            "status": "blocked", "model": result,
            "blocker": "live ownership and Rust-to-Python rollback proof are absent"}


def validate_model(
    model: dict, project: str, services_reference: str, disposable_root: Path,
    *, migrations_reference: str | None = None, legacy_reference: str | None = None,
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
        expected_image = (infra_images.get(name)
                          or (services_reference if name == "signing-keys" else None)
                          or (migrations_reference if name == "db-migrate" else None)
                          or (legacy_reference if name == "issuance" else None))
        if expected_image is not None:
            require(service.get("image") == expected_image,
                    f"Compose {name} differs from the protected image reference")
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
    callback_networks = {
        "passport-callback-signer": {"callback_signing"},
        "passport-beta-bureau": {"private", "callback_signing"},
        "openbao": {"private", "callback_signing"},
    }
    for name in services:
        expected = callback_networks.get(name, {"private"})
        joined = services[name].get("networks")
        require(isinstance(joined, (list, dict)) and set(joined) == expected,
                f"Compose {name} leaves the dedicated callback signing boundary")
    signer = services["passport-callback-signer"]["environment"]
    bureau = services["passport-beta-bureau"]["environment"]
    native = services["issuance-native"]["environment"]
    gateway = services["gateway"]["environment"]
    flow = services["flow"]["environment"]
    require(native.get("ENVIRONMENT") == ("beta" if surface == "selfhost" else "development")
            and gateway.get("ENVIRONMENT") == ("production" if surface == "selfhost" else "development")
            and flow.get("ENVIRONMENT") == ("production" if surface == "selfhost" else "development"),
            "Disposable surface environment selectors are incompatible with the beta simulator")
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
            and bureau.get("PASSPORT_BUREAU_CALLBACK_URL")
            == "http://issuance-native:8005/v1/passport/webhooks/personalization"
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
            "model_safe": True, "rollback_accepted": False}


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
            and isinstance(plan.get("legacy_reference"), str)
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
    return validate_model(model, plan["project"], plan["services_reference"],
                          disposable_root,
                          migrations_reference=plan["migrations_reference"],
                          legacy_reference=plan["legacy_reference"])


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
