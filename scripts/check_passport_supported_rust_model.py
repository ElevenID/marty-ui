#!/usr/bin/env python3
"""Validate an already rendered disposable Rust Compose model.

This module has no mutation command. Passing its model check is necessary,
but never sufficient, for protected Rust acceptance.
"""

from __future__ import annotations

if __package__:
    from .passport_model_policy import evaluate as evaluate_passport_policy
else:
    try:
        from passport_model_policy import evaluate as evaluate_passport_policy
    except ModuleNotFoundError:
        from scripts.passport_model_policy import evaluate as evaluate_passport_policy

import argparse
from copy import deepcopy
from datetime import datetime, timezone
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Callable

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
PASSPORT_OPENBAO_CONSUMERS = frozenset({
    "db-migrate", "signing-keys", "issuance-native",
    "passport-callback-signer", "gateway",
})
PASSPORT_REMOTE_GRPC_SERVERS = {
    "event-stream": ("es_workload_server", "event-stream-server"),
    "organization": ("org_workload_server", "organization-server"),
    "revocation-profile": ("rp_workload_server", "revocation-profile-server"),
    "credential-template": ("ct_workload_server", "credential-template-server"),
    "issuance-native": ("issuance_workload_server", "issuance-server"),
}
PASSPORT_REMOTE_GRPC_CLIENTS = {
    "compliance-profile": ("compliance_profile_workload_client", "compliance-profile-client"),
    "deployment-profile": ("deployment_profile_workload_client", "deployment-profile-client"),
}


def remote_grpc_server_environment(service: str, project: str) -> dict[str, str]:
    prefix, role = PASSPORT_REMOTE_GRPC_SERVERS[service]
    return {
        "GRPC_WORKLOAD_TLS_SERVER_CERT": f"/run/secrets/{prefix}_cert",
        "GRPC_WORKLOAD_TLS_SERVER_KMS_ADDR": "https://openbao:8200",
        "GRPC_WORKLOAD_TLS_SERVER_KMS_CA_CERT": "/bao/public-ca/ca.crt",
        "GRPC_WORKLOAD_TLS_SERVER_KMS_TOKEN_FILE": f"/run/secrets/{prefix}_kms_token",
        "GRPC_WORKLOAD_TLS_SERVER_KMS_KEY_NAME": f"{project}-{role}",
        "GRPC_WORKLOAD_TLS_SERVER_KMS_KEY_VERSION": "1",
    }


def remote_grpc_client_environment(service: str, project: str) -> dict[str, str]:
    prefix, role = PASSPORT_REMOTE_GRPC_CLIENTS[service]
    return {
        "GRPC_WORKLOAD_TLS_CLIENT_CERT": f"/run/secrets/{prefix}_cert",
        "GRPC_WORKLOAD_TLS_CA_CERT": "/run/secrets/workload_identity_ca_cert",
        "GRPC_WORKLOAD_TLS_KMS_ADDR": "https://openbao:8200",
        "GRPC_WORKLOAD_TLS_KMS_CA_CERT": "/bao/public-ca/ca.crt",
        "GRPC_WORKLOAD_TLS_KMS_TOKEN_FILE": f"/run/secrets/{prefix}_kms_token",
        "GRPC_WORKLOAD_TLS_KMS_KEY_NAME": f"{project}-{role}",
        "GRPC_WORKLOAD_TLS_KMS_KEY_VERSION": "1",
    }
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
ROOT = Path(__file__).resolve().parents[1]


class ModelPreflightError(ValueError):
    pass


def require_keyless_tls_custody(model: dict) -> None:
    evaluate_passport_policy("keyless-custody", error_type=ModelPreflightError, model=model)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ModelPreflightError(message)


def _within(path: str, root: Path) -> bool:
    candidate = Path(path)
    return candidate.is_absolute() and candidate.resolve().is_relative_to(root.resolve())


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
    require(disposable_root.is_absolute() and disposable_root.is_dir(),
            "Disposable resource root is missing")
    evaluate_passport_policy("compose-supported-resources", error_type=ModelPreflightError,
                             model=model, project=project)
    services = model["services"]
    infra_images = qualified_images(verify_registry=False)
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
            and set(configs) == {"passport_supported_openbao_start"},
            "Compose configs are invalid")
    start_config = configs["passport_supported_openbao_start"]
    require(isinstance(start_config, dict)
            and start_config.get("external") not in (True, "true")
            and isinstance(start_config.get("file"), str)
            and Path(start_config["file"]).resolve()
            == (ROOT / "scripts/passport_supported_openbao_start.sh").resolve()
            and (ROOT / "scripts/passport_supported_openbao_start.sh").is_file(),
            "Compose OpenBao start config differs from protected source")
    evaluate_passport_policy("compose-supported-services", error_type=ModelPreflightError,
                             model=model, project=project, services_reference=services_reference,
                             migrations_reference=migrations_reference, infra_images=infra_images)
    return evaluate_passport_policy(
        "compose-supported-runtime", error_type=ModelPreflightError, model=model, project=project,
        organization_expiry_aware=_aware_datetime(
            services["organization"]["environment"].get("PASSPORT_ACCEPTANCE_EXPIRES_AT")),
    )


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
