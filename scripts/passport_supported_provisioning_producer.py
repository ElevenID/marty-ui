#!/usr/bin/env python3
"""Fail-closed gates and private helpers for a future disposable producer.

The protected workflow deliberately stops before provisioning until disposable
KMS, issuer profiles, and simulator secret files are governed and available.
"""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import tempfile
from typing import Callable
import uuid

from services.passport_disposable_identity import ORGANIZATION_ID

if __package__:
    from .check_passport_supported_compose_ownership import (
        _expected_image, _expected_mounts, _inspect, _labels, docker,
        verify as verify_ownership,
    )
    from .check_passport_supported_rust_model import (
        DISPOSABLE_SERVICES, PROJECT, ModelPreflightError, preflight_attested_plan,
        source_identity,
    )
    from .passport_supported_provisioning_plan import (
        COMMIT, PLAN_WORKFLOW, RUN_ID, PlanError, _attest, release_inputs,
    )
    from .passport_supported_infra_images import ROLES
    from .stage_passport_disposable_tls import TLS_FILES, stage_tls
else:
    from check_passport_supported_compose_ownership import (
        _expected_image, _expected_mounts, _inspect, _labels, docker,
        verify as verify_ownership,
    )
    from check_passport_supported_rust_model import (
        DISPOSABLE_SERVICES, PROJECT, ModelPreflightError, preflight_attested_plan,
        source_identity,
    )
    from passport_supported_provisioning_plan import (
        COMMIT, PLAN_WORKFLOW, RUN_ID, PlanError, _attest, release_inputs,
    )
    from passport_supported_infra_images import ROLES
    from stage_passport_disposable_tls import TLS_FILES, stage_tls


WORKFLOW_REF = (
    "ElevenID/marty-ui/.github/workflows/"
    "passport-supported-provisioning-producer.yml@refs/heads/main"
)
INFRA_WORKFLOW_REF = (
    "ElevenID/marty-ui/.github/workflows/"
    "passport-supported-infra-rehearsal.yml@refs/heads/main"
)
CERTIFICATE_WORKFLOW_REF = (
    "ElevenID/marty-ui/.github/workflows/"
    "passport-supported-certificate-rehearsal.yml@refs/heads/main"
)
RESOURCE_ID = re.compile(r"[0-9a-f]{64}\Z")
TEST_KEY = re.compile(rb"mk_test_[A-Za-z0-9]{43}\n\Z")
KEY_COMMAND = "/usr/local/bin/marty-passport-acceptance-api-key"
CONTAINER_KEY = "/app/data/passport-acceptance-api-key"
CONTAINER_OPERATOR_KEY = "/app/data/passport-acceptance-operator-api-key"
CONTAINER_TENANT_PROBE_KEY = "/app/data/passport-acceptance-tenant-probe-api-key"
TEXT_SECRETS = frozenset({
    "bao_root_token", "marty_db_password", "signing_keys_internal_api_key",
    "dsc_issue_gateway_key", "csca_issue_gateway_key",
    "issuance_api_key", "callback_signer_api_key", "grpc_service_token",
    "passport_beta_reconciliation_operator_token",
    "bureau_database_url", "token_hmac_key", "integration_secret_master_key",
    "flow_webhook_secret", "flow_application_event_hmac_key",
})
STAGED_SECRETS = TEXT_SECRETS | TLS_FILES
BOOTSTRAPPED_SECRETS = frozenset({"bao_token", "callback_signer_bao_token"})
EPHEMERAL_SECRETS = BOOTSTRAPPED_SECRETS | frozenset({
    "passport_acceptance_api_key", "passport_acceptance_operator_api_key",
    "passport_acceptance_tenant_probe_api_key",
})
DISPOSABLE_NETWORKS = frozenset({"private", "callback_signing"})
DISPOSABLE_VOLUMES = frozenset({
    "postgres_data", "redis_data", "openbao_data", "openbao_file", "openbao_logs",
})
PARTIAL_ONLY_SERVICES = frozenset({
    "passport-openbao-bootstrap", "passport-certificate-bootstrap",
    "passport-bureau-poll",
})


class ProducerError(ValueError):
    pass


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ProducerError(message)


def protected_context(environment: dict[str, str], *,
                      workflow_ref: str = WORKFLOW_REF) -> tuple[str, str]:
    require(workflow_ref in {WORKFLOW_REF, INFRA_WORKFLOW_REF,
                             CERTIFICATE_WORKFLOW_REF},
            "Protected producer workflow is not allowed")
    require(environment.get("GITHUB_ACTIONS") == "true"
            and environment.get("GITHUB_REPOSITORY") == "ElevenID/marty-ui"
            and environment.get("GITHUB_REF") == "refs/heads/main"
            and environment.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
            and environment.get("GITHUB_WORKFLOW_REF") == workflow_ref,
            "Protected producer workflow identity is invalid")
    source, run_id = environment.get("GITHUB_SHA"), environment.get("GITHUB_RUN_ID")
    require(isinstance(source, str) and COMMIT.fullmatch(source) is not None
            and isinstance(run_id, str) and RUN_ID.fullmatch(run_id) is not None,
            "Protected producer source/run is invalid")
    return source, run_id


def verify_plan_release(
    plan_path: Path, manifest_path: Path, plan_run_id: str,
    environment: dict[str, str], *,
    attest: Callable[[str, str, str, str, str], bool] = _attest,
    release: Callable[..., dict] = release_inputs,
    now: datetime | None = None,
    checkout: Callable[[], tuple[str, bool]] = source_identity,
    workflow_ref: str = WORKFLOW_REF,
) -> dict:
    """Verify source, exact plan run, lease and release before any model read."""
    source, _ = protected_context(environment, workflow_ref=workflow_ref)
    require(RUN_ID.fullmatch(plan_run_id) is not None,
            "Protected plan run ID is invalid")
    try:
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ProducerError("Protected plan artifact is invalid") from exc
    require(isinstance(plan, dict)
            and plan.get("schema") == "marty.passport-supported-provisioning-plan/v1"
            and plan.get("status") == "blocked"
            and plan.get("source_commit") == source
            and plan.get("run_id") == plan_run_id
            and plan.get("surface") in {"base", "selfhost"},
            "Protected plan source/run/surface mismatch")
    try:
        verified = attest(str(plan_path), "ElevenID/marty-ui", PLAN_WORKFLOW,
                          source, "refs/heads/main")
    except (OSError, ValueError) as exc:
        raise ProducerError("Protected plan attestation failed") from exc
    require(verified is True, "Protected plan attestation failed")
    head, dirty = checkout()
    require(head == source and not dirty,
            "Protected producer checkout differs from attested plan")
    try:
        created = datetime.fromisoformat(plan["created_at"])
        expires = datetime.fromisoformat(plan["expires_at"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ProducerError("Protected plan lease is invalid") from exc
    current = now or datetime.now(timezone.utc)
    require(current.tzinfo is not None and created.tzinfo is not None
            and expires.tzinfo is not None
            and created <= current < expires <= created + timedelta(hours=2),
            "Protected plan lease is expired or too broad")
    require(plan.get("stack_manifest_sha256") == hashlib.sha256(
        manifest_path.read_bytes()).hexdigest(),
        "Official release manifest differs from protected plan")
    try:
        official = release(manifest_path, source)
    except (PlanError, OSError, ValueError) as exc:
        raise ProducerError("Official release verification failed") from exc
    require(all(plan.get(key) == value for key, value in official.items()),
            "Official release differs from protected plan")
    return plan


def verify_pre_mutation(
    plan_path: Path, manifest_path: Path, plan_run_id: str,
    environment: dict[str, str], env_file: Path, disposable_root: Path,
    *, now: datetime | None = None,
    workflow_ref: str = WORKFLOW_REF,
) -> dict:
    """Complete release and model gates for a future explicitly enabled producer."""
    plan = verify_plan_release(plan_path, manifest_path, plan_run_id,
                               environment, now=now, workflow_ref=workflow_ref)
    report = preflight_attested_plan(
        plan["surface"], plan["project"], env_file, disposable_root,
        plan["services_reference"], plan_path, now=now)
    require(report.get("status") == "blocked"
            and report.get("model", {}).get("model_safe") is True,
            "Disposable model preflight failed")
    return plan


def stage_disposable_inputs(
    plan: dict, gateway_port: int, *, now: datetime | None = None,
) -> tuple[Path, Path]:
    """Create fresh, project-owned inputs before the isolated KMS bootstrap.

    The caller must first verify the protected plan and release. No Docker
    resource is created here. OpenBao service tokens are intentionally absent
    until the project-scoped bootstrap mints them.
    """
    project = plan.get("project")
    match = PROJECT.fullmatch(project) if isinstance(project, str) else None
    require(match is not None and match.group(1) == plan.get("surface"),
            "Disposable input project is invalid")
    require(type(gateway_port) is int and 1024 <= gateway_port <= 65535,
            "Disposable Gateway port is invalid")
    require(plan.get("schema") == "marty.passport-supported-provisioning-plan/v1"
            and plan.get("status") == "blocked"
            and plan.get("surface") in {"base", "selfhost"}
            and plan.get("run_id") is not None
            and RUN_ID.fullmatch(str(plan["run_id"])) is not None
            and isinstance(plan.get("source_commit"), str)
            and COMMIT.fullmatch(plan["source_commit"]) is not None,
            "Disposable input plan is invalid")
    labels = plan.get("owner_labels")
    require(isinstance(labels, dict)
            and labels == {
                "com.marty.passport.acceptance.owner": "supported-consumer",
                "com.marty.passport.acceptance.run-id": str(plan["run_id"]),
                "com.marty.passport.acceptance.source-commit": plan["source_commit"],
                "com.marty.passport.acceptance.services-image": plan.get("services_reference"),
            }, "Disposable input owner labels are invalid")
    try:
        created = datetime.fromisoformat(plan["created_at"])
        expires = datetime.fromisoformat(plan["expires_at"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ProducerError("Disposable input lease is invalid") from exc
    current = now or datetime.now(timezone.utc)
    require(current.tzinfo is not None and created.tzinfo is not None
            and expires.tzinfo is not None
            and created <= current < expires <= created + timedelta(hours=2),
            "Disposable input lease is invalid")
    images = plan.get("infra_images")
    require(isinstance(images, dict) and set(images) == set(ROLES),
            "Disposable infrastructure image set is invalid")
    references = {
        "MARTY_SERVICES_IMAGE": plan.get("services_reference"),
        "PASSPORT_ACCEPTANCE_MIGRATIONS_IMAGE": plan.get("migrations_reference"),
        **{f"PASSPORT_ACCEPTANCE_{name.upper()}_IMAGE": image
           for name, image in images.items()},
    }
    require(all(isinstance(value, str)
                and re.fullmatch(r"[^\s]+@sha256:[0-9a-f]{64}", value) is not None
                for value in references.values()),
            "Disposable image reference is invalid")
    expires_at = plan.get("expires_at")
    require(isinstance(expires_at, str) and "\r" not in expires_at
            and "\n" not in expires_at,
            "Disposable expiry is invalid")

    root = Path(tempfile.gettempdir()) / project
    require(root.is_absolute() and root.parent.resolve() == root.parent,
            "Disposable temporary root is invalid")
    root.mkdir(mode=0o700)
    try:
        secret_dir = root / "secrets"
        secret_dir.mkdir(mode=0o700)
        require(root.resolve() == root and secret_dir.resolve() == secret_dir,
                "Disposable secret root is not isolated")
        if os.name == "posix":
            require(all(path.stat().st_uid == os.getuid()
                        and stat.S_IMODE(path.stat().st_mode) == 0o700
                        for path in (root, secret_dir)),
                    "Disposable secret directory is not private")

        database_password = secrets.token_hex(24)
        values = {
            "bao_root_token": secrets.token_hex(32),
            "marty_db_password": database_password,
            "signing_keys_internal_api_key": secrets.token_hex(32),
            "dsc_issue_gateway_key": secrets.token_hex(32),
            "csca_issue_gateway_key": secrets.token_hex(32),
            "issuance_api_key": secrets.token_hex(32),
            "callback_signer_api_key": secrets.token_hex(32),
            "grpc_service_token": secrets.token_hex(32),
            "passport_beta_reconciliation_operator_token": secrets.token_hex(32),
            "bureau_database_url": f"postgresql://marty:{database_password}@postgres:5432/marty",
            "token_hmac_key": secrets.token_hex(32),
            "integration_secret_master_key": base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
            "flow_webhook_secret": secrets.token_hex(32),
            "flow_application_event_hmac_key": secrets.token_hex(32),
        }
        require(set(values) == TEXT_SECRETS, "Disposable secret set is incomplete")
        require(values["passport_beta_reconciliation_operator_token"]
                not in {values["grpc_service_token"], values["issuance_api_key"]},
                "Disposable native batch operator token is not distinct")
        env = {
            **references,
            "PASSPORT_ACCEPTANCE_PROJECT": project,
            "PASSPORT_ACCEPTANCE_PLAN_RUN_ID": str(plan["run_id"]),
            "PASSPORT_ACCEPTANCE_SOURCE_COMMIT": plan["source_commit"],
            "PASSPORT_ACCEPTANCE_EXPIRES_AT": expires_at,
            "PASSPORT_ACCEPTANCE_SECRET_DIR": secret_dir.as_posix(),
            "PASSPORT_ACCEPTANCE_GATEWAY_PORT": str(gateway_port),
            "PASSPORT_ACCEPTANCE_ADMIN_EMAIL": "disposable-passport@acceptance.invalid",
        }
        require(all("\n" not in value and "\r" not in value for value in env.values()),
                "Disposable environment input is invalid")
        for name, value in values.items():
            # File-backed Compose secrets are bind mounts. Marty services run as
            # UID 10001 and infrastructure images use other UIDs; a host-owned
            # 0600 file is unreadable there. The 0700 parent keeps host peers
            # out, while Compose exposes each read-only file only to its
            # intended containers. OpenBao's pinned image starts as root.
            mode = 0o600 if name == "bao_root_token" else 0o644
            _write_private(secret_dir / name, value.encode("ascii"), mode=mode)
        stage_tls(secret_dir)
        require({path.name for path in secret_dir.iterdir()} == STAGED_SECRETS,
                "Disposable TLS and secret set is incomplete")
        require(all(not (secret_dir / name).exists() for name in BOOTSTRAPPED_SECRETS),
                "Disposable OpenBao tokens were prepopulated")
        env_file = root / "acceptance.env"
        _write_private(env_file, "".join(
            f"{key}={value}\n" for key, value in sorted(env.items())
        ).encode("ascii"))
        return root, env_file
    except BaseException:
        _remove_staged_inputs(root)
        raise


def _remove_staged_inputs(root: Path) -> None:
    """Erase only files under the root this staging call just created."""
    require(root.resolve() == root and not root.is_symlink(),
            "Disposable input cleanup root changed identity")
    secret_dir = root / "secrets"
    if secret_dir.exists():
        require(secret_dir.resolve() == secret_dir and not secret_dir.is_symlink(),
                "Disposable input cleanup secret directory changed identity")
        for name in STAGED_SECRETS | EPHEMERAL_SECRETS:
            (secret_dir / name).unlink(missing_ok=True)
        for path in secret_dir.iterdir():
            require(re.fullmatch(
                r"\.(?:bao_token|callback_signer_bao_token)\.[A-Za-z0-9]{6}",
                path.name,
            ) is not None,
                "Disposable secret directory has an unexpected file")
            path.unlink()
        secret_dir.rmdir()
    (root / "acceptance.env").unlink(missing_ok=True)
    root.rmdir()


def _write_private(path: Path, value: bytes, *, mode: int = 0o600) -> None:
    require(mode in (0o600, 0o644), "Disposable secret file mode is invalid")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(value)
        output.flush()
        os.fsync(output.fileno())
    if os.name == "posix":
        os.chmod(path, mode)
        require(path.stat().st_uid == os.getuid()
                and stat.S_IMODE(path.stat().st_mode) == mode,
                "Disposable secret file is not private")


def collect_record(
    plan_path: Path, plan: dict, producer_run_id: str, disposable_root: Path,
    now: datetime, runner: Callable[[list[str]], str] = docker,
    *, ownership: Callable[..., dict] = verify_ownership,
) -> dict:
    """Read exact live IDs and require the ownership proof before returning a record."""
    require(isinstance(producer_run_id, str)
            and RUN_ID.fullmatch(producer_run_id) is not None,
            "Protected producer run ID is invalid")
    project = plan.get("project")
    require(isinstance(project, str), "Protected project is invalid")
    labels = plan.get("owner_labels")
    require(isinstance(labels, dict), "Protected resource labels are invalid")
    ids = runner(["ps", "-aq", "--no-trunc", "--filter",
                  f"label=com.docker.compose.project={project}"]).split()
    containers: dict[str, str] = {}
    for identifier in ids:
        require(RESOURCE_ID.fullmatch(identifier) is not None,
                "Disposable container ID is invalid")
        item = _inspect("container", identifier, runner)
        config = item.get("Config")
        actual_labels = config.get("Labels") if isinstance(config, dict) else None
        require(isinstance(actual_labels, dict),
                "Disposable container labels are missing")
        service = actual_labels.get("com.docker.compose.service")
        require(service in DISPOSABLE_SERVICES and service not in containers,
                "Disposable service set is invalid")
        containers[service] = identifier
    require(set(containers) == DISPOSABLE_SERVICES,
            "Disposable service set is incomplete")
    network_ids = runner(["network", "ls", "-q", "--no-trunc", "--filter",
                          f"label=com.docker.compose.project={project}"]).split()
    networks: dict[str, str] = {}
    for identifier in network_ids:
        require(RESOURCE_ID.fullmatch(identifier) is not None,
                "Disposable network ID is invalid")
        item = _inspect("network", identifier, runner)
        name = item.get("Name")
        require(isinstance(name, str) and name not in networks,
                "Disposable network set is invalid")
        networks[name] = identifier
    volumes = runner(["volume", "ls", "-q", "--filter",
                      f"label=com.docker.compose.project={project}"]).split()
    require(len(volumes) == len(set(volumes)), "Disposable volume set is invalid")
    record = {
        "schema": "marty.passport-supported-compose-ownership/v1",
        "plan_sha256": hashlib.sha256(plan_path.read_bytes()).hexdigest(),
        "producer_run_id": producer_run_id,
        "disposable_root": str(disposable_root),
        "containers": containers, "networks": networks, "volumes": volumes,
        **{key: plan[key] for key in (
            "run_id", "project", "source_commit", "services_reference",
            "migrations_reference", "infra_images",
            "created_at", "expires_at", "owner_labels",
        )},
    }
    proof = ownership(record, plan["surface"], now, runner)
    require(proof.get("live_ownership_verified") is True,
            "Disposable live ownership proof failed")
    return record


def _exec_docker(args: list[str], output: object = None) -> bool:
    """Run a fixed Docker command without returning its output or stderr."""
    try:
        result = subprocess.run(["docker", *args], stdout=output or subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, check=False, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


def _destroy_recorded_project(
    record: dict, inspector: Callable[[list[str]], str],
    executor: Callable[[list[str], object], bool], *, complete: bool,
    ceremony: bool | None = False,
) -> bool:
    """Reinspect exact resource IDs before deletion, then prove their absence."""
    project = record.get("project")
    containers = record.get("containers")
    networks = record.get("networks")
    volumes = record.get("volumes")
    require(isinstance(project, str) and PROJECT.fullmatch(project) is not None
            and record.get("schema") == "marty.passport-supported-compose-ownership/v1"
            and isinstance(containers, dict)
            and (set(containers) == DISPOSABLE_SERVICES if complete
                 else set(containers) <= DISPOSABLE_SERVICES | PARTIAL_ONLY_SERVICES)
            and all(isinstance(value, str) and RESOURCE_ID.fullmatch(value)
                    for value in containers.values())
            and len(set(containers.values())) == len(containers)
            and isinstance(networks, dict) and (bool(networks) if complete else True)
            and all(isinstance(name, str) and name.startswith(project + "_")
                    and isinstance(value, str) and RESOURCE_ID.fullmatch(value)
                    for name, value in networks.items())
            and len(set(networks.values())) == len(networks)
            and isinstance(volumes, list) and all(isinstance(name, str)
                    and name.startswith(project + "_") for name in volumes)
            and len(set(volumes)) == len(volumes),
            "Disposable teardown record is invalid")
    surface = PROJECT.fullmatch(project).group(1)
    disposable_root = Path(tempfile.gettempdir()) / project
    try:
        for service, identifier in containers.items():
            item = _inspect("container", identifier, inspector)
            config = item.get("Config")
            require(item.get("Id") == identifier and isinstance(config, dict),
                    "Recorded disposable container changed identity")
            labels = config.get("Labels")
            _labels(labels, record, project)
            require(labels.get("com.docker.compose.service") == service,
                    "Recorded disposable container changed service")
            if not complete:
                expected_image = _expected_image(record, service)
                require(isinstance(expected_image, str)
                        and config.get("Image") == expected_image
                        and re.fullmatch(r"/" + re.escape(project) + "-"
                                         + re.escape(service) + r"-[1-9][0-9]*",
                                         item.get("Name", "")) is not None
                        and labels.get("com.docker.compose.oneoff") != "True",
                        "Partial disposable container is outside the plan model")
                network_settings = item.get("NetworkSettings")
                host_config = item.get("HostConfig")
                helper_parent = ({"passport-certificate-bootstrap": "signing-keys",
                                  "passport-bureau-poll": "passport-beta-bureau"}
                                 .get(service))
                parent_id = containers.get(helper_parent) if helper_parent else None
                expected_mode = (f"container:{parent_id}" if helper_parent
                                 else project + "_callback_signing"
                                 if service == "passport-callback-signer"
                                 else project + "_private")
                expected_modes = {expected_mode}
                if service == "openbao":
                    # Compose may choose either owned attachment as the
                    # primary network mode when OpenBao joins both networks.
                    expected_modes.add(project + "_callback_signing")
                require(isinstance(host_config, dict)
                        and host_config.get("NetworkMode") in expected_modes
                        and (isinstance(parent_id, str) and not host_config.get("PortBindings")
                             if helper_parent else host_config.get("NetworkMode") in networks),
                        "Partial disposable container uses an unowned network mode")
                require(isinstance(network_settings, dict),
                        "Partial disposable container network state is invalid")
                attachments = network_settings.get("Networks")
                expected_networks = set() if helper_parent else {expected_mode}
                if service in {"openbao", "passport-beta-bureau"}:
                    expected_networks.add(project + "_callback_signing")
                state = item.get("State")
                created = isinstance(state, dict) and state.get("Status") == "created"
                detached_startup = (isinstance(state, dict)
                                    and (created
                                         or (state.get("Status") == "exited"
                                             and service in {"db-migrate",
                                                             "revocation-profile-migrate"})))
                require(isinstance(attachments, dict)
                        and (set(attachments) == expected_networks
                             or (not attachments and detached_startup))
                        and all(isinstance(endpoint, dict)
                                and (endpoint.get("NetworkID") == networks.get(name)
                                     or (created and endpoint.get("NetworkID") == ""))
                                for name, endpoint in attachments.items()),
                        "Partial disposable container joins an unowned network")
                mounts = item.get("Mounts")
                require(isinstance(mounts, list),
                        "Partial disposable container mounts are invalid")
                expected_mounts = _expected_mounts(
                    service, project, disposable_root, surface, ceremony=False)
                allowed_mount_sets = (expected_mounts,)
                if ceremony is None and service in {"gateway", "signing-keys"}:
                    allowed_mount_sets += (_expected_mounts(
                        service, project, disposable_root, surface, ceremony=True),)
                elif ceremony is True:
                    expected_mounts = _expected_mounts(
                        service, project, disposable_root, surface, ceremony=True)
                    allowed_mount_sets = (expected_mounts,)
                observed_mounts: set[tuple[str, str, str, bool]] = set()
                for mount in mounts:
                    require(isinstance(mount, dict)
                            and mount.get("Type") in {"bind", "volume"}
                            and isinstance(mount.get("Destination"), str)
                            and isinstance(mount.get("RW"), bool),
                            "Partial disposable container uses an unowned mount")
                    kind = mount["Type"]
                    source = mount.get("Source") if kind == "bind" else mount.get("Name")
                    require(isinstance(source, str)
                            and (kind != "bind" or Path(source).resolve() == Path(source)),
                            "Partial disposable container uses an unowned mount")
                    identity = (kind, str(Path(source)) if kind == "bind" else source,
                                mount["Destination"], mount["RW"])
                    require(any(identity in allowed for allowed in allowed_mount_sets)
                            and identity not in observed_mounts
                            and (kind != "volume" or source in volumes),
                            "Partial disposable container uses an unowned mount")
                    observed_mounts.add(identity)
                require(observed_mounts in allowed_mount_sets,
                        "Partial disposable container mount set is incomplete")
        for name, identifier in networks.items():
            item = _inspect("network", identifier, inspector)
            require(item.get("Id") == identifier and item.get("Name") == name,
                    "Recorded disposable network changed identity")
            _labels(item.get("Labels"), record, project)
            if not complete:
                members = item.get("Containers", {})
                require(item.get("Driver") == "bridge" and item.get("Internal") is True
                        and isinstance(members, dict)
                        and set(members) <= set(containers.values()),
                        "Partial disposable network is not isolated")
        for name in volumes:
            item = _inspect("volume", name, inspector)
            require(item.get("Name") == name,
                    "Recorded disposable volume changed identity")
            _labels(item.get("Labels"), record, project)
            if not complete:
                require(item.get("Driver") == "local" and not item.get("Options"),
                        "Partial disposable volume is outside the storage model")
        expected = (set(containers.values()), set(networks.values()), set(volumes))
        listed = (
            inspector(["ps", "-aq", "--no-trunc", "--filter",
                       f"label=com.docker.compose.project={project}"]).split(),
            inspector(["network", "ls", "-q", "--no-trunc", "--filter",
                       f"label=com.docker.compose.project={project}"]).split(),
            inspector(["volume", "ls", "-q", "--filter",
                       f"label=com.docker.compose.project={project}"]).split(),
        )
        require(all(len(found) == len(set(found)) and set(found) == wanted
                    for found, wanted in zip(listed, expected)),
                "Disposable project changed before teardown")
    except (OSError, ValueError, KeyError, TypeError):
        return False
    if containers:
        executor(["container", "rm", "-f", *containers.values()], None)
    if networks:
        executor(["network", "rm", *networks.values()], None)
    if volumes:
        executor(["volume", "rm", *volumes], None)
    try:
        project_absent = all(not inspector(args).split() for args in (
            ["ps", "-aq", "--no-trunc", "--filter",
             f"label=com.docker.compose.project={project}"],
            ["network", "ls", "-q", "--no-trunc", "--filter",
             f"label=com.docker.compose.project={project}"],
            ["volume", "ls", "-q", "--filter",
             f"label=com.docker.compose.project={project}"],
        ))
        live_containers = set(inspector(["ps", "-aq", "--no-trunc"]).split())
        live_networks = set(inspector(["network", "ls", "-q", "--no-trunc"]).split())
        live_volumes = set(inspector(["volume", "ls", "-q"]).split())
        return (project_absent
                and not set(containers.values()) & live_containers
                and not set(networks.values()) & live_networks
                and not set(volumes) & live_volumes)
    except (OSError, ValueError, KeyError):
        return False


def destroy_disposable_project(
    record: dict, inspector: Callable[[list[str]], str] = docker,
    executor: Callable[[list[str], object], bool] = _exec_docker,
) -> bool:
    """Remove only the complete recorded project after accepted ownership proof."""
    return _destroy_recorded_project(record, inspector, executor, complete=True)


def destroy_partial_disposable_project(
    plan_path: Path, manifest_path: Path, plan_run_id: str,
    environment: dict[str, str], inspector: Callable[[list[str]], str] = docker,
    executor: Callable[[list[str], object], bool] = _exec_docker,
    *, now: datetime | None = None,
    attest: Callable[[str, str, str, str, str], bool] = _attest,
    release: Callable[..., dict] = release_inputs,
    checkout: Callable[[], tuple[str, bool]] = source_identity,
    workflow_ref: str = WORKFLOW_REF,
) -> bool:
    """Clean a failed startup only after rechecking protected plan provenance.

    Every discovered resource must match the plan's image, mounts, network,
    volume, labels, and fixed names. The caller must quiesce startup first;
    the final project inventory rejects added resources before deletion.
    The caller must retain the plan and release.
    """
    plan = verify_plan_release(
        plan_path, manifest_path, plan_run_id, environment, now=now,
        attest=attest, release=release, checkout=checkout,
        workflow_ref=workflow_ref,
    )
    project = plan.get("project")
    surface = plan.get("surface")
    owner_labels = plan.get("owner_labels")
    require(isinstance(project, str) and (match := PROJECT.fullmatch(project))
            and match.group(1) == surface
            and plan.get("schema") == "marty.passport-supported-provisioning-plan/v1"
            and plan.get("status") == "blocked"
            and isinstance(plan.get("run_id"), str)
            and RUN_ID.fullmatch(plan["run_id"]) is not None
            and isinstance(plan.get("source_commit"), str)
            and COMMIT.fullmatch(plan["source_commit"]) is not None
            and isinstance(plan.get("services_reference"), str)
            and re.fullmatch(r"ghcr\.io/elevenid/marty-ui-oss/services@sha256:[0-9a-f]{64}",
                             plan["services_reference"]) is not None
            and isinstance(owner_labels, dict)
            and owner_labels == {
                "com.marty.passport.acceptance.owner": "supported-consumer",
                "com.marty.passport.acceptance.run-id": plan["run_id"],
                "com.marty.passport.acceptance.source-commit": plan["source_commit"],
                "com.marty.passport.acceptance.services-image": plan["services_reference"],
            }, "Partial teardown plan is invalid")
    try:
        containers = {}
        for identifier in inspector(["ps", "-aq", "--no-trunc", "--filter",
                                     f"label=com.docker.compose.project={project}"]).split():
            require(RESOURCE_ID.fullmatch(identifier) is not None,
                    "Partial disposable container ID is invalid")
            item = _inspect("container", identifier, inspector)
            config = item.get("Config")
            require(isinstance(config, dict),
                    "Partial disposable container config is invalid")
            labels = config.get("Labels")
            _labels(labels, plan, project)
            service = labels.get("com.docker.compose.service")
            require(item.get("Id") == identifier
                    and service in DISPOSABLE_SERVICES | PARTIAL_ONLY_SERVICES
                    and service not in containers,
                    "Partial disposable service identity is invalid")
            containers[service] = identifier
        networks = {}
        for identifier in inspector(["network", "ls", "-q", "--no-trunc", "--filter",
                                     f"label=com.docker.compose.project={project}"]).split():
            require(RESOURCE_ID.fullmatch(identifier) is not None,
                    "Partial disposable network ID is invalid")
            item = _inspect("network", identifier, inspector)
            _labels(item.get("Labels"), plan, project)
            name = item.get("Name")
            require(item.get("Id") == identifier
                    and name in {f"{project}_{suffix}" for suffix in DISPOSABLE_NETWORKS}
                    and name not in networks,
                    "Partial disposable network identity is invalid")
            networks[name] = identifier
        volumes = inspector(["volume", "ls", "-q", "--filter",
                             f"label=com.docker.compose.project={project}"]).split()
        require(len(volumes) == len(set(volumes)),
                "Partial disposable volume set is invalid")
        for name in volumes:
            require(name in {f"{project}_{suffix}" for suffix in DISPOSABLE_VOLUMES},
                    "Partial disposable volume name is invalid")
            item = _inspect("volume", name, inspector)
            _labels(item.get("Labels"), plan, project)
            require(item.get("Name") == name,
                    "Partial disposable volume identity is invalid")
    except (OSError, ValueError, KeyError, TypeError):
        return False
    record = {"schema": "marty.passport-supported-compose-ownership/v1",
              "project": project, "run_id": plan["run_id"],
              "source_commit": plan["source_commit"],
              "services_reference": plan["services_reference"],
              "migrations_reference": plan["migrations_reference"],
              "infra_images": plan["infra_images"],
              "containers": containers, "networks": networks, "volumes": volumes}
    return _destroy_recorded_project(
        record, inspector, executor, complete=False,
        ceremony=(None if workflow_ref == WORKFLOW_REF and surface == "selfhost"
                  else workflow_ref == CERTIFICATE_WORKFLOW_REF and surface == "selfhost"),
    )


def issue_disposable_api_key(
    record: dict, surface: str, now: datetime,
    inspector: Callable[[list[str]], str] = docker,
    executor: Callable[[list[str], object], bool] = _exec_docker,
    *, ownership: Callable[..., dict] = verify_ownership,
    teardown: Callable[..., bool] = destroy_disposable_project,
) -> Path:
    """Issue the narrow lease-bound credential key from the owned Organization."""
    return _issue_disposable_key(
        record, surface, now, inspector, executor, ownership=ownership,
        teardown=teardown, operator=False,
    )


def issue_disposable_operator_key(
    record: dict, surface: str, now: datetime,
    inspector: Callable[[list[str]], str] = docker,
    executor: Callable[[list[str], object], bool] = _exec_docker,
    *, ownership: Callable[..., dict] = verify_ownership,
    teardown: Callable[..., bool] = destroy_disposable_project,
) -> Path:
    """Issue the separate lease-bound Flow operator key and membership."""
    return _issue_disposable_key(
        record, surface, now, inspector, executor, ownership=ownership,
        teardown=teardown, operator=True,
    )


def issue_disposable_tenant_probe_key(
    record: dict, surface: str, now: datetime,
    inspector: Callable[[list[str]], str] = docker,
    executor: Callable[[list[str], object], bool] = _exec_docker,
    *, ownership: Callable[..., dict] = verify_ownership,
    teardown: Callable[..., bool] = destroy_disposable_project,
) -> Path:
    """Create a second disposable Organization and its short-lived Gateway key."""
    return _issue_disposable_key(
        record, surface, now, inspector, executor, ownership=ownership,
        teardown=teardown, operator=False, tenant_probe=True,
    )


def _issue_disposable_key(
    record: dict, surface: str, now: datetime,
    inspector: Callable[[list[str]], str],
    executor: Callable[[list[str], object], bool],
    *, ownership: Callable[..., dict], teardown: Callable[..., bool],
    operator: bool, tenant_probe: bool = False,
) -> Path:
    """Extract one key with the same private file and failure cleanup rules."""
    require(not (operator and tenant_probe), "Disposable key purpose is ambiguous")
    proof = ownership(record, surface, now, inspector)
    require(proof.get("live_ownership_verified") is True,
            "Disposable live ownership proof failed before key issuance")
    container = record["containers"]["organization"]
    require(RESOURCE_ID.fullmatch(container) is not None,
            "Disposable Organization container ID is invalid")
    root = Path(record["disposable_root"])
    secrets = root / "secrets"
    info = secrets.lstat()
    require(stat.S_ISDIR(info.st_mode) and not secrets.is_symlink(),
            "Disposable key directory is invalid")
    if os.name == "posix":
        require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
                "Disposable key directory is not private")
    name = ("passport_acceptance_tenant_probe_api_key" if tenant_probe else
            "passport_acceptance_operator_api_key" if operator else
            "passport_acceptance_api_key")
    container_key = (CONTAINER_TENANT_PROBE_KEY if tenant_probe else
                     CONTAINER_OPERATOR_KEY if operator else CONTAINER_KEY)
    destination = secrets / name
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    base = ["exec", "--user", "10001:10001", container]
    attempted = False
    erased = False
    created = False
    succeeded = False
    try:
        descriptor = os.open(destination, flags, 0o600)
        created = True
        with os.fdopen(descriptor, "wb") as output:
            attempted = True
            issue = ([*base, KEY_COMMAND, "--tenant-probe"] if tenant_probe else
                     [*base, KEY_COMMAND, "--operator"] if operator else
                     [*base, KEY_COMMAND])
            require(executor(issue, None),
                    "Disposable Organization key issuer failed")
            require(executor([*base, "cat", container_key], output),
                    "Disposable Organization key extraction failed")
            output.flush()
            os.fsync(output.fileno())
        output_bytes = destination.read_bytes()
        if tenant_probe:
            lines = output_bytes.splitlines(keepends=True)
            try:
                tenant_id = str(uuid.UUID(lines[0].decode("ascii").rstrip("\n")))
            except (IndexError, UnicodeError, ValueError) as exc:
                raise ProducerError("Disposable tenant probe identity is invalid") from exc
            require(len(lines) == 2 and lines[0] == f"{tenant_id}\n".encode("ascii")
                    and tenant_id != ORGANIZATION_ID
                    and TEST_KEY.fullmatch(lines[1]) is not None,
                    "Disposable tenant probe key output is invalid")
        else:
            require(len(output_bytes) == 52 and TEST_KEY.fullmatch(output_bytes) is not None,
                    "Disposable Organization key output is invalid")
        erased = executor([*base, "rm", "-f", container_key], None)
        require(erased, "Disposable Organization key erasure failed")
        succeeded = True
        return destination
    finally:
        if attempted and not succeeded:
            try:
                try:
                    executor([*base, KEY_COMMAND, "--revoke-run"], None)
                finally:
                    try:
                        if not erased:
                            executor([*base, "rm", "-f", container_key], None)
                    finally:
                        if created:
                            destination.unlink(missing_ok=True)
            finally:
                require(teardown(record, inspector, executor),
                        "Disposable project teardown is unverified after key issuance failure")
        elif created and not succeeded:
            destination.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--plan-run-id", required=True)
    args = parser.parse_args()
    try:
        verify_plan_release(args.plan, args.manifest, args.plan_run_id, os.environ)
    except (ProducerError, ModelPreflightError, OSError, ValueError) as exc:
        parser.exit(1, f"Protected disposable provisioning blocked: {exc}\n")
    parser.exit(1, "Protected disposable provisioning blocked: governed KMS/bootstrap and simulator inputs are absent\n")


if __name__ == "__main__":
    raise SystemExit(main())
