#!/usr/bin/env python3
"""Read-only ownership proof for an already provisioned passport Compose project.

The caller's record is not an attestation. A protected provisioner must create
and bind it to a release before this can become a rollback authorization.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
import subprocess
import tempfile
from typing import Callable

if __package__:
    from .check_passport_supported_rollback_model import (
        DISPOSABLE_SERVICES, PROJECT, RUST_DEPENDENCIES, SELECTED,
    )
    from .passport_supported_infra_images import ROLES
else:
    from check_passport_supported_rollback_model import (
        DISPOSABLE_SERVICES, PROJECT, RUST_DEPENDENCIES, SELECTED,
    )
    from passport_supported_infra_images import ROLES


COMMIT = re.compile(r"[0-9a-f]{40}\Z")
IMAGE = re.compile(r"ghcr\.io/elevenid/marty-ui-oss/services@sha256:[0-9a-f]{64}\Z")
IDENTIFIER = re.compile(r"[0-9a-f]{64}\Z")
RUN_ID = re.compile(r"[1-9][0-9]{0,19}\Z")
MIGRATIONS_IMAGE = re.compile(
    r"ghcr\.io/elevenid/marty-ui-oss/migrations@sha256:[0-9a-f]{64}\Z")
LEGACY_IMAGE = re.compile(
    r"ghcr\.io/elevenid/marty-credentials-issuance@sha256:[0-9a-f]{64}\Z")
REQUIRED_ROLLBACK = frozenset({"issuance", "db-migrate", "signing-keys"})
OWNER_LABELS = {
    "com.marty.passport.acceptance.owner": "supported-consumer",
    "com.marty.passport.acceptance.run-id": "run_id",
    "com.marty.passport.acceptance.source-commit": "source_commit",
    "com.marty.passport.acceptance.services-image": "services_reference",
}
COMPLETED_INIT = frozenset({
    "db-migrate", "issuance-migrations", "verification-migrations",
    "revocation-profile-migrate", "keycloak-configurator", "openbao-init",
})
SECRET_MOUNTS = {
    "edge": ("passport_edge_tls_cert", "passport_edge_tls_key"),
    "postgres": ("marty_db_password",),
    "redis": (),
    "openbao": ("bao_root_token",),
    "db-migrate": ("marty_db_password", "bao_token"),
    "signing-keys": ("marty_db_password", "bao_token", "signing_keys_internal_api_key"),
    "issuance": ("issuance_api_key", "signing_keys_internal_api_key",
                 "physical_document_artifact_key", "grpc_service_token"),
    "revocation-profile-migrate": ("marty_db_password",),
    "revocation-profile": ("marty_db_password", "grpc_service_token"),
    "event-stream": (),
    "organization": ("marty_db_password", "grpc_service_token"),
    "credential-template": ("marty_db_password", "grpc_service_token",
                            "signing_keys_internal_api_key"),
    "trust-profile": ("marty_db_password", "grpc_service_token",
                      "signing_keys_internal_api_key"),
    "presentation-policy": ("marty_db_password", "grpc_service_token",
                            "issuance_api_key"),
    "deployment-profile": ("marty_db_password", "grpc_service_token"),
    "issuance-native": ("marty_db_password", "bao_token", "signing_keys_internal_api_key",
                        "issuance_api_key", "grpc_service_token", "token_hmac_key",
                        "integration_secret_master_key"),
    "flow": ("marty_db_password", "signing_keys_internal_api_key",
             "issuance_api_key", "grpc_service_token"),
    "passport-callback-signer": ("callback_signer_bao_token", "callback_signer_api_key"),
    "passport-beta-bureau": ("bureau_database_url", "grpc_service_token",
                             "callback_signer_api_key"),
    "gateway": ("bao_token", "signing_keys_internal_api_key", "issuance_api_key",
                "grpc_service_token"),
}
BASE_CEREMONY_MOUNTS = ("dsc_issue_gateway_key", "csca_issue_gateway_key")
DATA_MOUNTS = {
    "postgres": (("postgres_data", "/var/lib/postgresql/data"),),
    "redis": (("redis_data", "/data"),),
    "openbao": (("openbao_data", "/bao/data"),
                ("openbao_file", "/openbao/file"),
                ("openbao_logs", "/openbao/logs")),
}


class OwnershipError(ValueError):
    pass


def require(value: bool, message: str) -> None:
    if not value:
        raise OwnershipError(message)


def docker(args: list[str]) -> str:
    try:
        result = subprocess.run(["docker", *args], capture_output=True, text=True,
                                encoding="utf-8", check=True, timeout=25)
    except (OSError, subprocess.SubprocessError) as exc:
        raise OwnershipError("Disposable Docker inspection failed") from exc
    require(len(result.stdout) <= 1024 * 1024,
            "Disposable Docker inspection is oversized")
    return result.stdout


def _inspect(kind: str, identifier: str, runner: Callable[[list[str]], str]) -> dict:
    try:
        result = json.loads(runner([kind, "inspect", identifier]))
    except ValueError as exc:
        raise OwnershipError("Disposable resource inspection is invalid") from exc
    require(isinstance(result, list) and len(result) == 1
            and isinstance(result[0], dict),
            "Disposable resource inspection is ambiguous")
    return result[0]


def _labels(actual: object, record: dict, project: str) -> None:
    require(isinstance(actual, dict)
            and actual.get("com.docker.compose.project") == project,
            "Disposable resource has no project ownership")
    for key, expected in OWNER_LABELS.items():
        value = expected if key.endswith(".owner") else record[expected]
        require(actual.get(key) == value,
                "Disposable resource has no release/runner ownership")


def _ids(value: object, name: str) -> dict[str, str]:
    require(isinstance(value, dict) and bool(value),
            f"Disposable {name} record is missing")
    require(all(isinstance(key, str) and isinstance(item, str)
                and IDENTIFIER.fullmatch(item) for key, item in value.items())
            and len(set(value.values())) == len(value),
            f"Disposable {name} identities are invalid")
    return value


def _runtime_environment(actual: object, service: str) -> dict[str, str]:
    require(isinstance(actual, list)
            and all(isinstance(entry, str) and "=" in entry
                    and bool(entry.partition("=")[0]) for entry in actual),
            f"{service} runtime identity is invalid")
    entries = [entry.partition("=") for entry in actual]
    environment = {key: value for key, _, value in entries}
    require(len(environment) == len(entries),
            f"{service} runtime identity has duplicate environment keys")
    return environment


def _organization_environment(actual: object, record: dict) -> None:
    environment = _runtime_environment(actual, "Organization")
    expected = {
        "SERVICE_NAME": "organization",
        "ORGANIZATION_SERVICE_PORT": "8002",
        "ORG_GRPC_PORT": "9002",
        "DATABASE_URL_TEMPLATE": (
            "postgresql+asyncpg://marty:${MARTY_DB_PASSWORD}@postgres:5432/marty"),
        "MARTY_DB_PASSWORD_FILE": "/run/secrets/marty_db_password",
        "GRPC_SERVICE_TOKEN_FILE": "/run/secrets/grpc_service_token",
        "ES_GRPC_TARGET": "event-stream:9015",
        "MARTY_ORG_ID": "00000000-0000-0000-0000-000000000001",
        "PASSPORT_ACCEPTANCE_PROJECT": record["project"],
        "PASSPORT_ACCEPTANCE_RUN_ID": record["run_id"],
        "PASSPORT_ACCEPTANCE_SOURCE_COMMIT": record["source_commit"],
        "PASSPORT_ACCEPTANCE_EXPIRES_AT": record["expires_at"],
    }
    require(all(environment.get(key) == value for key, value in expected.items())
            and "MARTY_DB_PASSWORD" not in environment
            and "GRPC_SERVICE_TOKEN" not in environment,
            "Organization runtime identity differs from protected run")


def _revocation_environment(actual: object, status_origin: str) -> None:
    environment = _runtime_environment(actual, "Revocation Profile")
    expected = {
        "SERVICE_NAME": "revocation_profile",
        "ENVIRONMENT": "development",
        "REVOCATION_PROFILE_SERVICE_PORT": "8013",
        "RP_GRPC_ENABLED": "true",
        "RP_GRPC_PORT": "9013",
        "DATABASE_URL_TEMPLATE": (
            "postgresql://marty:${MARTY_DB_PASSWORD}@postgres:5432/marty"),
        "MARTY_DB_PASSWORD_FILE": "/run/secrets/marty_db_password",
        "GRPC_SERVICE_TOKEN_FILE": "/run/secrets/grpc_service_token",
        "REDIS_URL": "redis://redis:6379/4",
        "ORG_GRPC_TARGET": "organization:9002",
        "PUBLIC_API_URL": "http://gateway:8000",
        "STATUS_LIST_BASE_URL": status_origin,
        "MARTY_ORG_ID": "00000000-0000-0000-0000-000000000001",
    }
    require(all(environment.get(key) == value for key, value in expected.items())
            and "RP_MIGRATE_ONLY" not in environment
            and "MARTY_DB_PASSWORD" not in environment
            and "GRPC_SERVICE_TOKEN" not in environment,
            "Revocation Profile runtime identity differs from disposable model")


def _support_environment(actual: object, service: str, status_origin: str,
                         surface: str) -> None:
    environment = _runtime_environment(actual, service)
    database = "postgresql+asyncpg://marty:${MARTY_DB_PASSWORD}@postgres:5432/marty"
    common = {
        "ENVIRONMENT": "development",
        "DATABASE_URL_TEMPLATE": database,
        "MARTY_DB_PASSWORD_FILE": "/run/secrets/marty_db_password",
        "GRPC_SERVICE_TOKEN_FILE": "/run/secrets/grpc_service_token",
        "ORG_GRPC_TARGET": "organization:9002",
    }
    public_origin = status_origin
    expected = {
        "trust-profile": {
            **common, "SERVICE_NAME": "trust_profile", "TRUST_PROFILE_SERVICE_PORT": "8004",
            "SIGNING_KEYS_INTERNAL_API_KEY_FILE":
                "/run/secrets/signing_keys_internal_api_key",
            "MARTY_ISSUER_DID":
                f"did:web:localhost%3A{status_origin.rsplit(':', 1)[1]}:orgs:marty",
            "MARTY_ISSUER_BASE_URL": public_origin,
            "MARTY_ORG_ID": "00000000-0000-0000-0000-000000000001",
            "MARTY_ORG_SLUG": "marty",
            "PUBLIC_DOMAIN": f"localhost:{status_origin.rsplit(':', 1)[1]}",
            "DID_RESOLUTION_BASE_URL": "http://gateway:8000",
        },
        "credential-template": {
            **common, "SERVICE_NAME": "credential_template",
            "CREDENTIAL_TEMPLATE_SERVICE_PORT": "8003", "CT_GRPC_PORT": "9003",
            "RP_GRPC_TARGET": "revocation-profile:9013",
            "SIGNING_KEYS_INTERNAL_URL": "http://signing-keys:8017/internal",
            "SIGNING_KEYS_INTERNAL_API_KEY_FILE":
                "/run/secrets/signing_keys_internal_api_key",
            "TRUST_PROFILE_SERVICE_URL": "http://trust-profile:8004",
            "PUBLIC_API_URL": public_origin,
            "MARTY_ORG_ID": "00000000-0000-0000-0000-000000000001",
            "MARTY_MIGRATION_PROFILE": "dev",
        },
        "presentation-policy": {
            **common, "SERVICE_NAME": "presentation_policy",
            "PRESENTATION_POLICY_SERVICE_PORT": "8009", "PP_GRPC_PORT": "9009",
            "ISSUANCE_API_KEY_FILE": "/run/secrets/issuance_api_key",
            "TRUST_PROFILE_SERVICE_URL": "http://trust-profile:8004",
            "ISSUANCE_NATIVE_SERVICE_URL": "http://issuance-native:8005",
            "PUBLIC_BASE_URL": public_origin,
            "ISSUER_BASE_URL": public_origin,
            "DID_RESOLUTION_BASE_URL": "http://gateway:8000",
            "PUBLIC_DOMAIN": f"localhost:{status_origin.rsplit(':', 1)[1]}",
            "MARTY_ORG_SLUG": "marty",
        },
        "deployment-profile": {
            **common, "SERVICE_NAME": "deployment_profile",
            "DEPLOYMENT_PROFILE_SERVICE_PORT": "8010",
        },
    }[service]
    if service == "presentation-policy" and surface == "selfhost":
        expected.update({
            "ENVIRONMENT": "production",
            "GRPC_WORKLOAD_TLS_SERVER_CERT": "/run/secrets/pp_workload_server_cert",
            "GRPC_WORKLOAD_TLS_SERVER_KEY": "/run/secrets/pp_workload_server_key",
            "GRPC_WORKLOAD_TLS_CA_CERT": "/run/secrets/workload_identity_ca_cert",
        })
    require(all(environment.get(key) == value for key, value in expected.items())
            and all(key not in environment for key in (
                "MARTY_DB_PASSWORD", "GRPC_SERVICE_TOKEN", "ISSUANCE_API_KEY",
                "SIGNING_KEYS_INTERNAL_API_KEY")),
            f"{service} runtime identity differs from disposable model")


def _issuer_origin_environment(actual: object, service: str,
                               status_origin: str) -> None:
    environment = _runtime_environment(actual, service)
    origin = status_origin
    key = "MARTY_ISSUER_BASE_URL" if service == "db-migrate" else "ISSUER_BASE_URL"
    require(environment.get(key) == origin,
            f"{service} issuer origin differs from disposable Gateway")


def _flow_surface_environment(actual: object, surface: str) -> None:
    environment = _runtime_environment(actual, "Flow")
    expected = {
        "FLOW_CALLBACK_DESTINATIONS": (
            "00000000-0000-0000-0000-000000000001|"
            "https://edge:8443/__disposable/flow-callback?nonce=__MARTY_TOKEN__"),
        "FLOW_WEBHOOK_SECRET_FILE": "/run/secrets/flow_webhook_secret",
        "FLOW_APPLICATION_EVENT_HMAC_KEY_FILE":
            "/run/secrets/flow_application_event_hmac_key",
        "FLOW_CALLBACK_CA_CERT_FILE": "/run/secrets/workload_identity_ca_cert",
        "GRPC_WORKLOAD_TLS_CLIENT_CERT": "/run/secrets/flow_workload_client_cert",
        "GRPC_WORKLOAD_TLS_CLIENT_KEY": "/run/secrets/flow_workload_client_key",
        "GRPC_WORKLOAD_TLS_SERVER_CERT": "/run/secrets/flow_workload_server_cert",
        "GRPC_WORKLOAD_TLS_SERVER_KEY": "/run/secrets/flow_workload_server_key",
        "GRPC_WORKLOAD_TLS_CA_CERT": "/run/secrets/workload_identity_ca_cert",
    }
    require((surface == "selfhost"
             and environment.get("ENVIRONMENT") == "production"
             and all(environment.get(key) == value for key, value in expected.items()))
            or (surface == "base"
                and environment.get("ENVIRONMENT") == "development"
                and not any(key in environment for key in expected)),
            "Disposable Flow callback or workload TLS runtime differs from surface")


def _ceremony_environment(actual: object, service: str, surface: str) -> None:
    environment = _runtime_environment(actual, service)
    credentials = {
        "SIGNING_KEYS_DSC_ISSUE_GATEWAY_KEY_FILE": "/run/secrets/dsc_issue_gateway_key",
        "SIGNING_KEYS_CSCA_ISSUE_GATEWAY_KEY_FILE": "/run/secrets/csca_issue_gateway_key",
    }
    require(all(key.removesuffix("_FILE") not in environment for key in credentials),
            "Disposable certificate operator key appears in runtime environment")
    if surface == "base":
        expected = {**credentials, "ENVIRONMENT": "beta"}
        if service == "gateway":
            expected["GRPC_INSECURE_ALLOWED"] = "true"
        else:
            expected["SIGNING_KEYS_BETA_CSCA_ISSUANCE_ENABLED"] = "true"
        require(all(environment.get(key) == value for key, value in expected.items()),
                "Disposable certificate ceremony runtime differs from protected model")
    else:
        require(all(key not in environment for key in credentials)
                and "SIGNING_KEYS_BETA_CSCA_ISSUANCE_ENABLED" not in environment
                and (service != "gateway" or environment.get("ENVIRONMENT") == "production"),
                "Selfhost runtime carries a beta certificate ceremony credential")


def _status_origin(edge: dict) -> str:
    host = edge.get("HostConfig")
    networks = edge.get("NetworkSettings")
    bindings = host.get("PortBindings") if isinstance(host, dict) else None
    published = networks.get("Ports") if isinstance(networks, dict) else None
    require(isinstance(bindings, dict) and set(bindings) == {"8443/tcp"}
            and isinstance(bindings["8443/tcp"], list)
            and len(bindings["8443/tcp"]) == 1
            and isinstance(bindings["8443/tcp"][0], dict)
            and isinstance(published, dict)
            and published.get("8443/tcp") == bindings["8443/tcp"]
            and all(value is None for key, value in published.items()
                    if key != "8443/tcp"),
            "Disposable HTTPS edge published port identity is invalid")
    binding = bindings["8443/tcp"][0]
    port = binding.get("HostPort")
    require(binding.get("HostIp") == "127.0.0.1"
            and isinstance(port, str) and port.isdigit()
            and 1024 <= int(port) <= 65535,
            "Disposable HTTPS edge published port leaves loopback")
    return f"https://localhost:{port}"


def _expected_mounts(service: str, project: str, disposable_root: Path,
                     surface: str, *, ceremony: bool = False,
                     ) -> set[tuple[str, str, str, bool]]:
    if service in {"passport-certificate-bootstrap", "passport-bureau-poll"}:
        return set()
    if service == "passport-openbao-bootstrap":
        source = Path(__file__).resolve().parents[1]
        return {
            ("bind", str(disposable_root / "secrets" / "bao_root_token"),
             "/run/secrets/bao_root_token", False),
            ("bind", str(disposable_root / "bootstrap-output"),
             "/work/secrets", True),
            ("bind", str(source / "scripts/passport_supported_openbao_bootstrap.sh"),
             "/scripts/passport_supported_openbao_bootstrap.sh", False),
            ("bind", str(source / "docker/openbao-init.sh"),
             "/scripts/openbao-init.sh", False),
        }
    expected = {
        ("bind", str(disposable_root / "secrets" / secret),
         f"/run/secrets/{secret}", False)
        for secret in (SECRET_MOUNTS[service]
                       + (BASE_CEREMONY_MOUNTS if (surface == "base" or ceremony)
                          and service in {"gateway", "signing-keys"} else ()))
    }
    if surface == "selfhost":
        extra = {
            "flow": ("flow_webhook_secret", "flow_application_event_hmac_key",
                     "flow_workload_client_cert", "flow_workload_client_key",
                     "flow_workload_server_cert", "flow_workload_server_key",
                     "workload_identity_ca_cert"),
            "presentation-policy": ("pp_workload_server_cert", "pp_workload_server_key",
                                    "workload_identity_ca_cert"),
        }.get(service, ())
        expected.update(("bind", str(disposable_root / "secrets" / name),
                         f"/run/secrets/{name}", False) for name in extra)
    if service == "openbao":
        expected.add(("bind", str(Path(__file__).resolve().parents[1]
                                   / "scripts/passport_supported_openbao_start.sh"),
                      "/usr/local/bin/passport-supported-openbao-start", False))
    if service == "edge":
        expected.add(("bind", str(Path(__file__).resolve().parents[1]
                                   / "scripts/passport_supported_edge.conf"),
                      "/etc/nginx/conf.d/default.conf", False))
    if service in DATA_MOUNTS:
        expected.update(("volume", f"{project}_{name}", destination, True)
                        for name, destination in DATA_MOUNTS[service])
    return expected


def _expected_image(record: dict, service: str) -> str | None:
    """Use the same plan-bound image role for live and partial ownership."""
    if service == "passport-openbao-bootstrap":
        return record.get("infra_images", {}).get("openbao")
    if service in {"passport-certificate-bootstrap", "passport-bureau-poll"}:
        return record.get("migrations_reference")
    return (record.get("legacy_reference") if service == "issuance" else
            record.get("migrations_reference") if service == "db-migrate" else
            record.get("services_reference")
            if service in SELECTED | RUST_DEPENDENCIES | {"signing-keys"} else
            record.get("infra_images", {}).get(service))


def verify(record: dict, surface: str, now: datetime,
           runner: Callable[[list[str]], str] = docker) -> dict:
    """Compare a short-lived run record against every live project resource."""
    require(isinstance(record, dict)
            and record.get("schema") == "marty.passport-supported-compose-ownership/v1",
            "Disposable provisioning record schema is invalid")
    project = record.get("project")
    match = PROJECT.fullmatch(project) if isinstance(project, str) else None
    require(match is not None and match.group(1) == surface,
            "Disposable project/surface mismatch")
    require(isinstance(record.get("run_id"), str)
            and RUN_ID.fullmatch(record["run_id"]) is not None,
            "Protected run ID is invalid")
    require(isinstance(record.get("source_commit"), str)
            and COMMIT.fullmatch(record["source_commit"]) is not None,
            "Protected source commit is invalid")
    require(isinstance(record.get("services_reference"), str)
            and IMAGE.fullmatch(record["services_reference"]) is not None,
            "Released services image is invalid")
    require(isinstance(record.get("migrations_reference"), str)
            and MIGRATIONS_IMAGE.fullmatch(record["migrations_reference"]) is not None
            and isinstance(record.get("legacy_reference"), str)
            and LEGACY_IMAGE.fullmatch(record["legacy_reference"]) is not None,
            "Released migration or legacy rollback image is invalid")
    infra_images = record.get("infra_images")
    require(isinstance(infra_images, dict) and set(infra_images) == set(ROLES)
            and all(isinstance(infra_images[role], str)
                    and infra_images[role].startswith(repository + "@")
                    and re.fullmatch(r"sha256:[0-9a-f]{64}",
                                     infra_images[role].removeprefix(repository + "@"))
                    for role, repository in ROLES.items()),
            "Disposable infrastructure image references are invalid")
    try:
        created = datetime.fromisoformat(record["created_at"])
        expires = datetime.fromisoformat(record["expires_at"])
    except (KeyError, TypeError, ValueError) as exc:
        raise OwnershipError("Disposable lease is invalid") from exc
    require(now.tzinfo is not None and created.tzinfo is not None
            and expires.tzinfo is not None
            and created <= now < expires <= created + timedelta(hours=4),
            "Disposable lease is expired or too broad")
    containers = _ids(record.get("containers"), "container")
    networks = _ids(record.get("networks"), "network")
    volumes = record.get("volumes")
    require(isinstance(volumes, list)
            and all(isinstance(item, str) and item.startswith(project + "_")
                    for item in volumes)
            and len(volumes) == len(set(volumes)),
            "Disposable volume identities are invalid")
    require(set(containers) == DISPOSABLE_SERVICES
            and all(re.fullmatch(r"[a-z][a-z0-9-]+", name) for name in containers),
            "Disposable service ownership is incomplete")
    require(all(name.startswith(project + "_") for name in networks),
            "Disposable network identity escapes the project")
    disposable_root = Path(record.get("disposable_root", ""))
    require(disposable_root.is_absolute()
            and disposable_root == Path(tempfile.gettempdir()) / project
            and disposable_root.resolve() == disposable_root
            and (disposable_root / "secrets").resolve() == disposable_root / "secrets",
            "Disposable root is not the isolated project directory")
    require(set(SECRET_MOUNTS) == DISPOSABLE_SERVICES,
            "Disposable secret mount contract is incomplete")

    edge = _inspect("container", containers["edge"], runner)
    status_origin = _status_origin(edge)
    gateway = _inspect("container", containers["gateway"], runner)
    gateway_host = gateway.get("HostConfig")
    gateway_networks = gateway.get("NetworkSettings")
    require(isinstance(gateway_host, dict) and isinstance(gateway_networks, dict)
            and not gateway_host.get("PortBindings")
            and isinstance(gateway_networks.get("Ports"), dict)
            and not any(value for value in gateway_networks["Ports"].values()),
            "Disposable Gateway bypasses HTTPS edge")

    listed = set(runner(["ps", "-aq", "--no-trunc", "--filter",
                         f"label=com.docker.compose.project={project}"]).split())
    require(listed == set(containers.values()),
            "Live project container set differs from provisioning record")
    live_networks = set(runner(["network", "ls", "-q", "--no-trunc", "--filter",
                                f"label=com.docker.compose.project={project}"]).split())
    require(live_networks == set(networks.values()),
            "Live project network set differs from provisioning record")
    live_volumes = set(runner(["volume", "ls", "-q", "--filter",
                               f"label=com.docker.compose.project={project}"]).split())
    require(live_volumes == set(volumes),
            "Live project volume set differs from provisioning record")

    expected_network_members: dict[str, set[str]] = {name: set() for name in networks}
    completed_init_ids: set[str] = set()
    for service, identifier in containers.items():
        item = _inspect("container", identifier, runner)
        config = item.get("Config")
        require(item.get("Id") == identifier and isinstance(config, dict),
                "Disposable container identity changed")
        state = item.get("State")
        require(isinstance(state, dict), "Disposable container state is missing")
        running = (state.get("Running") is True
                   and state.get("Status") == "running"
                   and (not isinstance(state.get("Health"), dict)
                        or state["Health"].get("Status") == "healthy"))
        completed_init = (service in COMPLETED_INIT
                          and state.get("Running") is False
                          and state.get("Status") == "exited"
                          and state.get("ExitCode") == 0)
        require(running or completed_init,
                "Disposable container is stopped or unhealthy")
        if completed_init:
            completed_init_ids.add(identifier)
        labels = config.get("Labels")
        _labels(labels, record, project)
        require(labels.get("com.docker.compose.service") == service,
                "Disposable container service identity changed")
        if service == "organization":
            _organization_environment(config.get("Env"), record)
        elif service in {"gateway", "signing-keys"}:
            _ceremony_environment(config.get("Env"), service, surface)
            environment = _runtime_environment(config.get("Env"), service)
            require(environment.get("PUBLIC_DOMAIN")
                    == f"localhost:{status_origin.rsplit(':', 1)[1]}",
                    "Disposable runtime public domain differs from managed issuer DID")
            if service == "gateway":
                _issuer_origin_environment(config.get("Env"), service, status_origin)
        elif service == "issuance-native":
            _issuer_origin_environment(config.get("Env"), service, status_origin)
        elif service == "flow":
            _flow_surface_environment(config.get("Env"), surface)
        elif service == "revocation-profile":
            _revocation_environment(config.get("Env"), status_origin)
        elif service in {"credential-template", "trust-profile",
                         "presentation-policy", "deployment-profile"}:
            _support_environment(config.get("Env"), service, status_origin, surface)
        elif service == "revocation-profile-migrate":
            migration_env = _runtime_environment(config.get("Env"), "Revocation migration")
            require(migration_env.get("STATUS_LIST_BASE_URL") == status_origin,
                    "Revocation migration status origin differs from Gateway")
        elif service == "db-migrate":
            _issuer_origin_environment(config.get("Env"), service, status_origin)
            environment = _runtime_environment(config.get("Env"), service)
            require(environment.get("PUBLIC_DOMAIN")
                    == f"localhost:{status_origin.rsplit(':', 1)[1]}"
                    and environment.get("MARTY_ISSUER_DID")
                    == f"did:web:localhost%3A{status_origin.rsplit(':', 1)[1]}:orgs:marty",
                    "Disposable issuer bootstrap DID differs from public domain")
        require(re.fullmatch(r"/" + re.escape(project) + "-"
                             + re.escape(service) + r"-[1-9][0-9]*",
                             item.get("Name", "")) is not None
                and labels.get("com.docker.compose.oneoff") != "True",
                "Disposable container is not a named Compose service")
        network_settings = item.get("NetworkSettings")
        require(isinstance(network_settings, dict),
                "Disposable container network state is missing")
        attached = network_settings.get("Networks")
        require(isinstance(attached, dict) and (bool(attached) or completed_init)
                and set(attached) <= set(networks),
                "Disposable container joins an unowned network")
        for name, endpoint in attached.items():
            require(isinstance(endpoint, dict)
                    and (endpoint.get("NetworkID") == networks[name]
                         or completed_init and not endpoint.get("NetworkID")),
                    "Disposable container network identity changed")
            if running:
                expected_network_members[name].add(identifier)
        expected_image = _expected_image(record, service)
        require(expected_image is not None and config.get("Image") == expected_image,
                "Passport container image differs from signed release")
        mounts = item.get("Mounts", [])
        require(isinstance(mounts, list), "Disposable container mounts are invalid")
        expected_mounts = _expected_mounts(service, project, disposable_root, surface)
        observed_mounts: set[tuple[str, str, str, bool]] = set()
        for mount in mounts:
            require(isinstance(mount, dict)
                    and mount.get("Type") in {"bind", "volume"}
                    and isinstance(mount.get("Destination"), str)
                    and isinstance(mount.get("RW"), bool),
                    "Disposable container uses an unowned mount")
            kind = mount["Type"]
            source = mount.get("Source") if kind == "bind" else mount.get("Name")
            require(isinstance(source, str), "Disposable container uses an unowned mount")
            require(kind != "bind" or Path(source).resolve() == Path(source),
                    "Disposable container uses an unowned mount")
            identity = (kind, str(Path(source)) if kind == "bind" else source,
                        mount["Destination"], mount["RW"])
            require(identity in expected_mounts and identity not in observed_mounts
                    and (kind != "volume" or source in volumes),
                    "Disposable container uses an unowned mount")
            observed_mounts.add(identity)
        require(observed_mounts == expected_mounts,
                "Disposable container mount set is incomplete")
    for name, identifier in networks.items():
        item = _inspect("network", identifier, runner)
        require(item.get("Id") == identifier and item.get("Name") == name
                and item.get("Driver") == "bridge"
                and item.get("Internal") is True,
                "Disposable network identity or isolation changed")
        _labels(item.get("Labels"), record, project)
        members = item.get("Containers", {})
        require(isinstance(members, dict)
                and expected_network_members[name] <= set(members)
                and set(members) <= expected_network_members[name] | completed_init_ids,
                "Disposable network has an unowned member")
    for name in volumes:
        item = _inspect("volume", name, runner)
        require(item.get("Name") == name and item.get("Driver") == "local"
                and not item.get("Options"),
                "Disposable volume identity or options changed")
        _labels(item.get("Labels"), record, project)

    return {"schema": "marty.passport-supported-compose-ownership-proof/v1",
            "status": "blocked", "project": project,
            "live_ownership_verified": True, "rollback_accepted": False,
            "blocker": "protected provisioning provenance and live rollback transition are absent"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record", type=Path, required=True)
    parser.add_argument("--surface", choices=("base", "selfhost"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        record = json.loads(args.record.read_text(encoding="utf-8"))
        report = verify(record, args.surface, datetime.now(timezone.utc))
    except (OSError, ValueError, OwnershipError) as exc:
        report = {"schema": "marty.passport-supported-compose-ownership-proof/v1",
                  "status": "blocked", "blocker": str(exc)}
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    parser.exit(1, "Supported Compose ownership remains blocked\n")


if __name__ == "__main__":
    raise SystemExit(main())
