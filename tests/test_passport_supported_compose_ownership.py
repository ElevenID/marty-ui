"""Rust acceptance must never trust an unowned disposable Compose project."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile

import pytest

from scripts import check_passport_supported_compose_ownership as ownership_module
from scripts.check_passport_supported_compose_ownership import (
    OwnershipError, verify,
)
from scripts.check_passport_supported_rust_model import (
    DISPOSABLE_SERVICES, RUST_DEPENDENCIES, SELECTED,
)


PROJECT = "marty-passport-acceptance-base-abcdef"
IMAGE = "ghcr.io/elevenid/marty-ui-oss/services@sha256:" + "a" * 64
MIGRATIONS = "ghcr.io/elevenid/marty-ui-oss/migrations@sha256:" + "b" * 64
INFRA = {
    "edge": "docker.io/library/nginx@sha256:" + "4" * 64,
    "postgres": "docker.io/library/postgres@sha256:" + "1" * 64,
    "redis": "docker.io/library/redis@sha256:" + "2" * 64,
    "openbao": "quay.io/openbao/openbao@sha256:" + "3" * 64,
}
NOW = datetime(2026, 9, 27, 12, tzinfo=timezone.utc)
LABELS = {
    "com.docker.compose.project": PROJECT,
    "com.marty.passport.acceptance.owner": "supported-consumer",
    "com.marty.passport.acceptance.run-id": "123456",
    "com.marty.passport.acceptance.source-commit": "b" * 40,
    "com.marty.passport.acceptance.services-image": IMAGE,
}
ROOT = Path(tempfile.gettempdir()) / PROJECT
SECRETS = {
    "edge": ("passport_edge_tls_cert", "passport_edge_tls_key"),
    "postgres": ("marty_db_password",),
    "redis": (),
    "openbao": ("bao_root_token",),
    "db-migrate": ("marty_db_password", "bao_token"),
    "issuance-migrations": ("marty_db_password",),
    "signing-keys": ("marty_db_password", "bao_token", "signing_keys_internal_api_key",
                     "signing_keys_service_sign_gateway_key", "signing_keys_issuer_sign_key",
                     "dsc_issue_gateway_key", "csca_issue_gateway_key",
                     "signing_keys_workload_server_cert", "signing_keys_workload_server_key",
                     "workload_identity_ca_cert"),
    "revocation-profile-migrate": ("marty_db_password",),
    "revocation-profile": ("marty_db_password", "grpc_service_token"),
    "event-stream": (),
    "organization": ("marty_db_password", "grpc_service_token"),
    "credential-template": ("marty_db_password", "grpc_service_token",
                            "signing_keys_internal_api_key"),
    "compliance-profile": ("marty_db_password", "grpc_service_token"),
    "trust-profile": ("marty_db_password", "grpc_service_token",
                      "signing_keys_internal_api_key"),
    "presentation-policy": ("marty_db_password", "grpc_service_token",
                            "issuance_api_key"),
    "deployment-profile": ("marty_db_password", "grpc_service_token"),
    "issuance-native": ("marty_db_password", "bao_token", "signing_keys_internal_api_key",
                        "signing_keys_issuer_sign_key",
                        "issuance_api_key", "grpc_service_token", "token_hmac_key",
                        "passport_beta_reconciliation_operator_token",
                        "workload_identity_ca_cert"),
    "flow": ("marty_db_password", "signing_keys_internal_api_key", "signing_keys_issuer_sign_key", "issuance_api_key",
             "grpc_service_token", "flow_application_event_hmac_key"),
    "passport-callback-signer": ("callback_signer_bao_token", "callback_signer_api_key"),
    "passport-beta-bureau": ("bureau_database_url", "grpc_service_token",
                             "callback_signer_api_key"),
    "gateway": ("bao_token", "signing_keys_internal_api_key", "signing_keys_service_sign_gateway_key", "signing_keys_issuer_sign_key", "issuance_api_key",
                "grpc_service_token", "device_registration_gateway_key",
                "dsc_issue_gateway_key", "csca_issue_gateway_key"),
}
DATA = {
    "postgres": ("postgres_data", "/var/lib/postgresql/data"),
    "redis": ("redis_data", "/data"),
    "openbao": ("openbao_data", "/bao/data"),
    "openbao-file": ("openbao_file", "/openbao/file"),
    "openbao-logs": ("openbao_logs", "/openbao/logs"),
}


def mounts_for(service: str) -> list[dict]:
    mounts = [{"Type": "bind", "Source": str(ROOT / "secrets" / name),
               "Destination": f"/run/secrets/{name}", "RW": False}
              for name in SECRETS[service]]
    if service == "openbao":
        mounts.append({
            "Type": "bind",
            "Source": str(Path(__file__).resolve().parents[1]
                          / "scripts/passport_supported_openbao_start.sh"),
            "Destination": "/usr/local/bin/passport-supported-openbao-start",
            "RW": False,
        })
    if service == "edge":
        mounts.append({
            "Type": "bind",
            "Source": str(Path(__file__).resolve().parents[1]
                          / "scripts/passport_supported_edge.conf"),
            "Destination": "/etc/nginx/conf.d/default.conf",
            "RW": False,
        })
    for key in ((service,) if service != "openbao" else
                ("openbao", "openbao-file", "openbao-logs")):
        if key in DATA:
            name, destination = DATA[key]
            mounts.append({"Type": "volume", "Name": f"{PROJECT}_{name}",
                           "Destination": destination, "RW": True})
    return mounts


def fixture() -> tuple[dict, dict[tuple[str, ...], str]]:
    containers = {name: format(i + 1, "064x") for i, name in
                  enumerate(sorted(DISPOSABLE_SERVICES))}
    network_name = PROJECT + "_private"
    network_id = "e" * 64
    callback_network_name = PROJECT + "_callback_signing"
    callback_network_id = "f" * 64
    ingress_network_name = PROJECT + "_ingress"
    ingress_network_id = "a" * 64
    volume_names = [f"{PROJECT}_{name}" for name, _ in DATA.values()]
    record = {
        "schema": "marty.passport-supported-compose-ownership/v1",
        "project": PROJECT, "run_id": "123456", "source_commit": "b" * 40,
        "services_reference": IMAGE,
        "migrations_reference": MIGRATIONS,
        "infra_images": INFRA,
        "created_at": (NOW - timedelta(minutes=5)).isoformat(),
        "expires_at": (NOW + timedelta(minutes=55)).isoformat(),
        "disposable_root": str(ROOT),
        "containers": containers, "networks": {
            network_name: network_id, callback_network_name: callback_network_id,
            ingress_network_name: ingress_network_id},
        "volumes": volume_names,
    }
    calls: dict[tuple[str, ...], str] = {
        ("ps", "-aq", "--no-trunc", "--filter", f"label=com.docker.compose.project={PROJECT}"):
            "\n".join(containers.values()),
        ("network", "ls", "-q", "--no-trunc", "--filter",
         f"label=com.docker.compose.project={PROJECT}"):
            "\n".join((network_id, callback_network_id, ingress_network_id)),
        ("volume", "ls", "-q", "--filter",
         f"label=com.docker.compose.project={PROJECT}"): "\n".join(volume_names),
    }
    for service, identifier in containers.items():
        organization_env = {
            "SERVICE_NAME": "organization",
            "ORGANIZATION_SERVICE_PORT": "8002",
            "ORG_GRPC_PORT": "9002",
            "DATABASE_URL_TEMPLATE": (
                "postgresql+asyncpg://marty:${MARTY_DB_PASSWORD}@postgres:5432/marty"),
            "MARTY_DB_PASSWORD_FILE": "/run/secrets/marty_db_password",
            "GRPC_SERVICE_TOKEN_FILE": "/run/secrets/grpc_service_token",
            "ES_GRPC_TARGET": "event-stream:9015",
            "MARTY_ORG_ID": "00000000-0000-0000-0000-000000000001",
            "PASSPORT_ACCEPTANCE_PROJECT": PROJECT,
            "PASSPORT_ACCEPTANCE_RUN_ID": record["run_id"],
            "PASSPORT_ACCEPTANCE_SOURCE_COMMIT": record["source_commit"],
            "PASSPORT_ACCEPTANCE_EXPIRES_AT": record["expires_at"],
        }
        revocation_env = {
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
            "STATUS_LIST_BASE_URL": "https://localhost:29876",
            "MARTY_ORG_ID": "00000000-0000-0000-0000-000000000001",
        }
        migration_env = {"STATUS_LIST_BASE_URL": "https://localhost:29876"}
        ceremony_env = {
            "ENVIRONMENT": "beta",
            "SIGNING_KEYS_DSC_ISSUE_GATEWAY_KEY_FILE":
                "/run/secrets/dsc_issue_gateway_key",
            "SIGNING_KEYS_CSCA_ISSUE_GATEWAY_KEY_FILE":
                "/run/secrets/csca_issue_gateway_key",
        }
        gateway_env = {**ceremony_env, "GRPC_INSECURE_ALLOWED": "true",
                       "DEVICE_REGISTRATION_GATEWAY_KEY_FILE":
                           "/run/secrets/device_registration_gateway_key",
                       "PUBLIC_DOMAIN": "localhost:29876",
                       "ISSUER_BASE_URL": "https://localhost:29876"}
        native_env = {"ISSUER_BASE_URL": "https://localhost:29876",
                      "ENVIRONMENT": "beta",
                      "INTEGRATION_SECRET_KMS_URL": "https://signing-keys:8018/internal",
                      "INTEGRATION_SECRET_KMS_CA_FILE":
                          "/run/secrets/workload_identity_ca_cert",
                      "PASSPORT_BETA_RECONCILIATION_ENABLED": "true",
                      "PASSPORT_BETA_RECONCILIATION_OPERATOR_TOKEN_FILE":
                          "/run/secrets/passport_beta_reconciliation_operator_token"}
        signing_env = {**ceremony_env,
                       "SIGNING_KEYS_BETA_CSCA_ISSUANCE_ENABLED": "true",
                       "SIGNING_KEYS_INTEGRATION_SECRET_TLS_CERT_FILE":
                           "/run/secrets/signing_keys_workload_server_cert",
                       "SIGNING_KEYS_INTEGRATION_SECRET_TLS_KEY_FILE":
                           "/run/secrets/signing_keys_workload_server_key"}
        support_common = {
            "ENVIRONMENT": "development",
            "DATABASE_URL_TEMPLATE": (
                "postgresql+asyncpg://marty:${MARTY_DB_PASSWORD}@postgres:5432/marty"),
            "MARTY_DB_PASSWORD_FILE": "/run/secrets/marty_db_password",
            "GRPC_SERVICE_TOKEN_FILE": "/run/secrets/grpc_service_token",
            "ORG_GRPC_TARGET": "organization:9002",
        }
        support_env = {
            "compliance-profile": {
                **support_common, "SERVICE_NAME": "compliance_profile",
                "COMPLIANCE_PROFILE_SERVICE_PORT": "8008",
            },
            "trust-profile": {
                **support_common, "SERVICE_NAME": "trust_profile",
                "TRUST_PROFILE_SERVICE_PORT": "8004",
                "SIGNING_KEYS_INTERNAL_API_KEY_FILE":
                    "/run/secrets/signing_keys_internal_api_key",
                "MARTY_ISSUER_DID": "did:web:localhost%3A29876:orgs:marty",
                "MARTY_ISSUER_BASE_URL": "https://localhost:29876",
                "MARTY_ORG_ID": "00000000-0000-0000-0000-000000000001",
                "MARTY_ORG_SLUG": "marty", "PUBLIC_DOMAIN": "localhost:29876",
                "DID_RESOLUTION_BASE_URL": "http://gateway:8000",
            },
            "credential-template": {
                **support_common, "SERVICE_NAME": "credential_template",
                "CREDENTIAL_TEMPLATE_SERVICE_PORT": "8003", "CT_GRPC_PORT": "9003",
                "RP_GRPC_TARGET": "revocation-profile:9013",
                "SIGNING_KEYS_INTERNAL_URL": "http://gateway:8000/internal/signing-keys",
                "SIGNING_KEYS_INTERNAL_API_KEY_FILE":
                    "/run/secrets/signing_keys_internal_api_key",
                "TRUST_PROFILE_SERVICE_URL": "http://trust-profile:8004",
                "PUBLIC_API_URL": "https://localhost:29876",
                "MARTY_ORG_ID": "00000000-0000-0000-0000-000000000001",
                "MARTY_MIGRATION_PROFILE": "dev",
            },
            "presentation-policy": {
                **support_common, "SERVICE_NAME": "presentation_policy",
                "PRESENTATION_POLICY_SERVICE_PORT": "8009", "PP_GRPC_PORT": "9009",
                "ISSUANCE_API_KEY_FILE": "/run/secrets/issuance_api_key",
                "TRUST_PROFILE_SERVICE_URL": "http://trust-profile:8004",
                "ISSUANCE_NATIVE_SERVICE_URL": "http://issuance-native:8005",
                "PUBLIC_BASE_URL": "https://localhost:29876",
                "ISSUER_BASE_URL": "https://localhost:29876",
                "DID_RESOLUTION_BASE_URL": "http://gateway:8000",
                "PUBLIC_DOMAIN": "localhost:29876", "MARTY_ORG_SLUG": "marty",
            },
            "deployment-profile": {
                **support_common, "SERVICE_NAME": "deployment_profile",
                "DEPLOYMENT_PROFILE_SERVICE_PORT": "8010",
            },
        }
        runtime_env = (organization_env if service == "organization" else
                       {"MARTY_ISSUER_BASE_URL": "https://localhost:29876",
                        "MARTY_ISSUER_DID": "did:web:localhost%3A29876:orgs:marty",
                        "PUBLIC_DOMAIN": "localhost:29876"}
                       if service == "db-migrate" else
                       {"SERVICE_NAME": "issuance_native",
                        "DATABASE_URL_TEMPLATE": (
                            "postgresql://marty:${MARTY_DB_PASSWORD}@postgres:5432/marty"),
                        "MARTY_DB_PASSWORD_FILE": "/run/secrets/marty_db_password"}
                       if service == "issuance-migrations" else
                       revocation_env if service == "revocation-profile" else
                       migration_env if service == "revocation-profile-migrate" else
                       gateway_env if service == "gateway" else
                       {"ENVIRONMENT": "development",
                        "FLOW_APPLICATION_EVENT_HMAC_KEY_FILE":
                            "/run/secrets/flow_application_event_hmac_key"}
                       if service == "flow" else
                       native_env if service == "issuance-native" else
                       {**signing_env, "PUBLIC_DOMAIN": "localhost:29876"}
                       if service == "signing-keys" else
                       support_env.get(service, {}))
        edge_binding = [{"HostIp": "127.0.0.1", "HostPort": "29876"}]
        primary_network = (callback_network_name if service == "passport-callback-signer"
                           else ingress_network_name if service == "edge" else network_name)
        attached_networks = {primary_network: {"NetworkID": (
            callback_network_id if primary_network == callback_network_name else
            ingress_network_id if primary_network == ingress_network_name else network_id)}}
        if service in {"openbao", "passport-beta-bureau"}:
            attached_networks[callback_network_name] = {"NetworkID": callback_network_id}
        if service == "edge":
            attached_networks[network_name] = {"NetworkID": network_id}
        calls[("container", "inspect", identifier)] = json.dumps([{
            "Id": identifier, "Name": f"/{PROJECT}-{service}-1",
            "HostConfig": {"NetworkMode": primary_network,
                           **({"PortBindings": {"8443/tcp": edge_binding}}
                              if service == "edge" else {})},
            "State": ({"Running": False, "Status": "exited", "ExitCode": 0}
                      if service == "issuance-migrations" else
                      {"Running": True, "Status": "running",
                       "Health": {"Status": "healthy"}}),
            "Config": {"Labels": {**LABELS, "com.docker.compose.service": service},
                       "Env": [f"{key}={value}" for key, value in runtime_env.items()],
                       **({"Entrypoint": ["/bin/sh", "-c"],
                            "Cmd": [". /app/load-secrets-env.sh\n"
                                    "exec /usr/local/bin/marty-issuance-service migrate\n"]}
                          if service == "issuance-migrations" else {}),
                       "Image": (MIGRATIONS if service == "db-migrate" else
                                 IMAGE if service == "issuance-migrations" else
                                 IMAGE if service in SELECTED | RUST_DEPENDENCIES | {"signing-keys"} else
                                 INFRA[service])},
            "NetworkSettings": {"Networks": attached_networks,
                                "Ports": {"8443/tcp": edge_binding}
                                if service == "edge" else {}},
            "Mounts": mounts_for(service),
        }])
    calls[("network", "inspect", network_id)] = json.dumps([{
        "Id": network_id, "Name": network_name, "Driver": "bridge",
        "Internal": True, "Labels": LABELS,
        "Containers": {identifier: {} for service, identifier in containers.items()
                       if service != "passport-callback-signer"},
    }])
    calls[("network", "inspect", callback_network_id)] = json.dumps([{
        "Id": callback_network_id, "Name": callback_network_name,
        "Driver": "bridge", "Internal": True, "Labels": LABELS,
        "Containers": {identifier: {} for service, identifier in containers.items()
                       if service in {"passport-callback-signer", "openbao",
                                      "passport-beta-bureau"}},
    }])
    calls[("network", "inspect", ingress_network_id)] = json.dumps([{
        "Id": ingress_network_id, "Name": ingress_network_name,
        "Driver": "bridge", "Internal": False, "Labels": LABELS,
        "Containers": {containers["edge"]: {}},
    }])
    for volume_name in volume_names:
        calls[("volume", "inspect", volume_name)] = json.dumps([{
            "Name": volume_name, "Driver": "local", "Options": None,
            "Labels": LABELS,
        }])
    return record, calls


def test_rust_schema_container_is_exact_signed_one_shot() -> None:
    record, calls = fixture()
    assert verify(record, "base", NOW, lambda args: calls[tuple(args)])["live_ownership_verified"]
    key = ("container", "inspect", record["containers"]["issuance-migrations"])
    item = json.loads(calls[key])
    item[0]["Config"]["Cmd"][-1] = "true"
    calls[key] = json.dumps(item)
    with pytest.raises(OwnershipError, match="Rust schema command"):
        verify(record, "base", NOW, lambda args: calls[tuple(args)])
    record, calls = fixture()
    item = json.loads(calls[key])
    item[0]["Config"]["Image"] = "ghcr.io/other/services@sha256:" + "f" * 64
    calls[key] = json.dumps(item)
    with pytest.raises(OwnershipError, match="signed release"):
        verify(record, "base", NOW, lambda args: calls[tuple(args)])
    record, calls = fixture()
    item = json.loads(calls[key])
    item[0]["Mounts"][-1]["Source"] = str(ROOT / "unreviewed-script.sh")
    calls[key] = json.dumps(item)
    with pytest.raises(OwnershipError, match="unowned mount"):
        verify(record, "base", NOW, lambda args: calls[tuple(args)])


@pytest.mark.parametrize("key,value", [
    ("SERVICE_NAME", "issuance"),
    ("DATABASE_URL_TEMPLATE", "postgresql://marty:secret@production:5432/marty"),
    ("MARTY_DB_PASSWORD_FILE", "/run/secrets/other"),
    ("DATABASE_URL", "postgresql://marty:secret@production:5432/marty"),
])
def test_live_rust_schema_database_binding_is_disposable(key: str, value: str) -> None:
    record, calls = fixture()
    inspect_key = ("container", "inspect", record["containers"]["issuance-migrations"])
    item = json.loads(calls[inspect_key])
    item[0]["Config"]["Env"] = [entry for entry in item[0]["Config"]["Env"]
                                if not entry.startswith(key + "=")]
    item[0]["Config"]["Env"].append(f"{key}={value}")
    calls[inspect_key] = json.dumps(item)
    with pytest.raises(OwnershipError, match="Rust schema command"):
        run(record, calls)


@pytest.mark.parametrize("service,key,value", [
    ("compliance-profile", "COMPLIANCE_PROFILE_SERVICE_PORT", "8009"),
    ("credential-template", "PUBLIC_API_URL", "http://localhost:8000"),
    ("credential-template", "MARTY_MIGRATION_PROFILE", "other"),
    ("trust-profile", "MARTY_ISSUER_BASE_URL", "http://production.example"),
    ("trust-profile", "MARTY_ORG_ID", "00000000-0000-0000-0000-000000000002"),
    ("presentation-policy", "ISSUANCE_NATIVE_SERVICE_URL", "http://issuance:8005"),
    ("presentation-policy", "DID_RESOLUTION_BASE_URL", "http://production.example"),
    ("deployment-profile", "ORG_GRPC_TARGET", "gateway:9002"),
])
def test_live_rust_support_binding_matches_disposable_project(
    service: str, key: str, value: str,
) -> None:
    record, calls = fixture()
    identifier = record["containers"][service]
    inspect_key = ("container", "inspect", identifier)
    item = json.loads(calls[inspect_key])
    item[0]["Config"]["Env"] = [entry for entry in item[0]["Config"]["Env"]
                               if not entry.startswith(key + "=")]
    item[0]["Config"]["Env"].append(f"{key}={value}")
    calls[inspect_key] = json.dumps(item)
    with pytest.raises(OwnershipError, match="runtime identity"):
        run(record, calls)


@pytest.mark.parametrize("service,key,value", [
    ("gateway", "SIGNING_KEYS_CSCA_ISSUE_GATEWAY_KEY_FILE", "/run/secrets/other"),
    ("gateway", "ENVIRONMENT", "production"),
    ("signing-keys", "SIGNING_KEYS_BETA_CSCA_ISSUANCE_ENABLED", "false"),
    ("signing-keys", "SIGNING_KEYS_DSC_ISSUE_GATEWAY_KEY_FILE", "/run/secrets/other"),
])
def test_live_ceremony_secret_binding_is_exact(
    service: str, key: str, value: str,
) -> None:
    record, calls = fixture()
    identifier = record["containers"][service]
    inspect_key = ("container", "inspect", identifier)
    item = json.loads(calls[inspect_key])
    item[0]["Config"]["Env"] = [entry for entry in item[0]["Config"]["Env"]
                               if not entry.startswith(key + "=")]
    item[0]["Config"]["Env"].append(f"{key}={value}")
    calls[inspect_key] = json.dumps(item)
    with pytest.raises(OwnershipError, match="certificate ceremony runtime"):
        run(record, calls)


@pytest.mark.parametrize("service,key,reason", [
    ("signing-keys", "SIGNING_KEYS_INTEGRATION_SECRET_TLS_CERT_FILE",
     "remote-secret TLS listener"),
    ("issuance-native", "INTEGRATION_SECRET_KMS_URL",
     "remote-secret KMS binding"),
])
def test_live_remote_secret_custody_binding_is_exact(
    service: str, key: str, reason: str,
) -> None:
    record, calls = fixture()
    identifier = record["containers"][service]
    inspect_key = ("container", "inspect", identifier)
    item = json.loads(calls[inspect_key])
    item[0]["Config"]["Env"] = [entry for entry in item[0]["Config"]["Env"]
                               if not entry.startswith(key + "=")]
    calls[inspect_key] = json.dumps(item)
    with pytest.raises(OwnershipError, match=reason):
        run(record, calls)


@pytest.mark.parametrize("mutation", [
    lambda env: env.remove(next(item for item in env if item.startswith("PASSPORT_ACCEPTANCE_PROJECT="))),
    lambda env: env.append("PASSPORT_ACCEPTANCE_PROJECT=another-project"),
    lambda env: env.__setitem__(next(i for i, item in enumerate(env)
                                  if item.startswith("PASSPORT_ACCEPTANCE_RUN_ID=")),
                                "PASSPORT_ACCEPTANCE_RUN_ID=999999"),
    lambda env: env.__setitem__(next(i for i, item in enumerate(env)
                                  if item.startswith("PASSPORT_ACCEPTANCE_SOURCE_COMMIT=")),
                                "PASSPORT_ACCEPTANCE_SOURCE_COMMIT=" + "c" * 40),
    lambda env: env.__setitem__(next(i for i, item in enumerate(env)
                                  if item.startswith("PASSPORT_ACCEPTANCE_EXPIRES_AT=")),
                                "PASSPORT_ACCEPTANCE_EXPIRES_AT=2026-09-28T13:00:00+00:00"),
    lambda env: env.__setitem__(next(i for i, item in enumerate(env)
                                  if item.startswith("GRPC_SERVICE_TOKEN_FILE=")),
                                "GRPC_SERVICE_TOKEN_FILE=/srv/production/token"),
    lambda env: env.append("MARTY_DB_PASSWORD=secret"),
    lambda env: env.append("GRPC_SERVICE_TOKEN=secret"),
    lambda env: env.remove(next(item for item in env if item.startswith("DATABASE_URL_TEMPLATE="))),
    lambda env: env.__setitem__(next(i for i, item in enumerate(env)
                                  if item.startswith("DATABASE_URL_TEMPLATE=")),
                                "DATABASE_URL_TEMPLATE=postgresql+asyncpg://marty:secret@production:5432/marty"),
])
def test_organization_runtime_environment_must_match_protected_run(mutation) -> None:
    record, calls = fixture()
    key = ("container", "inspect", record["containers"]["organization"])
    item = json.loads(calls[key])
    mutation(item[0]["Config"]["Env"])
    calls[key] = json.dumps(item)
    with pytest.raises(OwnershipError, match="Organization runtime identity"):
        run(record, calls)


@pytest.mark.parametrize("mutation", [
    lambda env: env.remove(next(item for item in env if item.startswith("DATABASE_URL_TEMPLATE="))),
    lambda env: env.__setitem__(next(i for i, item in enumerate(env)
                                  if item.startswith("DATABASE_URL_TEMPLATE=")),
                                "DATABASE_URL_TEMPLATE=postgresql://marty:secret@production:5432/marty"),
    lambda env: env.append("RP_MIGRATE_ONLY=true"),
    lambda env: env.append("GRPC_SERVICE_TOKEN=raw-secret"),
    lambda env: env.append("ORG_GRPC_TARGET=gateway:9002"),
    lambda env: env.__setitem__(next(i for i, item in enumerate(env)
                                  if item.startswith("STATUS_LIST_BASE_URL=")),
                                "STATUS_LIST_BASE_URL=http://gateway:8000"),
])
def test_revocation_runtime_environment_stays_disposable(mutation) -> None:
    record, calls = fixture()
    key = ("container", "inspect", record["containers"]["revocation-profile"])
    item = json.loads(calls[key])
    mutation(item[0]["Config"]["Env"])
    calls[key] = json.dumps(item)
    with pytest.raises(OwnershipError, match="Revocation Profile runtime identity"):
        run(record, calls)


def test_live_edge_port_and_seeded_status_origin_are_bound() -> None:
    record, calls = fixture()
    edge_key = ("container", "inspect", record["containers"]["edge"])
    edge = json.loads(calls[edge_key])
    edge[0]["HostConfig"]["PortBindings"]["8443/tcp"][0]["HostPort"] = "29999"
    calls[edge_key] = json.dumps(edge)
    with pytest.raises(OwnershipError, match="published port"):
        run(record, calls)

    record, calls = fixture()
    migration_key = ("container", "inspect", record["containers"][
        "revocation-profile-migrate"])
    migration = json.loads(calls[migration_key])
    migration[0]["Config"]["Env"] = ["STATUS_LIST_BASE_URL=http://gateway:8000"]
    calls[migration_key] = json.dumps(migration)
    with pytest.raises(OwnershipError, match="status origin"):
        run(record, calls)


@pytest.mark.parametrize(("service", "key"), [
    ("db-migrate", "MARTY_ISSUER_BASE_URL"),
    ("gateway", "ISSUER_BASE_URL"),
    ("issuance-native", "ISSUER_BASE_URL"),
])
def test_live_issuer_origin_matches_disposable_gateway(service: str, key: str) -> None:
    record, calls = fixture()
    container_key = ("container", "inspect", record["containers"][service])
    item = json.loads(calls[container_key])
    environment = item[0]["Config"]["Env"]
    environment[environment.index(f"{key}=https://localhost:29876")] = (
        f"{key}=https://beta.elevenidllc.com")
    calls[container_key] = json.dumps(item)
    with pytest.raises(OwnershipError, match="issuer origin"):
        run(record, calls)


def run(record: dict, calls: dict[tuple[str, ...], str]) -> dict:
    return verify(record, "base", NOW, lambda args: calls[tuple(args)])


def add_migration(record: dict, calls: dict[tuple[str, ...], str],
                  service: str, exit_code: int) -> None:
    if service == "db-migrate":
        identifier = record["containers"][service]
        key = ("container", "inspect", identifier)
        item = json.loads(calls[key])
        item[0]["State"] = {"Running": False, "Status": "exited", "ExitCode": exit_code}
        calls[key] = json.dumps(item)
        network_key = ("network", "inspect", "e" * 64)
        network = json.loads(calls[network_key])
        network[0]["Containers"].pop(identifier)
        calls[network_key] = json.dumps(network)
        return
    identifier = "d" * 64
    record["containers"][service] = identifier
    list_key = ("ps", "-aq", "--no-trunc", "--filter",
                f"label=com.docker.compose.project={PROJECT}")
    calls[list_key] += "\n" + identifier
    calls[("container", "inspect", identifier)] = json.dumps([{
        "Id": identifier, "Name": f"/{PROJECT}-{service}-1",
        "State": {"Running": False, "Status": "exited", "ExitCode": exit_code},
        "Config": {"Labels": {**LABELS, "com.docker.compose.service": service},
                   "Image": "migrations@sha256:" + "c" * 64},
        "NetworkSettings": {"Networks": {}},
    }])


def test_exact_live_project_ownership_is_read_only_and_still_blocked() -> None:
    record, calls = fixture()
    observed = []
    def runner(args: list[str]) -> str:
        observed.append(args)
        return calls[tuple(args)]
    report = verify(record, "base", NOW, runner)
    assert report["live_ownership_verified"] is True
    assert report["status"] == "blocked"
    assert report["blocker"] == "protected provisioning provenance and Rust route proof are absent"
    assert all(args[0] in {"ps", "container", "network", "volume"}
               and "rm" not in args and "up" not in args for args in observed)
    assert ["ps", "-aq", "--no-trunc", "--filter",
            f"label=com.docker.compose.project={PROJECT}"] in observed
    assert ["network", "ls", "-q", "--no-trunc", "--filter",
            f"label=com.docker.compose.project={PROJECT}"] in observed


@pytest.mark.parametrize("mutation", [
    lambda item: item.update(Internal=True),
    lambda item: item["Containers"].update({"f" * 64: {}}),
])
def test_ingress_is_external_bridge_with_edge_as_sole_member(mutation) -> None:
    record, calls = fixture()
    key = ("network", "inspect", "a" * 64)
    item = json.loads(calls[key])
    mutation(item[0])
    calls[key] = json.dumps(item)
    with pytest.raises(OwnershipError, match="isolation|unowned member"):
        run(record, calls)


@pytest.mark.parametrize("service,mutation,match", [
    ("passport-callback-signer",
     lambda item: item["NetworkSettings"]["Networks"].update({
         PROJECT + "_private": {"NetworkID": "e" * 64}}), "network attachments"),
    ("issuance-native",
     lambda item: item["NetworkSettings"]["Networks"].update({
         PROJECT + "_callback_signing": {"NetworkID": "f" * 64}}),
     "network attachments"),
    ("passport-beta-bureau",
     lambda item: item["NetworkSettings"]["Networks"].pop(
         PROJECT + "_callback_signing"), "network attachments"),
    ("passport-callback-signer",
     lambda item: item["HostConfig"].update(
         NetworkMode=PROJECT + "_private"), "network mode"),
    ("edge", lambda item: item["NetworkSettings"]["Networks"].pop(
        PROJECT + "_ingress"), "network attachments"),
    ("gateway", lambda item: item["NetworkSettings"]["Networks"].update({
        PROJECT + "_ingress": {"NetworkID": "a" * 64}}), "network attachments"),
])
def test_runtime_network_membership_matches_rust_model(
    service: str, mutation, match: str,
) -> None:
    record, calls = fixture()
    key = ("container", "inspect", record["containers"][service])
    item = json.loads(calls[key])
    mutation(item[0])
    calls[key] = json.dumps(item)
    with pytest.raises(OwnershipError, match=match):
        run(record, calls)


@pytest.mark.parametrize("mutation", [
    lambda mounts: mounts[0].update(Source="/srv/production/marty_db_password"),
    lambda mounts: mounts[0].update(Destination="/run/secrets/other"),
    lambda mounts: mounts[0].update(RW=True),
    lambda mounts: mounts.append({"Type": "bind", "Source": "/srv/production/key",
                                 "Destination": "/run/secrets/extra", "RW": False}),
    lambda mounts: mounts.pop(),
])
def test_secret_mounts_must_match_exact_read_only_project_paths(mutation) -> None:
    record, calls = fixture()
    key = ("container", "inspect", record["containers"]["postgres"])
    item = json.loads(calls[key])
    mutation(item[0]["Mounts"])
    calls[key] = json.dumps(item)
    with pytest.raises(OwnershipError, match="mount"):
        run(record, calls)


def test_disposable_root_must_be_the_project_temp_directory() -> None:
    record, calls = fixture()
    record["disposable_root"] = "/srv/production/marty-passport-acceptance-base-abcdef"
    with pytest.raises(OwnershipError, match="Disposable root"):
        run(record, calls)


def test_docker_desktop_forward_slash_bind_sources_are_accepted() -> None:
    record, calls = fixture()
    for service in record["containers"]:
        key = ("container", "inspect", record["containers"][service])
        item = json.loads(calls[key])
        for mount in item[0]["Mounts"]:
            if mount["Type"] == "bind":
                mount["Source"] = Path(mount["Source"]).as_posix()
        calls[key] = json.dumps(item)
    assert run(record, calls)["live_ownership_verified"] is True


def test_secret_file_symlink_cannot_redirect_a_project_mount(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    record, calls = fixture()
    root = tmp_path / PROJECT
    secrets = root / "secrets"
    secrets.mkdir(parents=True)
    foreign = tmp_path / "foreign-secret"
    foreign.write_text("synthetic", encoding="utf-8")
    try:
        (secrets / "marty_db_password").symlink_to(foreign)
    except OSError:
        pytest.skip("Host does not permit test symlinks")
    monkeypatch.setattr(ownership_module.tempfile, "gettempdir", lambda: str(tmp_path))
    record["disposable_root"] = str(root)
    for service in record["containers"]:
        key = ("container", "inspect", record["containers"][service])
        item = json.loads(calls[key])
        for mount in item[0]["Mounts"]:
            if mount["Type"] == "bind" and mount["Source"].startswith(str(ROOT)):
                mount["Source"] = str(root) + mount["Source"][len(str(ROOT)):]
        calls[key] = json.dumps(item)
    with pytest.raises(OwnershipError, match="unowned mount"):
        run(record, calls)


def test_successful_completed_migration_service_is_allowed() -> None:
    record, calls = fixture()
    add_migration(record, calls, "db-migrate", 0)
    assert run(record, calls)["live_ownership_verified"] is True


def test_completed_migration_may_remain_in_network_member_listing() -> None:
    record, calls = fixture()
    add_migration(record, calls, "db-migrate", 0)
    key = ("network", "inspect", "e" * 64)
    item = json.loads(calls[key])
    item[0]["Containers"][record["containers"]["db-migrate"]] = {}
    calls[key] = json.dumps(item)
    assert run(record, calls)["live_ownership_verified"] is True


@pytest.mark.parametrize("network_id", ["", "e" * 64])
def test_completed_migration_may_keep_configured_detached_network(
    network_id: str,
) -> None:
    record, calls = fixture()
    add_migration(record, calls, "db-migrate", 0)
    key = ("container", "inspect", record["containers"]["db-migrate"])
    item = json.loads(calls[key])
    item[0]["NetworkSettings"]["Networks"] = {
        PROJECT + "_private": {"NetworkID": network_id}}
    calls[key] = json.dumps(item)
    assert run(record, calls)["live_ownership_verified"] is True


def test_completed_migration_rejects_foreign_configured_network_id() -> None:
    record, calls = fixture()
    add_migration(record, calls, "db-migrate", 0)
    key = ("container", "inspect", record["containers"]["db-migrate"])
    item = json.loads(calls[key])
    item[0]["NetworkSettings"]["Networks"] = {
        PROJECT + "_private": {"NetworkID": "f" * 64}}
    calls[key] = json.dumps(item)
    with pytest.raises(OwnershipError, match="network identity"):
        run(record, calls)


@pytest.mark.parametrize("service,exit_code", [
    ("db-migrate", 1), ("gateway-helper", 0), ("notification", 0),
])
def test_only_exact_successful_init_service_may_be_exited(
    service: str, exit_code: int,
) -> None:
    record, calls = fixture()
    add_migration(record, calls, service, exit_code)
    with pytest.raises(OwnershipError, match="service ownership|stopped or unhealthy"):
        run(record, calls)


@pytest.mark.parametrize("mutate,match", [
    (lambda record, calls: record.update(project="marty-selfhost-prod"), "project"),
    (lambda record, calls: record.update(run_id="0"), "run ID"),
    (lambda record, calls: record.update(expires_at=(NOW + timedelta(hours=5)).isoformat()),
     "lease"),
    (lambda record, calls: record["containers"].pop("postgres"), "service ownership"),
    (lambda record, calls: record["containers"].update({
        "prod-sidecar": "f" * 64}), "service ownership"),
    (lambda record, calls: record["containers"].update({
        "auth": "f" * 64}), "service ownership"),
    (lambda record, calls: calls.update({
        ("ps", "-aq", "--no-trunc", "--filter", f"label=com.docker.compose.project={PROJECT}"):
            "f" * 64}), "container set"),
    (lambda record, calls: calls.update({
        ("ps", "-aq", "--no-trunc", "--filter", f"label=com.docker.compose.project={PROJECT}"):
            "\n".join(identifier[:12] for identifier in record["containers"].values())}),
     "container set"),
    (lambda record, calls: calls.update({
        ("network", "ls", "-q", "--no-trunc", "--filter",
         f"label=com.docker.compose.project={PROJECT}"): "f" * 64}), "network set"),
    (lambda record, calls: calls.update({
        ("volume", "ls", "-q", "--filter",
         f"label=com.docker.compose.project={PROJECT}"): "other_volume"}), "volume set"),
])
def test_rejects_bad_lease_identity_and_resource_sets(mutate, match: str) -> None:
    record, calls = fixture()
    mutate(record, calls)
    with pytest.raises(OwnershipError, match=match):
        run(record, calls)


@pytest.mark.parametrize("resource,change,match", [
    ("gateway", lambda item: item["Config"]["Labels"].update({
        "com.marty.passport.acceptance.run-id": "other"}), "runner ownership"),
    ("gateway", lambda item: item["NetworkSettings"]["Networks"].update({
        "marty-selfhost-prod_default": {}}), "unowned network"),
    ("edge", lambda item: item.update(NetworkSettings=None),
     "published port identity"),
    ("gateway", lambda item: item["NetworkSettings"]["Networks"][
        PROJECT + "_private"].update(NetworkID="f" * 64), "network identity"),
    ("gateway", lambda item: item["Config"].update({
        "Image": "ghcr.io/other/services@sha256:" + "a" * 64}), "signed release"),
    ("db-migrate", lambda item: item["Config"].update({
        "Image": "ghcr.io/other/migrations@sha256:" + "b" * 64}), "signed release"),
    ("signing-keys", lambda item: item["Config"].update({
        "Image": "ghcr.io/other/signing-keys@sha256:" + "a" * 64}), "signed release"),
    ("postgres", lambda item: item["Config"].update({
        "Image": "postgres:15-alpine"}), "signed release"),
    ("redis", lambda item: item["Config"].update({
        "Image": "redis:7-alpine"}), "signed release"),
    ("openbao", lambda item: item["Config"].update({
        "Image": "quay.io/openbao/openbao:2"}), "signed release"),
    ("gateway", lambda item: item.update(Name="/marty-selfhost-prod-gateway-1"),
     "named Compose service"),
    ("gateway", lambda item: item.update(Mounts=[{
        "Type": "bind", "Source": "/srv/marty-selfhost-prod/secrets"}]),
     "unowned mount"),
    ("gateway", lambda item: item["State"].update(Running=False, Status="exited"),
     "stopped or unhealthy"),
    ("gateway", lambda item: item["State"]["Health"].update(Status="unhealthy"),
     "stopped or unhealthy"),
    ("network", lambda item: item.update(Internal=False), "isolation"),
    ("network", lambda item: item["Containers"].update({"f" * 64: {}}),
     "unowned member"),
    ("volume", lambda item: item.update(Options={"device": "/srv/prod"}),
     "options"),
])
def test_rejects_cross_project_or_shared_resource(resource, change, match: str) -> None:
    record, calls = fixture()
    if resource == "network":
        key = ("network", "inspect", "e" * 64)
    elif resource == "volume":
        key = ("volume", "inspect", PROJECT + "_postgres_data")
    else:
        key = ("container", "inspect", record["containers"][resource])
    item = deepcopy(json.loads(calls[key]))
    change(item[0])
    calls[key] = json.dumps(item)
    with pytest.raises(OwnershipError, match=match):
        run(record, calls)
