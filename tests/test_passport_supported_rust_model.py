"""Resolved Rust acceptance models cannot use shared production resources."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys

import pytest

from scripts import check_passport_supported_rust_model as preflight
from scripts.check_passport_supported_rust_model import (
    ModelPreflightError, SELECTED, preflight_attested_plan, preflight_read_only, validate_model,
    validate_planned_model,
)
from scripts.passport_supported_infra_images import qualified_images


PROJECT = "marty-passport-acceptance-base-abcdef"
IMAGE = "ghcr.io/elevenid/marty-ui-oss/services@sha256:" + "a" * 64
LABELS = {
    "com.marty.passport.acceptance.owner": "supported-consumer",
    "com.marty.passport.acceptance.run-id": "123456",
    "com.marty.passport.acceptance.source-commit": "a" * 40,
    "com.marty.passport.acceptance.services-image": IMAGE,
}


def safe_model(root: Path) -> dict:
    services = {name: {"image": IMAGE, "environment": {
        "DATABASE_URL": "postgresql://postgres:5432/test",
        "DATABASE_URL_TEMPLATE": "postgresql+asyncpg://marty:${MARTY_DB_PASSWORD}@postgres:5432/marty",
        "BAO_ADDR": "http://openbao:8200",
        "PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED": "true",
    }, "networks": ["private"]} for name in SELECTED}
    services["passport-callback-signer"]["environment"].update({
        "ENVIRONMENT": "beta",
        "PASSPORT_CALLBACK_SIGNER_ENABLED": "true",
        "SIGNING_KEYS_INTERNAL_API_KEY_FILE": "/run/secrets/callback_signer_api_key",
        "BAO_TOKEN_FILE": "/run/secrets/callback_signer_bao_token",
    })
    services["passport-callback-signer"]["networks"] = ["callback_signing"]
    services["passport-beta-bureau"]["environment"].update({
        "ENVIRONMENT": "beta",
        "PASSPORT_BETA_BUREAU_ENABLED": "true",
        "DATABASE_URL_FILE": "/run/secrets/bureau_database_url",
        "GRPC_SERVICE_TOKEN_FILE": "/run/secrets/grpc_service_token",
        "SIGNING_KEYS_INTERNAL_API_KEY_FILE": "/run/secrets/callback_signer_api_key",
        "SIGNING_KEYS_INTERNAL_URL": "http://passport-callback-signer:8018/internal/documents",
        "PASSPORT_BETA_BUREAU_GATEWAY_CALLBACK_ENABLED": "true",
        "PASSPORT_BUREAU_CALLBACK_URL": "http://gateway:8000/v1/passport/webhooks/personalization",
    })
    services["passport-beta-bureau"]["environment"].pop("DATABASE_URL")
    services["passport-beta-bureau"]["networks"] = ["private", "callback_signing"]
    services["issuance-native"]["environment"].update({
        "ENVIRONMENT": "beta",
        "PASSPORT_NATIVE_HTTP_ENABLED": "true",
        "PASSPORT_MANAGED_ISSUER_SIGNING_ENABLED": "true",
        "PASSPORT_KMS_ARTIFACTS_ENABLED": "true",
        "PASSPORT_KMS_CALLBACKS_ENABLED": "true",
        "PASSPORT_BETA_RECONCILIATION_ENABLED": "true",
        "PASSPORT_BETA_RECONCILIATION_OPERATOR_TOKEN_FILE":
            "/run/secrets/passport_beta_reconciliation_operator_token",
        "ISSUER_BASE_URL": "https://localhost:29876",
        "ISSUANCE_GRPC_ENABLED": "true", "ISSUANCE_GRPC_PORT": "9005",
        "CT_GRPC_TARGET": "credential-template:9003",
        "CREDENTIAL_TEMPLATE_SERVICE_URL": "http://credential-template:8003",
        "PERSONALIZATION_BUREAU_URL": "http://passport-beta-bureau:8020",
        "PERSONALIZATION_BUREAU_API_KEY_FILE": "/run/secrets/grpc_service_token",
        "PERSONALIZATION_BUREAU_PROVIDER_PROFILE_ID": "passport-beta-bureau",
        "TOKEN_HMAC_KEY_FILE": "/run/secrets/token_hmac_key",
        "INTEGRATION_SECRET_MASTER_KEY_FILE":
            "/run/secrets/integration_secret_master_key",
        "REVOCATION_PROFILE_SERVICE_URL": "http://revocation-profile:8013",
        "RP_GRPC_TARGET": "revocation-profile:9013",
    })
    services["issuance-native"]["depends_on"] = {
        "issuance-migrations": {"condition": "service_completed_successfully"},
        "revocation-profile": {"condition": "service_healthy"},
        "credential-template": {"condition": "service_healthy"},
    }
    services["gateway"]["environment"].update({
        "ENVIRONMENT": "beta",
        "PASSPORT_NATIVE_GATEWAY_ENABLED": "true",
        "ISSUANCE_SERVICE_URL": "http://issuance-native:8005",
        "ISSUANCE_NATIVE_SERVICE_URL": "http://issuance-native:8005",
        "GRPC_INSECURE_ALLOWED": "true",
        "SIGNING_KEYS_DSC_ISSUE_GATEWAY_KEY_FILE": "/run/secrets/dsc_issue_gateway_key",
        "SIGNING_KEYS_CSCA_ISSUE_GATEWAY_KEY_FILE": "/run/secrets/csca_issue_gateway_key",
        "PUBLIC_DOMAIN": "localhost:29876",
        "ISSUER_BASE_URL": "https://localhost:29876",
        "PASSPORT_PROVIDER_INGRESS_GATEWAY_ENABLED": "false",
        "ORGANIZATION_SERVICE_URL": "http://organization:8002",
        "ORG_GRPC_TARGET": "organization:9002",
        "ES_GRPC_TARGET": "event-stream:9015",
        "GRPC_SERVICE_TOKEN_FILE": "/run/secrets/grpc_service_token",
        "REVOCATION_PROFILE_SERVICE_URL": "http://revocation-profile:8013",
        "CREDENTIAL_TEMPLATE_SERVICE_URL": "http://credential-template:8003",
        "TRUST_PROFILE_SERVICE_URL": "http://trust-profile:8004",
        "PRESENTATION_POLICY_SERVICE_URL": "http://presentation-policy:8009",
        "DEPLOYMENT_PROFILE_SERVICE_URL": "http://deployment-profile:8010",
    })
    services["edge"] = {
        "image": qualified_images(verify_registry=False)["edge"],
        "networks": ["private", "ingress"],
        "ports": [{"host_ip": "127.0.0.1", "published": "29876", "target": 8443}],
        "depends_on": {"gateway": {"condition": "service_started"}},
        "configs": [{"source": "passport_supported_edge",
                     "target": "/etc/nginx/conf.d/default.conf"}],
        "secrets": [{"source": "passport_edge_tls_cert"},
                    {"source": "passport_edge_tls_key"}],
    }
    services["gateway"]["depends_on"] = {
        "organization": {"condition": "service_healthy"},
        "revocation-profile": {"condition": "service_healthy"},
        **{name: {"condition": "service_healthy"} for name in (
            "credential-template", "trust-profile", "presentation-policy",
            "deployment-profile")},
    }
    services["flow"]["environment"].update({
        "ENVIRONMENT": "development",
        "PASSPORT_NATIVE_FLOW_ENABLED": "true",
        "ISSUANCE_NATIVE_SERVICE_URL": "http://issuance-native:8005",
        "FLOW_APPLICATION_EVENT_HMAC_KEY_FILE":
            "/run/secrets/flow_application_event_hmac_key",
        "MARTY_ISSUER_DID": "did:web:localhost%3A29876:orgs:marty",
        "ORG_GRPC_TARGET": "organization:9002",
    })
    for name in ("gateway", "flow", "issuance-native"):
        services[name]["environment"].update({
            "ISSUANCE_API_KEY_FILE": "/run/secrets/issuance_api_key",
            "SIGNING_KEYS_INTERNAL_API_KEY_FILE":
                "/run/secrets/signing_keys_internal_api_key",
        })
        services[name]["secrets"] = [
            {"source": "issuance_api_key"},
            {"source": "signing_keys_internal_api_key"},
        ]
    services["flow"]["secrets"].append(
        {"source": "flow_application_event_hmac_key"})
    services["issuance-native"]["secrets"].extend([
        {"source": "token_hmac_key"},
        {"source": "integration_secret_master_key"},
        {"source": "passport_beta_reconciliation_operator_token"},
    ])
    services["issuance-native"]["environment"]["SIGNING_KEYS_INTERNAL_URL"] = (
        "http://gateway:8000/internal/signing-keys"
    )
    infra = qualified_images(verify_registry=False)
    services["postgres"] = {"image": infra["postgres"], "networks": ["private"], "volumes": [
        {"type": "volume", "source": "postgres_data",
         "target": "/var/lib/postgresql/data"},
    ]}
    services["openbao"] = {
        "image": infra["openbao"],
        "networks": ["private", "callback_signing"],
        "volumes": [
            {"type": "volume", "source": "openbao_data", "target": "/bao/data"},
            {"type": "volume", "source": "openbao_file", "target": "/openbao/file"},
            {"type": "volume", "source": "openbao_logs", "target": "/openbao/logs"},
        ],
        "entrypoint": ["/bin/sh", "/usr/local/bin/passport-supported-openbao-start"],
        "configs": [{"source": "passport_supported_openbao_start",
                     "target": "/usr/local/bin/passport-supported-openbao-start"}],
        "secrets": [{"source": "bao_root_token"}],
    }
    services["redis"] = {"image": infra["redis"], "networks": ["private"],
                         "volumes": [{"type": "volume", "source": "redis_data",
                                      "target": "/data"}]}
    services["revocation-profile-migrate"] = {
        "image": IMAGE,
        "networks": ["private"],
        "environment": {
            "SERVICE_NAME": "revocation_profile",
            "RP_MIGRATE_ONLY": "true",
            "ENVIRONMENT": "development",
            "DATABASE_URL_TEMPLATE":
                "postgresql://marty:${MARTY_DB_PASSWORD}@postgres:5432/marty",
            "MARTY_DB_PASSWORD_FILE": "/run/secrets/marty_db_password",
            "PUBLIC_API_URL": "http://gateway:8000",
            "STATUS_LIST_BASE_URL": "https://localhost:29876",
            "MARTY_ORG_ID": "00000000-0000-0000-0000-000000000001",
        },
        "secrets": [{"source": "marty_db_password"}],
        "depends_on": {"postgres": {"condition": "service_healthy"}},
        "healthcheck": {"disable": True},
        "restart": "no",
    }
    services["event-stream"] = {
        "image": IMAGE,
        "networks": ["private"],
        "environment": {"SERVICE_NAME": "event_stream",
                        "EVENT_STREAM_SERVICE_PORT": "8015",
                        "EVENT_STREAM_GRPC_ENABLED": "true",
                        "EVENT_STREAM_GRPC_PORT": "9015"},
    }
    services["organization"] = {
        "image": IMAGE,
        "networks": ["private"],
        "environment": {
            "SERVICE_NAME": "organization",
            "ORGANIZATION_SERVICE_PORT": "8002",
            "ORG_GRPC_PORT": "9002",
            "DATABASE_URL_TEMPLATE":
                "postgresql+asyncpg://marty:${MARTY_DB_PASSWORD}@postgres:5432/marty",
            "MARTY_DB_PASSWORD_FILE": "/run/secrets/marty_db_password",
            "GRPC_SERVICE_TOKEN_FILE": "/run/secrets/grpc_service_token",
            "REDIS_URL": "redis://redis:6379",
            "ES_GRPC_TARGET": "event-stream:9015",
            "MARTY_ORG_ADMIN_EMAIL": "admin@example.invalid",
            "MARTY_ORG_ID": "00000000-0000-0000-0000-000000000001",
            "PASSPORT_ACCEPTANCE_PROJECT": PROJECT,
            "PASSPORT_ACCEPTANCE_RUN_ID": "123456",
            "PASSPORT_ACCEPTANCE_SOURCE_COMMIT": "a" * 40,
            "PASSPORT_ACCEPTANCE_EXPIRES_AT": "2026-09-27T12:55:00+00:00",
        },
        "secrets": [{"source": "marty_db_password"},
                    {"source": "grpc_service_token"}],
        "depends_on": {
            "db-migrate": {"condition": "service_completed_successfully"},
            "redis": {"condition": "service_healthy"},
            "event-stream": {"condition": "service_healthy"},
        },
    }
    services["revocation-profile"] = {
        "image": IMAGE,
        "networks": ["private"],
        "environment": {
            "SERVICE_NAME": "revocation_profile",
            "ENVIRONMENT": "development",
            "REVOCATION_PROFILE_SERVICE_PORT": "8013",
            "RP_GRPC_ENABLED": "true",
            "RP_GRPC_PORT": "9013",
            "DATABASE_URL_TEMPLATE":
                "postgresql://marty:${MARTY_DB_PASSWORD}@postgres:5432/marty",
            "MARTY_DB_PASSWORD_FILE": "/run/secrets/marty_db_password",
            "GRPC_SERVICE_TOKEN_FILE": "/run/secrets/grpc_service_token",
            "REDIS_URL": "redis://redis:6379/4",
            "ORG_GRPC_TARGET": "organization:9002",
            "PUBLIC_API_URL": "http://gateway:8000",
            "STATUS_LIST_BASE_URL": "https://localhost:29876",
            "MARTY_ORG_ID": "00000000-0000-0000-0000-000000000001",
        },
        "secrets": [{"source": "marty_db_password"},
                    {"source": "grpc_service_token"}],
        "depends_on": {
            "db-migrate": {"condition": "service_completed_successfully"},
            "organization": {"condition": "service_healthy"},
            "redis": {"condition": "service_healthy"},
        },
        "healthcheck": {"test": ["CMD", "curl", "--fail",
                                 "http://localhost:8013/health"]},
    }
    shared = {
        "ENVIRONMENT": "development",
        "DATABASE_URL_TEMPLATE": (
            "postgresql+asyncpg://marty:${MARTY_DB_PASSWORD}@postgres:5432/marty"),
        "MARTY_DB_PASSWORD_FILE": "/run/secrets/marty_db_password",
        "GRPC_SERVICE_TOKEN_FILE": "/run/secrets/grpc_service_token",
        "ORG_GRPC_TARGET": "organization:9002",
    }
    for service, port in (("credential-template", 8003), ("trust-profile", 8004),
                          ("presentation-policy", 8009), ("deployment-profile", 8010)):
        services[service] = {
            "image": IMAGE, "networks": ["private"],
            "environment": {**shared, "SERVICE_NAME": service.replace("-", "_"),
                            f"{service.replace('-', '_').upper()}_SERVICE_PORT": str(port)},
            "secrets": [{"source": "marty_db_password"},
                        {"source": "grpc_service_token"}],
        }
    services["credential-template"]["environment"].update({
        "CT_GRPC_PORT": "9003", "RP_GRPC_TARGET": "revocation-profile:9013",
        "SIGNING_KEYS_INTERNAL_URL": "http://signing-keys:8017/internal",
        "SIGNING_KEYS_INTERNAL_API_KEY_FILE": "/run/secrets/signing_keys_internal_api_key",
        "TRUST_PROFILE_SERVICE_URL": "http://trust-profile:8004",
        "PUBLIC_API_URL": "https://localhost:29876",
        "MARTY_ORG_ID": "00000000-0000-0000-0000-000000000001",
        "MARTY_MIGRATION_PROFILE": "dev",
    })
    services["trust-profile"]["environment"].update({
        "SIGNING_KEYS_INTERNAL_API_KEY_FILE": "/run/secrets/signing_keys_internal_api_key",
        "MARTY_ORG_ID": "00000000-0000-0000-0000-000000000001",
        "MARTY_ORG_SLUG": "marty", "MARTY_ISSUER_DID": "did:web:localhost%3A29876:orgs:marty",
        "MARTY_ISSUER_BASE_URL": "https://localhost:29876",
        "PUBLIC_DOMAIN": "localhost:29876", "DID_RESOLUTION_BASE_URL": "http://gateway:8000",
    })
    for service in ("credential-template", "trust-profile"):
        services[service]["secrets"].append(
            {"source": "signing_keys_internal_api_key"})
    services["presentation-policy"]["environment"].update({
        "PP_GRPC_PORT": "9009", "ISSUANCE_API_KEY_FILE": "/run/secrets/issuance_api_key",
        "DID_RESOLUTION_BASE_URL": "http://gateway:8000",
        "TRUST_PROFILE_SERVICE_URL": "http://trust-profile:8004",
        "ISSUANCE_NATIVE_SERVICE_URL": "http://issuance-native:8005",
        "PUBLIC_DOMAIN": "localhost:29876", "PUBLIC_BASE_URL": "https://localhost:29876",
        "ISSUER_BASE_URL": "https://localhost:29876", "MARTY_ORG_SLUG": "marty",
    })
    services["presentation-policy"]["secrets"].append({"source": "issuance_api_key"})
    for service, port, dependencies in (
        ("trust-profile", 8004, ("db-migrate", "organization")),
        ("credential-template", 8003, ("db-migrate", "organization",
                                       "revocation-profile", "trust-profile",
                                       "signing-keys")),
        ("presentation-policy", 8009, ("db-migrate", "organization",
                                        "trust-profile", "issuance-native")),
        ("deployment-profile", 8010, ("db-migrate", "organization")),
    ):
        services[service]["depends_on"] = {
            name: {"condition": "service_completed_successfully"
                   if name == "db-migrate" else "service_healthy"}
            for name in dependencies
        }
        services[service]["healthcheck"] = {
            "test": ["CMD", "curl", "--fail", f"http://localhost:{port}/health"]}
    services["flow"]["environment"].update({
        "PUBLIC_BASE_URL": "https://localhost:29876",
        "CT_GRPC_TARGET": "credential-template:9003",
        "PP_GRPC_TARGET": "presentation-policy:9009",
        "ISSUANCE_GRPC_TARGET": "issuance-native:9005",
        "CREDENTIAL_TEMPLATE_SERVICE_URL": "http://credential-template:8003",
        "TRUST_PROFILE_SERVICE_URL": "http://trust-profile:8004",
        "DEPLOYMENT_PROFILE_SERVICE_URL": "http://deployment-profile:8010",
    })
    services["flow"]["depends_on"] = {
        name: {"condition": "service_healthy"} for name in (
            "credential-template", "trust-profile", "presentation-policy",
            "deployment-profile", "issuance-native", "signing-keys")}
    services["issuance-native"]["healthcheck"] = {
        "test": ["CMD", "curl", "--fail", "http://localhost:8005/health"]}
    services["signing-keys"] = {
        "image": IMAGE,
        "networks": ["private"],
        "environment": {"SIGNING_KEYS_REDIS_URL": "redis://redis:6379/2",
                        "ENVIRONMENT": "beta",
                        "SIGNING_KEYS_BETA_CSCA_ISSUANCE_ENABLED": "true",
                        "SIGNING_KEYS_DSC_ISSUE_GATEWAY_KEY_FILE":
                            "/run/secrets/dsc_issue_gateway_key",
                        "SIGNING_KEYS_CSCA_ISSUE_GATEWAY_KEY_FILE":
                            "/run/secrets/csca_issue_gateway_key",
                        "PUBLIC_DOMAIN": "localhost:29876",
                        "SIGNING_KEYS_INTERNAL_API_KEY_FILE":
                            "/run/secrets/signing_keys_internal_api_key"},
        "secrets": [{"source": "signing_keys_internal_api_key"}],
        "depends_on": {"redis": {"condition": "service_healthy"}},
        "healthcheck": {"test": ["CMD", "curl", "--fail",
                                 "http://localhost:8017/health"]},
    }
    services["db-migrate"] = {
        "image": "ghcr.io/elevenid/marty-ui-oss/migrations@sha256:" + "b" * 64,
        "networks": ["private"],
        "environment": {
            "REDIS_URL": "redis://redis:6379/2",
            "BAO_ADDR": "http://openbao:8200",
            "BAO_TOKEN_FILE": "/run/secrets/bao_token",
            "MARTY_KMS_BOOTSTRAP_ENABLED": "true",
            "PASSPORT_DISPOSABLE_ICAO_BOOTSTRAP": "true",
            "PASSPORT_ACCEPTANCE_PROJECT": PROJECT,
            "PASSPORT_ACCEPTANCE_GATEWAY_PORT": "29876",
            "MARTY_ORG_ADMIN_EMAIL": "admin@example.invalid",
            "MARTY_ORG_ID": "00000000-0000-0000-0000-000000000001",
            "PUBLIC_DOMAIN": "localhost:29876",
            "MARTY_ISSUER_BASE_URL": "https://localhost:29876",
            "MARTY_ISSUER_DID": "did:web:localhost%3A29876:orgs:marty",
        },
        "depends_on": {**{name: {"condition": "service_healthy"}
                          for name in ("postgres", "redis", "openbao")},
                       "revocation-profile-migrate": {
                           "condition": "service_completed_successfully"}},
        "secrets": [{"source": "bao_token"}],
    }
    services["issuance-migrations"] = {
        "image": "ghcr.io/elevenid/marty-credentials-issuance@sha256:" + "c" * 64,
        "networks": ["private"],
        "command": ["/bin/sh", "/usr/local/bin/passport-supported-issuance-migrate"],
        "configs": [{"source": "passport_supported_issuance_migrate",
                     "target": "/usr/local/bin/passport-supported-issuance-migrate"}],
        "secrets": [{"source": "marty_db_password"}],
        "depends_on": {
            "db-migrate": {"condition": "service_completed_successfully"},
            "organization": {"condition": "service_healthy"},
        },
        "healthcheck": {"disable": True},
        "restart": "no",
    }
    for name in ("gateway", "signing-keys"):
        services[name]["secrets"].extend([
            {"source": "dsc_issue_gateway_key"},
            {"source": "csca_issue_gateway_key"},
        ])
    for service in services.values():
        service["labels"] = LABELS
    return {"name": PROJECT, "services": services,
            "networks": {
                "private": {"name": PROJECT + "_private",
                            "internal": True, "labels": LABELS},
                "callback_signing": {"name": PROJECT + "_callback_signing",
                                     "internal": True, "labels": LABELS},
                "ingress": {"name": PROJECT + "_ingress",
                            "internal": False, "labels": LABELS},
            },
            "volumes": {name: {"name": PROJECT + "_" + name, "labels": LABELS}
                        for name in ("postgres_data", "redis_data", "openbao_data",
                                     "openbao_file", "openbao_logs")},
            "secrets": {
                "db": {"file": str(root / "secrets/db")},
                "marty_db_password": {"file": str(root / "secrets/marty_db_password")},
                "grpc_service_token": {"file": str(root / "secrets/grpc_service_token")},
                "passport_beta_reconciliation_operator_token": {
                    "file": str(root / "secrets/passport_beta_reconciliation_operator_token")},
                "bao_root_token": {"file": str(root / "secrets/bao_root_token")},
                "bao_token": {"file": str(root / "secrets/bao_token")},
                "issuance_api_key": {"file": str(root / "secrets/issuance_api_key")},
                "signing_keys_internal_api_key": {
                    "file": str(root / "secrets/signing_keys_internal_api_key")},
                "dsc_issue_gateway_key": {
                    "file": str(root / "secrets/dsc_issue_gateway_key")},
                "csca_issue_gateway_key": {
                    "file": str(root / "secrets/csca_issue_gateway_key")},
                "token_hmac_key": {"file": str(root / "secrets/token_hmac_key")},
                "integration_secret_master_key": {
                    "file": str(root / "secrets/integration_secret_master_key")},
                "flow_application_event_hmac_key": {
                    "file": str(root / "secrets/flow_application_event_hmac_key")},
                "passport_edge_tls_cert": {
                    "file": str(root / "secrets/passport_edge_tls_cert")},
                "passport_edge_tls_key": {
                    "file": str(root / "secrets/passport_edge_tls_key")},
            },
            "configs": {"passport_supported_openbao_start": {
                "file": str(preflight.ROOT / "scripts/passport_supported_openbao_start.sh")},
                "passport_supported_issuance_migrate": {
                    "file": str(preflight.ROOT / "scripts/passport_supported_issuance_migrate.sh")},
                "passport_supported_edge": {
                    "file": str(preflight.ROOT / "scripts/passport_supported_edge.conf")}},
            }


def test_isolated_resolved_compose_model_passes_only_static_preflight(
    tmp_path: Path,
) -> None:
    report = validate_model(safe_model(tmp_path), PROJECT, IMAGE, tmp_path)
    assert report["model_safe"] is True
    assert "issuance" not in report["services"]


@pytest.mark.parametrize("change,match", [
    (lambda model: model["networks"]["ingress"].update(internal=True),
     "network is external or shared"),
    (lambda model: model["services"]["gateway"].update(
        networks=["private", "ingress"]), "callback signing boundary"),
    (lambda model: model["services"]["edge"].update(
        networks=["private"]), "callback signing boundary"),
])
def test_only_edge_joins_host_facing_ingress(
    tmp_path: Path, change, match: str,
) -> None:
    model = safe_model(tmp_path)
    change(model)
    with pytest.raises(ModelPreflightError, match=match):
        validate_model(model, PROJECT, IMAGE, tmp_path)


@pytest.mark.parametrize("changed", [
    {"PASSPORT_BETA_BUREAU_GATEWAY_CALLBACK_ENABLED": "false"},
    {"PASSPORT_BUREAU_CALLBACK_URL":
     "http://issuance-native:8005/v1/passport/webhooks/personalization"},
    {"PASSPORT_BUREAU_CALLBACK_URL":
     "https://external.example/v1/passport/webhooks/personalization"},
])
def test_disposable_bureau_requires_signed_gateway_callback_route(
    tmp_path: Path, changed: dict[str, str],
) -> None:
    model = safe_model(tmp_path)
    model["services"]["passport-beta-bureau"]["environment"].update(changed)
    with pytest.raises(ModelPreflightError,
                       match="private Marty simulator|endpoint leaves disposable services"):
        validate_model(model, PROJECT, IMAGE, tmp_path)


@pytest.mark.parametrize("change", [
    lambda service: service["environment"].update(HTTP_PROXY="http://gateway:8000"),
    lambda service: service.update(extra_hosts=["gateway:10.0.0.9"]),
    lambda service: service.update(dns=["10.0.0.9"]),
    lambda service: service.update(networks={"private": {"aliases": ["gateway"]},
                                    "callback_signing": None}),
])
def test_disposable_bureau_cannot_redirect_private_gateway_callback(
    tmp_path: Path, change,
) -> None:
    model = safe_model(tmp_path)
    change(model["services"]["passport-beta-bureau"])
    with pytest.raises(ModelPreflightError):
        validate_model(model, PROJECT, IMAGE, tmp_path)


@pytest.mark.parametrize("service,key,value", [
    ("gateway", "PASSPORT_NATIVE_GATEWAY_ENABLED", "false"),
    ("flow", "PASSPORT_NATIVE_FLOW_ENABLED", "false"),
    ("issuance-native", "PASSPORT_MANAGED_ISSUER_SIGNING_ENABLED", "false"),
    ("issuance-native", "PASSPORT_KMS_ARTIFACTS_ENABLED", "false"),
    ("issuance-native", "PASSPORT_KMS_CALLBACKS_ENABLED", "false"),
    ("issuance-native", "PASSPORT_BETA_RECONCILIATION_ENABLED", "false"),
    ("issuance-native", "PASSPORT_BETA_RECONCILIATION_OPERATOR_TOKEN_FILE",
     "/run/secrets/grpc_service_token"),
    ("gateway", "ISSUANCE_SERVICE_URL", "http://flow:8011"),
    ("gateway", "ISSUANCE_NATIVE_SERVICE_URL", "http://flow:8011"),
    ("flow", "ISSUANCE_SERVICE_URL", "http://gateway:8000"),
    ("flow", "ISSUANCE_NATIVE_SERVICE_URL", "http://gateway:8000"),
])
def test_disposable_model_requires_one_rust_passport_owner(
    tmp_path: Path, service: str, key: str, value: str,
) -> None:
    model = safe_model(tmp_path)
    model["services"][service]["environment"][key] = value
    with pytest.raises(ModelPreflightError, match="one Rust owner"):
        validate_model(model, PROJECT, IMAGE, tmp_path)


def test_native_batch_operator_token_is_file_backed_and_native_only(tmp_path: Path) -> None:
    model = safe_model(tmp_path)
    native = model["services"]["issuance-native"]
    native["environment"]["PASSPORT_BETA_RECONCILIATION_OPERATOR_TOKEN"] = "raw-token"
    with pytest.raises(ModelPreflightError):
        validate_model(model, PROJECT, IMAGE, tmp_path)

    model = safe_model(tmp_path)
    model["services"]["gateway"]["secrets"].append(
        {"source": "passport_beta_reconciliation_operator_token"})
    with pytest.raises(ModelPreflightError, match="escaped its owner"):
        validate_model(model, PROJECT, IMAGE, tmp_path)


@pytest.mark.parametrize("service,key,value", [
    ("flow", "ISSUANCE_GRPC_TARGET", "issuance:9006"),
    ("credential-template", "PUBLIC_API_URL", "http://gateway:8000"),
    ("trust-profile", "MARTY_ISSUER_BASE_URL", "http://localhost:8000"),
    ("presentation-policy", "ISSUANCE_NATIVE_SERVICE_URL", "http://issuance:8005"),
    ("deployment-profile", "ORG_GRPC_TARGET", "gateway:9002"),
])
def test_rust_support_runtime_binding_is_required(
    tmp_path: Path, service: str, key: str, value: str,
) -> None:
    model = safe_model(tmp_path)
    model["services"][service]["environment"][key] = value
    with pytest.raises(ModelPreflightError):
        validate_model(model, PROJECT, IMAGE, tmp_path)


@pytest.mark.parametrize("service,change", [
    ("gateway", lambda item: item["environment"].update(
        SIGNING_KEYS_CSCA_ISSUE_GATEWAY_KEY="raw-in-docker-inspect")),
    ("gateway", lambda item: item["environment"].update(
        SIGNING_KEYS_CSCA_ISSUE_GATEWAY_KEY_FILE="/run/secrets/other")),
    ("signing-keys", lambda item: item["secrets"].pop()),
    ("signing-keys", lambda item: item["environment"].update(
        SIGNING_KEYS_BETA_CSCA_ISSUANCE_ENABLED="false")),
])
def test_disposable_ceremony_credential_isolation_is_required(
    tmp_path: Path, service: str, change,
) -> None:
    model = safe_model(tmp_path)
    change(model["services"][service])
    with pytest.raises(ModelPreflightError):
        validate_model(model, PROJECT, IMAGE, tmp_path)


def test_attested_plan_binds_all_disposable_images(tmp_path: Path) -> None:
    model = safe_model(tmp_path)
    plan = {
        "schema": "marty.passport-supported-provisioning-plan/v1",
        "status": "blocked", "surface": "base", "project": PROJECT,
        "services_reference": IMAGE,
        "migrations_reference": model["services"]["db-migrate"]["image"],
        "issuance_reference": model["services"]["issuance-migrations"]["image"],
        "infra_images": qualified_images(verify_registry=False),
        "run_id": "123456", "source_commit": "a" * 40,
        "expires_at": "2026-09-27T12:55:00+00:00",
        "owner_labels": LABELS,
    }
    assert validate_planned_model(model, plan, tmp_path)["model_safe"] is True
    changed_lease = deepcopy(plan)
    changed_lease["expires_at"] = "2026-09-27T12:56:00+00:00"
    with pytest.raises(ModelPreflightError, match="API key lease"):
        validate_planned_model(model, changed_lease, tmp_path)
    for role in ("postgres", "redis", "openbao", "db-migrate", "issuance-migrations",
                 "signing-keys", "organization", "event-stream",
                 "revocation-profile", "revocation-profile-migrate"):
        bad = deepcopy(model)
        bad["services"][role]["image"] = "other@sha256:" + "f" * 64
        with pytest.raises(ModelPreflightError, match="protected image|signed services"):
            validate_planned_model(bad, plan, tmp_path)
    bad_plan = deepcopy(plan)
    bad_plan["infra_images"]["redis"] = "docker.io/library/redis@sha256:" + "f" * 64
    with pytest.raises(ModelPreflightError, match="plan image bindings"):
        validate_planned_model(model, bad_plan, tmp_path)
    for section, name in (("services", "gateway"), ("networks", "private")):
        bad = deepcopy(model)
        bad[section][name]["labels"]["com.marty.passport.acceptance.run-id"] = "other"
        with pytest.raises(ModelPreflightError, match="resource labels"):
            validate_planned_model(bad, plan, tmp_path)
    for mutate in (
        lambda service: service["environment"].pop("SIGNING_KEYS_REDIS_URL"),
        lambda service: service["environment"].update(
            SIGNING_KEYS_REDIS_URL="redis://localhost:6379/2"),
        lambda service: service["depends_on"]["redis"].update(
            condition="service_started"),
    ):
        bad = deepcopy(model)
        mutate(bad["services"]["signing-keys"])
        with pytest.raises(ModelPreflightError, match="isolated Redis readiness"):
            validate_planned_model(bad, plan, tmp_path)


@pytest.mark.parametrize("change,match", [
    (lambda model, root: model.update(name="marty-selfhost-prod"), "project"),
    (lambda model, root: model["services"]["gateway"].update(
        container_name="marty-selfhost-prod-gateway"), "fixed-name"),
    (lambda model, root: model["services"]["gateway"].update(
        image="ghcr.io/other/unsigned@sha256:" + "a" * 64), "signed services"),
    (lambda model, root: model["services"]["postgres"].update(
        image="postgres:15-alpine"), "immutable"),
    (lambda model, root: model["services"]["gateway"].update(
        network_mode="host"), "shared-host"),
    (lambda model, root: model["networks"]["private"].update(
        name="marty-selfhost-prod_default"), "network"),
    (lambda model, root: model["services"]["passport-callback-signer"].update(
        networks=["private", "callback_signing"]), "callback signing boundary"),
    (lambda model, root: model["services"]["issuance-native"].update(
        networks=["private", "callback_signing"]), "callback signing boundary"),
    (lambda model, root: model["volumes"].update(
        data={"name": PROJECT + "_data", "driver": "local",
              "driver_opts": {"type": "none", "o": "bind",
                              "device": "/srv/marty-selfhost-prod"}}), "volume"),
    (lambda model, root: model["secrets"]["db"].update(
        file="/etc/marty-selfhost-prod/secrets/db"), "secret"),
    (lambda model, root: model["secrets"]["token_hmac_key"].update(
        file=str(root / "secrets/bao_root_token")), "secret"),
    (lambda model, root: model["secrets"]["integration_secret_master_key"].update(
        file=str(root / "secrets/bao_root_token")), "secret"),
    (lambda model, root: next(secret for secret in
        model["services"]["issuance-native"]["secrets"]
        if secret["source"] == "token_hmac_key").update(
            target="/run/secrets/not_token_hmac_key"), "secret"),
    (lambda model, root: model["services"]["gateway"].update(
        volumes=[{"type": "bind", "source": "/srv/marty-selfhost-prod/db",
                  "target": "/data"}]), "bind mount"),
    (lambda model, root: model["services"]["gateway"].update(
        environment={"BAO_ADDR": "https://prod-kms.example.com"}), "endpoint"),
    (lambda model, root: model["services"]["gateway"].update(
        environment={"PUBLIC_API_URL": "https://api.prod.example.com"}), "endpoint"),
    (lambda model, root: model["services"]["gateway"].update(
        environment={"REDIS_URL": "redis://prod-redis:6379"}), "endpoint"),
    (lambda model, root: model["services"]["gateway"].update(
        environment={"REDIS_HOST": "prod-redis"}), "endpoint"),
    (lambda model, root: model["services"]["gateway"].update(
        volumes_from=["marty-selfhost-prod-postgres"]), "shared-host"),
    (lambda model, root: model["services"]["gateway"].update(
        build={"context": "/srv/marty-selfhost-prod"}), "shared-host"),
    (lambda model, root: model["services"]["gateway"].update(
        pull_policy="build"), "immutable"),
    (lambda model, root: model["services"].update(
        {"prod-write": {"image": "alpine@sha256:" + "e" * 64,
                        "command": "curl https://prod.example/write"}}),
     "unexpected or missing service"),
    (lambda model, root: model.update(configs={
        "prod": {"file": "/etc/marty-selfhost-prod/secret"}}), "config"),
    (lambda model, root: model["services"]["gateway"].update(
        ports=[{"host_ip": "0.0.0.0", "published": "8000", "target": 8000}]),
     "loopback|endpoint"),
    (lambda model, root: model["services"]["gateway"]["environment"].update(
        PASSPORT_PROVIDER_INGRESS_GATEWAY_ENABLED="true"), "external provider"),
    (lambda model, root: model["services"]["issuance-native"]["environment"].update(
        PERSONALIZATION_BUREAU_PROVIDER_PROFILE_ID="unbound-provider"), "external provider"),
    (lambda model, root: model["services"]["passport-callback-signer"]["environment"].update(
        BAO_TOKEN="raw-secret"), "isolated beta KMS"),
    (lambda model, root: model["services"]["passport-beta-bureau"]["environment"].update(
        GRPC_SERVICE_TOKEN="raw-secret"), "private Marty simulator"),
    (lambda model, root: model["services"]["db-migrate"]["environment"].pop(
        "REDIS_URL"), "issuer profile bootstrap"),
    (lambda model, root: model["services"]["db-migrate"]["environment"].update(
        REDIS_URL="redis://redis:6379/0"), "issuer profile bootstrap"),
    (lambda model, root: model["services"]["db-migrate"]["environment"].update(
        MARTY_KMS_BOOTSTRAP_ENABLED="false"), "issuer profile bootstrap"),
    (lambda model, root: model["services"]["db-migrate"]["environment"].update(
        PASSPORT_DISPOSABLE_ICAO_BOOTSTRAP="false"), "issuer profile bootstrap"),
    (lambda model, root: model["services"]["db-migrate"]["environment"].update(
        PASSPORT_ACCEPTANCE_GATEWAY_PORT="29877"), "issuer profile bootstrap"),
    (lambda model, root: model["services"]["db-migrate"]["depends_on"].pop(
        "openbao"), "issuer profile bootstrap"),
    (lambda model, root: model["services"]["db-migrate"]["secrets"].clear(),
     "issuer profile bootstrap"),
    (lambda model, root: model["services"]["gateway"]["environment"].update(
        PUBLIC_DOMAIN="gateway"), "managed issuer DID"),
    (lambda model, root: model["services"]["signing-keys"]["environment"].pop(
        "PUBLIC_DOMAIN"), "managed issuer DID"),
    (lambda model, root: model["services"]["flow"]["environment"].update(
        MARTY_ISSUER_DID="did:web:other:orgs:marty"), "managed issuer DID"),
    (lambda model, root: model["services"]["db-migrate"]["environment"].update(
        MARTY_ISSUER_DID="did:web:localhost%3A8000:orgs:marty"), "managed issuer DID"),
    (lambda model, root: model["services"]["db-migrate"]["environment"].update(
        MARTY_ISSUER_BASE_URL="http://gateway:8000"), "issuer profile bootstrap"),
    (lambda model, root: model["services"]["gateway"]["environment"].update(
        ISSUER_BASE_URL="http://gateway:8000"), "managed issuer DID"),
    (lambda model, root: model["services"]["issuance-native"]["environment"].update(
        ISSUER_BASE_URL="https://beta.elevenidllc.com"), "endpoint leaves disposable services"),
    (lambda model, root: model["services"]["gateway"]["environment"].update(
        PASSPORT_TENANT_API_KEYS_FILE="/run/secrets/tenant_keys"),
     "internal passport authentication"),
    (lambda model, root: model["services"]["gateway"]["environment"].update(
        PASSPORT_TENANT_API_KEYS_FILE=""),
     "internal passport authentication"),
    (lambda model, root: model["services"]["flow"]["environment"].update(
        PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED="false"),
     "internal passport authentication"),
    (lambda model, root: model["services"]["issuance-native"]["environment"].update(
        PASSPORT_TENANT_API_KEYS="raw-secret"),
     "internal passport authentication"),
    (lambda model, root: model["services"]["gateway"]["environment"].pop(
        "SIGNING_KEYS_INTERNAL_API_KEY_FILE"), "share project credentials"),
    (lambda model, root: model["services"]["flow"]["secrets"].remove(
        {"source": "signing_keys_internal_api_key"}),
     "share project credentials"),
    (lambda model, root: model["services"]["signing-keys"]["environment"].update(
        SIGNING_KEYS_INTERNAL_API_KEY_FILE="/run/secrets/other"),
     "share project credentials"),
    (lambda model, root: model["services"]["issuance-native"]["environment"].pop(
        "TOKEN_HMAC_KEY_FILE"), "native issuance startup secrets"),
    (lambda model, root: model["services"]["issuance-native"]["environment"].update(
        INTEGRATION_SECRET_MASTER_KEY="raw-secret"), "native issuance startup secrets"),
    (lambda model, root: model["services"]["issuance-native"]["secrets"].pop(),
     "native issuance startup secrets"),
    (lambda model, root: model["services"]["organization"]["environment"].update(
        ES_GRPC_TARGET="production-events:9015"), "endpoint"),
    (lambda model, root: model["services"]["organization"]["environment"].update(
        GRPC_SERVICE_TOKEN="raw-secret"), "Organization API-key authority"),
    (lambda model, root: model["services"]["organization"]["environment"].pop(
        "DATABASE_URL_TEMPLATE"), "Organization API-key authority"),
    (lambda model, root: model["services"]["organization"]["environment"].update(
        ORG_GRPC_PORT="9902"), "Organization API-key authority"),
    (lambda model, root: model["services"]["organization"]["environment"].update(
        MARTY_ORG_ADMIN_EMAIL="other@example.invalid"), "Organization API-key authority"),
    (lambda model, root: model["services"]["organization"]["environment"].update(
        PASSPORT_ACCEPTANCE_PROJECT="marty-passport-acceptance-base-ffffff"),
     "Organization API-key authority"),
    (lambda model, root: model["services"]["organization"]["environment"].update(
        PASSPORT_ACCEPTANCE_RUN_ID="999999"), "Organization API-key authority"),
    (lambda model, root: model["services"]["organization"]["environment"].update(
        PASSPORT_ACCEPTANCE_EXPIRES_AT="never"), "Organization API-key authority"),
    (lambda model, root: model["services"]["revocation-profile-migrate"][
        "environment"].update(RP_MIGRATE_ONLY="false"), "revocation schema migration"),
    (lambda model, root: model["services"]["revocation-profile-migrate"][
        "environment"].update(DATABASE_URL_TEMPLATE=
                              "postgresql://marty:other@postgres:5432/marty"),
     "revocation schema migration"),
    (lambda model, root: model["services"]["db-migrate"]["depends_on"].pop(
        "revocation-profile-migrate"), "revocation schema migration"),
    (lambda model, root: model["services"]["revocation-profile"][
        "environment"].update(RP_MIGRATE_ONLY="true"), "revocation runtime"),
    (lambda model, root: model["services"]["revocation-profile"][
        "environment"].update(DATABASE_URL_TEMPLATE=
                              "postgresql://marty:other@postgres:5432/marty"),
     "revocation runtime"),
    (lambda model, root: model["services"]["revocation-profile"][
        "environment"].update(ORG_GRPC_TARGET="gateway:9002"), "revocation runtime"),
    (lambda model, root: model["services"]["revocation-profile"][
        "environment"].update(RP_GRPC_ENABLED="false"), "revocation runtime"),
    (lambda model, root: model["services"]["revocation-profile"][
        "environment"].update(STATUS_LIST_BASE_URL="http://gateway:8000"),
     "revocation runtime"),
    (lambda model, root: model["services"]["revocation-profile-migrate"][
        "environment"].update(STATUS_LIST_BASE_URL="http://gateway:8000"),
     "revocation schema migration"),
    (lambda model, root: model["services"]["revocation-profile"][
        "secrets"].pop(), "revocation runtime"),
    (lambda model, root: model["services"]["revocation-profile"][
        "depends_on"].pop("organization"), "revocation runtime"),
    (lambda model, root: model["services"]["gateway"]["environment"].update(
        REVOCATION_PROFILE_SERVICE_URL="http://gateway:8013"), "revocation runtime"),
    (lambda model, root: model["services"]["issuance-native"]["depends_on"].pop(
        "revocation-profile"), "revocation runtime"),
    (lambda model, root: model["services"]["organization"]["secrets"].pop(),
     "Organization API-key authority"),
    (lambda model, root: model["services"]["event-stream"]["environment"].update(
        EVENT_STREAM_GRPC_ENABLED="false"), "Organization API-key authority"),
    (lambda model, root: model["services"]["gateway"]["environment"].update(
        ORG_GRPC_TARGET="flow:9002"), "Organization API-key authority"),
    (lambda model, root: model["services"]["gateway"]["depends_on"].pop(
        "organization"), "Organization authority"),
    (lambda model, root: model["services"]["flow"]["environment"].update(
        ORG_GRPC_TARGET="gateway:9002"), "Organization authority"),
])
def test_model_rejects_production_escape(tmp_path: Path, change, match: str) -> None:
    model = deepcopy(safe_model(tmp_path))
    change(model, tmp_path)
    with pytest.raises(ModelPreflightError, match=match):
        validate_model(model, PROJECT, IMAGE, tmp_path)


def test_render_uses_fixed_repo_compose_files_and_never_transitions(
    tmp_path: Path,
) -> None:
    env_file = tmp_path / "acceptance.env"
    env_file.write_text("MARTY_SERVICES_IMAGE=" + IMAGE, encoding="utf-8")
    captured = []

    def render(args: list[str], environment: dict[str, str]) -> str:
        captured.append((args, environment))
        return json.dumps(safe_model(tmp_path))

    report = preflight_read_only("base", PROJECT, env_file, tmp_path, IMAGE, render)
    assert report["status"] == "blocked"
    assert report["model"]["static_isolation_verified"] is True
    assert report["model"]["model_safe"] is False
    args, environment = captured[0]
    assert args[:4] == ["docker", "compose", "--project-name", PROJECT]
    assert args[-3:] == ["config", "--format", "json"]
    assert "up" not in args and "down" not in args
    assert environment["MARTY_SERVICES_IMAGE"] == IMAGE


def test_render_rejects_python_owner_phase_before_docker(tmp_path: Path) -> None:
    env_file = tmp_path / "acceptance.env"
    env_file.write_text("MARTY_SERVICES_IMAGE=" + IMAGE, encoding="utf-8")
    called = []
    with pytest.raises(ModelPreflightError, match="owner phase is invalid"):
        preflight.render_model("base", PROJECT, env_file, tmp_path, IMAGE,
                               lambda *args: called.append(args), phase="python")
    assert called == []


def test_executable_planned_preflight_rejects_unsigned_and_mutated_images(
    tmp_path: Path,
) -> None:
    now = datetime(2026, 9, 27, 12, tzinfo=timezone.utc)
    model = safe_model(tmp_path)
    plan = {
        "schema": "marty.passport-supported-provisioning-plan/v1",
        "status": "blocked", "surface": "base", "project": PROJECT,
        "source_commit": "a" * 40,
        "services_reference": IMAGE,
        "migrations_reference": model["services"]["db-migrate"]["image"],
        "issuance_reference": model["services"]["issuance-migrations"]["image"],
        "infra_images": qualified_images(verify_registry=False),
        "run_id": "123456", "owner_labels": LABELS,
        "created_at": (now - timedelta(minutes=5)).isoformat(),
        "expires_at": (now + timedelta(minutes=55)).isoformat(),
    }
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    env_file = tmp_path / "acceptance.env"
    env_file.write_text("synthetic", encoding="utf-8")
    rendered = []

    def render(args, environment):
        rendered.append(args)
        return json.dumps(model)

    with pytest.raises(ModelPreflightError, match="attestation"):
        preflight_attested_plan("base", PROJECT, env_file, tmp_path, IMAGE,
                                plan_path, render, attest=lambda *args: False, now=now,
                                checkout=lambda: ("a" * 40, False))
    assert rendered == []
    report = preflight_attested_plan("base", PROJECT, env_file, tmp_path, IMAGE,
                                     plan_path, render, attest=lambda *args: True, now=now,
                                     checkout=lambda: ("a" * 40, False))
    assert report["status"] == "blocked"
    assert report["model"]["model_safe"] is True
    bad = deepcopy(model)
    bad["services"]["db-migrate"]["image"] = "other@sha256:" + "f" * 64
    with pytest.raises(ModelPreflightError, match="protected image"):
        preflight_attested_plan("base", PROJECT, env_file, tmp_path, IMAGE,
                                plan_path, lambda *args: json.dumps(bad),
                                attest=lambda *args: True, now=now,
                                checkout=lambda: ("a" * 40, False))
    for source, dirty in (("b" * 40, False), ("a" * 40, True)):
        rendered.clear()
        with pytest.raises(ModelPreflightError, match="source checkout"):
            preflight_attested_plan("base", PROJECT, env_file, tmp_path, IMAGE,
                                    plan_path, render, attest=lambda *args: True,
                                    now=now, checkout=lambda: (source, dirty))
        assert rendered == []


@pytest.mark.parametrize("dirty_path", [
    "docker-compose.passport-supported-disposable.yml",
    "scripts/collect_passport_beta_acceptance.py",
])
def test_source_identity_detects_dirty_checkout(
    monkeypatch: pytest.MonkeyPatch,
    dirty_path: str,
) -> None:
    observed = []

    def fake_run(args, **kwargs):
        observed.append(args)
        output = ("a" * 40 + "\n" if "rev-parse" in args else
                  f" M {dirty_path}\n")
        return type("Result", (), {"stdout": output})()

    monkeypatch.setattr(preflight.subprocess, "run", fake_run)
    assert preflight.source_identity() == ("a" * 40, True)
    assert "--untracked-files=all" in observed[1]
    assert "--" not in observed[1]


def test_render_rejects_production_env_file_before_docker(tmp_path: Path) -> None:
    disposable_root = tmp_path / "acceptance"
    disposable_root.mkdir()
    env_file = tmp_path / "marty-selfhost-prod.env"
    env_file.write_text("BAO_ADDR=https://prod-kms.example.com", encoding="utf-8")
    called = []
    with pytest.raises(ModelPreflightError, match="outside the disposable root"):
        preflight_read_only("base", PROJECT, env_file, disposable_root, IMAGE,
                            lambda *args: called.append(args))
    assert called == []


def test_cli_remains_red_even_if_static_model_is_safe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    report_file = tmp_path / "report.json"
    monkeypatch.setattr(preflight, "preflight_read_only", lambda *args: {
        "schema": "marty.passport-supported-rust-model-preflight/v1",
        "status": "blocked", "model": {"model_safe": True},
    })
    monkeypatch.setattr(sys, "argv", [
        "preflight", "--surface", "base", "--project", PROJECT,
        "--env-file", str(tmp_path / "acceptance.env"),
        "--disposable-root", str(tmp_path), "--services-reference", IMAGE,
        "--output", str(report_file),
    ])
    with pytest.raises(SystemExit) as exc:
        preflight.main()
    assert exc.value.code == 1
    report = json.loads(report_file.read_text(encoding="utf-8"))
    assert report["status"] == "blocked"
