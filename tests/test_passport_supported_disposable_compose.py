"""Render both disposable passport surfaces with Docker's actual Compose parser."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import shutil

import pytest

from scripts.check_passport_supported_rust_model import (
    ModelPreflightError, preflight_attested_plan, render_model, validate_model,
    validate_planned_model, validate_selfhost_ceremony_model,
)
from scripts.passport_supported_infra_images import qualified_images


SERVICES = "ghcr.io/elevenid/marty-ui-oss/services@sha256:" + "a" * 64
MIGRATIONS = "ghcr.io/elevenid/marty-ui-oss/migrations@sha256:" + "b" * 64
ISSUANCE = "ghcr.io/elevenid/marty-credentials-issuance@sha256:" + "c" * 64


def inputs(root: Path) -> Path:
    secrets = root / "secrets"
    secrets.mkdir()
    for name in (
        "marty_db_password", "bao_root_token", "bao_token", "signing_keys_internal_api_key",
        "issuance_api_key", "dsc_issue_gateway_key", "csca_issue_gateway_key",
        "callback_signer_api_key",
        "callback_signer_bao_token", "grpc_service_token", "bureau_database_url",
        "passport_beta_reconciliation_operator_token",
        "passport_edge_tls_cert", "passport_edge_tls_key",
        "flow_webhook_secret", "flow_application_event_hmac_key",
        "workload_identity_ca_cert", "flow_workload_client_cert",
        "flow_workload_client_key", "flow_workload_server_cert",
        "flow_workload_server_key", "pp_workload_server_cert",
        "pp_workload_server_key",
    ):
        (secrets / name).write_text("synthetic-disposable-only", encoding="utf-8")
    env_file = root / "acceptance.env"
    env_file.write_text("\n".join([
        "PASSPORT_ACCEPTANCE_POSTGRES_IMAGE=postgres@sha256:" + "d" * 64,
        "PASSPORT_ACCEPTANCE_REDIS_IMAGE=redis@sha256:" + "e" * 64,
        "PASSPORT_ACCEPTANCE_OPENBAO_IMAGE=quay.io/openbao/openbao@sha256:" + "f" * 64,
        "PASSPORT_ACCEPTANCE_EDGE_IMAGE=docker.io/library/nginx@sha256:" + "1" * 64,
        "PASSPORT_ACCEPTANCE_MIGRATIONS_IMAGE=" + MIGRATIONS,
        "PASSPORT_ACCEPTANCE_ISSUANCE_IMAGE=" + ISSUANCE,
        "PASSPORT_ACCEPTANCE_PLAN_RUN_ID=123456789",
        "PASSPORT_ACCEPTANCE_SOURCE_COMMIT=" + "a" * 40,
        "PASSPORT_ACCEPTANCE_ADMIN_EMAIL=disposable@acceptance.invalid",
        "PASSPORT_ACCEPTANCE_EXPIRES_AT=2026-09-27T12:55:00+00:00",
        "PASSPORT_ACCEPTANCE_GATEWAY_PORT=29876",
        "PASSPORT_ACCEPTANCE_SECRET_DIR=" + secrets.as_posix(),
    ]) + "\n", encoding="utf-8")
    return env_file


@pytest.mark.skipif(shutil.which("docker") is None, reason="Docker Compose CLI unavailable")
@pytest.mark.parametrize("surface", ["base", "selfhost"])
def test_real_compose_render_is_safe_but_not_accepted(
    tmp_path: Path, surface: str,
) -> None:
    env_file = inputs(tmp_path)
    project = f"marty-passport-acceptance-{surface}-abcdef"
    model = render_model(surface, project, env_file, tmp_path, SERVICES)
    assert set(model["services"]) >= {
        "gateway", "flow", "issuance-native",
        "passport-callback-signer", "passport-beta-bureau",
        "signing-keys", "db-migrate", "issuance-migrations", "postgres", "redis", "openbao",
        "organization", "event-stream",
        "revocation-profile", "revocation-profile-migrate",
        "credential-template", "trust-profile", "presentation-policy",
        "deployment-profile",
    }
    result = validate_model(model, project, SERVICES, tmp_path)
    assert result["model_safe"] is True
    assert "issuance" not in model["services"]
    assert model["services"]["issuance-native"]["environment"]["SIGNING_KEYS_INTERNAL_URL"] == (
        "http://gateway:8000/internal/signing-keys"
    )
    bypass = deepcopy(model)
    bypass["services"]["issuance-native"]["environment"]["SIGNING_KEYS_INTERNAL_URL"] = (
        "http://signing-keys:8017/internal"
    )
    with pytest.raises(ModelPreflightError, match="managed issuer signer bypasses"):
        validate_model(bypass, project, SERVICES, tmp_path)
    selected = ("gateway", "flow", "issuance-native",
                "passport-callback-signer", "passport-beta-bureau")
    for name in selected:
        env = model["services"][name]["environment"]
        assert env["PASSPORT_ACCEPTANCE_SURFACE"] == surface
        assert env["ENVIRONMENT"] == (
            "beta" if name in {"passport-callback-signer", "passport-beta-bureau"}
            or (surface == "base" and name == "gateway")
            or name == "issuance-native"
            else "development" if surface == "base" else "production"
        )
    for name in ("gateway", "flow", "issuance-native"):
        env = model["services"][name]["environment"]
        assert env["PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED"] == "true"
        assert "PASSPORT_TENANT_API_KEYS" not in env
        assert "PASSPORT_TENANT_API_KEYS_FILE" not in env
        assert env["ISSUANCE_API_KEY_FILE"] == "/run/secrets/issuance_api_key"
        assert env["SIGNING_KEYS_INTERNAL_API_KEY_FILE"] == (
            "/run/secrets/signing_keys_internal_api_key")
    ceremony_keys = {
        "SIGNING_KEYS_DSC_ISSUE_GATEWAY_KEY_FILE": "dsc_issue_gateway_key",
        "SIGNING_KEYS_CSCA_ISSUE_GATEWAY_KEY_FILE": "csca_issue_gateway_key",
    }
    for name in ("gateway", "signing-keys"):
        service = model["services"][name]
        env = service["environment"]
        mounts = {item["source"] for item in service["secrets"]}
        if surface == "base":
            assert all(env[key] == f"/run/secrets/{secret}"
                       and secret in mounts for key, secret in ceremony_keys.items())
            assert all(key.removesuffix("_FILE") not in env for key in ceremony_keys)
        else:
            assert all(key not in env and key.removesuffix("_FILE") not in env
                       for key in ceremony_keys)
            assert not (set(ceremony_keys.values()) & mounts)
    if surface == "base":
        assert model["services"]["gateway"]["environment"][
            "GRPC_INSECURE_ALLOWED"] == "true"
        assert model["services"]["signing-keys"]["environment"][
            "SIGNING_KEYS_BETA_CSCA_ISSUANCE_ENABLED"] == "true"
        assert model["services"]["signing-keys"]["environment"][
            "ENVIRONMENT"] == "beta"
    else:
        assert "SIGNING_KEYS_BETA_CSCA_ISSUANCE_ENABLED" not in model["services"][
            "signing-keys"]["environment"]
        for service, key in (
            ("flow", "FLOW_CALLBACK_DESTINATIONS"),
            ("flow", "GRPC_WORKLOAD_TLS_CA_CERT"),
            ("presentation-policy", "GRPC_WORKLOAD_TLS_SERVER_CERT"),
        ):
            broken = deepcopy(model)
            broken["services"][service]["environment"].pop(key)
            with pytest.raises(ModelPreflightError, match="Flow callback|presentation-policy runtime"):
                validate_model(broken, project, SERVICES, tmp_path)
        assert model["services"]["flow"]["environment"][
            "FLOW_CALLBACK_DESTINATIONS"].startswith(
                "00000000-0000-0000-0000-000000000001|https://edge:8443/")
    assert "passport_tenant_api_keys" not in model["secrets"]
    assert model["services"]["issuance-native"]["environment"][
        "PERSONALIZATION_BUREAU_PROVIDER_PROFILE_ID"] == "passport-beta-bureau"
    assert model["services"]["gateway"]["environment"][
        "PASSPORT_PROVIDER_INGRESS_GATEWAY_ENABLED"] == "false"
    assert model["services"]["gateway"]["environment"][
        "ORG_GRPC_TARGET"] == "organization:9002"
    assert model["services"]["organization"]["environment"][
        "ES_GRPC_TARGET"] == "event-stream:9015"
    assert model["services"]["organization"]["environment"][
        "PASSPORT_ACCEPTANCE_PROJECT"] == project
    assert model["services"]["gateway"]["environment"][
        "ISSUANCE_SERVICE_URL"] == "http://issuance-native:8005"
    assert model["services"]["flow"]["environment"][
        "ISSUANCE_SERVICE_URL"] == "http://issuance-native:8005"
    signing = model["services"]["signing-keys"]
    assert signing["environment"]["SIGNING_KEYS_REDIS_URL"] == "redis://redis:6379/2"
    assert signing["environment"]["PUBLIC_DOMAIN"] == "localhost:29876"
    assert signing["depends_on"]["redis"]["condition"] == "service_healthy"
    openbao = model["services"]["openbao"]
    assert openbao["entrypoint"] == [
        "/bin/sh", "/usr/local/bin/passport-supported-openbao-start"]
    assert {secret["source"] for secret in openbao["secrets"]} == {"bao_root_token"}
    assert "BAO_DEV_ROOT_TOKEN_ID" not in openbao.get("environment", {})
    migration = model["services"]["db-migrate"]
    issuance_migration = model["services"]["issuance-migrations"]
    assert issuance_migration["image"] == ISSUANCE
    assert issuance_migration["depends_on"]["db-migrate"]["condition"] == (
        "service_completed_successfully")
    assert model["services"]["issuance-native"]["depends_on"]["issuance-migrations"][
        "condition"] == "service_completed_successfully"
    assert issuance_migration["command"] == [
        "/bin/sh", "/usr/local/bin/passport-supported-issuance-migrate"]
    assert {secret["source"] for secret in issuance_migration["secrets"]} == {
        "marty_db_password"}
    assert "DATABASE_URL" not in issuance_migration.get("environment", {})
    assert issuance_migration["configs"] == [{
        "source": "passport_supported_issuance_migrate",
        "target": "/usr/local/bin/passport-supported-issuance-migrate"}]
    assert migration["depends_on"]["revocation-profile-migrate"]["condition"] == (
        "service_completed_successfully")
    assert model["services"]["revocation-profile-migrate"]["environment"][
        "RP_MIGRATE_ONLY"] == "true"
    revocation = model["services"]["revocation-profile"]
    assert revocation["depends_on"]["organization"]["condition"] == "service_healthy"
    assert revocation["environment"]["ORG_GRPC_TARGET"] == "organization:9002"
    assert revocation["environment"]["STATUS_LIST_BASE_URL"] == (
        "https://localhost:29876")
    assert model["services"]["revocation-profile-migrate"]["environment"][
        "STATUS_LIST_BASE_URL"] == revocation["environment"]["STATUS_LIST_BASE_URL"]
    assert {secret["source"] for secret in revocation["secrets"]} == {
        "marty_db_password", "grpc_service_token"}
    assert model["services"]["gateway"]["environment"][
        "REVOCATION_PROFILE_SERVICE_URL"] == "http://revocation-profile:8013"
    assert model["services"]["issuance-native"]["environment"][
        "RP_GRPC_TARGET"] == "revocation-profile:9013"
    assert migration["environment"]["REDIS_URL"] == signing["environment"][
        "SIGNING_KEYS_REDIS_URL"]
    assert migration["environment"]["PUBLIC_DOMAIN"] == model["services"][
        "gateway"]["environment"]["PUBLIC_DOMAIN"]
    assert migration["environment"]["MARTY_ISSUER_DID"] == model["services"][
        "flow"]["environment"]["MARTY_ISSUER_DID"]
    assert migration["environment"]["MARTY_ISSUER_BASE_URL"] == model["services"][
        "gateway"]["environment"]["ISSUER_BASE_URL"]
    assert migration["environment"]["MARTY_ISSUER_BASE_URL"] == model["services"][
        "issuance-native"]["environment"]["ISSUER_BASE_URL"]
    assert migration["environment"]["MARTY_ISSUER_BASE_URL"] == (
        "https://localhost:29876")
    for role, reference in qualified_images(verify_registry=False).items():
        assert model["services"][role]["image"] == reference
    labels = model["services"]["gateway"]["labels"]
    assert labels["com.marty.passport.acceptance.run-id"] == "123456789"
    assert labels["com.marty.passport.acceptance.source-commit"] == "a" * 40
    for section in ("services", "networks", "volumes"):
        assert all(item["labels"] == labels for item in model[section].values())


@pytest.mark.skipif(shutil.which("docker") is None, reason="Docker Compose CLI unavailable")
def test_selfhost_ceremony_is_temporary_and_exact(tmp_path: Path) -> None:
    env_file = inputs(tmp_path)
    project = "marty-passport-acceptance-selfhost-abcdef"
    final = render_model("selfhost", project, env_file, tmp_path, SERVICES)
    ceremony = render_model("selfhost", project, env_file, tmp_path, SERVICES,
                            phase="selfhost_ceremony")
    assert validate_selfhost_ceremony_model(
        ceremony, final, project, SERVICES, tmp_path) == {
            "project": project, "model_safe": True,
            "ceremony_only": True,
        }
    assert final["services"]["gateway"]["environment"]["ENVIRONMENT"] == "production"
    assert ceremony["services"]["gateway"]["environment"]["ENVIRONMENT"] == "beta"
    assert final["services"]["signing-keys"]["environment"].get(
        "SIGNING_KEYS_BETA_CSCA_ISSUANCE_ENABLED") is None
    assert ceremony["services"]["signing-keys"]["environment"][
        "SIGNING_KEYS_BETA_CSCA_ISSUANCE_ENABLED"] == "true"
    with pytest.raises(ModelPreflightError, match="selfhost surface"):
        render_model("base", "marty-passport-acceptance-base-abcdef",
                     env_file, tmp_path, SERVICES, phase="selfhost_ceremony")
    changed = deepcopy(ceremony)
    changed["services"]["gateway"]["environment"]["PASSPORT_PROVIDER_INGRESS_GATEWAY_ENABLED"] = "true"
    with pytest.raises(ModelPreflightError, match="changes more"):
        validate_selfhost_ceremony_model(changed, final, project, SERVICES, tmp_path)
    with pytest.raises(ModelPreflightError, match="surface environment"):
        validate_model(ceremony, project, SERVICES, tmp_path)


@pytest.mark.skipif(shutil.which("docker") is None, reason="Docker Compose CLI unavailable")
def test_attested_selfhost_preflight_includes_ceremony_model(tmp_path: Path) -> None:
    env_file = inputs(tmp_path)
    project = "marty-passport-acceptance-selfhost-abcdef"
    now = datetime(2026, 9, 27, 12, tzinfo=timezone.utc)
    plan = {
        "schema": "marty.passport-supported-provisioning-plan/v1",
        "status": "blocked", "surface": "selfhost", "project": project,
        "source_commit": "a" * 40, "run_id": "123456789",
        "services_reference": SERVICES,
        "migrations_reference": MIGRATIONS,
        "issuance_reference": ISSUANCE,
        "infra_images": qualified_images(verify_registry=False),
        "owner_labels": {
            "com.marty.passport.acceptance.owner": "supported-consumer",
            "com.marty.passport.acceptance.run-id": "123456789",
            "com.marty.passport.acceptance.source-commit": "a" * 40,
            "com.marty.passport.acceptance.services-image": SERVICES,
        },
        "created_at": (now - timedelta(minutes=5)).isoformat(),
        "expires_at": (now + timedelta(minutes=55)).isoformat(),
    }
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    report = preflight_attested_plan(
        "selfhost", project, env_file, tmp_path, SERVICES, plan_path,
        attest=lambda *args: True, now=now,
        checkout=lambda: (plan["source_commit"], False),
    )
    assert report["status"] == "blocked"
    assert report["model"]["model_safe"] is True
    assert report["ceremony_model"]["ceremony_only"] is True
    changed = render_model("selfhost", project, env_file, tmp_path, SERVICES)
    changed["services"]["issuance-migrations"]["image"] = (
        "ghcr.io/elevenid/marty-credentials-issuance@sha256:" + "e" * 64)
    with pytest.raises(ModelPreflightError, match="protected image reference"):
        validate_planned_model(changed, plan, tmp_path)


@pytest.mark.skipif(shutil.which("docker") is None, reason="Docker Compose CLI unavailable")
def test_rendered_model_rejects_escape_and_mutated_rust_image(tmp_path: Path) -> None:
    model = render_model("base", "marty-passport-acceptance-base-abcdef",
                         inputs(tmp_path), tmp_path, SERVICES)
    project = "marty-passport-acceptance-base-abcdef"
    bad = deepcopy(model)
    bad["networks"]["private"]["internal"] = False
    with pytest.raises(ModelPreflightError, match="network"):
        validate_model(bad, project, SERVICES, tmp_path)
    bad = deepcopy(model)
    bad["services"]["issuance-native"]["environment"]["DATABASE_URL_TEMPLATE"] = (
        "postgresql://marty@prod-db.example:5432/marty")
    with pytest.raises(ModelPreflightError, match="endpoint"):
        validate_model(bad, project, SERVICES, tmp_path)
    bad = deepcopy(model)
    bad["services"]["issuance-native"]["image"] = "marty-credentials:latest"
    with pytest.raises(ModelPreflightError, match="immutable"):
        validate_model(bad, project, SERVICES, tmp_path)
    bad = deepcopy(model)
    bad["services"]["issuance-migrations"]["command"][-1] = "python other.py upgrade"
    with pytest.raises(ModelPreflightError, match="Credentials issuance schema"):
        validate_model(bad, project, SERVICES, tmp_path)
    bad = deepcopy(model)
    bad["configs"]["passport_supported_issuance_migrate"]["file"] = (
        tmp_path / "unreviewed-issuance-migrate.sh").as_posix()
    with pytest.raises(ModelPreflightError, match="Credentials migration script"):
        validate_model(bad, project, SERVICES, tmp_path)
    bad = deepcopy(model)
    bad["services"]["issuance-native"]["depends_on"].pop("issuance-migrations")
    with pytest.raises(ModelPreflightError, match="Credentials issuance schema"):
        validate_model(bad, project, SERVICES, tmp_path)
    bad = deepcopy(model)
    bad["services"]["openbao"]["entrypoint"] = ["/bin/sh", "/tmp/start.sh"]
    with pytest.raises(ModelPreflightError, match="OpenBao start command"):
        validate_model(bad, project, SERVICES, tmp_path)
    bad = deepcopy(model)
    bad["configs"]["passport_supported_openbao_start"]["file"] = (
        tmp_path / "unreviewed-start.sh").as_posix()
    with pytest.raises(ModelPreflightError, match="OpenBao start config"):
        validate_model(bad, project, SERVICES, tmp_path)
    bad = deepcopy(model)
    bad["services"]["openbao"]["environment"] = {
        "BAO_DEV_ROOT_TOKEN_ID": "visible-in-docker-inspect"}
    with pytest.raises(ModelPreflightError, match="OpenBao root token"):
        validate_model(bad, project, SERVICES, tmp_path)
    bad = deepcopy(model)
    bad["services"]["openbao"]["volumes"].append({
        "type": "bind", "source": str(tmp_path / "replacement.sh"),
        "target": "/usr/local/bin/passport-supported-openbao-start",
    })
    with pytest.raises(ModelPreflightError, match="bind mount"):
        validate_model(bad, project, SERVICES, tmp_path)
