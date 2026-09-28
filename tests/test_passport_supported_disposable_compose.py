"""Render both disposable passport surfaces with Docker's actual Compose parser."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import shutil

import pytest

from scripts.check_passport_supported_rollback_model import (
    ModelPreflightError, render_model, validate_model,
)
from scripts.passport_supported_infra_images import qualified_images


SERVICES = "ghcr.io/elevenid/marty-ui-oss/services@sha256:" + "a" * 64
MIGRATIONS = "ghcr.io/elevenid/marty-ui-oss/migrations@sha256:" + "b" * 64
LEGACY = "ghcr.io/elevenid/marty-credentials/issuance@sha256:" + "c" * 64


def inputs(root: Path) -> Path:
    secrets = root / "secrets"
    secrets.mkdir()
    for name in (
        "marty_db_password", "bao_root_token", "bao_token", "signing_keys_internal_api_key",
        "issuance_api_key",
        "callback_signer_api_key",
        "callback_signer_bao_token", "grpc_service_token", "bureau_database_url",
    ):
        (secrets / name).write_text("synthetic-disposable-only", encoding="utf-8")
    env_file = root / "acceptance.env"
    env_file.write_text("\n".join([
        "PASSPORT_ACCEPTANCE_POSTGRES_IMAGE=postgres@sha256:" + "d" * 64,
        "PASSPORT_ACCEPTANCE_REDIS_IMAGE=redis@sha256:" + "e" * 64,
        "PASSPORT_ACCEPTANCE_OPENBAO_IMAGE=quay.io/openbao/openbao@sha256:" + "f" * 64,
        "PASSPORT_ACCEPTANCE_MIGRATIONS_IMAGE=" + MIGRATIONS,
        "PASSPORT_ACCEPTANCE_LEGACY_IMAGE=" + LEGACY,
        "PASSPORT_ACCEPTANCE_PLAN_RUN_ID=123456789",
        "PASSPORT_ACCEPTANCE_SOURCE_COMMIT=" + "a" * 40,
        "PASSPORT_ACCEPTANCE_DATABASE_URL=postgresql+asyncpg://marty:synthetic-disposable-only@postgres:5432/marty",
        "PASSPORT_ACCEPTANCE_ADMIN_EMAIL=disposable@acceptance.invalid",
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
        "gateway", "flow", "issuance-native", "issuance",
        "passport-callback-signer", "passport-beta-bureau",
        "signing-keys", "db-migrate", "postgres", "redis", "openbao",
        "organization", "event-stream",
        "revocation-profile-migrate",
    }
    result = validate_model(model, project, SERVICES, tmp_path)
    assert result["model_safe"] is True
    assert result["rollback_accepted"] is False
    selected = ("gateway", "flow", "issuance-native",
                "passport-callback-signer", "passport-beta-bureau")
    for name in selected:
        env = model["services"][name]["environment"]
        assert env["PASSPORT_ACCEPTANCE_SURFACE"] == surface
        assert env["ENVIRONMENT"] == (
            "beta" if name in {"passport-callback-signer", "passport-beta-bureau"}
            or (surface == "selfhost" and name == "issuance-native")
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
    assert "passport_tenant_api_keys" not in model["secrets"]
    assert model["services"]["issuance-native"]["environment"][
        "PERSONALIZATION_BUREAU_PROVIDER_PROFILE_ID"] == "passport-beta-bureau"
    assert model["services"]["gateway"]["environment"][
        "PASSPORT_PROVIDER_INGRESS_GATEWAY_ENABLED"] == "false"
    assert model["services"]["gateway"]["environment"][
        "ORG_GRPC_TARGET"] == "organization:9002"
    assert model["services"]["organization"]["environment"][
        "ES_GRPC_TARGET"] == "event-stream:9015"
    assert model["services"]["issuance"]["image"] == LEGACY
    signing = model["services"]["signing-keys"]
    assert signing["environment"]["SIGNING_KEYS_REDIS_URL"] == "redis://redis:6379/2"
    assert signing["environment"]["PUBLIC_DOMAIN"] == "localhost"
    assert signing["depends_on"]["redis"]["condition"] == "service_healthy"
    openbao = model["services"]["openbao"]
    assert openbao["entrypoint"] == [
        "/bin/sh", "/usr/local/bin/passport-supported-openbao-start"]
    assert {secret["source"] for secret in openbao["secrets"]} == {"bao_root_token"}
    assert "BAO_DEV_ROOT_TOKEN_ID" not in openbao.get("environment", {})
    migration = model["services"]["db-migrate"]
    assert migration["depends_on"]["revocation-profile-migrate"]["condition"] == (
        "service_completed_successfully")
    assert model["services"]["revocation-profile-migrate"]["environment"][
        "RP_MIGRATE_ONLY"] == "true"
    assert migration["environment"]["REDIS_URL"] == signing["environment"][
        "SIGNING_KEYS_REDIS_URL"]
    assert migration["environment"]["PUBLIC_DOMAIN"] == model["services"][
        "gateway"]["environment"]["PUBLIC_DOMAIN"]
    assert migration["environment"]["MARTY_ISSUER_DID"] == model["services"][
        "flow"]["environment"]["MARTY_ISSUER_DID"]
    assert migration["environment"]["MARTY_ISSUER_BASE_URL"] == model["services"][
        "gateway"]["environment"]["ISSUER_BASE_URL"]
    for role, reference in qualified_images(verify_registry=False).items():
        assert model["services"][role]["image"] == reference
    labels = model["services"]["gateway"]["labels"]
    assert labels["com.marty.passport.acceptance.run-id"] == "123456789"
    assert labels["com.marty.passport.acceptance.source-commit"] == "a" * 40
    for section in ("services", "networks", "volumes"):
        assert all(item["labels"] == labels for item in model[section].values())


@pytest.mark.skipif(shutil.which("docker") is None, reason="Docker Compose CLI unavailable")
@pytest.mark.parametrize("surface", ["base", "selfhost"])
def test_python_owner_phase_changes_only_two_frozen_selectors(
    tmp_path: Path, surface: str,
) -> None:
    env_file = inputs(tmp_path)
    project = f"marty-passport-acceptance-{surface}-abcdef"
    rust = render_model(surface, project, env_file, tmp_path, SERVICES)
    python = render_model(surface, project, env_file, tmp_path, SERVICES,
                          phase="python")
    assert validate_model(python, project, SERVICES, tmp_path)["rollback_accepted"] is False
    differences = {
        (service, key, rust["services"][service]["environment"][key], value)
        for service, item in python["services"].items()
        for key, value in item.get("environment", {}).items()
        if value != rust["services"][service].get("environment", {}).get(key)
    }
    assert differences == {
        ("gateway", "PASSPORT_NATIVE_GATEWAY_ENABLED", "true", "false"),
        ("flow", "PASSPORT_NATIVE_FLOW_ENABLED", "true", "false"),
    }
    assert set(rust["services"]) == set(python["services"])


@pytest.mark.skipif(shutil.which("docker") is None, reason="Docker Compose CLI unavailable")
def test_rendered_model_rejects_escape_and_mutated_legacy_image(tmp_path: Path) -> None:
    model = render_model("base", "marty-passport-acceptance-base-abcdef",
                         inputs(tmp_path), tmp_path, SERVICES)
    project = "marty-passport-acceptance-base-abcdef"
    bad = deepcopy(model)
    bad["networks"]["private"]["internal"] = False
    with pytest.raises(ModelPreflightError, match="network"):
        validate_model(bad, project, SERVICES, tmp_path)
    bad = deepcopy(model)
    bad["services"]["issuance"]["environment"]["DATABASE_URL"] = (
        "postgresql://marty@prod-db.example:5432/marty")
    with pytest.raises(ModelPreflightError, match="endpoint"):
        validate_model(bad, project, SERVICES, tmp_path)
    bad = deepcopy(model)
    bad["services"]["issuance"]["image"] = "marty-credentials:latest"
    with pytest.raises(ModelPreflightError, match="immutable"):
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
