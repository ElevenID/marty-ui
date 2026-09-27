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
        "marty_db_password", "bao_token", "signing_keys_internal_api_key",
        "passport_tenant_api_keys", "callback_signer_api_key",
        "provider_webhook_secret",
    ):
        (secrets / name).write_text("synthetic-disposable-only", encoding="utf-8")
    env_file = root / "acceptance.env"
    env_file.write_text("\n".join([
        "PASSPORT_ACCEPTANCE_POSTGRES_IMAGE=postgres@sha256:" + "d" * 64,
        "PASSPORT_ACCEPTANCE_REDIS_IMAGE=redis@sha256:" + "e" * 64,
        "PASSPORT_ACCEPTANCE_OPENBAO_IMAGE=quay.io/openbao/openbao@sha256:" + "f" * 64,
        "PASSPORT_ACCEPTANCE_MIGRATIONS_IMAGE=" + MIGRATIONS,
        "PASSPORT_ACCEPTANCE_LEGACY_IMAGE=" + LEGACY,
        "PASSPORT_ACCEPTANCE_DATABASE_URL=postgresql+asyncpg://marty:synthetic-disposable-only@postgres:5432/marty",
        "PASSPORT_ACCEPTANCE_ADMIN_EMAIL=disposable@acceptance.invalid",
        "PASSPORT_ACCEPTANCE_PROVIDER_PROFILE_ID=disposable-physical-profile",
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
        "passport-callback-signer-supported", "passport-provider-ingress",
        "signing-keys", "db-migrate", "postgres", "redis", "openbao",
    }
    result = validate_model(model, project, SERVICES, tmp_path)
    assert result["model_safe"] is True
    assert result["rollback_accepted"] is False
    selected = ("gateway", "flow", "issuance-native",
                "passport-callback-signer-supported", "passport-provider-ingress")
    for name in selected:
        env = model["services"][name]["environment"]
        assert env["PASSPORT_ACCEPTANCE_SURFACE"] == surface
        assert env["ENVIRONMENT"] == ("development" if surface == "base"
                                       else "production")
    assert model["services"]["issuance"]["image"] == LEGACY
    for role, reference in qualified_images(verify_registry=False).items():
        assert model["services"][role]["image"] == reference


@pytest.mark.skipif(shutil.which("docker") is None, reason="Docker Compose CLI unavailable")
@pytest.mark.parametrize("surface", ["base", "selfhost"])
def test_python_owner_phase_changes_only_three_frozen_selectors(
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
        ("gateway", "PASSPORT_PROVIDER_INGRESS_GATEWAY_ENABLED", "true", "false"),
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
