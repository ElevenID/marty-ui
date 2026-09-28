"""Resolved rollback models cannot use shared production resources."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys

import pytest

from scripts import check_passport_supported_rollback_model as preflight
from scripts.check_passport_supported_rollback_model import (
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
        "PASSPORT_BUREAU_CALLBACK_URL": "http://issuance-native:8005/v1/passport/webhooks/personalization",
    })
    services["passport-beta-bureau"]["environment"].pop("DATABASE_URL")
    services["passport-beta-bureau"]["networks"] = ["private", "callback_signing"]
    services["issuance-native"]["environment"].update({
        "ENVIRONMENT": "development",
        "MARTY_ISSUER_DID": "did:web:localhost:orgs:marty",
        "PERSONALIZATION_BUREAU_URL": "http://passport-beta-bureau:8020",
        "PERSONALIZATION_BUREAU_API_KEY_FILE": "/run/secrets/grpc_service_token",
        "PERSONALIZATION_BUREAU_PROVIDER_PROFILE_ID": "passport-beta-bureau",
    })
    services["gateway"]["environment"].update({
        "ENVIRONMENT": "development",
        "PUBLIC_DOMAIN": "localhost",
        "ISSUER_BASE_URL": "http://gateway:8000",
        "PASSPORT_PROVIDER_INGRESS_GATEWAY_ENABLED": "false",
    })
    services["flow"]["environment"].update({
        "ENVIRONMENT": "development",
        "MARTY_ISSUER_DID": "did:web:localhost:orgs:marty",
    })
    infra = qualified_images(verify_registry=False)
    services["postgres"] = {"image": infra["postgres"], "networks": ["private"], "volumes": [
        {"type": "bind", "source": str(root / "postgres"),
         "target": "/var/lib/postgresql/data"},
    ]}
    services["openbao"] = {"image": infra["openbao"],
                           "networks": ["private", "callback_signing"]}
    services["redis"] = {"image": infra["redis"], "networks": ["private"]}
    services["signing-keys"] = {
        "image": IMAGE,
        "networks": ["private"],
        "environment": {"SIGNING_KEYS_REDIS_URL": "redis://redis:6379/2",
                        "PUBLIC_DOMAIN": "localhost"},
        "depends_on": {"redis": {"condition": "service_healthy"}},
    }
    services["db-migrate"] = {
        "image": "ghcr.io/elevenid/marty-ui-oss/migrations@sha256:" + "b" * 64,
        "networks": ["private"],
        "environment": {
            "REDIS_URL": "redis://redis:6379/2",
            "BAO_ADDR": "http://openbao:8200",
            "BAO_TOKEN_FILE": "/run/secrets/bao_token",
            "MARTY_KMS_BOOTSTRAP_ENABLED": "true",
            "PUBLIC_DOMAIN": "localhost",
            "MARTY_ISSUER_BASE_URL": "http://gateway:8000",
            "MARTY_ISSUER_DID": "did:web:localhost:orgs:marty",
        },
        "depends_on": {name: {"condition": "service_healthy"}
                       for name in ("postgres", "redis", "openbao")},
        "secrets": [{"source": "bao_token"}],
    }
    services["issuance"] = {"image": "ghcr.io/elevenid/marty-credentials-issuance@sha256:" + "c" * 64,
                            "networks": ["private"]}
    for service in services.values():
        service["labels"] = LABELS
    return {"name": PROJECT, "services": services,
            "networks": {
                "private": {"name": PROJECT + "_private",
                            "internal": True, "labels": LABELS},
                "callback_signing": {"name": PROJECT + "_callback_signing",
                                     "internal": True, "labels": LABELS},
            },
            "volumes": {}, "secrets": {
                "db": {"file": str(root / "secrets/db")},
                "bao_token": {"file": str(root / "secrets/bao_token")},
            }}


def test_isolated_resolved_compose_model_passes_only_static_preflight(
    tmp_path: Path,
) -> None:
    report = validate_model(safe_model(tmp_path), PROJECT, IMAGE, tmp_path)
    assert report["model_safe"] is True
    assert report["rollback_accepted"] is False


def test_attested_plan_binds_all_disposable_images(tmp_path: Path) -> None:
    model = safe_model(tmp_path)
    plan = {
        "schema": "marty.passport-supported-provisioning-plan/v1",
        "status": "blocked", "surface": "base", "project": PROJECT,
        "services_reference": IMAGE,
        "migrations_reference": model["services"]["db-migrate"]["image"],
        "legacy_reference": model["services"]["issuance"]["image"],
        "infra_images": qualified_images(verify_registry=False),
        "run_id": "123456", "source_commit": "a" * 40,
        "owner_labels": LABELS,
    }
    assert validate_planned_model(model, plan, tmp_path)["model_safe"] is True
    for role in ("postgres", "redis", "openbao", "db-migrate", "issuance", "signing-keys"):
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
     "loopback"),
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
    (lambda model, root: model["services"]["gateway"]["environment"].update(
        PASSPORT_TENANT_API_KEYS_FILE="/run/secrets/tenant_keys"),
     "internal passport authentication"),
    (lambda model, root: model["services"]["flow"]["environment"].update(
        PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED="false"),
     "internal passport authentication"),
    (lambda model, root: model["services"]["issuance-native"]["environment"].update(
        PASSPORT_TENANT_API_KEYS="raw-secret"),
     "internal passport authentication"),
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
    assert report["model"]["rollback_accepted"] is False
    args, environment = captured[0]
    assert args[:4] == ["docker", "compose", "--project-name", PROJECT]
    assert args[-3:] == ["config", "--format", "json"]
    assert "up" not in args and "down" not in args
    assert environment["MARTY_SERVICES_IMAGE"] == IMAGE


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
        "legacy_reference": model["services"]["issuance"]["image"],
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
    bad["services"]["issuance"]["image"] = "other@sha256:" + "f" * 64
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
        "schema": "marty.passport-supported-rollback-preflight/v1",
        "status": "blocked", "model": {"model_safe": True,
                                      "rollback_accepted": False},
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
