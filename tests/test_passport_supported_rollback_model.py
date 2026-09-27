"""Resolved rollback models cannot use shared production resources."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import sys

import pytest

from scripts import check_passport_supported_rollback_model as preflight
from scripts.check_passport_supported_rollback_model import (
    ModelPreflightError, SELECTED, preflight_read_only, validate_model,
)


PROJECT = "marty-passport-acceptance-base-abcdef"
IMAGE = "ghcr.io/elevenid/marty-ui-oss/services@sha256:" + "a" * 64


def safe_model(root: Path) -> dict:
    services = {name: {"image": IMAGE, "environment": {
        "DATABASE_URL": "postgresql://postgres:5432/test",
        "BAO_ADDR": "http://openbao:8200",
    }} for name in SELECTED}
    services["postgres"] = {"image": "postgres@sha256:" + "b" * 64, "volumes": [
        {"type": "bind", "source": str(root / "postgres"),
         "target": "/var/lib/postgresql/data"},
    ]}
    services["openbao"] = {"image": "openbao@sha256:" + "c" * 64}
    services["redis"] = {"image": "redis@sha256:" + "d" * 64}
    return {"name": PROJECT, "services": services,
            "networks": {"default": {"name": PROJECT + "_default",
                                     "internal": True}},
            "volumes": {}, "secrets": {"db": {"file": str(root / "secrets/db")}}}


def test_isolated_resolved_compose_model_passes_only_static_preflight(
    tmp_path: Path,
) -> None:
    report = validate_model(safe_model(tmp_path), PROJECT, IMAGE, tmp_path)
    assert report["model_safe"] is True
    assert report["rollback_accepted"] is False


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
    (lambda model, root: model["networks"]["default"].update(
        name="marty-selfhost-prod_default"), "network"),
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
     "unexpected service"),
    (lambda model, root: model.update(configs={
        "prod": {"file": "/etc/marty-selfhost-prod/secret"}}), "config"),
    (lambda model, root: model["services"]["gateway"].update(
        ports=[{"host_ip": "0.0.0.0", "published": "8000", "target": 8000}]),
     "loopback"),
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
    assert report["model"]["model_safe"] is True
    assert report["model"]["rollback_accepted"] is False
    args, environment = captured[0]
    assert args[:4] == ["docker", "compose", "--project-name", PROJECT]
    assert args[-3:] == ["config", "--format", "json"]
    assert "up" not in args and "down" not in args
    assert environment["MARTY_SERVICES_IMAGE"] == IMAGE


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
