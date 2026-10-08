"""Safety and evidence contracts for the release-only migration probe."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from scripts.qualify_selfhost_migrations import (
    QualificationError, _assert_run, qualify, validate_images, validate_model,
)


IMAGES = {
    "migrations": "ghcr.io/elevenid/marty-ui-oss/migrations@sha256:" + "a" * 64,
    "postgres": "docker.io/library/postgres@sha256:" + "b" * 64,
    "redis": "docker.io/library/redis@sha256:" + "c" * 64,
    "openbao": "quay.io/openbao/openbao@sha256:" + "d" * 64,
}
SUCCESS = ("Profile: selfhost-production (persistent=True)\n"
           "Marty KMS identity: ready\n"
           "Ensured non-exportable notification webhook envelope key\n"
           "All migrations completed successfully\n"
           "notification schema migrated\n")


def model(secret_dir: Path) -> dict:
    return {
        "services": {
            "postgres": {"image": IMAGES["postgres"],
                         "networks": {"private": None}},
            "redis": {"image": IMAGES["redis"],
                      "networks": {"private": None}},
            "openbao": {"image": IMAGES["openbao"],
                        "networks": {"private": None}},
            "db-migrate": {"image": IMAGES["migrations"],
                           "networks": {"private": None},
                           "environment": {
                               "MARTY_MIGRATION_PROFILE": "selfhost-production",
                               "MARTY_KMS_BOOTSTRAP_ENABLED": "true",
                               "REDIS_DB_GATEWAY": "2",
                               "MARTY_DB_PASSWORD_FILE": "/run/secrets/marty_db_password",
                               "BAO_TOKEN_FILE": "/run/secrets/bao_root_token",
                               "BAO_ADDR": "http://openbao:8200",
                               "DATABASE_URL_TEMPLATE":
                                   "postgresql://marty:$${MARTY_DB_PASSWORD}@postgres:5432/marty",
                           }},
        },
        "networks": {"private": {"internal": True}},
        "secrets": {
            name: {"file": str(secret_dir / name)}
            for name in ("marty_db_password", "bao_root_token")
        },
    }


def result(args: list[str], stdout: str = "", status: int = 0
           ) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args, status, stdout, "")


def test_rejects_mutable_or_foreign_image() -> None:
    validate_images(IMAGES)
    for bad in ("ghcr.io/elevenid/marty-ui-oss/migrations:latest",
                "ghcr.io/other/migrations@sha256:" + "a" * 64):
        images = dict(IMAGES, migrations=bad)
        with pytest.raises(QualificationError, match="migrations must use"):
            validate_images(images)


def test_model_rejects_profile_network_port_or_secret_escape(tmp_path: Path) -> None:
    source = model(tmp_path)
    validate_model(source, IMAGES, tmp_path)
    for edit in (
        lambda m: m["services"]["db-migrate"]["environment"].update(
            MARTY_MIGRATION_PROFILE="dev"),
        lambda m: m["services"]["db-migrate"].update(command=["true"]),
        lambda m: m["services"]["db-migrate"].update(ports=["5432:5432"]),
        lambda m: m["networks"]["private"].update(internal=False),
        lambda m: m["secrets"]["bao_root_token"].update(file="/production/token"),
    ):
        changed = deepcopy(source)
        edit(changed)
        with pytest.raises(QualificationError):
            validate_model(changed, IMAGES, tmp_path)


def test_evidence_must_include_profile_kms_and_native_notification() -> None:
    _assert_run(SUCCESS)
    for missing in ("Profile: selfhost-production ", "persistent=True",
                    "Marty KMS identity: ready",
                    "Ensured non-exportable notification webhook envelope key",
                    "notification schema migrated"):
        with pytest.raises(QualificationError):
            _assert_run(SUCCESS.replace(missing, ""))


def test_exact_digest_probe_reruns_and_cleans(tmp_path: Path) -> None:
    calls: list[list[str]] = []

    def run(args: list[str], environment: dict[str, str], timeout: int = 90
            ) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        assert environment["PROBE_MIGRATIONS_IMAGE"] == IMAGES["migrations"]
        assert Path(environment["PROBE_SECRET_DIR"]).is_dir()
        if args[-3:] == ["config", "--format", "json"]:
            return result(args, json.dumps(model(Path(environment["PROBE_SECRET_DIR"]))))
        if args[-1:] == ["db-migrate"]:
            return result(args, SUCCESS)
        if "psql" in args:
            return result(args, "20260808_0002\n")
        if "redis-cli" in args:
            return result(args, "1\n")
        if "bao read" in " ".join(args):
            return result(args, "aes256-gcm96\nfalse\n")
        return result(args)

    report = qualify(IMAGES, run=run, project="marty-selfhost-migrate-probe-" + "1" * 16)
    assert report["runs"] == "2"
    assert report["notification_head"] == "20260808_0002"
    assert sum(args[-1:] == ["db-migrate"] for args in calls) == 2
    assert sum("psql" in args for args in calls) == 2
    assert any("down" in args and "--volumes" in args for args in calls)


def test_migration_failure_still_cleans(tmp_path: Path) -> None:
    calls: list[list[str]] = []

    def run(args: list[str], environment: dict[str, str], timeout: int = 90
            ) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        if args[-3:] == ["config", "--format", "json"]:
            return result(args, json.dumps(model(Path(environment["PROBE_SECRET_DIR"]))))
        if args[-1:] == ["db-migrate"]:
            return result(args, "secret-bearing failure", 1)
        return result(args)

    with pytest.raises(QualificationError, match="Released self-host migrations failed"):
        qualify(IMAGES, run=run, project="marty-selfhost-migrate-probe-" + "2" * 16)
    assert any("down" in args and "--volumes" in args for args in calls)


@pytest.mark.skipif(shutil.which("docker") is None, reason="Compose CLI unavailable")
def test_actual_compose_render_is_isolated(tmp_path: Path) -> None:
    from scripts.qualify_selfhost_migrations import COMPOSE

    environment = {
        "PROBE_MIGRATIONS_IMAGE": IMAGES["migrations"],
        "PROBE_POSTGRES_IMAGE": IMAGES["postgres"],
        "PROBE_REDIS_IMAGE": IMAGES["redis"],
        "PROBE_OPENBAO_IMAGE": IMAGES["openbao"],
        "PROBE_SECRET_DIR": str(tmp_path),
    }
    import os
    completed = subprocess.run(["docker", "compose", "-f", str(COMPOSE),
                                "config", "--format", "json"],
                               env={**os.environ, **environment},
                               capture_output=True, text=True, check=True)
    validate_model(json.loads(completed.stdout), IMAGES, tmp_path)
