#!/usr/bin/env python3
"""Run released migrations and Rust Issuance images on disposable dependencies.

This is a release-role compatibility probe, not a full bundle installation or
an OpenBao least-privilege qualification. It never selects an existing stack.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import tempfile
from typing import Callable


ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "docker-compose.selfhost-migrations-disposable.yml"
IMAGES = {
    "migrations": "ghcr.io/elevenid/marty-ui-oss/migrations",
    "services": "ghcr.io/elevenid/marty-ui-oss/services",
    "postgres": "docker.io/library/postgres",
    "redis": "docker.io/library/redis",
    "openbao": "quay.io/openbao/openbao",
}
SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
PROJECT = re.compile(r"marty-selfhost-migrate-probe-[0-9a-f]{16}\Z")
ORG_ID = "00000000-0000-0000-0000-000000000001"
NOTIFICATION_HEAD = (
    "SELECT version_num FROM notification_service.alembic_version LIMIT 1"
)
PRIVATE_KEY_SCHEMA_QUERY = """
SELECT 'table:' || table_schema || '.' || table_name
FROM information_schema.tables
WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
  AND (table_name = 'issuer_signing_keys' OR table_name ILIKE '%private_key%'
       OR table_name ILIKE '%private_jwk%' OR table_name ILIKE '%secret_key%')
UNION ALL
SELECT 'column:' || table_schema || '.' || table_name || '.' || column_name
FROM information_schema.columns
WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
  AND (column_name ILIKE '%private_key%' OR column_name ILIKE '%private_jwk%'
       OR column_name ILIKE '%encrypted_jwk%' OR column_name ILIKE '%secret_key%'
       OR column_name ILIKE '%key_material%')
ORDER BY 1
LIMIT 20
"""
REDIS_REGISTRY = f"org:{ORG_ID}:signing-key-services"
NATIVE_BINARIES = (
    "marty-organization", "marty-credential-template", "marty-issuance-service",
)


def native_command(operation: str) -> str:
    return ". /app/load-secrets-env.sh; " + " && ".join(
        ("exec " if index == len(NATIVE_BINARIES) - 1 else "")
        + f"/usr/local/bin/{binary} {operation}"
        for index, binary in enumerate(NATIVE_BINARIES)
    )


class QualificationError(ValueError):
    pass


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise QualificationError(reason)


def validate_images(images: dict[str, str]) -> None:
    require(set(images) == set(IMAGES), "Image role set is incomplete")
    for role, repository in IMAGES.items():
        reference = images[role]
        require(isinstance(reference, str)
                and reference.startswith(repository + "@")
                and SHA256.fullmatch(reference.removeprefix(repository + "@")) is not None,
                f"{role} must use its reviewed repository and an exact digest")


def validate_model(model: dict, images: dict[str, str], secret_dir: Path,
                   project: str) -> None:
    """Fail before startup if Compose can escape the disposable dependency set."""
    require(isinstance(model, dict)
            and set(model) == {"name", "services", "networks", "secrets", "configs"}
            and model["name"] == project
            and set(model.get("services", {})) ==
            {"postgres", "redis", "openbao", "db-migrate", "native-schema-migrate"},
            "Disposable service set changed")
    services = model["services"]
    service_keys = {
        "postgres": {"command", "entrypoint", "environment", "healthcheck",
                     "image", "networks", "secrets"},
        "redis": {"command", "entrypoint", "healthcheck", "image", "networks"},
        "openbao": {"command", "configs", "entrypoint", "healthcheck",
                    "image", "networks", "secrets"},
        "db-migrate": {"command", "depends_on", "entrypoint", "environment",
                       "image", "networks", "restart", "secrets"},
        "native-schema-migrate": {"command", "depends_on", "entrypoint", "environment",
                                  "image", "networks", "restart", "secrets"},
    }
    for name, role in (("postgres", "postgres"), ("redis", "redis"),
                       ("openbao", "openbao"), ("db-migrate", "migrations"),
                       ("native-schema-migrate", "services")):
        service = services[name]
        require(set(service) == service_keys[name]
                and service.get("image") == images[role]
                and service.get("networks") == {"private": None},
                f"{name} is not isolated to the pinned disposable image")
    require(services["postgres"]["environment"] == {
                "POSTGRES_DB": "marty", "POSTGRES_USER": "marty",
                "POSTGRES_PASSWORD_FILE": "/run/secrets/marty_db_password"}
            and services["postgres"]["command"] is None
            and services["postgres"]["entrypoint"] is None
            and services["postgres"]["healthcheck"] == {
                "test": ["CMD-SHELL", "pg_isready -U marty -d marty"],
                "interval": "2s", "retries": 30}
            and services["postgres"]["secrets"] == [{
                "source": "marty_db_password",
                "target": "/run/secrets/marty_db_password"}]
            and services["redis"]["command"] is None
            and services["redis"]["entrypoint"] is None
            and services["redis"]["healthcheck"] == {
                "test": ["CMD", "redis-cli", "ping"],
                "interval": "2s", "retries": 30}
            and services["openbao"]["command"] is None
            and services["openbao"]["entrypoint"] == [
                "/bin/sh", "/usr/local/bin/passport-supported-openbao-start"]
            and services["openbao"]["healthcheck"] == {
                "test": ["CMD", "bao", "status", "-address=http://127.0.0.1:8200"],
                "interval": "2s", "retries": 30}
            and services["openbao"]["secrets"] == [{
                "source": "bao_root_token", "target": "/run/secrets/bao_root_token"}]
            and services["openbao"]["configs"] == [{
                "source": "openbao_start",
                "target": "/usr/local/bin/passport-supported-openbao-start"}],
            "Disposable dependency wiring changed")
    migration = services["db-migrate"]
    env = migration.get("environment", {})
    require(set(env) == {
                "ENVIRONMENT", "MARTY_DB_PASSWORD_FILE", "DATABASE_URL_TEMPLATE",
                "MARTY_ORG_ADMIN_EMAIL", "MARTY_ORG_ID", "MARTY_ORG_SLUG",
                "MARTY_MIGRATION_PROFILE", "MARTY_KMS_BOOTSTRAP_ENABLED",
                "REDIS_URL", "REDIS_DB_GATEWAY", "BAO_ADDR", "BAO_TOKEN_FILE",
                "NOTIFICATION_OPENBAO_TOKEN_FILE", "PUBLIC_DOMAIN",
                "PUBLIC_API_URL", "ISSUER_BASE_URL"}
            and env.get("ENVIRONMENT") == "production"
            and env.get("MARTY_MIGRATION_PROFILE") == "selfhost-production"
            and env.get("MARTY_KMS_BOOTSTRAP_ENABLED") == "true"
            and env.get("REDIS_DB_GATEWAY") == "2"
            and env.get("MARTY_DB_PASSWORD_FILE") == "/run/secrets/marty_db_password"
            and env.get("BAO_TOKEN_FILE") == "/run/secrets/bao_root_token"
            and env.get("NOTIFICATION_OPENBAO_TOKEN_FILE") ==
            "/run/secrets/notification_openbao_token"
            and env.get("BAO_ADDR") == "http://openbao:8200"
            and env.get("DATABASE_URL_TEMPLATE") ==
            "postgresql://marty:$${MARTY_DB_PASSWORD}@postgres:5432/marty"
            and env.get("REDIS_URL") == "redis://redis:6379"
            and env.get("MARTY_ORG_ID") == ORG_ID
            and env.get("MARTY_ORG_ADMIN_EMAIL") == "probe@migration.invalid"
            and env.get("MARTY_ORG_SLUG") == "marty"
            and env.get("PUBLIC_DOMAIN") == "migration.invalid"
            and env.get("PUBLIC_API_URL") == "https://migration.invalid"
            and env.get("ISSUER_BASE_URL") == "https://migration.invalid"
            and migration.get("entrypoint") is None
            and migration.get("command") is None
            and migration.get("restart") == "no"
            and migration.get("secrets") == [
                {"source": "marty_db_password",
                 "target": "/run/secrets/marty_db_password"},
                {"source": "bao_root_token",
                 "target": "/run/secrets/bao_root_token"},
                {"source": "notification_openbao_token",
                 "target": "/run/secrets/notification_openbao_token"}]
            and migration.get("depends_on") == {
                name: {"condition": "service_healthy", "required": True}
                for name in ("postgres", "redis", "openbao")},
            "Self-host migration entrypoint, profile or dependencies changed")
    native = services["native-schema-migrate"]
    require(native["entrypoint"] == ["/bin/sh", "-ec"]
            and native["command"] == [native_command("migrate")]
            and native["environment"] == {
                "MARTY_DB_PASSWORD_FILE": "/run/secrets/marty_db_password",
                "DATABASE_URL_TEMPLATE":
                    "postgresql://marty:$${MARTY_DB_PASSWORD}@postgres:5432/marty"}
            and native["secrets"] == [{
                "source": "marty_db_password",
                "target": "/run/secrets/marty_db_password"}]
            and native["depends_on"] == {
                "postgres": {"condition": "service_healthy", "required": True}}
            and native["restart"] == "no",
            "Rust services image does not own the disposable native migrations")
    require(model.get("networks") == {"private": {
                "name": f"{project}_private", "ipam": {}, "internal": True}},
            "Disposable network is not internal")
    secret_paths = model.get("secrets", {})
    require(set(secret_paths) == {"marty_db_password", "bao_root_token",
                                  "notification_openbao_token"}
            and all(set(value) == {"name", "file"}
                    and value["name"] == f"{project}_{name}"
                    and Path(value["file"]).resolve() == (secret_dir / name).resolve()
                    for name, value in secret_paths.items()),
            "Disposable secrets escape the owned directory")
    require(model.get("configs") == {"openbao_start": {
                "name": f"{project}_openbao_start",
                "file": str((ROOT / "scripts/passport_supported_openbao_start.sh").resolve())}},
            "Disposable OpenBao launch config changed")


def command(args: list[str], environment: dict[str, str], timeout: int = 90
            ) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(args, env=environment, capture_output=True,
                                text=True, encoding="utf-8", errors="replace",
                                timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise QualificationError("Disposable Docker command did not finish") from exc
    require(len(result.stdout) + len(result.stderr) < 2 * 1024 * 1024,
            "Disposable Docker output exceeded limit")
    return result


def _checked(result: subprocess.CompletedProcess[str], reason: str) -> str:
    # Do not echo Docker output: migration failures can contain operator data.
    require(result.returncode == 0, reason)
    return result.stdout


def _empty_project(project: str, environment: dict[str, str],
                   run: Callable[..., subprocess.CompletedProcess[str]]) -> None:
    for noun in ("ps", "network ls", "volume ls"):
        args = ["docker", *noun.split(), "-aq" if noun == "ps" else "-q", "--filter",
                f"label=com.docker.compose.project={project}"]
        require(not _checked(run(args, environment), "Docker preflight failed").strip(),
                "Disposable project namespace is occupied")


def _assert_run(stdout: str) -> None:
    require("Profile: selfhost-production " in stdout
            and "persistent=True" in stdout
            and "Marty KMS identity: ready" in stdout
            and "Ensured non-exportable notification webhook envelope key" in stdout
            and "All migrations completed successfully" in stdout
            and "notification schema migrated" in stdout,
            "Released migration image did not complete the self-host entrypoint")


def qualify(images: dict[str, str], *,
            run: Callable[..., subprocess.CompletedProcess[str]] = command,
            project: str | None = None) -> dict[str, str]:
    validate_images(images)
    project = project or "marty-selfhost-migrate-probe-" + secrets.token_hex(8)
    require(PROJECT.fullmatch(project) is not None, "Disposable project name is invalid")
    with tempfile.TemporaryDirectory(prefix="marty-selfhost-migrate-probe-") as temporary:
        secret_dir = Path(temporary)
        if os.name == "posix":
            secret_dir.chmod(0o700)
        root_token = secrets.token_hex(32)
        for name in ("marty_db_password", "bao_root_token",
                     "notification_openbao_token"):
            path = secret_dir / name
            # Two separate synthetic secret files exercise production's
            # dedicated-token requirement. Least-privilege policy remains a
            # separate release qualification, not a claim of this probe.
            value = root_token if name != "marty_db_password" else secrets.token_hex(32)
            path.write_text(value, encoding="ascii")
            if os.name == "posix":
                path.chmod(0o600)
        environment = os.environ.copy()
        environment.update({
            "PROBE_MIGRATIONS_IMAGE": images["migrations"],
            "PROBE_SERVICES_IMAGE": images["services"],
            "PROBE_POSTGRES_IMAGE": images["postgres"],
            "PROBE_REDIS_IMAGE": images["redis"],
            "PROBE_OPENBAO_IMAGE": images["openbao"],
            "PROBE_SECRET_DIR": str(secret_dir),
            "COMPOSE_PROFILES": "",
        })
        compose = ["docker", "compose", "--project-name", project,
                   "-f", str(COMPOSE)]
        rendered = _checked(run([*compose, "config", "--format", "json"], environment),
                            "Disposable Compose model is invalid")
        try:
            validate_model(json.loads(rendered), images, secret_dir, project)
        except (TypeError, ValueError, KeyError) as exc:
            raise QualificationError("Disposable Compose model is invalid") from exc
        _empty_project(project, environment, run)
        started = False
        try:
            started = True
            _checked(run([*compose, "up", "-d", "--wait", "--wait-timeout", "120",
                          "postgres", "redis", "openbao"], environment, 240),
                     "Disposable dependencies did not become ready")
            ledger = None
            for _ in range(2):
                migration = run([*compose, "run", "--no-deps", "--rm",
                                 "db-migrate"], environment, 900)
                _checked(migration, "Released self-host migrations failed")
                _assert_run(migration.stdout + migration.stderr)
                _checked(run([*compose, "run", "--no-deps", "--rm",
                              "native-schema-migrate"], environment, 900),
                         "Released Rust native schema migrations failed")
                _checked(run([*compose, "run", "--no-deps", "--rm",
                              "--entrypoint", "/bin/sh", "native-schema-migrate",
                              "-ec", native_command("verify-owned-schema")],
                             environment, 900),
                         "Released Rust native schema verification failed")
                head = _checked(run([*compose, "exec", "-T", "postgres", "psql",
                                     "-U", "marty", "-d", "marty", "-Atqc",
                                     NOTIFICATION_HEAD], environment),
                                "Notification migration ledger is unavailable").strip()
                require(re.fullmatch(r"[0-9]{8}_[0-9]{4}", head) is not None,
                        "Notification migration ledger has no head")
                require(ledger is None or head == ledger,
                        "Notification migration head changed on idempotent rerun")
                ledger = head
                alembic = _checked(run([
                    *compose, "exec", "-T", "postgres", "psql", "-U", "marty",
                    "-d", "marty", "-Atqc",
                    "SELECT to_regclass('issuance_service.alembic_version') IS NULL",
                ], environment), "Issuance historical schema inventory failed").strip()
                require(alembic == "t", "Released Issuance schema retains Alembic state")
                private_schema = _checked(run([
                    *compose, "exec", "-T", "postgres", "psql", "-U", "marty",
                    "-d", "marty", "-Atqc", PRIVATE_KEY_SCHEMA_QUERY,
                ], environment), "Private-key schema inventory failed").strip()
                require(not private_schema,
                        "Released self-host migrations created private-key storage")
                redis = _checked(run([*compose, "exec", "-T", "redis", "redis-cli",
                                      "-n", "2", "EXISTS", REDIS_REGISTRY], environment),
                                 "KMS registry verification failed").strip()
                require(redis == "1", "KMS registry was not seeded in Redis")
                transit = _checked(run([
                    *compose, "exec", "-T", "openbao", "sh", "-c",
                    "BAO_ADDR=http://127.0.0.1:8200; export BAO_ADDR; "
                    "BAO_TOKEN=$(cat /run/secrets/bao_root_token); export BAO_TOKEN; "
                    "bao read -field=type "
                    "transit/keys/notification-webhook-envelope-marty-aes256 && "
                    "printf '\\n' && "
                    "bao read -field=exportable "
                    "transit/keys/notification-webhook-envelope-marty-aes256",
                ], environment), "OpenBao notification key verification failed").strip()
                require(transit.splitlines() == ["aes256-gcm96", "false"],
                        "Notification envelope key has unsafe attributes")
            return {"schema": "marty.selfhost-migrations-qualification/v2",
                    "migrations_image": images["migrations"],
                    "services_image": images["services"],
                    "native_schemas": "verified",
                    "notification_head": ledger,
                    "private_key_storage": "absent",
                    "profile": "selfhost-production", "runs": "2"}
        finally:
            if started:
                _checked(run([*compose, "down", "--volumes"],
                             environment, 120), "Disposable teardown failed")
                _empty_project(project, environment, run)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for role in IMAGES:
        parser.add_argument(f"--{role}-image", required=True)
    args = parser.parse_args()
    try:
        result = qualify({role: getattr(args, f"{role}_image") for role in IMAGES})
    except QualificationError as exc:
        parser.exit(1, f"Self-host migrations qualification failed: {exc}\n")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
