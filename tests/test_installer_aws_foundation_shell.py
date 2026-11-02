"""Exercise existing bootstrap owners with the fresh external-auth selection."""
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def run_database_init(tmp_path, selected):
    commands = tmp_path / "commands"
    commands.mkdir()
    sql = tmp_path / "observed.sql"
    psql = commands / "psql"
    psql.write_text('#!/bin/sh\ncat >> "$SQL_TRACE"\n')
    psql.chmod(0o700)
    env = {
        "PATH": f"{commands}:/usr/bin:/bin",
        "POSTGRES_USER": "postgres", "POSTGRES_DB": "postgres",
        "MARTY_DB_PASSWORD": "synthetic-private-password",
        "SQL_TRACE": str(sql),
    }
    if selected is not None:
        env["MARTY_INITIALIZE_KEYCLOAK_DATABASE"] = selected
        # External auth must not attempt to read even an inherited KC path.
        env["KEYCLOAK_DB_PASSWORD_FILE"] = str(tmp_path / "absent-kc-password")
    result = subprocess.run(
        ["/bin/sh", str(ROOT / "docker/init-databases.sh")],
        env=env, text=True, capture_output=True, check=False, timeout=5,
    )
    return result, sql.read_text() if sql.exists() else ""


def test_external_auth_database_bootstrap_has_no_keycloak_dependency(tmp_path):
    result, sql = run_database_init(tmp_path, "false")
    assert result.returncode == 0
    assert "CREATE USER marty" in sql and "marty_applicants" in sql
    assert "keycloak" not in sql
    assert "synthetic-private-password" not in result.stdout + result.stderr


def test_managed_default_still_creates_keycloak_database(tmp_path):
    result, sql = run_database_init(tmp_path, None)
    assert result.returncode == 0
    assert "CREATE USER keycloak" in sql and "CREATE DATABASE keycloak" in sql


def test_unknown_database_selection_refuses_before_sql(tmp_path):
    result, sql = run_database_init(tmp_path, "invalid")
    assert result.returncode != 0
    assert sql == ""
    assert "must be true or false" in result.stderr


def test_external_oidc_secret_uses_existing_secret_loader(tmp_path):
    secret = tmp_path / "client-secret"
    secret.write_text("synthetic-oidc-client-secret\n")
    secret.chmod(0o600)
    result = subprocess.run(
        ["/bin/sh", "-c", '. "$1"; printf "%s" "$OIDC_CLIENT_SECRET"; test -z "${OIDC_CLIENT_SECRET_FILE:-}"',
         "fixture", str(ROOT / "scripts/load-secrets-env.sh")],
        env={"PATH": "/usr/bin:/bin", "OIDC_CLIENT_SECRET_FILE": str(secret)},
        text=True, capture_output=True, check=False, timeout=5,
    )
    assert result.returncode == 0
    assert result.stdout == "synthetic-oidc-client-secret"
    assert result.stderr == ""
