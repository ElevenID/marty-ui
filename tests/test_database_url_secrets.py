"""Database URI construction must preserve secret bytes without evaluating code."""

import os
from pathlib import Path
import subprocess
from urllib.parse import quote

import pytest


ROOT = Path(__file__).resolve().parents[1]
LOADERS = [
    "scripts/load-secrets-env.sh",
    "deploy/helm/marty/files/keycloak/load-secrets-env.sh",
]


def run_loader(loader: str, environment: dict[str, str], command: str | None = None):
    return subprocess.run([
        "/bin/sh", "-c", command or '. "$1"; printf "%s" "$DATABASE_URL"',
        "database-uri-test", str(ROOT / loader),
    ], env={"PATH": "/usr/bin:/bin", **environment}, capture_output=True, text=True,
        check=False, timeout=5)


@pytest.mark.parametrize("loader", LOADERS)
@pytest.mark.parametrize("scheme", ["postgresql", "postgresql+asyncpg"])
@pytest.mark.parametrize("placeholder", ["${MARTY_DB_PASSWORD}", "$${MARTY_DB_PASSWORD}"])
@pytest.mark.parametrize("password", [
    "literal%40%2F", "reserved@:/?#[]'\\$`\n", "customer-é-東京", "Unreserved-._~0123",
])
def test_literal_password_slot_preserves_bytes(loader, scheme, placeholder, password):
    result = run_loader(loader, {
        "MARTY_DB_PASSWORD": password,
        "DATABASE_URL_TEMPLATE": f"{scheme}://marty:{placeholder}@postgres:5432/marty",
    })
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    assert result.stdout == f"{scheme}://marty:{quote(password, safe='-._~')}@postgres:5432/marty"


@pytest.mark.parametrize("loader", LOADERS)
def test_password_from_file_is_data_and_keeps_existing_file_normalization(tmp_path, loader):
    marker = tmp_path / "must-not-exist"
    password = f"customer%40'\\\né-東京$(touch {marker})"
    secret = tmp_path / "password"
    secret.write_text(password + "\r\n\n", encoding="utf-8")
    secret.chmod(0o600)
    result = run_loader(loader, {
        "MARTY_DB_PASSWORD_FILE": str(secret),
        "DATABASE_URL_TEMPLATE": "postgresql://marty:${MARTY_DB_PASSWORD}@postgres:5432/marty",
    }, '. "$1"; test -z "${MARTY_DB_PASSWORD_FILE:-}"; printf "%s" "$DATABASE_URL"')
    assert result.returncode == 0, result.stderr
    assert result.stdout == f"postgresql://marty:{quote(password, safe='-._~')}@postgres:5432/marty"
    assert not marker.exists()


@pytest.mark.parametrize("loader", LOADERS)
@pytest.mark.parametrize("expression", [
    "$(touch MARKER)", "`touch MARKER`", "${OTHER_PASSWORD}", "$MARTY_DB_PASSWORD",
    "${MARTY_DB_PASSWORD:-fallback}", "${MARTY_DB_PASSWORD}${MARTY_DB_PASSWORD}",
])
def test_template_refuses_shell_expressions_without_execution_or_disclosure(tmp_path, loader, expression):
    marker = tmp_path / "must-not-exist"
    expression = expression.replace("MARKER", str(marker))
    secret = "private-placeholder-test-password"
    result = run_loader(loader, {
        "MARTY_DB_PASSWORD": secret,
        "DATABASE_URL_TEMPLATE": f"postgresql://marty:{expression}@postgres:5432/marty",
    })
    assert result.returncode != 0
    assert "DATABASE_URL_TEMPLATE only supports" in result.stderr
    assert result.stdout == ""
    assert expression not in result.stderr and secret not in result.stderr
    assert not marker.exists()


@pytest.mark.parametrize("loader", LOADERS)
@pytest.mark.parametrize("template", [None, "", "postgresql://marty:literal%2540@owned.example:6432/db"])
def test_direct_database_url_and_unselected_settings_keep_their_bytes(tmp_path, loader, template):
    marker = tmp_path / "must-not-exist"
    direct = "postgresql://marty:direct%2540%3A%40@database.example:6432/customer?sslmode=require"
    environment = {
        "DATABASE_URL": direct, "MARTY_DB_PASSWORD": "not-selected-as-a-uri-password",
        "UNRELATED_TEMPLATE": f"$(touch {marker})", "LC_ALL": "C.UTF-8",
    }
    if template is not None:
        environment["DATABASE_URL_TEMPLATE"] = template
    result = run_loader(loader, environment,
                        '. "$1"; test "$LC_ALL" = C.UTF-8; printf "%s" "$DATABASE_URL"')
    assert result.returncode == 0, result.stderr
    assert result.stdout == (template or direct)
    assert not marker.exists()


def test_packaged_secret_loader_matches_canonical_script():
    assert (ROOT / LOADERS[0]).read_bytes() == (ROOT / LOADERS[1]).read_bytes()


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell process environment is required")
def test_encoding_does_not_overwrite_the_raw_database_password():
    password = "customer%40@:/#é"
    result = run_loader(LOADERS[0], {
        "MARTY_DB_PASSWORD": password,
        "DATABASE_URL_TEMPLATE": "postgresql://marty:${MARTY_DB_PASSWORD}@postgres/marty",
    }, '. "$1"; printf "%s" "$MARTY_DB_PASSWORD"')
    assert result.returncode == 0
    assert result.stdout == password
