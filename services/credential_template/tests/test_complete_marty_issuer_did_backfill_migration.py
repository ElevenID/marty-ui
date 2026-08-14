from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


MIGRATION_PATH = (
    Path(__file__).resolve().parents[1]
    / "infrastructure"
    / "migrations"
    / "versions"
    / "20260814_0001_complete_marty_issuer_did_backfill.py"
)


def _load_migration():
    spec = importlib.util.spec_from_file_location(
        "complete_marty_issuer_did_backfill",
        MIGRATION_PATH,
    )
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


class _Connection:
    def __init__(self):
        self.calls: list[tuple[str, dict]] = []

    def execute(self, statement, parameters=None):
        self.calls.append((str(statement), parameters or {}))


def _clear_public_origins(monkeypatch) -> None:
    for name in (
        "PUBLIC_DOMAIN",
        "PUBLIC_API_URL",
        "ISSUER_BASE_URL",
        "UI_BASE_URL",
    ):
        monkeypatch.delenv(name, raising=False)


def test_upgrade_binds_every_active_marty_template_missing_a_did(monkeypatch) -> None:
    migration = _load_migration()
    connection = _Connection()
    _clear_public_origins(monkeypatch)
    monkeypatch.setenv("PUBLIC_API_URL", "https://beta.elevenidllc.com/")
    monkeypatch.setattr(migration.op, "get_bind", lambda: connection)

    migration.upgrade()

    assert len(connection.calls) == 1
    sql, parameters = connection.calls[0]
    assert "lower(status) = 'active'" in sql
    assert "nullif(trim(issuer_did), '') IS NULL" in sql
    assert "key_access_mode" not in sql
    assert "issuer_profile_id" not in sql
    assert parameters == {
        "organization_id": "00000000-0000-0000-0000-000000000001",
        "issuer_did": "did:web:beta.elevenidllc.com:orgs:marty",
    }


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("PUBLIC_DOMAIN", "https://beta.elevenidllc.com/path"),
        ("PUBLIC_API_URL", "beta.elevenidllc.com"),
        ("ISSUER_BASE_URL", "https://beta.elevenidllc.com/issuer"),
    ],
)
def test_upgrade_rejects_ambiguous_public_origin(
    monkeypatch,
    name: str,
    value: str,
) -> None:
    migration = _load_migration()
    _clear_public_origins(monkeypatch)
    monkeypatch.setenv(name, value)

    with pytest.raises(RuntimeError):
        migration.upgrade()


def test_downgrade_is_intentionally_one_way() -> None:
    migration = _load_migration()

    with pytest.raises(RuntimeError, match="one-way"):
        migration.downgrade()
