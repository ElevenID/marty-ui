from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


MIGRATION_PATH = (
    Path(__file__).resolve().parents[1]
    / "infrastructure"
    / "migrations"
    / "versions"
    / "20260712_0004_replace_legacy_vct_hosts.py"
)


def _load_migration():
    spec = importlib.util.spec_from_file_location("replace_legacy_vct_hosts", MIGRATION_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


class _Result:
    def __init__(self, value: int = 0):
        self.value = value

    def scalar(self):
        return self.value


class _Connection:
    def __init__(self, select_results: list[int]):
        self.select_results = iter(select_results)
        self.calls: list[tuple[str, dict]] = []

    def execute(self, statement, parameters=None):
        sql = str(statement)
        self.calls.append((sql, parameters or {}))
        if "SELECT count(*)" in sql:
            return _Result(next(self.select_results))
        return _Result()


def _clear_public_urls(monkeypatch) -> None:
    for name in ("PUBLIC_API_URL", "ISSUER_BASE_URL", "PUBLIC_BASE_URL"):
        monkeypatch.delenv(name, raising=False)


def test_upgrade_rewrites_only_active_legacy_vcts(monkeypatch) -> None:
    migration = _load_migration()
    connection = _Connection([9, 0])
    monkeypatch.setenv("PUBLIC_API_URL", "https://beta.elevenidllc.com/")
    monkeypatch.setenv("MARTY_MIGRATION_PROFILE", "beta")
    monkeypatch.setattr(migration.op, "get_bind", lambda: connection)

    migration.upgrade()

    update_sql, parameters = connection.calls[1]
    assert "lower(status) = 'active'" in update_sql
    assert "vct LIKE :legacy_pattern" in update_sql
    assert parameters == {
        "public_prefix": "https://beta.elevenidllc.com/credentials/",
        "suffix_start": len(migration.LEGACY_PREFIX) + 1,
        "legacy_pattern": "https://marty.example/credentials/%",
    }
    assert len(connection.calls) == 3


def test_upgrade_with_no_active_legacy_rows_does_not_require_public_url(monkeypatch) -> None:
    migration = _load_migration()
    connection = _Connection([0])
    _clear_public_urls(monkeypatch)
    monkeypatch.setenv("MARTY_MIGRATION_PROFILE", "beta")
    monkeypatch.setattr(migration.op, "get_bind", lambda: connection)

    migration.upgrade()

    assert len(connection.calls) == 1


@pytest.mark.parametrize("public_url", [
    "",
    "http://beta.elevenidllc.com",
    "https://gateway",
    "https://marty.example",
    "https://beta.elevenidllc.com/api",
])
def test_beta_upgrade_rejects_missing_insecure_or_nonpublic_origins(monkeypatch, public_url: str) -> None:
    migration = _load_migration()
    connection = _Connection([1])
    _clear_public_urls(monkeypatch)
    if public_url:
        monkeypatch.setenv("PUBLIC_API_URL", public_url)
    monkeypatch.setenv("MARTY_MIGRATION_PROFILE", "beta")
    monkeypatch.setattr(migration.op, "get_bind", lambda: connection)

    with pytest.raises(RuntimeError, match="PUBLIC_API_URL"):
        migration.upgrade()


def test_downgrade_is_intentionally_one_way() -> None:
    migration = _load_migration()

    with pytest.raises(RuntimeError, match="one-way"):
        migration.downgrade()
