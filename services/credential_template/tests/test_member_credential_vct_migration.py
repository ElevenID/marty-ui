from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import types


MIGRATION_PATH = (
    Path(__file__).resolve().parents[1]
    / "infrastructure"
    / "migrations"
    / "versions"
    / "20260710_0002_update_marty_member_credential_vct.py"
)


def _load_migration():
    if "alembic" not in sys.modules and importlib.util.find_spec("alembic") is None:
        alembic = types.ModuleType("alembic")
        alembic.op = types.SimpleNamespace(get_bind=lambda: None)
        sys.modules["alembic"] = alembic
    if "sqlalchemy" not in sys.modules and importlib.util.find_spec("sqlalchemy") is None:
        sqlalchemy = types.ModuleType("sqlalchemy")
        sqlalchemy.text = lambda value: value
        sys.modules["sqlalchemy"] = sqlalchemy

    spec = importlib.util.spec_from_file_location("member_credential_vct_migration", MIGRATION_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class _Result:
    def __init__(self, value: bool):
        self.value = value

    def scalar(self):
        return self.value


class _Connection:
    def __init__(self):
        self.calls: list[tuple[str, dict | None]] = []

    def execute(self, statement, params=None):
        sql = str(statement)
        self.calls.append((sql, params))
        if "to_regclass" in sql:
            return _Result(True)
        return _Result(False)


def test_upgrade_updates_marty_member_credential_vct(monkeypatch):
    migration = _load_migration()
    conn = _Connection()
    monkeypatch.setenv("PUBLIC_API_URL", "https://beta.elevenidllc.com/")
    monkeypatch.setattr(migration.op, "get_bind", lambda: conn)

    migration.upgrade()

    sql, params = conn.calls[-1]
    assert "UPDATE credential_template_service.credential_templates" in sql
    assert "credential_type = 'MemberCredential'" in sql
    assert "credential_payload_format IN" in sql
    assert params == {
        "id": "50000000-0000-0000-0000-000000000010",
        "organization_id": "00000000-0000-0000-0000-000000000001",
        "vct": "https://beta.elevenidllc.com/credentials/marty-verified-member-badge",
        "legacy_vct": "https://marty.example/credentials/MemberCredential",
    }


def test_downgrade_restores_only_rows_migrated_to_public_vct(monkeypatch):
    migration = _load_migration()
    conn = _Connection()
    monkeypatch.setenv("PUBLIC_API_URL", "https://beta.elevenidllc.com")
    monkeypatch.setattr(migration.op, "get_bind", lambda: conn)

    migration.downgrade()

    sql, params = conn.calls[-1]
    assert "AND vct = :vct" in sql
    assert "CASE WHEN version = 2 THEN 1 ELSE version END" in sql
    assert params["vct"] == "https://beta.elevenidllc.com/credentials/marty-verified-member-badge"
    assert params["legacy_vct"] == "https://marty.example/credentials/MemberCredential"
