from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType


MIGRATION = (
    Path(__file__).resolve().parents[3]
    / "services"
    / "organization"
    / "infrastructure"
    / "migrations"
    / "versions"
    / "20260720_0001_reconcile_verification_permissions.py"
)


def _load_migration() -> ModuleType:
    spec = importlib.util.spec_from_file_location("verification_permission_migration", MIGRATION)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _Result:
    def scalar(self) -> bool:
        return True


class _Connection:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict | None]] = []

    def execute(self, statement, parameters=None) -> _Result:
        self.calls.append((str(statement), parameters))
        return _Result()


def test_forward_migration_inserts_and_backfills_verification_permissions(
    monkeypatch,
) -> None:
    migration = _load_migration()
    connection = _Connection()
    monkeypatch.setattr(migration.op, "get_bind", lambda: connection)

    migration.upgrade()

    assert migration.revision == "20260720_0001"
    assert migration.down_revision == "20260712_0003"
    assert [call[1]["action"] for call in connection.calls[1:3]] == [
        "view",
        "execute",
    ]
    role_sql = connection.calls[3][0]
    for binding in (
        "('owner', 'view')",
        "('owner', 'execute')",
        "('admin', 'view')",
        "('admin', 'execute')",
        "('operator', 'view')",
        "('operator', 'execute')",
        "('viewer', 'view')",
    ):
        assert binding in role_sql
    assert "ON CONFLICT DO NOTHING" in role_sql
