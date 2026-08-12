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
    / "20260811_0001_grant_applicant_wallet_view.py"
)


def _load_migration() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "applicant_wallet_permission_migration", MIGRATION
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _Connection:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def execute(self, statement) -> None:
        self.calls.append(str(statement))


def test_forward_migration_grants_only_applicant_wallet_view(monkeypatch) -> None:
    migration = _load_migration()
    connection = _Connection()
    monkeypatch.setattr(migration.op, "get_bind", lambda: connection)

    migration.upgrade()

    assert migration.revision == "20260811_0001"
    assert migration.down_revision == "20260806_0001"
    assert len(connection.calls) == 1
    sql = connection.calls[0]
    assert "role.name = 'applicant'" in sql
    assert "permission.resource = 'wallet'" in sql
    assert "permission.action = 'view'" in sql
    assert "wallet" not in sql.replace("permission.resource = 'wallet'", "")
    assert "write" not in sql
    assert "ON CONFLICT DO NOTHING" in sql


def test_reverse_migration_removes_only_applicant_wallet_view(monkeypatch) -> None:
    migration = _load_migration()
    connection = _Connection()
    monkeypatch.setattr(migration.op, "get_bind", lambda: connection)

    migration.downgrade()

    assert len(connection.calls) == 1
    sql = connection.calls[0]
    assert "DELETE FROM organization_service.role_permissions" in sql
    assert "role.name = 'applicant'" in sql
    assert "permission.resource = 'wallet'" in sql
    assert "permission.action = 'view'" in sql
