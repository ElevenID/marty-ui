from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

from services.organization._migration_permissions import PERMISSION_CATALOG
from services.organization.application import rbac_use_cases


MIGRATION = (
    Path(__file__).resolve().parents[3]
    / "services"
    / "organization"
    / "infrastructure"
    / "migrations"
    / "versions"
    / "20260806_0001_add_wallet_permissions.py"
)


def _load_migration() -> ModuleType:
    spec = importlib.util.spec_from_file_location("wallet_permission_migration", MIGRATION)
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


def test_permission_catalog_and_new_system_roles_include_wallet_boundary() -> None:
    catalog = {(resource, action) for resource, action, _description in PERMISSION_CATALOG}
    assert {("wallet", "view"), ("wallet", "write")} <= catalog

    templates = {
        template["name"]: set(template["permission_keys"])
        for template in rbac_use_cases._SYSTEM_ROLE_TEMPLATES
    }
    for role_name in ("owner", "admin", "catalog_admin"):
        assert {"wallet:view", "wallet:write"} <= templates[role_name]
    for role_name in ("reviewer", "operator", "viewer"):
        assert "wallet:view" in templates[role_name]
        assert "wallet:write" not in templates[role_name]


def test_forward_migration_inserts_and_backfills_wallet_permissions(monkeypatch) -> None:
    migration = _load_migration()
    connection = _Connection()
    monkeypatch.setattr(migration.op, "get_bind", lambda: connection)

    migration.upgrade()

    assert migration.revision == "20260806_0001"
    assert migration.down_revision == "20260730_0001"
    assert [call[1]["action"] for call in connection.calls[1:3]] == [
        "view",
        "write",
    ]
    role_sql = connection.calls[3][0]
    for binding in (
        "('owner', 'view')",
        "('owner', 'write')",
        "('admin', 'view')",
        "('admin', 'write')",
        "('catalog_admin', 'view')",
        "('catalog_admin', 'write')",
        "('reviewer', 'view')",
        "('operator', 'view')",
        "('viewer', 'view')",
    ):
        assert binding in role_sql
    assert "ON CONFLICT DO NOTHING" in role_sql
