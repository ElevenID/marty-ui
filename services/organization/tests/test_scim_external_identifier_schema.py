from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

from sqlalchemy import String

from services.organization.infrastructure.models import members_table


MIGRATION = (
    Path(__file__).resolve().parents[3]
    / "services"
    / "organization"
    / "infrastructure"
    / "migrations"
    / "versions"
    / "20260730_0001_expand_member_external_identifier.py"
)


def _load_migration() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "scim_external_identifier_migration",
        MIGRATION,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_member_schema_accepts_opaque_scim_external_identifiers() -> None:
    column_type = members_table.c.user_id.type
    assert isinstance(column_type, String)
    assert column_type.length == 255
    assert len("foreign-user-" + "0" * 32) > 36
    assert len("foreign-user-" + "0" * 32) <= column_type.length


def test_migration_expands_existing_member_identifier_column(
    monkeypatch,
) -> None:
    migration = _load_migration()
    calls: list[tuple[tuple, dict]] = []
    monkeypatch.setattr(
        migration.op,
        "alter_column",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )

    migration.upgrade()

    assert migration.revision == "20260730_0001"
    assert migration.down_revision == "20260720_0001"
    assert calls[0][0] == ("members", "user_id")
    assert calls[0][1]["schema"] == "organization_service"
    assert calls[0][1]["existing_type"].length == 36
    assert calls[0][1]["type_"].length == 255
