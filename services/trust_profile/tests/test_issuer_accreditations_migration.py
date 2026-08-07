from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import sqlalchemy as sa


MIGRATION = (
    Path(__file__).parents[1]
    / "infrastructure"
    / "migrations"
    / "versions"
    / "20260807_0001_add_issuer_accreditations.py"
)


def _load_migration() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "issuer_accreditations_migration",
        MIGRATION,
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_upgrade_adds_fail_closed_accreditation_set(monkeypatch) -> None:
    migration = _load_migration()
    calls: list[tuple[str, sa.Column[object], str | None]] = []
    connection = object()
    monkeypatch.setattr(migration.op, "get_bind", lambda: connection)
    monkeypatch.setattr(migration, "_has_table", lambda conn: conn is connection)
    monkeypatch.setattr(migration, "_has_column", lambda conn: False)
    monkeypatch.setattr(
        migration.op,
        "add_column",
        lambda table, column, schema=None: calls.append((table, column, schema)),
    )

    migration.upgrade()

    assert migration.revision == "issuer_accreditations_001"
    assert migration.down_revision == "trust_kms_cleanup_001"
    assert len(calls) == 1
    table, column, schema = calls[0]
    assert table == "issuer_entities"
    assert schema == "trust_profile_service"
    assert column.name == "accreditations"
    assert isinstance(column.type, sa.JSON)
    assert column.nullable is False
    assert str(column.server_default.arg) == "'[]'::json"


def test_upgrade_defers_to_current_model_when_table_does_not_exist(monkeypatch) -> None:
    migration = _load_migration()
    calls: list[object] = []
    connection = object()
    monkeypatch.setattr(migration.op, "get_bind", lambda: connection)
    monkeypatch.setattr(migration, "_has_table", lambda conn: False)
    monkeypatch.setattr(
        migration.op,
        "add_column",
        lambda *_args, **_kwargs: calls.append(object()),
    )

    migration.upgrade()

    assert calls == []


def test_upgrade_is_idempotent_when_current_model_created_column(monkeypatch) -> None:
    migration = _load_migration()
    calls: list[object] = []
    connection = object()
    monkeypatch.setattr(migration.op, "get_bind", lambda: connection)
    monkeypatch.setattr(migration, "_has_table", lambda conn: True)
    monkeypatch.setattr(migration, "_has_column", lambda conn: True)
    monkeypatch.setattr(
        migration.op,
        "add_column",
        lambda *_args, **_kwargs: calls.append(object()),
    )

    migration.upgrade()

    assert calls == []


def test_downgrade_removes_only_the_accreditation_column(monkeypatch) -> None:
    migration = _load_migration()
    calls: list[tuple[str, str, str | None]] = []
    connection = object()
    monkeypatch.setattr(migration.op, "get_bind", lambda: connection)
    monkeypatch.setattr(migration, "_has_table", lambda conn: True)
    monkeypatch.setattr(migration, "_has_column", lambda conn: True)
    monkeypatch.setattr(
        migration.op,
        "drop_column",
        lambda table, column, schema=None: calls.append((table, column, schema)),
    )

    migration.downgrade()

    assert calls == [
        ("issuer_entities", "accreditations", "trust_profile_service")
    ]


def test_downgrade_is_safe_when_runtime_table_is_absent(monkeypatch) -> None:
    migration = _load_migration()
    calls: list[object] = []
    connection = object()
    monkeypatch.setattr(migration.op, "get_bind", lambda: connection)
    monkeypatch.setattr(migration, "_has_table", lambda conn: False)
    monkeypatch.setattr(
        migration.op,
        "drop_column",
        lambda *_args, **_kwargs: calls.append(object()),
    )

    migration.downgrade()

    assert calls == []
