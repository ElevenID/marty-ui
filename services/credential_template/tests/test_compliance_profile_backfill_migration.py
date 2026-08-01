from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


MIGRATION_PATH = (
    Path(__file__).resolve().parents[1]
    / "infrastructure"
    / "migrations"
    / "versions"
    / "20260801_0001_backfill_compliance_profile_ids.py"
)


def _load_migration():
    spec = importlib.util.spec_from_file_location(
        "compliance_profile_backfill_migration",
        MIGRATION_PATH,
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class _Connection:
    def __init__(self) -> None:
        self.calls: list[tuple[object, dict]] = []

    def execute(self, statement, params):
        self.calls.append((statement, params))


def test_upgrade_maps_every_legacy_format_to_a_real_profile(monkeypatch) -> None:
    migration = _load_migration()
    connection = _Connection()
    alter_calls: list[tuple[tuple, dict]] = []
    monkeypatch.setattr(migration.op, "get_bind", lambda: connection)
    monkeypatch.setattr(
        migration.op,
        "alter_column",
        lambda *args, **kwargs: alter_calls.append((args, kwargs)),
    )

    migration.upgrade()

    assert len(connection.calls) == 1
    statement, params = connection.calls[0]
    sql = str(statement)
    assert "WHEN id IN" in sql
    assert "('mdoc', 'mso_mdoc')" in sql
    assert "= 'vds_nc'" in sql
    assert "WHERE nullif(trim(compliance_profile_id), '') IS NULL" in sql
    assert params == {
        "open_badge_template_ids": migration.OPEN_BADGE_TEMPLATE_IDS,
        "open_badges_profile_id": migration.OPEN_BADGES_PROFILE_ID,
        "mdoc_profile_id": migration.MDOC_PROFILE_ID,
        "vds_nc_profile_id": migration.VDS_NC_PROFILE_ID,
        "oid4vc_profile_id": migration.OID4VC_PROFILE_ID,
    }
    assert len(alter_calls) == 1
    alter_args, alter_kwargs = alter_calls[0]
    assert alter_args == ("credential_templates", "compliance_profile_id")
    assert alter_kwargs["schema"] == "credential_template_service"
    assert isinstance(alter_kwargs["existing_type"], migration.sa.String)
    assert alter_kwargs["existing_type"].length == 36
    assert alter_kwargs["nullable"] is False


def test_downgrade_refuses_to_restore_inline_compliance() -> None:
    migration = _load_migration()

    with pytest.raises(RuntimeError, match="one-way protocol repair"):
        migration.downgrade()
