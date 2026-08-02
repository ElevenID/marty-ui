from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


MIGRATION_PATH = (
    Path(__file__).resolve().parents[1]
    / "infrastructure"
    / "migrations"
    / "versions"
    / "20260801_0002_standardize_spruce_oid4vci.py"
)


def _load_migration():
    spec = importlib.util.spec_from_file_location("standardize_spruce_oid4vci", MIGRATION_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class _Connection:
    def __init__(self) -> None:
        self.statements: list[str] = []

    def exec_driver_sql(self, statement: str) -> None:
        self.statements.append(statement)


def test_upgrade_normalizes_registry_and_template_wallet_data(monkeypatch) -> None:
    migration = _load_migration()
    connection = _Connection()
    monkeypatch.setattr(migration.op, "get_bind", lambda: connection)

    migration.upgrade()

    assert len(connection.statements) == 2
    registry, templates = connection.statements
    assert "credential_template_service.wallet_registry" in registry
    assert "dc+sd-jwt" in registry
    assert "mso_mdoc" in registry
    assert "wr-spruce-001" in registry
    assert "credential_template_service.credential_templates" in templates
    assert "- 'format_variant'" in templates
    assert "- 'credential_configuration_id'" in templates
    assert "- 'issuer_url_suffix'" in templates
    assert "spruce-vc+sd-jwt" in templates
    assert "#spruce-sd-jwt" in templates
    assert "'/spruce'" in templates


def test_downgrade_refuses_to_restore_nonstandard_protocol_aliases() -> None:
    migration = _load_migration()

    with pytest.raises(RuntimeError, match="one-way protocol repair"):
        migration.downgrade()
