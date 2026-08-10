from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace


MIGRATION_PATH = (
    Path(__file__).resolve().parents[1]
    / "infrastructure"
    / "migrations"
    / "versions"
    / "20260802_0001_drop_cached_custody_routing.py"
)


def _load_migration():
    spec = importlib.util.spec_from_file_location(
        "drop_cached_custody_routing",
        MIGRATION_PATH,
    )
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def test_upgrade_drops_every_cached_private_custody_selector(monkeypatch) -> None:
    migration = _load_migration()
    dropped: list[tuple[str, str, str | None]] = []
    monkeypatch.setattr(
        migration,
        "op",
        SimpleNamespace(
            drop_column=lambda table, column, schema=None: dropped.append(
                (table, column, schema)
            )
        ),
    )

    migration.upgrade()

    assert dropped == [
        ("credential_templates", "auto_generate_artifacts", "credential_template_service"),
        ("credential_templates", "issuer_certificate_chain_pem", "credential_template_service"),
        ("credential_templates", "remote_signing_config", "credential_template_service"),
        ("credential_templates", "issuer_key_id", "credential_template_service"),
        ("credential_templates", "key_access_mode", "credential_template_service"),
        ("credential_templates", "issuer_profile_id", "credential_template_service"),
    ]


def test_downgrade_restores_nullable_columns_without_reconstructing_routing(
    monkeypatch,
) -> None:
    migration = _load_migration()
    added: list[tuple[str, str, str | None, bool]] = []

    def record(table, column, schema=None):
        added.append((table, column.name, schema, column.nullable))

    monkeypatch.setattr(migration, "op", SimpleNamespace(add_column=record))

    migration.downgrade()

    assert added == [
        ("credential_templates", "issuer_certificate_chain_pem", "credential_template_service", True),
        ("credential_templates", "auto_generate_artifacts", "credential_template_service", False),
        ("credential_templates", "issuer_profile_id", "credential_template_service", True),
        ("credential_templates", "key_access_mode", "credential_template_service", True),
        ("credential_templates", "issuer_key_id", "credential_template_service", True),
        ("credential_templates", "remote_signing_config", "credential_template_service", True),
    ]
