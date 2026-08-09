"""Marty-owned contracts for Notification schema ownership and cleanup."""

from __future__ import annotations

import ast
import importlib.util
import os
from pathlib import Path
import subprocess
import sys

import pytest

from notification.infrastructure.models import (
    mapper_registry,
    webhook_deliveries,
    webhook_endpoints,
)
from services.notification import main as notification


MIGRATIONS = (
    Path(__file__).resolve().parents[1] / "infrastructure" / "migrations"
)
ROOT = Path(__file__).resolve().parents[3]
REVISION = MIGRATIONS / "versions" / "20260808_0001_adopt_notification_schema.py"
ENVELOPE_REVISION = (
    MIGRATIONS / "versions" / "20260808_0002_protect_webhook_secrets.py"
)


def _load_revision():
    spec = importlib.util.spec_from_file_location("notification_schema_adoption", REVISION)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_notification_migration_graph_has_exactly_one_head() -> None:
    revisions: set[str] = set()
    parents: set[str] = set()
    for path in (MIGRATIONS / "versions").glob("*.py"):
        if path.name == "__init__.py":
            continue
        assignments = {
            node.targets[0].id: ast.literal_eval(node.value)
            for node in ast.parse(path.read_text(encoding="utf-8")).body
            if isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id in {"revision", "down_revision"}
        }
        revisions.add(assignments["revision"])
        if assignments["down_revision"] is not None:
            parents.add(assignments["down_revision"])

    assert revisions - parents == {"20260808_0002"}


def test_owned_schema_and_initial_revision_forbid_receiver_body_storage() -> None:
    revision = _load_revision()
    migrated_delivery = revision._owned_metadata().tables[
        "notification_service.webhook_deliveries"
    ]

    assert "response_body" not in webhook_deliveries.c
    assert "response_body" not in migrated_delivery.c


def test_adoption_downgrade_cannot_recreate_deleted_receiver_data() -> None:
    with pytest.raises(RuntimeError, match="irreversible"):
        _load_revision().downgrade()


def test_owned_schema_head_forbids_plaintext_webhook_secret_storage() -> None:
    assert "secret" not in webhook_endpoints.c
    assert "secret_envelope" in webhook_endpoints.c
    assert "secret_hint" in webhook_endpoints.c
    source = ENVELOPE_REVISION.read_text(encoding="utf-8")
    assert 'op.drop_column(TABLE, "secret"' in source
    assert "online migration required to protect webhook secrets" in source


def test_notification_migration_generates_offline_sql_in_isolation() -> None:
    code = f"""
from alembic import command
from alembic.config import Config
from notification.infrastructure.models import mapper_registry
config = Config({str(MIGRATIONS / 'alembic.ini')!r})
config.set_main_option('script_location', {str(MIGRATIONS)!r})
config.set_main_option('sqlalchemy.url', 'postgresql+psycopg2://user:pass@localhost/db')
config.attributes['target_metadata'] = mapper_registry.metadata
command.upgrade(config, 'head', sql=True)
"""
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join(
        [str(ROOT), str(ROOT / "services"), str(ROOT / "packages")]
    )

    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "CREATE SCHEMA IF NOT EXISTS notification_service" in result.stdout
    assert "DROP COLUMN IF EXISTS response_body" in result.stdout
    assert "online migration required to protect webhook secrets" in result.stdout
    assert "DROP COLUMN secret" in result.stdout


def test_notification_startup_requires_versioned_clean_schema(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = {
        table.name
        for table in mapper_registry.metadata.tables.values()
        if table.schema == "notification_service"
    }

    class Inspector:
        def __init__(
            self,
            tables: set[str],
            *,
            retains_body: bool = False,
            retains_plaintext_secret: bool = False,
        ) -> None:
            self.tables = tables
            self.retains_body = retains_body
            self.retains_plaintext_secret = retains_plaintext_secret

        def get_table_names(self, *, schema: str) -> list[str]:
            assert schema == "notification_service"
            return sorted(self.tables)

        def get_columns(self, table: str, *, schema: str) -> list[dict[str, str]]:
            assert schema == "notification_service"
            if table == "webhook_endpoints":
                columns = [
                    {"name": "id"},
                    {"name": "secret_envelope"},
                    {"name": "secret_hint"},
                ]
                if self.retains_plaintext_secret:
                    columns.append({"name": "secret"})
                return columns
            assert table == "webhook_deliveries"
            columns = [{"name": "id"}]
            if self.retains_body:
                columns.append({"name": "response_body"})
            return columns

    monkeypatch.setattr(
        notification,
        "inspect",
        lambda _connection: Inspector(expected | {"alembic_version"}),
    )
    notification._require_migrated_notification_schema(object())

    monkeypatch.setattr(
        notification,
        "inspect",
        lambda _connection: Inspector(expected | {"alembic_version"}, retains_body=True),
    )
    with pytest.raises(RuntimeError, match="receiver-body retention"):
        notification._require_migrated_notification_schema(object())

    monkeypatch.setattr(
        notification,
        "inspect",
        lambda _connection: Inspector(
            expected | {"alembic_version"}, retains_plaintext_secret=True
        ),
    )
    with pytest.raises(RuntimeError, match="plaintext webhook secrets"):
        notification._require_migrated_notification_schema(object())

    monkeypatch.setattr(
        notification,
        "inspect",
        lambda _connection: Inspector(expected - {"webhook_outbox"}),
    )
    with pytest.raises(RuntimeError, match="webhook_outbox"):
        notification._require_migrated_notification_schema(object())
