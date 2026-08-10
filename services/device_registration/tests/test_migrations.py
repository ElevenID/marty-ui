"""Marty-owned contracts for Device Registration migration ownership."""

from __future__ import annotations

import ast
import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest

from services.device_registration import main as device
from services.device_registration.infrastructure.models import (
    device_registration_keys,
    mapper_registry,
)

MIGRATIONS = Path(__file__).resolve().parents[1] / "infrastructure" / "migrations"
ROOT = Path(__file__).resolve().parents[3]
REVISION = MIGRATIONS / "versions" / "20260809_0001_version_device_keys.py"


def _load_revision():
    spec = importlib.util.spec_from_file_location("version_device_keys", REVISION)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_device_registration_migration_graph_has_exactly_one_head() -> None:
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

    assert revisions - parents == {"20260809_0001"}


def test_runtime_model_has_immutable_version_and_single_current_constraints() -> None:
    constraint_names = {
        constraint.name for constraint in device_registration_keys.constraints
    }
    index_names = {index.name for index in device_registration_keys.indexes}

    assert "uq_device_key_registration_version" in constraint_names
    assert "ck_device_key_version_range" in constraint_names
    assert "ck_device_key_kid_length" in constraint_names
    assert "ck_device_key_state" in constraint_names
    assert "ux_device_key_one_current" in index_names


def test_device_migration_generates_backfill_and_atomicity_ddl_offline() -> None:
    code = f"""
import logging
from alembic import command
from alembic.config import Config
from device_registration.infrastructure.models import mapper_registry
probe_logger = logging.getLogger('marty.device-migration.probe')
config = Config({str(MIGRATIONS / "alembic.ini")!r})
config.set_main_option('script_location', {str(MIGRATIONS)!r})
config.set_main_option('sqlalchemy.url', 'postgresql+psycopg2://user:pass@localhost/db')
config.attributes['target_metadata'] = mapper_registry.metadata
command.upgrade(config, 'head', sql=True)
print(f'probe_logger_disabled={{probe_logger.disabled}}')
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
    assert "device_registration_keys" in result.stdout
    assert "ux_device_key_one_current" in result.stdout
    assert "key_version = 1" in result.stdout
    assert "device_key_transitions" in result.stdout
    assert "probe_logger_disabled=False" in result.stdout


def test_device_startup_requires_owned_migration_and_versioned_projection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = {
        table.name
        for table in mapper_registry.metadata.tables.values()
        if table.schema == "device_registration_service"
    }

    class Inspector:
        def __init__(self, tables: set[str], columns: set[str]) -> None:
            self.tables = tables
            self.columns = columns

        def get_table_names(self, *, schema: str) -> list[str]:
            assert schema == "device_registration_service"
            return sorted(self.tables)

        def get_columns(self, table: str, *, schema: str) -> list[dict[str, str]]:
            assert table == "device_registrations"
            assert schema == "device_registration_service"
            return [{"name": name} for name in sorted(self.columns)]

    monkeypatch.setattr(
        device,
        "inspect",
        lambda _connection: Inspector(
            expected | {"alembic_version"}, {"id", "key_version"}
        ),
    )
    device._require_migrated_device_schema(object())

    monkeypatch.setattr(
        device,
        "inspect",
        lambda _connection: Inspector(expected, {"id", "key_version"}),
    )
    with pytest.raises(RuntimeError, match="version table"):
        device._require_migrated_device_schema(object())

    monkeypatch.setattr(
        device,
        "inspect",
        lambda _connection: Inspector(expected | {"alembic_version"}, {"id"}),
    )
    with pytest.raises(RuntimeError, match="key projection"):
        device._require_migrated_device_schema(object())


def test_versioned_key_history_downgrade_is_irreversible() -> None:
    with pytest.raises(RuntimeError, match="cannot be safely discarded"):
        _load_revision().downgrade()
