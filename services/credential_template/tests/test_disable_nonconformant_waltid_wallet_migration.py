from __future__ import annotations

import importlib.util
import pathlib
import sys
from types import SimpleNamespace


class _Result:
    def scalar(self):
        return 1


class _Connection:
    def __init__(self):
        self.calls = []

    def execute(self, statement, parameters=None):
        self.calls.append((str(statement), parameters or {}))
        return _Result()


def _load_migration(connection):
    sys.modules["alembic"] = SimpleNamespace(op=SimpleNamespace(get_bind=lambda: connection))
    path = (
        pathlib.Path(__file__).parents[1]
        / "infrastructure"
        / "migrations"
        / "versions"
        / "20260712_0001_disable_nonconformant_waltid_wallet.py"
    )
    spec = importlib.util.spec_from_file_location("disable_nonconformant_waltid_wallet", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_upgrade_deactivates_waltid_wallet() -> None:
    connection = _Connection()
    migration = _load_migration(connection)

    migration.upgrade()

    statement, parameters = connection.calls[-1]
    assert "SET is_active = :active" in statement
    assert parameters == {"active": False, "wallet_id": "wr-waltid-001"}


def test_downgrade_reactivates_waltid_wallet() -> None:
    connection = _Connection()
    migration = _load_migration(connection)

    migration.downgrade()

    assert connection.calls[-1][1]["active"] is True
