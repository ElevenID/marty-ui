#!/usr/bin/env python3
"""Manage the Device Registration service's owned Alembic migrations."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from device_registration.infrastructure.models import mapper_registry
from marty_common.migration import AlembicMigrationAdapter


def _adapter() -> AlembicMigrationAdapter:
    database_url = os.environ.get(
        "DATABASE_URL",
        "postgresql+asyncpg://marty:marty_dev@localhost:5432/marty_credentials",
    ).replace("postgresql+asyncpg://", "postgresql+psycopg2://")
    return AlembicMigrationAdapter(
        database_url=database_url,
        metadata=mapper_registry.metadata,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=["upgrade", "downgrade", "current", "history", "verify"],
    )
    parser.add_argument("--revision", default="head")
    args = parser.parse_args()

    adapter = _adapter()
    migrations_dir = Path(__file__).parent / "infrastructure" / "migrations"
    adapter.initialize("device_registration", migrations_dir)
    if args.command == "upgrade":
        adapter.upgrade(args.revision)
    elif args.command == "downgrade":
        adapter.downgrade(args.revision)
    elif args.command == "current":
        adapter.current()
    elif args.command == "history":
        adapter.history()
    else:
        adapter.verify_schema()


if __name__ == "__main__":
    main()
