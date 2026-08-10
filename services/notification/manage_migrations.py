#!/usr/bin/env python3
"""Manage the Notification service's owned Alembic migration chain."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from marty_common.migration import AlembicMigrationAdapter

from notification.infrastructure.models import mapper_registry


def _adapter() -> AlembicMigrationAdapter:
    database_url = os.environ.get(
        "DATABASE_URL",
        "postgresql+asyncpg://marty:marty_dev@localhost:5432/marty_credentials",
    )
    database_url = database_url.replace(
        "postgresql+asyncpg://", "postgresql+psycopg2://"
    )
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
    adapter.initialize("notification", migrations_dir)
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
