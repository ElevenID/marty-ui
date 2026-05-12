#!/usr/bin/env python3
"""
CLI tool for managing Alembic migrations for deployment_profile service.
"""

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from infrastructure.models import mapper_registry

from marty_common.migration import AlembicMigrationAdapter


SERVICE_NAME = "deployment_profile"


def main() -> None:
    parser = argparse.ArgumentParser(description="Manage Alembic migrations for deployment_profile service")
    parser.add_argument(
        "command",
        choices=["init", "create", "upgrade", "downgrade", "current", "history", "verify"],
        help="Migration command to execute",
    )
    parser.add_argument("-m", "--message", help="Migration message (required for create)")
    parser.add_argument("-r", "--revision", default="head", help="Revision to upgrade/downgrade to")
    args = parser.parse_args()

    db_url = os.environ.get(
        "DATABASE_URL",
        "postgresql+asyncpg://marty:marty_dev@localhost:5432/marty_credentials",
    )

    migrations_dir = Path(__file__).parent / "infrastructure" / "migrations"
    adapter = AlembicMigrationAdapter(database_url=db_url, metadata=mapper_registry.metadata)

    try:
        if args.command == "init":
            adapter.initialize(SERVICE_NAME, migrations_dir)
            print("Initialized migrations")
        elif args.command == "create":
            if not args.message:
                print("Error: --message is required for create")
                sys.exit(1)
            adapter.initialize(SERVICE_NAME, migrations_dir)
            revision_id = adapter.create_migration(args.message)
            print(f"Created migration: {revision_id}")
        elif args.command == "upgrade":
            adapter.initialize(SERVICE_NAME, migrations_dir)
            adapter.upgrade(args.revision)
            print(f"Upgraded to {args.revision}")
        elif args.command == "downgrade":
            adapter.initialize(SERVICE_NAME, migrations_dir)
            adapter.downgrade(args.revision)
            print(f"Downgraded to {args.revision}")
        elif args.command == "current":
            adapter.initialize(SERVICE_NAME, migrations_dir)
            print(adapter.current() or "No migrations applied")
        elif args.command == "history":
            adapter.initialize(SERVICE_NAME, migrations_dir)
            for entry in adapter.history():
                print(entry)
        elif args.command == "verify":
            adapter.initialize(SERVICE_NAME, migrations_dir)
            if adapter.verify():
                print("No migration issues found")
            else:
                print("Migration issues found")
                sys.exit(1)
    except Exception as exc:
        print(f"Migration command failed: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
