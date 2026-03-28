"""
Billing Service Migration Management
"""

import os
import sys
from pathlib import Path

service_root = Path(__file__).parent.parent
sys.path.insert(0, str(service_root.parent))

from mmf.framework.infrastructure.migration import (
    AlembicMigrationAdapter,
    MigrationError,
)
from infrastructure.models import mapper_registry


def get_migration_adapter() -> AlembicMigrationAdapter:
    """Create and return configured migration adapter."""
    database_url = os.getenv(
        "DATABASE_URL",
        "postgresql+asyncpg://marty:martypass@localhost:5432/marty",
    )
    sync_url = database_url.replace("+asyncpg", "")

    adapter = AlembicMigrationAdapter(
        database_url=sync_url,
        metadata=mapper_registry.metadata,
    )

    migrations_dir = service_root / "infrastructure" / "migrations"
    adapter.initialize(service_name="billing", migrations_dir=migrations_dir)

    return adapter


def main():
    """Main entry point for migration commands."""
    import argparse

    parser = argparse.ArgumentParser(description="Manage billing service migrations")
    parser.add_argument("command", choices=["upgrade", "downgrade", "revision", "current", "history"])
    parser.add_argument("--revision", default="head", help="Target revision")
    parser.add_argument("--message", "-m", help="Revision message")

    args = parser.parse_args()
    adapter = get_migration_adapter()

    try:
        if args.command == "upgrade":
            adapter.upgrade(args.revision)
        elif args.command == "downgrade":
            adapter.downgrade(args.revision)
        elif args.command == "revision":
            adapter.create_revision(args.message or "auto")
        elif args.command == "current":
            adapter.current()
        elif args.command == "history":
            adapter.history()
    except MigrationError as e:
        print(f"Migration error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
