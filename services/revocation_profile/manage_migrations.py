"""
Migration management CLI for revocation-profile service.
"""

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from marty_common.migration import AlembicMigrationAdapter

SERVICE_NAME = "revocation_profile"


def main():
    parser = argparse.ArgumentParser(description="Manage database migrations for revocation-profile service")
    parser.add_argument("command", choices=["init", "create", "upgrade", "downgrade", "current", "history", "verify"])
    parser.add_argument("-m", "--message", help="Migration message (for create command)")
    parser.add_argument("-r", "--revision", default="head")

    args = parser.parse_args()

    db_url = os.environ.get(
        "DATABASE_URL",
        "postgresql+asyncpg://marty:marty_dev@localhost:5432/marty_credentials"
    )

    from infrastructure.models import mapper_registry

    migrations_dir = Path(__file__).parent / "infrastructure" / "migrations"

    adapter = AlembicMigrationAdapter(
        database_url=db_url,
        metadata=mapper_registry.metadata,
    )

    try:
        if args.command == "upgrade":
            adapter.initialize(SERVICE_NAME, migrations_dir)
            adapter.upgrade(args.revision)
            print("✅ Upgraded to", args.revision)
        elif args.command == "current":
            adapter.initialize(SERVICE_NAME, migrations_dir)
            print(adapter.current())
        elif args.command == "history":
            adapter.initialize(SERVICE_NAME, migrations_dir)
            for entry in adapter.history():
                print(f"  {entry}")
        elif args.command == "verify":
            adapter.initialize(SERVICE_NAME, migrations_dir)
            if not adapter.verify():
                sys.exit(1)
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
