#!/usr/bin/env python3
"""
Auth Service Migration Management

CLI tool for managing Alembic database migrations using MMF framework.
"""

import os
import sys
from pathlib import Path

# Add service to Python path
service_root = Path(__file__).parent
sys.path.insert(0, str(service_root))

from mmf.framework.infrastructure.migration import AlembicMigrationAdapter
from infrastructure.models import mapper_registry

# Configuration
SERVICE_NAME = "auth"  # Framework will append "_service"
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://marty:marty_dev@localhost:5432/marty_credentials"
)

# Convert asyncpg URL to psycopg2 for Alembic (synchronous)
SYNC_DATABASE_URL = DATABASE_URL.replace("postgresql+asyncpg://", "postgresql+psycopg2://")

def get_adapter() -> AlembicMigrationAdapter:
    """Create and return the migration adapter."""
    return AlembicMigrationAdapter(
        database_url=SYNC_DATABASE_URL,
        metadata=mapper_registry.metadata
    )


def main():
    """Main CLI entry point."""
    if len(sys.argv) < 2:
        print("Usage: python manage_migrations.py <command> [options]")
        print("\nCommands:")
        print("  init                    - Initialize Alembic configuration")
        print("  create -m 'message'     - Create a new migration")
        print("  upgrade [revision]      - Upgrade to revision (default: head)")
        print("  downgrade <revision>    - Downgrade to revision")
        print("  current                 - Show current revision")
        print("  history                 - Show migration history")
        print("  show <revision>         - Show migration details")
        sys.exit(1)
    
    command = sys.argv[1]
    adapter = get_adapter()
    
    migrations_dir = service_root / "infrastructure" / "migrations"
    
    try:
        if command == "init":
            print(f"Initializing Alembic for {SERVICE_NAME} service...")
            adapter.initialize(SERVICE_NAME, str(migrations_dir))
            print(f"✅ Alembic initialized in {migrations_dir}")
            print(f"   Schema: {SERVICE_NAME}_service")
            
        elif command == "create":
            if "-m" not in sys.argv:
                print("Error: -m flag with message required")
                print("Usage: python manage_migrations.py create -m 'migration message'")
                sys.exit(1)
            
            message_idx = sys.argv.index("-m") + 1
            if message_idx >= len(sys.argv):
                print("Error: No message provided after -m")
                sys.exit(1)
            
            message = sys.argv[message_idx]
            print(f"Creating migration: {message}")
            adapter.initialize(SERVICE_NAME, str(migrations_dir))
            revision_id = adapter.create_migration(message)
            print(f"✅ Created migration: {revision_id}")
            
        elif command == "upgrade":
            revision = sys.argv[2] if len(sys.argv) > 2 else "head"
            print(f"Upgrading to {revision}...")
            adapter.initialize(SERVICE_NAME, str(migrations_dir))
            adapter.upgrade(revision)
            print(f"✅ Upgraded to {revision}")
            
        elif command == "downgrade":
            if len(sys.argv) < 3:
                print("Error: Revision required for downgrade")
                print("Usage: python manage_migrations.py downgrade <revision>")
                sys.exit(1)
            
            revision = sys.argv[2]
            print(f"Downgrading to {revision}...")
            adapter.initialize(SERVICE_NAME, str(migrations_dir))
            adapter.downgrade(revision)
            print(f"✅ Downgraded to {revision}")
            
        elif command == "current":
            print("Getting current revision...")
            adapter.initialize(SERVICE_NAME, str(migrations_dir))
            adapter.current()
            
        elif command == "history":
            print("Migration history:")
            adapter.initialize(SERVICE_NAME, str(migrations_dir))
            adapter.history()
            
        elif command == "show":
            if len(sys.argv) < 3:
                print("Error: Revision required")
                print("Usage: python manage_migrations.py show <revision>")
                sys.exit(1)
            
            revision = sys.argv[2]
            adapter.initialize(SERVICE_NAME, str(migrations_dir))
            adapter.show(revision)
            
        else:
            print(f"Unknown command: {command}")
            sys.exit(1)
            
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
