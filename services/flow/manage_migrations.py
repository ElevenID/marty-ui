#!/usr/bin/env python3
"""
CLI tool for managing Alembic migrations for flow service.

Usage:
    python manage_migrations.py init              # Initialize Alembic
    python manage_migrations.py create -m "msg"   # Create new migration
    python manage_migrations.py upgrade           # Apply all migrations
    python manage_migrations.py downgrade         # Rollback one migration
    python manage_migrations.py current           # Show current revision
    python manage_migrations.py history           # Show migration history
    python manage_migrations.py verify            # Verify migrations
"""

import sys
import os
import argparse
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from infrastructure.models import mapper_registry

# Import AlembicMigrationAdapter from MMF
from mmf.framework.infrastructure.migration import AlembicMigrationAdapter


SERVICE_NAME = "flow"  # Will be appended with "_service" to match schema


def main():
    parser = argparse.ArgumentParser(description="Manage Alembic migrations for flow service")
    parser.add_argument("command", choices=["init", "create", "upgrade", "downgrade", "current", "history", "verify"],
                        help="Migration command to execute")
    parser.add_argument("-m", "--message", help="Migration message (required for 'create' command)")
    parser.add_argument("-r", "--revision", default="head", help="Revision to upgrade/downgrade to (default: head)")
    
    args = parser.parse_args()
    
    # Get database URL from environment
    db_url = os.environ.get(
        "DATABASE_URL",
        "postgresql://marty:marty_dev@localhost:5432/marty_credentials"
    )
    
    # Create migration adapter
    migrations_dir = Path(__file__).parent / "infrastructure" / "migrations"
    
    adapter = AlembicMigrationAdapter(
        database_url=db_url,
        metadata=mapper_registry.metadata
    )
    
    try:
        if args.command == "init":
            print(f"Initializing migrations in {migrations_dir}...")
            adapter.initialize(SERVICE_NAME, migrations_dir)
            print("✅ Migrations initialized")
            
        elif args.command == "create":
            if not args.message:
                print("❌ Error: --message is required for create command")
                sys.exit(1)
            adapter.initialize(SERVICE_NAME, migrations_dir)
            print(f"Creating migration: {args.message}")
            revision_id = adapter.create_migration(args.message)
            print(f"✅ Created migration: {revision_id}")
            
        elif args.command == "upgrade":
            adapter.initialize(SERVICE_NAME, migrations_dir)
            print(f"Upgrading to {args.revision}...")
            adapter.upgrade(args.revision)
            print(f"✅ Upgraded to {args.revision}")
            
        elif args.command == "downgrade":
            adapter.initialize(SERVICE_NAME, migrations_dir)
            print(f"Downgrading to {args.revision}...")
            adapter.downgrade(args.revision)
            print(f"✅ Downgraded to {args.revision}")
            
        elif args.command == "current":
            adapter.initialize(SERVICE_NAME, migrations_dir)
            current = adapter.current()
            if current:
                print(f"Current revision: {current}")
            else:
                print("No migrations applied yet")
            
        elif args.command == "history":
            adapter.initialize(SERVICE_NAME, migrations_dir)
            history = adapter.history()
            if history:
                print("Migration history:")
                for rev in history:
                    print(f"  {rev}")
            else:
                print("No migrations found")
            
        elif args.command == "verify":
            adapter.initialize(SERVICE_NAME, migrations_dir)
            print("Verifying migrations...")
            # Basic verification - check if migrations dir exists and has alembic.ini
            if (migrations_dir / "alembic.ini").exists():
                print("✅ Migrations directory is valid")
            else:
                raise Exception("Migrations directory is not initialized")
            
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
