#!/usr/bin/env python3
"""
Credential Template Service - Migration Management CLI

Manages Alembic migrations for the credential-template service using MMF framework.
"""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(project_root))

from mmf.framework.infrastructure.migration import AlembicMigrationAdapter, MigrationError


def main():
    """Run migration commands."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Manage credential-template service migrations")
    parser.add_argument("command", choices=["init", "create", "upgrade", "downgrade", "current", "history", "verify"])
    parser.add_argument("-m", "--message", help="Migration message (for create)")
    parser.add_argument("-r", "--revision", default="head", help="Target revision (for upgrade/downgrade)")
    
    args = parser.parse_args()
    
    # Configuration
    service_dir = Path(__file__).parent
    migrations_dir = service_dir / "infrastructure" / "migrations"
    service_name = "credential_template"  # Use underscore for schema names
    
    # Database URL from environment or default
    import os
    database_url = os.environ.get(
        "DATABASE_URL",
        "postgresql+asyncpg://marty:marty@localhost:5432/marty"
    )
    
    # Convert asyncpg to psycopg2 for Alembic (it's synchronous)
    database_url = database_url.replace("postgresql+asyncpg://", "postgresql://")
    
    # Import metadata from models
    from infrastructure.models import metadata
    
    # Create migration adapter
    adapter = AlembicMigrationAdapter(
        database_url=database_url,
        metadata=metadata,
    )
    
    # Initialize for all commands except init
    if args.command != "init":
        adapter.initialize(service_name, migrations_dir)
    
    try:
        if args.command == "init":
            print(f"Initializing migrations in {migrations_dir}...")
            adapter.initialize(service_name, migrations_dir)
            print("✅ Migrations initialized")
        
        elif args.command == "create":
            if not args.message:
                print("ERROR: --message required for create command")
                sys.exit(1)
            print(f"Creating migration: {args.message}...")
            revision_id = adapter.create_migration(args.message)
            print(f"✅ Created migration: {revision_id}")
        
        elif args.command == "upgrade":
            print(f"Upgrading to {args.revision}...")
            adapter.upgrade(args.revision)
            print(f"✅ Upgraded to {args.revision}")
        
        elif args.command == "downgrade":
            print(f"Downgrading to {args.revision}...")
            adapter.downgrade(args.revision)
            print(f"✅ Downgraded to {args.revision}")
        
        elif args.command == "current":
            current = adapter.current()
            if current:
                print(f"Current revision: {current}")
            else:
                print("No migrations applied yet")
        
        elif args.command == "history":
            history = adapter.history()
            if history:
                print("Migration history:")
                for rev in history:
                    print(f"  {rev}")
            else:
                print("No migration history")
        
        elif args.command == "verify":
            print("Verifying schema...")
            is_valid = adapter.verify_schema()
            if is_valid:
                print("✅ Schema is up to date")
            else:
                print("❌ Schema is out of sync - migrations needed")
                sys.exit(1)
    
    except MigrationError as e:
        print(f"❌ Migration error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

