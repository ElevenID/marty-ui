"""
Migration management CLI for trust-profile service.

Provides commands for managing database migrations using Alembic.
"""

import argparse
import os
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from marty_common.migration import AlembicMigrationAdapter


SERVICE_NAME = "trust_profile"  # Use underscore format for schema


def main():
    parser = argparse.ArgumentParser(description="Manage database migrations for trust-profile service")
    parser.add_argument("command", choices=["init", "create", "upgrade", "downgrade", "current", "history", "verify"],
                       help="Migration command to execute")
    parser.add_argument("-m", "--message", help="Migration message (for create command)")
    parser.add_argument("-r", "--revision", default="head", help="Target revision (for upgrade/downgrade)")
    
    args = parser.parse_args()
    
    # Get database URL from environment
    db_url = os.environ.get(
        "DATABASE_URL",
        "postgresql+asyncpg://marty:marty_dev@localhost:5432/marty_credentials"
    )
    
    # Import metadata from models
    from infrastructure.models import mapper_registry
    
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
            print("✅ Upgraded to", args.revision)
            
        elif args.command == "downgrade":
            adapter.initialize(SERVICE_NAME, migrations_dir)
            print(f"Downgrading to {args.revision}...")
            adapter.downgrade(args.revision)
            print("✅ Downgraded to", args.revision)
            
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
            print("Migration history:")
            for entry in history:
                print(f"  {entry}")
                
        elif args.command == "verify":
            adapter.initialize(SERVICE_NAME, migrations_dir)
            result = adapter.verify()
            if result:
                print("✅ No migration issues found")
            else:
                print("❌ Migration issues found")
                sys.exit(1)
                
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
