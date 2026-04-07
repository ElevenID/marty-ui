"""
Organization Service Migration Management

This module provides migration management for the organization service using
the MMF framework's migration infrastructure. It follows hexagonal architecture:
- Uses MigrationManagerPort interface (application layer)
- Implemented by AlembicMigrationAdapter (infrastructure layer)
"""

import os
import sys
from pathlib import Path

# Add parent directories to path for imports
service_root = Path(__file__).parent.parent
sys.path.insert(0, str(service_root.parent))

from marty_common.migration import (
    AlembicMigrationAdapter,
    MigrationError,
)
from infrastructure.models import mapper_registry


def get_migration_adapter() -> AlembicMigrationAdapter:
    """Create and return configured migration adapter."""
    database_url = os.getenv(
        "DATABASE_URL",
        "postgresql+asyncpg://marty:marty_dev@localhost:5432/marty_credentials",
    )
    
    # Convert asyncpg URL to sync for Alembic
    sync_url = database_url.replace("+asyncpg", "")
    
    adapter = AlembicMigrationAdapter(
        database_url=sync_url,
        metadata=mapper_registry.metadata,
    )
    
    migrations_dir = service_root / "infrastructure" / "migrations"
    adapter.initialize(service_name="organization", migrations_dir=migrations_dir)
    
    return adapter


def main():
    """Main entry point for migration commands."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Manage organization service migrations")
    subparsers = parser.add_subparsers(dest="command", help="Migration command")
    
    # Init command
    subparsers.add_parser("init", help="Initialize migration infrastructure")
    
    # Create migration command
    create_parser = subparsers.add_parser("create", help="Create a new migration")
    create_parser.add_argument("message", help="Migration message")
    create_parser.add_argument(
        "--manual",
        action="store_true",
        help="Create empty migration (no autogenerate)",
    )
    
    # Upgrade command
    upgrade_parser = subparsers.add_parser("upgrade", help="Apply migrations")
    upgrade_parser.add_argument(
        "revision",
        nargs="?",
        default="head",
        help="Target revision (default: head)",
    )
    
    # Downgrade command
    downgrade_parser = subparsers.add_parser("downgrade", help="Rollback migrations")
    downgrade_parser.add_argument("revision", help="Target revision")
    
    # Current command
    subparsers.add_parser("current", help="Show current revision")
    
    # History command
    history_parser = subparsers.add_parser("history", help="Show migration history")
    history_parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show detailed information",
    )
    
    # Verify command
    subparsers.add_parser("verify", help="Verify schema is up-to-date")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    try:
        adapter = get_migration_adapter()
        
        if args.command == "init":
            print("✓ Migration infrastructure initialized")
            print(f"  Location: {service_root / 'infrastructure' / 'migrations'}")
            
        elif args.command == "create":
            autogenerate = not args.manual
            migration_path = adapter.create_migration(
                message=args.message,
                autogenerate=autogenerate,
            )
            if migration_path:
                print(f"✓ Created migration: {migration_path}")
            else:
                print("No changes detected")
                
        elif args.command == "upgrade":
            adapter.upgrade(revision=args.revision)
            print(f"✓ Upgraded to: {args.revision}")
            
        elif args.command == "downgrade":
            adapter.downgrade(revision=args.revision)
            print(f"✓ Downgraded to: {args.revision}")
            
        elif args.command == "current":
            current = adapter.current()
            if current:
                print(f"Current revision: {current}")
            else:
                print("No migrations applied")
                
        elif args.command == "history":
            history = adapter.history(verbose=args.verbose)
            if history:
                print("Migration history:")
                for rev in history:
                    print(f"  {rev}")
            else:
                print("No migrations found")
                
        elif args.command == "verify":
            is_valid = adapter.verify_schema(raise_on_mismatch=False)
            if is_valid:
                print("✓ Schema is up-to-date")
            else:
                print("✗ Schema is outdated - run migrations")
                sys.exit(1)
                
    except MigrationError as e:
        print(f"✗ Migration error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"✗ Unexpected error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
