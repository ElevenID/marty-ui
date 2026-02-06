#!/usr/bin/env python3
"""
Migration Runner for All Marty-UI Services

This script runs database migrations for all microservices in the correct order.
It ensures that the database schema is up-to-date before services start.

Usage:
    python run_all_migrations.py [--verify-only]

Options:
    --verify-only    Check if migrations are up-to-date without applying them

Environment Variables:
    DATABASE_URL     PostgreSQL connection string (required)
"""

import os
import sys
from pathlib import Path
from sqlalchemy import create_engine, text

# Add services to path
services_root = Path(__file__).parent
sys.path.insert(0, str(services_root))

from mmf.framework.infrastructure.migration import (
    AlembicMigrationAdapter,
    MigrationError,
)


# Service configurations
SERVICES = [
    {
        "name": "organization",
        "module": "organization.infrastructure.models",
    },
    {
        "name": "auth",
        "module": "auth.infrastructure.models",
    },
    {
        "name": "credential_template",
        "module": "credential_template.infrastructure.models",
    },
    {
        "name": "trust_profile",
        "module": "trust_profile.infrastructure.models",
    },
    {
        "name": "issuance",
        "module": "issuance.infrastructure.models",
    },
    {
        "name": "presentation_policy",
        "module": "presentation_policy.infrastructure.models",
    },
    {
        "name": "flow",
        "module": "flow.infrastructure.models",
    },
]


def get_database_url() -> str:
    """Get database URL from environment."""
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        print("✗ Error: DATABASE_URL environment variable not set", file=sys.stderr)
        sys.exit(1)
    
    # Convert asyncpg URL to sync for Alembic
    return database_url.replace("+asyncpg", "")


def ensure_schemas(database_url: str) -> None:
    """Ensure all service schemas exist."""
    print("\n" + "="*60)
    print("Creating database schemas...")
    print("="*60)
    
    schemas = [
        "organization_service",
        "auth_service",
        "credential_template_service",
        "trust_profile_service",
        "issuance_service",
        "presentation_policy_service",
        "flow_service",
    ]
    
    engine = create_engine(database_url)
    try:
        with engine.connect() as conn:
            for schema in schemas:
                conn.execute(text(f"CREATE SCHEMA IF NOT EXISTS {schema}"))
                print(f"  ✓ {schema}")
            conn.commit()
        print("✓ All schemas ready")
    except Exception as e:
        print(f"✗ Error creating schemas: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        engine.dispose()


def run_service_migration(service_config: dict, database_url: str, verify_only: bool = False) -> bool:
    """Run migrations for a single service.
    
    Args:
        service_config: Service configuration dict with name and module
        database_url: Database connection URL
        verify_only: If True, only verify schema without applying migrations
        
    Returns:
        True if migrations successful/verified, False otherwise
    """
    service_name = service_config["name"]
    module_name = service_config["module"]
    
    print(f"\n{'='*60}")
    print(f"Service: {service_name}")
    print(f"{'='*60}")
    
    try:
        # Import service models
        module = __import__(module_name, fromlist=["mapper_registry"])
        mapper_registry = module.mapper_registry
        
        # Create migration adapter
        adapter = AlembicMigrationAdapter(
            database_url=database_url,
            metadata=mapper_registry.metadata,
        )
        
        # Initialize migrations directory (creates alembic.ini, env.py, etc. if they don't exist)
        migrations_dir = services_root / service_name / "infrastructure" / "migrations"
        
        # Only initialize if migrations directory doesn't have required files
        if not (migrations_dir / "alembic.ini").exists() or not (migrations_dir / "env.py").exists():
            adapter.initialize(service_name=service_name, migrations_dir=migrations_dir)
        else:
            # Manually configure the adapter to use existing migration infrastructure
            adapter._service_name = service_name
            adapter._migrations_dir = migrations_dir
            alembic_ini_path = migrations_dir / "alembic.ini"
            
            from alembic.config import Config
            adapter.alembic_cfg = Config(str(alembic_ini_path))
            adapter.alembic_cfg.set_main_option("script_location", str(migrations_dir))
            adapter.alembic_cfg.set_main_option("sqlalchemy.url", database_url)
            adapter.alembic_cfg.attributes["target_metadata"] = mapper_registry.metadata
        
        if verify_only:
            # Verify schema is up-to-date
            is_valid = adapter.verify_schema(raise_on_mismatch=False)
            if is_valid:
                print(f"✓ {service_name}: Schema is up-to-date")
                return True
            else:
                print(f"✗ {service_name}: Schema is outdated")
                return False
        else:
            # Apply migrations
            current = adapter.current()
            print(f"  Current revision: {current or 'None'}")
            
            # Check if there are any migrations to apply
            from alembic.script import ScriptDirectory
            script_dir = ScriptDirectory.from_config(adapter.alembic_cfg)
            head = script_dir.get_current_head()
            print(f"  Head revision: {head or 'None'}")
            
            if not head:
                print(f"⚠ {service_name}: No migration files found in versions directory")
                print(f"  Versions directory: {migrations_dir / 'versions'}")
            elif current != head:
                # Run migrations when current doesn't match head
                # This includes the case when current is None (first run)
                adapter.upgrade(revision="head")
                new_current = adapter.current()
                print(f"  New revision: {new_current or 'None'}")
                print(f"✓ {service_name}: Migrations applied successfully")
            else:
                print(f"  Already up-to-date")
                print(f"✓ {service_name}: No migrations needed")
            
            return True
            
    except ImportError as e:
        print(f"⚠ {service_name}: No models module found ({e}), skipping...")
        return True  # Not an error if service doesn't have migrations yet
        
    except MigrationError as e:
        print(f"✗ {service_name}: Migration error: {e}", file=sys.stderr)
        return False
        
    except Exception as e:
        print(f"✗ {service_name}: Unexpected error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return False


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Run migrations for all Marty-UI services"
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Only verify migrations are up-to-date without applying",
    )
    
    args = parser.parse_args()
    
    # Get database URL
    database_url = get_database_url()
    
    print("="*60)
    print("MARTY-UI DATABASE MIGRATION RUNNER")
    print("="*60)
    print(f"Database: {database_url.split('@')[1] if '@' in database_url else database_url}")
    print(f"Mode: {'Verify Only' if args.verify_only else 'Apply Migrations'}")
    
    # Ensure schemas exist first
    if not args.verify_only:
        ensure_schemas(database_url)
    
    # Run migrations for each service
    success_count = 0
    failure_count = 0
    
    for service_config in SERVICES:
        success = run_service_migration(service_config, database_url, args.verify_only)
        if success:
            success_count += 1
        else:
            failure_count += 1
    
    # Print summary
    print(f"\n{'='*60}")
    print("MIGRATION SUMMARY")
    print(f"{'='*60}")
    print(f"Total services: {len(SERVICES)}")
    print(f"✓ Successful: {success_count}")
    print(f"✗ Failed: {failure_count}")
    
    if failure_count > 0:
        print(f"\n✗ {failure_count} service(s) failed migration")
        sys.exit(1)
    else:
        print(f"\n✓ All migrations completed successfully")
        sys.exit(0)


if __name__ == "__main__":
    main()
