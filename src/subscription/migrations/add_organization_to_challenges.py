"""
Database Migration: Add organization_id to push_challenges

Adds organization_id column to the push_challenges table for multi-tenant isolation.
This enables:
  - Proper tenant isolation in PostgreSQL
  - Authorization checks based on organization membership
  - Consistent multi-tenancy with Redis hash tag patterns
  - Audit trail and compliance requirements

Run this migration with:
  python -m marty-ui.src.subscription.migrations.add_organization_to_challenges

Or manually execute the SQL:
  psql -U marty -d marty_applicants -f this_file.sql
"""

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


async def upgrade(session: AsyncSession) -> None:
    """Add organization_id column to push_challenges table."""
    
    # Add organization_id column (nullable initially for existing data)
    await session.execute(text("""
        ALTER TABLE push_challenges
        ADD COLUMN IF NOT EXISTS organization_id VARCHAR(36);
    """))
    
    # Add foreign key constraint to organizations table
    await session.execute(text("""
        ALTER TABLE push_challenges
        ADD CONSTRAINT fk_push_challenges_organization
        FOREIGN KEY (organization_id)
        REFERENCES organizations(id)
        ON DELETE CASCADE;
    """))
    
    # Create index for efficient org-scoped queries
    await session.execute(text("""
        CREATE INDEX IF NOT EXISTS idx_push_challenges_organization_id
        ON push_challenges(organization_id);
    """))
    
    # Backfill organization_id from device_registrations
    # For existing challenges, set org from the associated device
    await session.execute(text("""
        UPDATE push_challenges pc
        SET organization_id = dr.organization_id
        FROM device_registrations dr
        WHERE pc.device_id = dr.device_id
        AND pc.organization_id IS NULL;
    """))
    
    await session.commit()
    print("✅ Migration completed: Added organization_id to push_challenges")


async def downgrade(session: AsyncSession) -> None:
    """Remove organization_id column from push_challenges table."""
    
    # Drop index
    await session.execute(text("""
        DROP INDEX IF EXISTS idx_push_challenges_organization_id;
    """))
    
    # Drop foreign key constraint
    await session.execute(text("""
        ALTER TABLE push_challenges
        DROP CONSTRAINT IF EXISTS fk_push_challenges_organization;
    """))
    
    # Drop column
    await session.execute(text("""
        ALTER TABLE push_challenges
        DROP COLUMN IF EXISTS organization_id;
    """))
    
    await session.commit()
    print("✅ Migration rolled back: Removed organization_id from push_challenges")


# Standalone migration runner
if __name__ == "__main__":
    import asyncio
    import os
    from sqlalchemy.ext.asyncio import create_async_engine
    
    database_url = os.environ.get(
        "DATABASE_URL",
        "postgresql+asyncpg://marty:marty@localhost:5433/marty_applicants"
    )
    
    async def run_migration():
        engine = create_async_engine(database_url, echo=True)
        async with engine.begin() as conn:
            await conn.run_sync(lambda sync_conn: print(f"Connected to: {sync_conn.engine.url}"))
            
            # Create session
            from sqlalchemy.ext.asyncio import async_sessionmaker
            SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
            
            async with SessionLocal() as session:
                await upgrade(session)
        
        await engine.dispose()
    
    asyncio.run(run_migration())
