"""Subscription Database Configuration.

Provides async database session management for subscription/organization models.
"""

from __future__ import annotations

import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from .models import Base

logger = logging.getLogger(__name__)

# Global engine and session factory
_engine = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def get_database_url() -> str:
    """Get database URL from environment."""
    db_url = os.environ.get(
        "SUBSCRIPTION_DB_URL",
        os.environ.get("DATABASE_URL", "sqlite+aiosqlite:///data/subscription.db"),
    )
    
    # Convert postgres:// to postgresql+asyncpg://
    if db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql+asyncpg://", 1)
    elif db_url.startswith("postgresql://") and "+asyncpg" not in db_url:
        db_url = db_url.replace("postgresql://", "postgresql+asyncpg://", 1)
    
    return db_url


def get_engine():
    """Get or create the async engine."""
    global _engine
    if _engine is None:
        db_url = get_database_url()
        echo = os.environ.get("DB_ECHO", "false").lower() == "true"
        
        # SQLite doesn't support pool options
        if "sqlite" in db_url:
            _engine = create_async_engine(db_url, echo=echo)
        else:
            _engine = create_async_engine(
                db_url,
                echo=echo,
                pool_size=int(os.environ.get("DB_POOL_SIZE", "10")),
                max_overflow=int(os.environ.get("DB_MAX_OVERFLOW", "20")),
            )
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    """Get or create the session factory."""
    global _session_factory
    if _session_factory is None:
        engine = get_engine()
        _session_factory = async_sessionmaker(engine, expire_on_commit=False)
    return _session_factory


async def get_db_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency for database sessions.
    
    Usage:
        @app.get("/example")
        async def example(db: AsyncSession = Depends(get_db_session)):
            result = await db.execute(select(Organization))
            ...
    """
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
        finally:
            await session.close()


@asynccontextmanager
async def session_scope() -> AsyncIterator[AsyncSession]:
    """Context manager for database sessions.
    
    Usage:
        async with session_scope() as session:
            result = await session.execute(select(Organization))
    """
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_database() -> None:
    """Initialize database tables."""
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Subscription database tables created")


async def close_database() -> None:
    """Close database connections."""
    global _engine, _session_factory
    if _engine:
        await _engine.dispose()
        _engine = None
        _session_factory = None
    logger.info("Subscription database connections closed")
