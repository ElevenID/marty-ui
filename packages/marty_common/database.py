"""
Database Utilities

Schema-aware database connection utilities for Marty microservices.
Each service uses its own schema within the shared PostgreSQL database.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import AsyncGenerator
from urllib.parse import quote_plus, urlparse, urlunparse

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool


@dataclass
class DatabaseConfig:
    """Database configuration."""
    
    host: str = "localhost"
    port: int = 5432
    database: str = "marty"
    username: str = "marty"
    password: str = "marty"
    schema: str = "public"
    pool_size: int = 5
    max_overflow: int = 10
    pool_pre_ping: bool = True
    pool_recycle: int = -1  # -1 = disabled; 3600 = recycle connections after 1 hour
    echo: bool = False
    database_url_override: str = ""  # If set, used directly instead of building from parts
    
    @classmethod
    def from_env(cls, service_name: str) -> DatabaseConfig:
        """Create config from environment variables.

        Supports two modes:
          1. ``DATABASE_URL`` env var — used directly (for existing setups).
          2. Individual ``DB_HOST/PORT/NAME/USER/PASSWORD`` vars — composed into URL.
        """
        # Schema is derived from service name
        schema = os.environ.get(
            f"{service_name.upper().replace('-', '_')}_DB_SCHEMA",
            f"{service_name.replace('-', '_')}_service"
        )
        
        return cls(
            host=os.environ.get("DB_HOST", "localhost"),
            port=int(os.environ.get("DB_PORT", "5432")),
            database=os.environ.get("DB_NAME", "marty"),
            username=os.environ.get("DB_USER", "marty"),
            password=os.environ.get("DB_PASSWORD", "marty"),
            schema=schema,
            pool_size=int(os.environ.get("DB_POOL_SIZE", "5")),
            max_overflow=int(os.environ.get("DB_MAX_OVERFLOW", "10")),
            pool_pre_ping=os.environ.get("DB_POOL_PRE_PING", "true").lower() == "true",
            pool_recycle=int(os.environ.get("DB_POOL_RECYCLE", "-1")),
            echo=os.environ.get("DB_ECHO", "false").lower() == "true",
            database_url_override=os.environ.get("DATABASE_URL", ""),
        )
    
    @property
    def url(self) -> str:
        """Get the database URL with schema in search_path."""
        password_encoded = quote_plus(self.password)
        base_url = (
            f"postgresql+asyncpg://{self.username}:{password_encoded}"
            f"@{self.host}:{self.port}/{self.database}"
        )
        # Set schema via connection options
        return f"{base_url}?options=-c%20search_path%3D{self.schema}"
    
    @property
    def sync_url(self) -> str:
        """Get synchronous database URL (for Alembic migrations)."""
        password_encoded = quote_plus(self.password)
        base_url = (
            f"postgresql://{self.username}:{password_encoded}"
            f"@{self.host}:{self.port}/{self.database}"
        )
        return f"{base_url}?options=-c%20search_path%3D{self.schema}"


class DatabaseManager:
    """Manages database connections for a service."""
    
    def __init__(self, config: DatabaseConfig):
        self.config = config
        self._engine: AsyncEngine | None = None
        self._session_factory: async_sessionmaker[AsyncSession] | None = None
    
    @property
    def engine(self) -> AsyncEngine:
        """Get or create the database engine."""
        if self._engine is None:
            url = self.config.database_url_override or self.config.url
            engine_kwargs: dict = {
                "pool_size": self.config.pool_size,
                "max_overflow": self.config.max_overflow,
                "pool_pre_ping": self.config.pool_pre_ping,
                "echo": self.config.echo,
            }
            if self.config.pool_recycle > 0:
                engine_kwargs["pool_recycle"] = self.config.pool_recycle
            self._engine = create_async_engine(url, **engine_kwargs)
        return self._engine
    
    @property
    def session_factory(self) -> async_sessionmaker[AsyncSession]:
        """Get or create the session factory."""
        if self._session_factory is None:
            self._session_factory = async_sessionmaker(
                self.engine,
                class_=AsyncSession,
                expire_on_commit=False,
            )
        return self._session_factory
    
    @asynccontextmanager
    async def session(self) -> AsyncGenerator[AsyncSession, None]:
        """Get a database session with automatic cleanup."""
        async with self.session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise
    
    @asynccontextmanager
    async def transaction(self) -> AsyncGenerator[AsyncSession, None]:
        """Get a database session within a transaction."""
        async with self.session_factory() as session:
            async with session.begin():
                yield session
    
    async def close(self) -> None:
        """Close database connections."""
        if self._engine:
            await self._engine.dispose()
            self._engine = None
            self._session_factory = None


# Global database manager instances per service
_database_managers: dict[str, DatabaseManager] = {}


def get_database_manager(service_name: str) -> DatabaseManager:
    """Get or create a database manager for a service."""
    if service_name not in _database_managers:
        config = DatabaseConfig.from_env(service_name)
        _database_managers[service_name] = DatabaseManager(config)
    return _database_managers[service_name]


async def get_db_session(service_name: str) -> AsyncGenerator[AsyncSession, None]:
    """Dependency for getting a database session."""
    manager = get_database_manager(service_name)
    async with manager.session() as session:
        yield session
