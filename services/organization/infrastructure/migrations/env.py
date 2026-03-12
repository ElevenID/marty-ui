"""Alembic environment configuration for organization."""

import os
from logging.config import fileConfig
from sqlalchemy import engine_from_config, pool
from alembic import context

# Import your service's metadata
# This will be set dynamically by AlembicMigrationAdapter
target_metadata = context.config.attributes.get("target_metadata", None)

# Alembic Config object
config = context.config

# Interpret the config file for Python logging
if config.config_file_name is not None:
    fileConfig(config.config_file_name)


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    url = config.get_main_option("sqlalchemy.url")
    if not url:
        url = os.environ.get("DATABASE_URL", "")
        if url:
            url = url.replace("postgresql+asyncpg://", "postgresql+psycopg2://")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        # Include schema in autogenerate
        include_schemas=True,
        # Service-specific schema
        version_table_schema="organization_service",
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.
    """
    # Allow DATABASE_URL env var to override (convert asyncpg to psycopg2 for sync migrations)
    db_url = config.get_main_option("sqlalchemy.url")
    if not db_url:
        db_url = os.environ.get("DATABASE_URL", "")
        if db_url:
            # Replace asyncpg driver with psycopg2 for synchronous Alembic usage
            db_url = db_url.replace("postgresql+asyncpg://", "postgresql+psycopg2://")
            db_url = db_url.replace("postgresql+asyncpg+", "postgresql+psycopg2+")

    cfg_section = dict(config.get_section(config.config_ini_section, {}))
    if db_url:
        cfg_section["sqlalchemy.url"] = db_url

    connectable = engine_from_config(
        cfg_section,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            # Include schema in autogenerate
            include_schemas=True,
            # Service-specific schema
            version_table_schema="organization_service",
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
