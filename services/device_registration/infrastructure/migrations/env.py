"""Alembic environment for the Device Registration schema."""

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool, text

config = context.config
target_metadata = config.attributes.get("target_metadata")
if config.config_file_name is not None:
    # Alembic runs in-process during startup and some verification paths. Keep
    # service and audit loggers alive when loading Alembic's logging settings.
    fileConfig(config.config_file_name, disable_existing_loggers=False)


def run_migrations_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        include_schemas=True,
        version_table_schema="device_registration_service",
    )
    context.execute("CREATE SCHEMA IF NOT EXISTS device_registration_service")
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        connection.execute(
            text("CREATE SCHEMA IF NOT EXISTS device_registration_service")
        )
        connection.commit()
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            include_schemas=True,
            version_table_schema="device_registration_service",
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
