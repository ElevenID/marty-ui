"""Alembic migration adapter for marty-ui services.

Inlined from mmf.framework.infrastructure.migration to avoid requiring
the full marty-microservices-framework as a dependency.
"""

import logging
import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, pool

logger = logging.getLogger(__name__)


class MigrationError(Exception):
    """Exception raised for migration-related errors."""

    pass


class MigrationManagerPort(ABC):
    """Abstract port for database migration management."""

    @abstractmethod
    def initialize(self, service_name: str, migrations_dir: Path) -> None:
        pass

    @abstractmethod
    def create_migration(
        self, message: str, autogenerate: bool = True, sql_mode: bool = False
    ) -> Optional[str]:
        pass

    @abstractmethod
    def upgrade(self, revision: str = "head", sql_mode: bool = False) -> None:
        pass

    @abstractmethod
    def downgrade(self, revision: str, sql_mode: bool = False) -> None:
        pass

    @abstractmethod
    def current(self) -> Optional[str]:
        pass

    @abstractmethod
    def history(self, verbose: bool = False) -> list[str]:
        pass

    @abstractmethod
    def verify_schema(self, raise_on_mismatch: bool = True) -> bool:
        pass


class AlembicMigrationAdapter(MigrationManagerPort):
    """Alembic-based implementation of MigrationManagerPort.

    Args:
        database_url: SQLAlchemy database URL
        metadata: SQLAlchemy MetaData object containing table definitions
    """

    def __init__(self, database_url: str, metadata):
        self.database_url = database_url
        self.metadata = metadata
        self.alembic_cfg: Optional[Config] = None
        self._service_name: Optional[str] = None
        self._migrations_dir: Optional[Path] = None

    def initialize(self, service_name: str, migrations_dir: Path) -> None:
        try:
            self._service_name = service_name
            self._migrations_dir = Path(migrations_dir)
            self._migrations_dir.mkdir(parents=True, exist_ok=True)

            alembic_ini_path = self._migrations_dir / "alembic.ini"
            if not alembic_ini_path.exists():
                self._create_alembic_ini(alembic_ini_path)

            versions_dir = self._migrations_dir / "versions"
            versions_dir.mkdir(exist_ok=True)

            env_py_path = self._migrations_dir / "env.py"
            if not env_py_path.exists():
                self._create_env_py(env_py_path, service_name)

            script_mako_path = self._migrations_dir / "script.py.mako"
            if not script_mako_path.exists():
                self._create_script_mako(script_mako_path)

            self.alembic_cfg = Config(str(alembic_ini_path))
            self.alembic_cfg.set_main_option("script_location", str(self._migrations_dir))
            self.alembic_cfg.set_main_option("sqlalchemy.url", self.database_url)

            logger.info(f"Initialized Alembic migrations for {service_name} at {migrations_dir}")

        except Exception as e:
            raise MigrationError(f"Failed to initialize migrations: {e}") from e

    def create_migration(
        self,
        message: str,
        autogenerate: bool = True,
        sql_mode: bool = False,
    ) -> Optional[str]:
        self._ensure_initialized()

        try:
            self.alembic_cfg.attributes["target_metadata"] = self.metadata

            if sql_mode:
                command.revision(
                    self.alembic_cfg,
                    message=message,
                    autogenerate=autogenerate,
                    sql=True,
                )
                return None
            else:
                result = command.revision(
                    self.alembic_cfg,
                    message=message,
                    autogenerate=autogenerate,
                )
                if result:
                    logger.info(f"Created migration: {result.path}")
                    return str(result.path)
                return None

        except Exception as e:
            raise MigrationError(f"Failed to create migration: {e}") from e

    def upgrade(self, revision: str = "head", sql_mode: bool = False) -> None:
        self._ensure_initialized()

        try:
            if sql_mode:
                command.upgrade(self.alembic_cfg, revision, sql=True)
            else:
                command.upgrade(self.alembic_cfg, revision)
                logger.info(f"Upgraded to revision: {revision}")

        except Exception as e:
            raise MigrationError(f"Failed to upgrade: {e}") from e

    def downgrade(self, revision: str, sql_mode: bool = False) -> None:
        self._ensure_initialized()

        try:
            if sql_mode:
                command.downgrade(self.alembic_cfg, revision, sql=True)
            else:
                command.downgrade(self.alembic_cfg, revision)
                logger.info(f"Downgraded to revision: {revision}")

        except Exception as e:
            raise MigrationError(f"Failed to downgrade: {e}") from e

    def current(self) -> Optional[str]:
        self._ensure_initialized()

        try:
            sync_url = self.database_url.replace("+asyncpg", "").replace("+aiomysql", "")
            engine = create_engine(sync_url, poolclass=pool.NullPool)

            with engine.connect() as connection:
                config_opts = {}
                if self._service_name:
                    config_opts["version_table_schema"] = f"{self._service_name}_service"

                context = MigrationContext.configure(connection, opts=config_opts)
                current_rev = context.get_current_revision()
                return current_rev

        except Exception as e:
            raise MigrationError(f"Failed to get current revision: {e}") from e

    def history(self, verbose: bool = False) -> list[str]:
        self._ensure_initialized()

        try:
            script = ScriptDirectory.from_config(self.alembic_cfg)
            revisions = []

            for revision in script.walk_revisions():
                if verbose:
                    revisions.append(
                        f"{revision.revision}: {revision.doc} "
                        f"(down: {revision.down_revision})"
                    )
                else:
                    revisions.append(revision.revision)

            return list(reversed(revisions))

        except Exception as e:
            raise MigrationError(f"Failed to get history: {e}") from e

    def verify_schema(self, raise_on_mismatch: bool = True) -> bool:
        self._ensure_initialized()

        try:
            current_rev = self.current()
            script = ScriptDirectory.from_config(self.alembic_cfg)
            head_rev = script.get_current_head()

            is_up_to_date = current_rev == head_rev

            if not is_up_to_date and raise_on_mismatch:
                raise MigrationError(
                    f"Schema mismatch: current={current_rev}, expected={head_rev}. "
                    f"Run migrations to update schema."
                )

            return is_up_to_date

        except MigrationError:
            raise
        except Exception as e:
            raise MigrationError(f"Failed to verify schema: {e}") from e

    def _ensure_initialized(self) -> None:
        if not self.alembic_cfg:
            raise MigrationError(
                "Migration adapter not initialized. Call initialize() first."
            )

    def _create_alembic_ini(self, path: Path) -> None:
        content = """\
[alembic]
script_location = %(here)s
file_template = %%(year)d%%(month).2d%%(day).2d_%%(hour).2d%%(minute).2d_%%(rev)s_%%(slug)s
timezone = UTC
truncate_slug_length = 40

[loggers]
keys = root,sqlalchemy,alembic

[handlers]
keys = console

[formatters]
keys = generic

[logger_root]
level = WARN
handlers = console
qualname =

[logger_sqlalchemy]
level = WARN
handlers =
qualname = sqlalchemy.engine

[logger_alembic]
level = INFO
handlers =
qualname = alembic

[handler_console]
class = StreamHandler
args = (sys.stderr,)
level = NOTSET
formatter = generic

[formatter_generic]
format = %(levelname)-5.5s [%(name)s] %(message)s
datefmt = %H:%M:%S
"""
        path.write_text(content)

    def _create_env_py(self, path: Path, service_name: str) -> None:
        content = f'''\
"""Alembic environment configuration for {service_name}."""

from logging.config import fileConfig
from sqlalchemy import engine_from_config, pool
from alembic import context

target_metadata = context.config.attributes.get("target_metadata", None)
config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={{"paramstyle": "named"}},
        include_schemas=True,
        version_table_schema="{service_name}_service",
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {{}}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            include_schemas=True,
            version_table_schema="{service_name}_service",
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
'''
        path.write_text(content)

    def _create_script_mako(self, path: Path) -> None:
        content = '''\
"""${message}

Revision ID: ${up_revision}
Revises: ${down_revision | comma,n}
Create Date: ${create_date}

"""
from alembic import op
import sqlalchemy as sa
${imports if imports else ""}

revision = ${repr(up_revision)}
down_revision = ${repr(down_revision)}
branch_labels = ${repr(branch_labels)}
depends_on = ${repr(depends_on)}


def upgrade() -> None:
    ${upgrades if upgrades else "pass"}


def downgrade() -> None:
    ${downgrades if downgrades else "pass"}
'''
        path.write_text(content)
