"""Real PostgreSQL proof for migration and concurrent verification finalization."""

from __future__ import annotations

import asyncio
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from flow.infrastructure.adapters.postgres_adapter import PostgresFlowRepository
from flow.infrastructure.models import (
    flow_instances,
    flow_nonce_consumptions,
    mapper_registry,
)
from flow.main import FlowInstance, FlowInstanceStatus

MIGRATIONS_DIR = Path(__file__).parents[1] / "infrastructure" / "migrations"
TEST_DATABASE_NAME = "marty_atomic_test"
TEST_DATABASE_HOSTS = {"127.0.0.1", "localhost"}


def _upgrade_flow_schema(database_url: str) -> None:
    config = Config(str(MIGRATIONS_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(MIGRATIONS_DIR))
    config.set_main_option("sqlalchemy.url", database_url)
    config.attributes["target_metadata"] = mapper_registry.metadata
    command.upgrade(config, "head")


def _terminal_instance(instance_id: str, decision: str) -> FlowInstance:
    now = datetime.now(timezone.utc)
    return FlowInstance(
        id=instance_id,
        flow_definition_id="__verification__",
        organization_id="org-1",
        status=FlowInstanceStatus.COMPLETED,
        context={"request_digest": "c" * 64},
        completed_at=now,
        updated_at=now,
        result={"evaluation_result": "passed", "decision": decision},
    )


@pytest.mark.asyncio
async def test_postgres_migration_and_concurrent_finalization_are_atomic() -> None:
    database_url = os.environ.get("FLOW_POSTGRES_TEST_URL")
    if not database_url:
        pytest.skip("FLOW_POSTGRES_TEST_URL is reserved for the isolated CI database")
    parsed_url = make_url(database_url)
    if (
        parsed_url.database != TEST_DATABASE_NAME
        or parsed_url.host not in TEST_DATABASE_HOSTS
    ):
        pytest.fail(
            "PostgreSQL atomicity tests require the isolated loopback database "
            f"{TEST_DATABASE_NAME!r}"
        )

    sync_database_url = database_url.replace("+asyncpg", "")
    sync_engine = create_engine(sync_database_url)
    engine = create_async_engine(database_url)
    try:
        with sync_engine.begin() as connection:
            connection.execute(text("DROP SCHEMA IF EXISTS flow_service CASCADE"))
            connection.execute(
                text("DROP SCHEMA IF EXISTS deployment_profile_service CASCADE")
            )
            connection.execute(text("CREATE SCHEMA flow_service"))
            connection.execute(text("CREATE SCHEMA deployment_profile_service"))
            connection.execute(
                text(
                    """
                    CREATE TABLE deployment_profile_service.deployment_profiles (
                        id VARCHAR(36) PRIMARY KEY,
                        enabled_flow_ids JSON NOT NULL DEFAULT '[]'::json,
                        updated_at TIMESTAMP WITH TIME ZONE
                    )
                    """
                )
            )
        _upgrade_flow_schema(sync_database_url)

        async with engine.begin() as connection:
            revision = await connection.scalar(
                text("SELECT version_num FROM flow_service.alembic_version")
            )
            assert revision == "20260808_0001"

            instance_id = "90000000-0000-0000-0000-000000000001"
            now = datetime.now(timezone.utc)
            await connection.execute(
                flow_instances.insert().values(
                    id=instance_id,
                    flow_definition_id="__verification__",
                    organization_id="org-1",
                    status=FlowInstanceStatus.AWAITING_WALLET.value,
                    context={"request_digest": "c" * 64},
                    step_history=[],
                    subject_type="applicant",
                    created_at=now,
                    updated_at=now,
                )
            )

        session_factory = async_sessionmaker(engine, expire_on_commit=False)
        repository = PostgresFlowRepository(session_factory)
        candidates = [
            (_terminal_instance(instance_id, "allow-a"), "a" * 64),
            (_terminal_instance(instance_id, "allow-b"), "b" * 64),
        ]
        outcomes = await asyncio.gather(
            *(
                repository.finalize_verification(
                    instance,
                    nonce_digest=nonce_digest,
                    replay_expires_at=instance.completed_at + timedelta(minutes=5),
                    expected_status=FlowInstanceStatus.AWAITING_WALLET,
                )
                for instance, nonce_digest in candidates
            )
        )

        assert sorted(outcomes) == [False, True]
        winning_index = outcomes.index(True)
        winning_instance, winning_digest = candidates[winning_index]

        async with session_factory() as session:
            stored_result = await session.scalar(
                select(flow_instances.c.result).where(
                    flow_instances.c.id == instance_id
                )
            )
            replay_rows = (
                await session.execute(
                    select(
                        flow_nonce_consumptions.c.nonce_digest,
                        flow_nonce_consumptions.c.flow_instance_id,
                    )
                )
            ).all()

        assert stored_result == winning_instance.result
        assert replay_rows == [(winning_digest, instance_id)]
    finally:
        with sync_engine.begin() as connection:
            connection.execute(text("DROP SCHEMA IF EXISTS flow_service CASCADE"))
            connection.execute(
                text("DROP SCHEMA IF EXISTS deployment_profile_service CASCADE")
            )
        sync_engine.dispose()
        await engine.dispose()
