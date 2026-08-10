"""Real PostgreSQL proof for migration and concurrent verification finalization."""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from flow.infrastructure.adapters.postgres_adapter import PostgresFlowRepository
from flow.infrastructure.models import (
    flow_callback_outbox,
    flow_instances,
    flow_nonce_consumptions,
)
from flow.callback_outbox import CallbackOutboxEvent
from flow.main import FlowInstance, FlowInstanceStatus

FLOW_SERVICE_DIR = Path(__file__).parents[1]
TEST_DATABASE_NAME = "marty_atomic_test"
TEST_DATABASE_HOSTS = {"127.0.0.1", "localhost"}


def _upgrade_flow_schema(database_url: str) -> None:
    environment = {
        **os.environ,
        "DATABASE_URL": database_url,
        "PYTHONIOENCODING": "utf-8",
    }
    subprocess.run(
        [sys.executable, "manage_migrations.py", "upgrade"],
        cwd=FLOW_SERVICE_DIR,
        env=environment,
        check=True,
    )


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


def _callback_event(instance: FlowInstance, marker: str) -> CallbackOutboxEvent:
    assert instance.completed_at is not None
    return CallbackOutboxEvent(
        event_id=instance.id,
        flow_instance_id=instance.id,
        organization_id=instance.organization_id,
        destination_url=(
            "https://auth.example/internal/credential-verified?nonce=" + marker * 32
        ),
        audience="marty-auth-service",
        event_type="flow.verification_completed",
        payload={"flow_instance_id": instance.id, "decision": marker},
        created_at=instance.completed_at,
        next_attempt_at=instance.completed_at,
        expires_at=instance.completed_at + timedelta(minutes=15),
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
            assert revision == "20260808_0002"

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
                    callback_event=_callback_event(instance, nonce_digest[0]),
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
            callback_rows = (
                await session.execute(
                    select(
                        flow_callback_outbox.c.flow_instance_id,
                        flow_callback_outbox.c.payload,
                        flow_callback_outbox.c.status,
                    )
                )
            ).all()

        assert stored_result == winning_instance.result
        assert replay_rows == [(winning_digest, instance_id)]
        assert callback_rows == [
            (
                instance_id,
                {"flow_instance_id": instance_id, "decision": winning_digest[0]},
                "pending",
            )
        ]

        claimed = await repository.claim_due_callback_events(
            now=winning_instance.completed_at + timedelta(seconds=1),
            lease_expires_at=winning_instance.completed_at + timedelta(seconds=31),
            limit=10,
        )
        assert len(claimed) == 1
        assert claimed[0].attempt_count == 1
        assert claimed[0].lease_token
        acknowledged = await repository.mark_callback_delivered(
            claimed[0].event_id,
            lease_token=claimed[0].lease_token or "",
            delivered_at=winning_instance.completed_at + timedelta(seconds=2),
        )
        assert acknowledged is True

        async with session_factory() as session:
            delivered_row = (
                await session.execute(
                    select(
                        flow_callback_outbox.c.status,
                        flow_callback_outbox.c.destination_url,
                        flow_callback_outbox.c.payload,
                        flow_callback_outbox.c.attempt_count,
                    )
                )
            ).one()
        assert delivered_row == ("delivered", "", {}, 1)

        # A handler that read the active row before finalization cannot
        # resurrect or expire the now-terminal transaction afterward.
        stale_instance = FlowInstance(
            id=instance_id,
            flow_definition_id="__verification__",
            organization_id="org-1",
            status=FlowInstanceStatus.EXPIRED,
            context={"request_digest": "c" * 64},
            completed_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        await repository.save_instance(stale_instance)
        persisted = await repository.get_instance(instance_id)
        assert persisted.status is FlowInstanceStatus.COMPLETED
        assert persisted.result == winning_instance.result

        # Expiry is re-evaluated by PostgreSQL in the finalization CAS, so a
        # verifier response cannot commit after expensive validation crosses
        # the transaction deadline.
        expired_instance_id = "90000000-0000-0000-0000-000000000002"
        now = datetime.now(timezone.utc)
        async with engine.begin() as connection:
            await connection.execute(
                flow_instances.insert().values(
                    id=expired_instance_id,
                    flow_definition_id="__verification__",
                    organization_id="org-1",
                    status=FlowInstanceStatus.AWAITING_WALLET.value,
                    context={"request_digest": "d" * 64},
                    step_history=[],
                    subject_type="applicant",
                    expires_at=now - timedelta(seconds=1),
                    created_at=now,
                    updated_at=now,
                )
            )
        expired_candidate = _terminal_instance(expired_instance_id, "allow")
        assert (
            await repository.finalize_verification(
                expired_candidate,
                nonce_digest="f" * 64,
                replay_expires_at=expired_candidate.completed_at
                + timedelta(minutes=5),
                expected_status=FlowInstanceStatus.AWAITING_WALLET,
            )
            is False
        )
        async with session_factory() as session:
            expired_status = await session.scalar(
                select(flow_instances.c.status).where(
                    flow_instances.c.id == expired_instance_id
                )
            )
            expired_replay = await session.scalar(
                select(flow_nonce_consumptions.c.nonce_digest).where(
                    flow_nonce_consumptions.c.flow_instance_id
                    == expired_instance_id
                )
            )
        assert expired_status == FlowInstanceStatus.AWAITING_WALLET.value
        assert expired_replay is None
    finally:
        with sync_engine.begin() as connection:
            connection.execute(text("DROP SCHEMA IF EXISTS flow_service CASCADE"))
            connection.execute(
                text("DROP SCHEMA IF EXISTS deployment_profile_service CASCADE")
            )
        sync_engine.dispose()
        await engine.dispose()
