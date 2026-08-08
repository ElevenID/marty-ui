"""Repository contract tests for atomic verification finalization."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from flow.infrastructure.adapters.postgres_adapter import PostgresFlowRepository
from flow.main import FlowInstance, FlowInstanceStatus, InMemoryFlowRepository


class _BeginContext:
    def __init__(self, session: "_FakeSession") -> None:
        self._session = session

    async def __aenter__(self) -> None:
        return None

    async def __aexit__(self, exc_type, _exc, _tb) -> bool:
        self._session.rolled_back = exc_type is not None
        return False


class _SessionContext:
    def __init__(self, session: "_FakeSession") -> None:
        self._session = session

    async def __aenter__(self) -> "_FakeSession":
        return self._session

    async def __aexit__(self, _exc_type, _exc, _tb) -> bool:
        return False


class _FakeSession:
    def __init__(self, *, replay_inserted: bool, updated_rows: int) -> None:
        self.replay_inserted = replay_inserted
        self.updated_rows = updated_rows
        self.statements: list[object] = []
        self.rolled_back = False

    def begin(self) -> _BeginContext:
        return _BeginContext(self)

    async def execute(self, statement):
        self.statements.append(statement)
        if len(self.statements) == 1:
            return SimpleNamespace()
        if len(self.statements) == 2:
            return SimpleNamespace(
                scalar_one_or_none=lambda: "digest" if self.replay_inserted else None
            )
        return SimpleNamespace(rowcount=self.updated_rows)


class _SessionFactory:
    def __init__(self, session: _FakeSession) -> None:
        self.session = session

    def __call__(self) -> _SessionContext:
        return _SessionContext(self.session)


def _terminal_instance() -> FlowInstance:
    now = datetime.now(timezone.utc)
    return FlowInstance(
        flow_definition_id="__verification__",
        organization_id="org-1",
        status=FlowInstanceStatus.COMPLETED,
        context={"nonce": "nonce"},
        completed_at=now,
        updated_at=now,
        result={"evaluation_result": "passed", "decision": "allow"},
    )


@pytest.mark.asyncio
async def test_postgres_finalization_commits_replay_and_result_together() -> None:
    session = _FakeSession(replay_inserted=True, updated_rows=1)
    repository = PostgresFlowRepository(_SessionFactory(session))
    instance = _terminal_instance()

    committed = await repository.finalize_verification(
        instance,
        nonce_digest="a" * 64,
        replay_expires_at=instance.completed_at + timedelta(minutes=5),
        expected_status=FlowInstanceStatus.AWAITING_WALLET,
    )

    assert committed is True
    assert session.rolled_back is False
    assert len(session.statements) == 3
    assert "ON CONFLICT DO NOTHING" in str(session.statements[1])
    update_sql = str(session.statements[2])
    assert "flow_instances.status" in update_sql
    assert "flow_instances.id" in update_sql


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("replay_inserted", "updated_rows", "statement_count"),
    [(False, 1, 2), (True, 0, 3)],
)
async def test_postgres_finalization_rolls_back_every_conflict(
    replay_inserted: bool,
    updated_rows: int,
    statement_count: int,
) -> None:
    session = _FakeSession(
        replay_inserted=replay_inserted,
        updated_rows=updated_rows,
    )
    repository = PostgresFlowRepository(_SessionFactory(session))
    instance = _terminal_instance()

    committed = await repository.finalize_verification(
        instance,
        nonce_digest="b" * 64,
        replay_expires_at=instance.completed_at + timedelta(minutes=5),
        expected_status=FlowInstanceStatus.AWAITING_WALLET,
    )

    assert committed is False
    assert session.rolled_back is True
    assert len(session.statements) == statement_count


@pytest.mark.asyncio
async def test_in_memory_finalization_rejects_a_stale_expected_status() -> None:
    repository = InMemoryFlowRepository()
    stored = FlowInstance(
        flow_definition_id="__verification__",
        organization_id="org-1",
        status=FlowInstanceStatus.IN_PROGRESS,
    )
    await repository.save_instance(stored)
    terminal = _terminal_instance()
    terminal.id = stored.id

    committed = await repository.finalize_verification(
        terminal,
        nonce_digest="c" * 64,
        replay_expires_at=terminal.completed_at + timedelta(minutes=5),
        expected_status=FlowInstanceStatus.AWAITING_WALLET,
    )

    assert committed is False
    assert stored.status is FlowInstanceStatus.IN_PROGRESS
    assert repository._consumed_nonce_digests == {}
