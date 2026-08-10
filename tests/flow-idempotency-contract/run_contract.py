from __future__ import annotations

import asyncio
import json
import os
import sys
import types
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from pathlib import Path

import psycopg
from alembic import command
from alembic.config import Config
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

DATABASE_URL = os.environ["DATABASE_URL"]
RESULT_PATH = Path(os.environ["CONTRACT_RESULT_PATH"])
SOURCE_REVISION = os.environ.get("CONTRACT_SOURCE_REVISION", "local-worktree")
FLOW_KEY_HASH = "a" * 64
SEMANTICS_HASH = "b" * 64
EVENT_ID_HASH = "c" * 64
EVENT_PAYLOAD_HASH = "d" * 64
CONFLICT_EVENT_ID_HASH = "e" * 64
CONFLICT_PAYLOAD_HASH = "f" * 64
ISSUANCE_TRANSACTION_ID = str(uuid.uuid4())


class FlowInstanceStatus(str, Enum):
    IN_PROGRESS = "in_progress"


class ArtifactStatus(str, Enum):
    ACTIVE = "active"


@dataclass
class FlowInstance:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    flow_definition_id: str = ""
    organization_id: str = ""
    status: FlowInstanceStatus = FlowInstanceStatus.IN_PROGRESS
    current_step_id: str | None = None
    context: dict = field(default_factory=dict)
    step_history: list[dict] = field(default_factory=list)
    subject_id: str | None = None
    subject_type: str = "applicant"
    external_reference: str | None = None
    application_flow_key_hash: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    expires_at: datetime | None = None
    result: dict | None = None
    error: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class FlowInstanceArtifact:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    flow_instance_id: str = ""
    issuance_transaction_id: str | None = None
    credential_offer_uri: str | None = None
    credential_offer_uris: dict[str, str] = field(default_factory=dict)
    credential_offer_labels: dict[str, str] = field(default_factory=dict)
    pre_authorized_code: str | None = None
    issuance_status: str | None = None
    qr_payload: str | None = None
    expires_at: datetime | None = None
    scanned_at: datetime | None = None
    status: ArtifactStatus = ArtifactStatus.ACTIVE
    state: str | None = None
    wallet_metadata: dict = field(default_factory=dict)
    attempt_number: int = 1
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class ApplicationEventPlanReceipt:
    event_id_sha256: str
    payload_sha256: str
    organization_id: str
    application_id: str
    flow_plan: list[dict[str, str]] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))


class ApplicationOfferConflictError(RuntimeError):
    pass


# The production adapter imports these domain types lazily from flow.main to
# avoid its own circular import.  Supply the exact adapter-facing shape here so
# this small contract image can execute production repository code without
# installing the entire HTTP/gRPC service dependency graph.
flow_main = types.ModuleType("flow.main")
for contract_type in (
    ApplicationEventPlanReceipt,
    ApplicationOfferConflictError,
    ArtifactStatus,
    FlowInstance,
    FlowInstanceArtifact,
    FlowInstanceStatus,
):
    setattr(flow_main, contract_type.__name__, contract_type)
sys.modules["flow.main"] = flow_main

from flow.infrastructure.adapters.postgres_adapter import (  # noqa: E402
    PostgresFlowRepository,
)


def _upgrade() -> None:
    with psycopg.connect(DATABASE_URL) as connection:
        connection.execute("CREATE SCHEMA IF NOT EXISTS flow_service")
        connection.execute("CREATE SCHEMA IF NOT EXISTS deployment_profile_service")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS deployment_profile_service.deployment_profiles (
                id VARCHAR PRIMARY KEY,
                enabled_flow_ids JSON NOT NULL DEFAULT '[]'::json,
                updated_at TIMESTAMPTZ
            )
            """
        )
        connection.commit()

    config = Config("/contract/migrations/alembic.ini")
    config.set_main_option("script_location", "/contract/migrations")
    config.set_main_option(
        "sqlalchemy.url",
        DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1),
    )
    command.upgrade(config, "head")


def _candidate_instance(*, semantics_hash: str = SEMANTICS_HASH) -> FlowInstance:
    now = datetime.now(UTC)
    return FlowInstance(
        flow_definition_id="flow-contract",
        organization_id="org-race",
        context={"_marty_application_offer_semantics_hash_v1": semantics_hash},
        subject_id="applicant-race",
        external_reference=f"application-flow:{FLOW_KEY_HASH}",
        application_flow_key_hash=FLOW_KEY_HASH,
        started_at=now,
        expires_at=now + timedelta(minutes=10),
    )


def _candidate_receipt(
    *,
    event_id_sha256: str = EVENT_ID_HASH,
    payload_sha256: str = EVENT_PAYLOAD_HASH,
) -> ApplicationEventPlanReceipt:
    return ApplicationEventPlanReceipt(
        event_id_sha256=event_id_sha256,
        payload_sha256=payload_sha256,
        organization_id="org-race",
        application_id="application-race",
    )


def _plan_entry(*, semantics_hash: str = SEMANTICS_HASH) -> dict[str, str]:
    return {
        "flow_definition_id": "flow-contract",
        "application_flow_key_hash": FLOW_KEY_HASH,
        "offer_semantics_hash": semantics_hash,
        "flow_definition_version": "1",
    }


def _candidate_artifact(flow_instance_id: str) -> FlowInstanceArtifact:
    return FlowInstanceArtifact(
        flow_instance_id=flow_instance_id,
        issuance_transaction_id=ISSUANCE_TRANSACTION_ID,
        credential_offer_uri="openid-credential-offer://contract",
        pre_authorized_code="sanitized-contract-code",
        issuance_status="pending",
        expires_at=datetime.now(UTC) + timedelta(minutes=10),
        state=ISSUANCE_TRANSACTION_ID,
    )


async def _exercise_production_repository() -> tuple[list[bool], str, bool, bool, bool]:
    engine = create_async_engine(
        DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1),
        pool_size=4,
        max_overflow=0,
    )
    repository = PostgresFlowRepository(
        async_sessionmaker(engine, expire_on_commit=False)
    )
    try:
        start = asyncio.Event()

        async def reserve_plan():
            await start.wait()
            return await repository.reserve_application_event_plan(
                _candidate_receipt(),
                [(_candidate_instance(), _plan_entry())],
            )

        plan_tasks = [asyncio.create_task(reserve_plan()) for _ in range(2)]
        start.set()
        plan_results = await asyncio.gather(*plan_tasks)
        created_results = [created for _receipt, created in plan_results]
        plan_instance_ids = {
            receipt.flow_plan[0]["instance_id"] for receipt, _created in plan_results
        }
        assert sorted(created_results) == [False, True]
        assert len(plan_instance_ids) == 1
        flow_instance_id = plan_instance_ids.pop()

        changed_semantics_hash = "0" * 64
        try:
            await repository.reserve_application_event_plan(
                _candidate_receipt(
                    event_id_sha256=CONFLICT_EVENT_ID_HASH,
                    payload_sha256=CONFLICT_PAYLOAD_HASH,
                ),
                [
                    (
                        _candidate_instance(semantics_hash=changed_semantics_hash),
                        _plan_entry(semantics_hash=changed_semantics_hash),
                    )
                ],
            )
        except ApplicationOfferConflictError:
            semantic_conflict_rolled_back = True
        else:
            semantic_conflict_rolled_back = False
        assert semantic_conflict_rolled_back

        try:
            await repository.reserve_application_event_plan(
                _candidate_receipt(payload_sha256="1" * 64),
                [(_candidate_instance(), _plan_entry())],
            )
        except ApplicationOfferConflictError:
            changed_payload_rejected = True
        else:
            changed_payload_rejected = False
        assert changed_payload_rejected

        artifact_start = asyncio.Event()

        async def reserve_artifact():
            await artifact_start.wait()
            return await repository.save_artifact(_candidate_artifact(flow_instance_id))

        artifact_tasks = [asyncio.create_task(reserve_artifact()) for _ in range(2)]
        artifact_start.set()
        artifact_results = await asyncio.gather(*artifact_tasks)
        assert len({artifact.id for artifact in artifact_results}) == 1

        other_instance = FlowInstance(
            flow_definition_id="flow-contract",
            organization_id="org-race",
            subject_id="applicant-race",
            started_at=datetime.now(UTC),
        )
        await repository.save_instance(other_instance)
        try:
            await repository.save_artifact(_candidate_artifact(other_instance.id))
        except RuntimeError as exc:
            cross_instance_rebind_rejected = "another flow instance" in str(exc)
        else:
            cross_instance_rebind_rejected = False
        assert cross_instance_rebind_rejected
        return (
            created_results,
            flow_instance_id,
            cross_instance_rebind_rejected,
            semantic_conflict_rolled_back,
            changed_payload_rejected,
        )
    finally:
        await engine.dispose()


def main() -> None:
    _upgrade()
    (
        instance_created_results,
        flow_instance_id,
        cross_instance_rebind_rejected,
        semantic_conflict_rolled_back,
        changed_payload_rejected,
    ) = asyncio.run(_exercise_production_repository())

    with psycopg.connect(DATABASE_URL) as connection:
        receipt_count, stored_plan = connection.execute(
            """
            SELECT count(*), min(flow_plan::text)
            FROM flow_service.flow_application_event_receipts
            WHERE event_id_sha256 = %s
            """,
            (EVENT_ID_HASH,),
        ).fetchone()
        instance_count = connection.execute(
            """
            SELECT count(*)
            FROM flow_service.flow_instances
            WHERE organization_id = 'org-race'
              AND application_flow_key_hash = %s
            """,
            (FLOW_KEY_HASH,),
        ).fetchone()[0]
        conflict_receipt_count = connection.execute(
            """
            SELECT count(*)
            FROM flow_service.flow_application_event_receipts
            WHERE event_id_sha256 = %s
            """,
            (CONFLICT_EVENT_ID_HASH,),
        ).fetchone()[0]
        artifact_count, artifact_owner = connection.execute(
            """
            SELECT count(*), min(flow_instance_id)
            FROM flow_service.flow_instance_artifacts
            WHERE issuance_transaction_id = %s
            """,
            (ISSUANCE_TRANSACTION_ID,),
        ).fetchone()
        version = connection.execute(
            "SELECT version_num FROM flow_service.alembic_version"
        ).fetchone()[0]

    stored_plan_value = json.loads(stored_plan)
    assert instance_count == 1
    assert receipt_count == 1
    assert conflict_receipt_count == 0
    assert len(stored_plan_value) == 1
    assert stored_plan_value[0]["instance_id"] == flow_instance_id
    assert artifact_count == 1
    assert artifact_owner == flow_instance_id
    assert version == "20260810_0100"

    instance_created_count = sum(instance_created_results)
    RESULT_PATH.parent.mkdir(parents=True, exist_ok=True)
    RESULT_PATH.write_text(
        json.dumps(
            {
                "status": "passed",
                "source_revision": SOURCE_REVISION,
                "migration_revision": version,
                "production_repository_exercised": True,
                "instance_created_count": instance_created_count,
                "instance_recovered_count": len(instance_created_results)
                - instance_created_count,
                "same_instance": True,
                "event_receipt_count": receipt_count,
                "same_durable_plan": True,
                "artifact_count": artifact_count,
                "same_artifact": True,
                "cross_instance_rebind_rejected": cross_instance_rebind_rejected,
                "semantic_conflict_rolled_back": semantic_conflict_rolled_back,
                "changed_payload_rejected": changed_payload_rejected,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
