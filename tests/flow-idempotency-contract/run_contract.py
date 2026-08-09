from __future__ import annotations

import json
import os
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import psycopg
from alembic import command
from alembic.config import Config

DATABASE_URL = os.environ["DATABASE_URL"]
RESULT_PATH = Path(os.environ["CONTRACT_RESULT_PATH"])
SOURCE_REVISION = os.environ.get("CONTRACT_SOURCE_REVISION", "local-worktree")
FLOW_KEY_HASH = "a" * 64
SEMANTICS_HASH = "b" * 64
ISSUANCE_TRANSACTION_ID = str(uuid.uuid4())


def _upgrade() -> None:
    with psycopg.connect(DATABASE_URL) as connection:
        connection.execute("CREATE SCHEMA IF NOT EXISTS flow_service")
        connection.commit()

    config = Config("/contract/migrations/alembic.ini")
    config.set_main_option("script_location", "/contract/migrations")
    config.set_main_option(
        "sqlalchemy.url",
        DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1),
    )
    command.upgrade(config, "head")


def _reserve_instance(barrier: threading.Barrier) -> tuple[str, bool]:
    instance_id = str(uuid.uuid4())
    now = datetime.now(UTC)
    barrier.wait(timeout=10)
    with psycopg.connect(DATABASE_URL) as connection:
        created = connection.execute(
            """
            INSERT INTO flow_service.flow_instances (
                id, flow_definition_id, organization_id, status,
                context, step_history, subject_type, external_reference,
                application_flow_key_hash, started_at, created_at, updated_at
            ) VALUES (
                %s, 'flow-contract', 'org-race', 'in_progress',
                %s::json, '[]'::json, 'applicant', %s, %s, %s, %s, %s
            )
            ON CONFLICT (organization_id, application_flow_key_hash) DO NOTHING
            RETURNING id
            """,
            (
                instance_id,
                json.dumps(
                    {"_marty_application_offer_semantics_hash_v1": SEMANTICS_HASH}
                ),
                f"application-flow:{FLOW_KEY_HASH}",
                FLOW_KEY_HASH,
                now,
                now,
                now,
            ),
        ).fetchone()
        if created is not None:
            connection.commit()
            return str(created[0]), True
        existing = connection.execute(
            """
            SELECT id
            FROM flow_service.flow_instances
            WHERE organization_id = 'org-race'
              AND application_flow_key_hash = %s
            """,
            (FLOW_KEY_HASH,),
        ).fetchone()
        assert existing is not None
        connection.commit()
        return str(existing[0]), False


def _reserve_artifact(
    barrier: threading.Barrier,
    flow_instance_id: str,
) -> tuple[str, bool]:
    artifact_id = str(uuid.uuid4())
    now = datetime.now(UTC)
    barrier.wait(timeout=10)
    with psycopg.connect(DATABASE_URL) as connection:
        row = connection.execute(
            """
            INSERT INTO flow_service.flow_instance_artifacts (
                id, flow_instance_id, issuance_transaction_id,
                credential_offer_uri, credential_offer_uris,
                credential_offer_labels, pre_authorized_code,
                issuance_status, expires_at, status, state,
                wallet_metadata, attempt_number, created_at, updated_at
            ) VALUES (
                %s, %s, %s, 'openid-credential-offer://contract',
                '{}'::json, '{}'::json, 'sanitized-contract-code',
                'pending', %s, 'active', %s, '{}'::json, 1, %s, %s
            )
            ON CONFLICT (issuance_transaction_id) DO UPDATE
            SET updated_at = EXCLUDED.updated_at
            WHERE flow_instance_artifacts.flow_instance_id = EXCLUDED.flow_instance_id
            RETURNING id, (xmax = 0) AS created
            """,
            (
                artifact_id,
                flow_instance_id,
                ISSUANCE_TRANSACTION_ID,
                now + timedelta(minutes=10),
                ISSUANCE_TRANSACTION_ID,
                now,
                now,
            ),
        ).fetchone()
        assert row is not None
        connection.commit()
        return str(row[0]), bool(row[1])


def _cross_instance_rebind_is_rejected(flow_instance_id: str) -> bool:
    other_instance_id = str(uuid.uuid4())
    now = datetime.now(UTC)
    with psycopg.connect(DATABASE_URL) as connection:
        connection.execute(
            """
            INSERT INTO flow_service.flow_instances (
                id, flow_definition_id, organization_id, status,
                context, step_history, subject_type, created_at, updated_at
            ) VALUES (
                %s, 'flow-contract', 'org-race', 'in_progress',
                '{}'::json, '[]'::json, 'applicant', %s, %s
            )
            """,
            (other_instance_id, now, now),
        )
        rebound = connection.execute(
            """
            INSERT INTO flow_service.flow_instance_artifacts (
                id, flow_instance_id, issuance_transaction_id,
                credential_offer_uris, credential_offer_labels,
                status, wallet_metadata, attempt_number, created_at, updated_at
            ) VALUES (
                %s, %s, %s, '{}'::json, '{}'::json,
                'active', '{}'::json, 1, %s, %s
            )
            ON CONFLICT (issuance_transaction_id) DO UPDATE
            SET updated_at = EXCLUDED.updated_at
            WHERE flow_instance_artifacts.flow_instance_id = EXCLUDED.flow_instance_id
            RETURNING id
            """,
            (
                str(uuid.uuid4()),
                other_instance_id,
                ISSUANCE_TRANSACTION_ID,
                now,
                now,
            ),
        ).fetchone()
        owner = connection.execute(
            """
            SELECT flow_instance_id
            FROM flow_service.flow_instance_artifacts
            WHERE issuance_transaction_id = %s
            """,
            (ISSUANCE_TRANSACTION_ID,),
        ).fetchone()
        connection.rollback()
        return rebound is None and owner is not None and str(owner[0]) == flow_instance_id


def main() -> None:
    _upgrade()

    instance_barrier = threading.Barrier(2)
    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(_reserve_instance, instance_barrier)
        second = executor.submit(_reserve_instance, instance_barrier)
        instance_results = [first.result(timeout=20), second.result(timeout=20)]

    assert sorted(created for _, created in instance_results) == [False, True]
    assert len({instance_id for instance_id, _ in instance_results}) == 1
    flow_instance_id = instance_results[0][0]

    artifact_barrier = threading.Barrier(2)
    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(_reserve_artifact, artifact_barrier, flow_instance_id)
        second = executor.submit(_reserve_artifact, artifact_barrier, flow_instance_id)
        artifact_results = [first.result(timeout=20), second.result(timeout=20)]

    assert len({artifact_id for artifact_id, _ in artifact_results}) == 1
    cross_instance_rebind_rejected = _cross_instance_rebind_is_rejected(
        flow_instance_id
    )
    assert cross_instance_rebind_rejected

    with psycopg.connect(DATABASE_URL) as connection:
        instance_count = connection.execute(
            """
            SELECT count(*)
            FROM flow_service.flow_instances
            WHERE organization_id = 'org-race'
              AND application_flow_key_hash = %s
            """,
            (FLOW_KEY_HASH,),
        ).fetchone()[0]
        artifact_count = connection.execute(
            """
            SELECT count(*)
            FROM flow_service.flow_instance_artifacts
            WHERE issuance_transaction_id = %s
            """,
            (ISSUANCE_TRANSACTION_ID,),
        ).fetchone()[0]
        version = connection.execute(
            "SELECT version_num FROM flow_service.alembic_version"
        ).fetchone()[0]

    assert instance_count == 1
    assert artifact_count == 1
    assert version == "20260809_0001"

    instance_created_count = sum(created for _, created in instance_results)
    RESULT_PATH.parent.mkdir(parents=True, exist_ok=True)
    RESULT_PATH.write_text(
        json.dumps(
            {
                "status": "passed",
                "source_revision": SOURCE_REVISION,
                "migration_revision": version,
                "instance_created_count": instance_created_count,
                "instance_recovered_count": len(instance_results)
                - instance_created_count,
                "same_instance": True,
                "artifact_count": artifact_count,
                "same_artifact": True,
                "cross_instance_rebind_rejected": cross_instance_rebind_rejected,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
