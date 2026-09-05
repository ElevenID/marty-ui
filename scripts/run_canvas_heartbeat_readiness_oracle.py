"""Actual published repository and readiness policy on an owned migrated DB.

Only the repository wall clock is fixed, to observe the exact inclusive SQL
cutoff without scheduler timing noise. No query or readiness decision is mocked.
Empty template inputs prevent external signing/document calls. Results cover
only the worker-heartbeat readiness check, not complete binding activation.
"""

import asyncio
from datetime import datetime, timedelta
import hashlib
import json
from pathlib import Path
from unittest.mock import patch

from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine


async def observe():
    from issuance.application import canvas_readiness
    from issuance.domain.entities import CanvasPlatform, CanvasProgramBinding
    from issuance.infrastructure.adapters import postgres_repository

    scenarios = json.loads(
        Path(
            "/verification/contracts/canvas-heartbeat-readiness-scenarios.json"
        ).read_text()
    )
    evaluated_at = datetime.fromisoformat(scenarios["evaluated_at"])

    class FixedClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return (
                evaluated_at.astimezone(tz) if tz else evaluated_at.replace(tzinfo=None)
            )

    engine = create_async_engine(
        "postgresql+asyncpg://oracle:synthetic-local-only@127.0.0.1:5432/canvas_published_schema_test",
        hide_parameters=True,
    )
    repo = postgres_repository.PostgresIssuanceRepository(
        async_sessionmaker(engine, expire_on_commit=False)
    )
    platform = CanvasPlatform(id="platform-heartbeat", organization_id="org-heartbeat")
    binding = CanvasProgramBinding(
        id="binding-heartbeat", organization_id="org-heartbeat", platform_id=platform.id
    )

    async def readiness(max_age):
        result = await canvas_readiness.evaluate_canvas_binding_readiness(
            repo=repo,
            platform=platform,
            binding=binding,
            application_template=None,
            credential_template=None,
            credential_status_profile=None,
            rollout_allowed=False,
            now=evaluated_at,
            worker_max_age_seconds=max_age,
        )
        checks = [
            check.to_dict()
            for check in result.checks
            if check.code == "worker_heartbeat"
        ]
        assert len(checks) == 1
        return checks[0]

    observations = []
    try:
        with patch.object(postgres_repository, "datetime", FixedClock):
            for case in scenarios["cases"]:
                async with engine.begin() as connection:
                    await connection.execute(
                        text("TRUNCATE issuance_service.canvas_worker_heartbeats")
                    )
                    for row in case["rows"]:
                        await connection.execute(
                            text(
                                "INSERT INTO issuance_service.canvas_worker_heartbeats "
                                "(worker_id, role, started_at, last_heartbeat_at, metadata) "
                                "VALUES (:id, :role, :started, :heartbeat, CAST(:metadata AS json))"
                            ),
                            {
                                "id": row["id"],
                                "role": row.get("role", "canvas_sync"),
                                "started": evaluated_at - timedelta(days=1),
                                "heartbeat": evaluated_at
                                - timedelta(microseconds=row["age_us"]),
                                "metadata": json.dumps(row["metadata"]),
                            },
                        )
                selected = await repo.get_fresh_canvas_worker_heartbeat(
                    role="canvas_sync", max_age_seconds=case["max_age_seconds"]
                )
                observations.append(
                    {
                        "name": case["name"],
                        "selected_worker": selected.worker_id if selected else None,
                        "check": await readiness(case["max_age_seconds"]),
                    }
                )
            # An actual SQL relation failure, not an injected successful result.
            async with engine.begin() as connection:
                await connection.execute(
                    text(
                        "ALTER TABLE issuance_service.canvas_worker_heartbeats "
                        "RENAME TO canvas_worker_heartbeats_unavailable"
                    )
                )
            try:
                observations.append(
                    {"name": "database_failure", "check": await readiness(120)}
                )
            finally:
                async with engine.begin() as connection:
                    await connection.execute(
                        text(
                            "ALTER TABLE issuance_service.canvas_worker_heartbeats_unavailable "
                            "RENAME TO canvas_worker_heartbeats"
                        )
                    )
        return {
            "repository_sha256": hashlib.sha256(
                Path(postgres_repository.__file__).read_text(encoding="utf-8").encode()
            ).hexdigest(),
            "readiness_sha256": hashlib.sha256(
                Path(canvas_readiness.__file__).read_text(encoding="utf-8").encode()
            ).hexdigest(),
            "observations": observations,
        }
    finally:
        await engine.dispose()


def run():
    return asyncio.run(observe())
