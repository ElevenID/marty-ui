"""Published Python hook + real PostgreSQL; provider responses alone are controlled."""

import asyncio
from contextlib import asynccontextmanager
import hashlib
import json
import os
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine


async def observe():
    os.environ["CANVAS_PORTABLE_INTEGRATION_ENABLED"] = "true"
    os.environ["CANVAS_PILOT_ORGANIZATION_IDS"] = "org-review"
    from issuance.infrastructure.api import canvas_routes
    from issuance.infrastructure.adapters.postgres_repository import (
        PostgresIssuanceRepository,
    )

    scenarios = json.loads(
        Path("/verification/contracts/canvas-issued-review-scenarios.json").read_text()
    )
    engine = create_async_engine(
        "postgresql+asyncpg://oracle:synthetic-local-only@127.0.0.1:5432/canvas_published_schema_test",
        hide_parameters=True,
    )
    repo = PostgresIssuanceRepository(
        async_sessionmaker(engine, expire_on_commit=False)
    )
    stage = {}

    @asynccontextmanager
    async def client(**_):
        yield None

    async def token(**_):
        return "synthetic-unused-token"

    async def read(*, requirement, canvas_user_id, **_):
        assert canvas_user_id == "7" and requirement.requirement_id == "assignment"
        if stage.get("error"):
            raise canvas_routes.CanvasLtiServiceError("synthetic unavailable")
        return {
            "id": 11,
            "assignment_id": 9,
            "score": stage["score"],
            "workflow_state": "graded",
            "assignment": {"points_possible": 100},
            "updated_at": f"2026-09-01T00:{stage['revision']:02}:00Z",
        }, requirement.scope.to_dict()

    # No policy/processor/repository/transaction method is replaced.
    canvas_routes.canvas_http_client = client
    canvas_routes._canvas_oauth_access_token = token
    canvas_routes._read_canvas_rest_evidence = read
    observations = []
    try:
        async with engine.begin() as connection:
            for statement in scenarios["seed"]:
                await connection.exec_driver_sql(statement)
        async with engine.connect() as connection:
            original = (
                await connection.execute(text(scenarios["preserved_rows_sql"]))
            ).scalar_one()
        for stage in scenarios["stages"]:
            if stage.get("action"):
                async with engine.begin() as connection:
                    result = await connection.execute(
                        text(scenarios["actions"][stage["action"]])
                    )
                    assert result.rowcount == 1, (
                        "Expected one manually claimed/released review"
                    )
            target = await repo.get_canvas_sync_target_for_org(
                "org-review", "target-review"
            )
            try:
                result = await canvas_routes.process_authoritative_canvas_sync_target(
                    repo, target
                )
                outcome = {"result": result}
            except canvas_routes.CanvasSyncProcessingError as error:
                outcome = {"error": {"code": error.code, "retryable": error.retryable}}
            async with engine.connect() as connection:
                snapshot = (
                    await connection.execute(text(scenarios["snapshot_sql"]))
                ).scalar_one()
                current = (
                    await connection.execute(text(scenarios["preserved_rows_sql"]))
                ).scalar_one()
            assert original == current, (
                "Reconciliation mutated synthetic credential or issuance transaction rows"
            )
            observations.append(
                {"name": stage["name"], **outcome, "snapshot": snapshot}
            )
        source = Path(canvas_routes.__file__).read_text(encoding="utf-8")
        return {
            "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
            "observations": observations,
        }
    finally:
        await engine.dispose()


def run():
    return asyncio.run(observe())
