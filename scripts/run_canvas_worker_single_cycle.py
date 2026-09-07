"""Test-only observer of the actual published cycle API and its return value."""

import asyncio
from dataclasses import asdict
import json
import os

from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from issuance.canvas_worker import (
    CanvasSyncWorkerConfig,
    load_canvas_sync_processor,
    run_canvas_sync_worker_cycle,
)
from issuance.infrastructure.adapters.postgres_repository import (
    PostgresIssuanceRepository,
)


async def run():
    # Only the fixed owned fixture database is accepted, never a deployment URL.
    database = "postgresql+asyncpg://oracle:synthetic-local-only@127.0.0.1:5432/canvas_published_schema_test"
    assert os.environ["DATABASE_URL"] == database
    engine = create_async_engine(database, hide_parameters=True)
    try:
        repository = PostgresIssuanceRepository(
            async_sessionmaker(engine, expire_on_commit=False)
        )
        result = await run_canvas_sync_worker_cycle(
            repo=repository,
            config=CanvasSyncWorkerConfig.from_env(),
            processor=load_canvas_sync_processor(
                os.environ.get("CANVAS_SYNC_PROCESSOR")
            ),
        )
        async with engine.begin() as connection:
            await connection.execute(
                text(
                    "INSERT INTO issuance_service.synthetic_revocation_cycle_result (result) VALUES (CAST(:result AS jsonb))"
                ),
                {"result": json.dumps(asdict(result))},
            )
    finally:
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(run())
