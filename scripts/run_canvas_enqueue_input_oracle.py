"""Published enqueue inputs and shared identifier conversion on disposable PG."""

import asyncio
from datetime import datetime
import hashlib
import json
import os
import unicodedata
from uuid import UUID
from pathlib import Path

import httpx
from fastapi import FastAPI
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine


async def observe():
    os.environ["ISSUANCE_API_KEY"] = "synthetic-operations-key"
    os.environ["CANVAS_PILOT_ORGANIZATION_IDS"] = "org-review"
    from issuance.application import canvas_sync_service as service
    from issuance.domain.ports import IIssuanceRepository
    from issuance.infrastructure.adapters import postgres_repository
    from issuance.infrastructure.api import canvas_operations_routes as operations

    root = Path("/verification/contracts")
    scenarios = json.loads((root / "canvas-enqueue-input-scenarios.json").read_text())
    shared = json.loads((root / "canvas-issued-review-scenarios.json").read_text())
    engine = create_async_engine(
        "postgresql+asyncpg://oracle:synthetic-local-only@127.0.0.1:5432/canvas_published_schema_test",
        hide_parameters=True,
    )
    repo = postgres_repository.PostgresIssuanceRepository(
        async_sessionmaker(engine, expire_on_commit=False)
    )
    app = FastAPI()
    app.include_router(operations.canvas_operations_router)
    app.dependency_overrides[IIssuanceRepository] = lambda: repo

    def normalize(value, key=""):
        if isinstance(value, dict):
            return {name: normalize(item, name) for name, item in value.items()}
        if isinstance(value, list):
            return [normalize(item) for item in value]
        if isinstance(value, str) and key.endswith("_at"):
            assert datetime.fromisoformat(value.replace("Z", "+00:00")).tzinfo
            return "$timestamp"
        if key == "id":
            UUID(value)
            return "$job"
        if key == "target_id":
            if value != "target-input":
                UUID(value)
            return "$target"
        return value

    identifiers = []
    for value in scenarios["identifier_values"]:
        try:
            result = {
                "value": service._required_context_identifier({"field": value}, "field")
            }
        except service.CanvasSyncConflictError:
            result = {"missing": "field"}
        identifiers.append(result)
    observations = []
    try:
        async with engine.begin() as connection:
            for statement in shared["seed"]:
                await connection.exec_driver_sql(statement)
            preserved = (
                await connection.execute(text(shared["preserved_rows_sql"]))
            ).scalar_one()
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
            base_url="http://synthetic-enqueue.invalid",
        ) as client:
            for case in scenarios["cases"]:
                os.environ["CANVAS_PORTABLE_INTEGRATION_ENABLED"] = (
                    "true" if case.get("rollout", True) else "false"
                )
                async with engine.begin() as connection:
                    # Only this exact-owned disposable database contains these synthetic rows.
                    await connection.exec_driver_sql(
                        "DELETE FROM issuance_service.canvas_evidence_sync_jobs"
                    )
                    await connection.exec_driver_sql(
                        "DELETE FROM issuance_service.canvas_evidence_sync_targets"
                    )
                    await connection.execute(
                        text(
                            "UPDATE issuance_service.applications SET integration_context=CAST(:context AS json),credential_id=:credential WHERE id='application-review'"
                        ),
                        {
                            "context": json.dumps(
                                case.get("context", scenarios["default_context"])
                            ),
                            "credential": case.get(
                                "credential_id", "credential-review"
                            ),
                        },
                    )
                    await connection.execute(
                        text(
                            "UPDATE issuance_service.canvas_platforms SET enabled=:enabled WHERE id='platform-review'"
                        ),
                        {"enabled": case.get("platform_enabled", True)},
                    )
                    await connection.execute(
                        text(
                            "UPDATE issuance_service.canvas_program_bindings SET enabled=:enabled WHERE id='binding-review'"
                        ),
                        {"enabled": case.get("binding_enabled", True)},
                    )
                    if "metadata" in case:
                        await connection.execute(
                            text(
                                "INSERT INTO issuance_service.canvas_evidence_sync_targets "
                                "(id,organization_id,platform_id,binding_id,target_type,logical_key,application_id,metadata) "
                                "VALUES ('target-input','org-review','platform-review','binding-review','issued_drift',"
                                "'application:application-review','application-review',CAST(:metadata AS json))"
                            ),
                            {"metadata": json.dumps(case["metadata"])},
                        )
                headers = {
                    "X-API-Key": "synthetic-operations-key",
                    "X-Organization-ID": "org-review",
                }
                headers.update(case.get("headers", {}))
                for key in case.get("omit_headers", []):
                    headers.pop(key)
                response = await client.post(
                    "/v1/integrations/canvas/applications/"
                    + case.get("application", "application-review")
                    + "/canvas-sync",
                    headers=headers,
                    content=case.get("raw_body", "{}"),
                )
                try:
                    body = response.json()
                except ValueError:
                    body = response.text
                async with engine.connect() as connection:
                    targets = (
                        await connection.execute(
                            text(
                                "SELECT jsonb_agg(jsonb_build_object('target_type',target_type,'schedule_seconds',schedule_seconds,'enabled',enabled,'metadata',metadata)) FROM issuance_service.canvas_evidence_sync_targets"
                            )
                        )
                    ).scalar_one()
                    jobs = (
                        await connection.execute(
                            text(
                                "SELECT jsonb_agg(jsonb_build_object('status',status,'attempt_count',attempt_count,'max_attempts',max_attempts)) FROM issuance_service.canvas_evidence_sync_jobs"
                            )
                        )
                    ).scalar_one()
                    current = (
                        await connection.execute(text(shared["preserved_rows_sql"]))
                    ).scalar_one()
                    assert current == preserved
                observations.append(
                    {
                        "name": case["name"],
                        "status": response.status_code,
                        "content_type": response.headers.get("content-type"),
                        "body": normalize(body),
                        "targets": targets,
                        "jobs": jobs,
                    }
                )
        printable = []
        for point in range(0x110000):
            if chr(point).isprintable():
                if printable and printable[-1][1] + 1 == point:
                    printable[-1][1] = point
                else:
                    printable.append([point, point])
        return {
            "unicode": {
                "unicode_version": unicodedata.unidata_version,
                "printable_ranges": printable,
                "whitespace": [
                    point for point in range(0x110000) if chr(point).isspace()
                ],
            },
            "boundary": "published ASGI/auth/service/PostgreSQL plus direct shared identifier conversion",
            "service_sha256": hashlib.sha256(
                Path(service.__file__).read_text(encoding="utf-8").encode()
            ).hexdigest(),
            "operations_sha256": hashlib.sha256(
                Path(operations.__file__).read_text(encoding="utf-8").encode()
            ).hexdigest(),
            "identifiers": identifiers,
            "observations": observations,
        }
    finally:
        await engine.dispose()


def run():
    return asyncio.run(asyncio.wait_for(observe(), timeout=60))
