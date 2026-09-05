"""Published ASGI operations and real PostgreSQL; external lifecycle ports controlled.

Generated UUID identities are consistently aliased, and timestamps are checked
as ISO datetimes then represented as present. Null/omitted fields are retained.
This is HTTP/state-machine evidence, not timestamp or external lifecycle parity.
"""

import asyncio
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
from unittest.mock import patch
from uuid import UUID

import httpx
from fastapi import FastAPI
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine


async def observe():
    os.environ["ISSUANCE_API_KEY"] = "synthetic-operations-key"
    os.environ["CANVAS_PORTABLE_INTEGRATION_ENABLED"] = "true"
    os.environ["CANVAS_PILOT_ORGANIZATION_IDS"] = "org-review"
    from issuance.application import canvas_sync_jobs, canvas_sync_service
    from issuance.domain.ports import IIssuanceRepository
    from issuance.infrastructure.adapters import postgres_repository
    from issuance.infrastructure.api import canvas_operations_routes as operations

    root = Path("/verification/contracts")
    scenarios = json.loads((root / "canvas-operations-scenarios.json").read_text())
    shared = json.loads((root / scenarios["shared_seed"]).read_text())
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
    aliases = {}
    calls = []
    stage = {}
    handler_entered, handler_release = asyncio.Event(), asyncio.Event()

    def normalize(value, key=None):
        if isinstance(value, dict):
            return {key: normalize(item, key) for key, item in value.items()}
        if isinstance(value, list):
            return [normalize(item) for item in value]
        if isinstance(value, str) and key and key.endswith("_at"):
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            assert parsed.tzinfo is not None
            return "$timestamp"
        if isinstance(value, str) and key in {"id", "target_id"}:
            try:
                UUID(value)
            except ValueError:
                return value
            return aliases.setdefault(value, f"$generated-id-{len(aliases) + 1}")
        return value

    async def sql(statements):
        async with engine.begin() as connection:
            for statement in statements:
                await connection.exec_driver_sql(statement)

    async def prepare_review(review_id):
        async with engine.begin() as connection:
            await connection.execute(
                text("DELETE FROM issuance_service.evidence_policy_reviews")
            )
            await connection.execute(
                text(
                    "INSERT INTO issuance_service.evidence_policy_reviews "
                    "(id,organization_id,application_id,credential_id,binding_id,status,"
                    "prior_decision,current_decision,resolution_recovery_pending,created_at,updated_at) "
                    "VALUES (:id,'org-review','application-review','credential-review','binding-review',"
                    "'open',CAST(:prior AS json),CAST(:current AS json),false,now(),now())"
                ),
                {
                    "id": review_id,
                    "prior": json.dumps({"allowed": True}),
                    "current": json.dumps({"allowed": False}),
                },
            )

    async def lifecycle(action, *, credential_id, request, repo):
        assert credential_id == "credential-review"
        async with engine.begin() as connection:
            claim = (
                await connection.execute(
                    text(
                        "SELECT resolution_claim_token IS NOT NULL AND status='open' "
                        "AND resolution_claim_action=:action FROM issuance_service.evidence_policy_reviews"
                    ),
                    {"action": action},
                )
            ).scalar_one()
            assert claim is True, "Lifecycle must follow the winning durable claim"
            if stage.get("recovery_during_handler"):
                await connection.exec_driver_sql(
                    "UPDATE issuance_service.evidence_policy_reviews SET "
                    "resolution_recovery_pending=true,current_decision='{\"allowed\":true}'"
                )
        calls.append(
            {
                "action": action,
                "credential_id": credential_id,
                "reason": request.reason,
                "claim_active": claim,
            }
        )
        if stage.get("concurrent"):
            handler_entered.set()
            await asyncio.wait_for(handler_release.wait(), timeout=5)
        if stage.get("handler_failure"):
            raise RuntimeError("synthetic lifecycle port unavailable")

    async def suspend(**arguments):
        await lifecycle("suspend", **arguments)

    async def revoke(**arguments):
        await lifecycle("revoke", **arguments)

    def response_projection(response):
        try:
            body = response.json()
        except ValueError:
            body = response.text
        return {
            "status": response.status_code,
            "content_type": response.headers.get("content-type"),
            "body": normalize(body),
        }

    observations = []
    try:
        await sql(shared["seed"] + scenarios["seed"])
        await prepare_review("review-dismiss")
        async with engine.connect() as connection:
            preserved = (
                await connection.execute(text(shared["preserved_rows_sql"]))
            ).scalar_one()
        with (
            patch.object(operations, "suspend_credential", suspend),
            patch.object(operations, "revoke_credential", revoke),
        ):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
                base_url="http://synthetic-operations.invalid",
                timeout=10,
            ) as client:
                for stage in scenarios["cases"]:
                    os.environ["CANVAS_PORTABLE_INTEGRATION_ENABLED"] = (
                        "true" if stage.get("rollout", True) else "false"
                    )
                    if stage.get("prepare_review"):
                        await prepare_review(stage["prepare_review"])
                    await sql(stage.get("sql", []))
                    headers = {
                        "X-API-Key": "synthetic-operations-key",
                        "X-Organization-ID": "org-review",
                    }
                    headers.update(stage.get("headers", {}))
                    for header in stage.get("omit_headers", []):
                        headers.pop(header)
                    body = dict(stage.get("body", {}))
                    if "note_length" in stage:
                        body["note"] = "n" * stage["note_length"]
                    arguments = {
                        "method": stage["method"],
                        "url": stage["path"],
                        "headers": headers,
                    }
                    if stage["method"] == "POST":
                        arguments["json"] = body
                    before_calls = len(calls)
                    competing = None
                    if stage.get("concurrent"):
                        handler_entered.clear()
                        handler_release.clear()
                        first = asyncio.create_task(client.request(**arguments))
                        try:
                            await asyncio.wait_for(handler_entered.wait(), timeout=5)
                            competing = await asyncio.wait_for(
                                client.request(**arguments), timeout=5
                            )
                            assert competing.status_code == 409
                        finally:
                            handler_release.set()
                            response = await asyncio.wait_for(first, timeout=5)
                    else:
                        response = await client.request(**arguments)
                    assert response.status_code == stage["expected_status"], (
                        stage["name"],
                        response.status_code,
                        response.text[:500],
                    )
                    async with engine.connect() as connection:
                        snapshot = (
                            await connection.execute(text(scenarios["snapshot_sql"]))
                        ).scalar_one()
                        current = (
                            await connection.execute(text(shared["preserved_rows_sql"]))
                        ).scalar_one()
                    assert current == preserved, (
                        "HTTP operations changed synthetic credential/transaction rows"
                    )
                    record = {
                        "name": stage["name"],
                        **response_projection(response),
                        "snapshot": normalize(snapshot),
                        "lifecycle_calls": calls[before_calls:],
                    }
                    if competing is not None:
                        record["competing_response"] = response_projection(competing)
                        assert len(record["lifecycle_calls"]) == 1
                    if stage.get("prepare_review"):
                        assert len(record["lifecycle_calls"]) == 1
                    public_body = json.dumps(record["body"])
                    assert "synthetic-private" not in public_body
                    assert "subject-private" not in public_body
                    observations.append(record)
        async with engine.connect() as connection:
            claim_constraint = (
                await connection.execute(
                    text(
                        "SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE "
                        "conrelid='issuance_service.evidence_policy_reviews'::regclass "
                        "AND conname='ck_evidence_policy_reviews_resolution_claim'"
                    )
                )
            ).scalar_one()
        return {
            "claim_constraint": claim_constraint,
            "operations_sha256": hashlib.sha256(
                Path(operations.__file__).read_text(encoding="utf-8").encode()
            ).hexdigest(),
            "repository_sha256": hashlib.sha256(
                Path(postgres_repository.__file__).read_text(encoding="utf-8").encode()
            ).hexdigest(),
            "sync_service_sha256": hashlib.sha256(
                Path(canvas_sync_service.__file__).read_text(encoding="utf-8").encode()
            ).hexdigest(),
            "sync_jobs_sha256": hashlib.sha256(
                Path(canvas_sync_jobs.__file__).read_text(encoding="utf-8").encode()
            ).hexdigest(),
            "normalization": "generated UUID identity aliases; validated ISO timestamp presence, not exact wall-clock values",
            "boundary": "actual ASGI/auth/service/PostgreSQL; controlled external suspend/revoke ports",
            "observations": observations,
        }
    finally:
        await engine.dispose()


def run():
    return asyncio.run(asyncio.wait_for(observe(), timeout=90))
