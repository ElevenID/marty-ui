"""Observe the published mixed-source roster processor; only transport is replaced."""

import asyncio
from contextlib import asynccontextmanager
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine


async def observe():
    os.environ["CANVAS_PORTABLE_INTEGRATION_ENABLED"] = "true"
    os.environ["CANVAS_PILOT_ORGANIZATION_IDS"] = "org-roster"
    os.environ["CANVAS_BACKGROUND_ROSTER_BATCH_SIZE"] = "2"
    os.environ["CANVAS_BACKGROUND_ROSTER_MAX_SIZE"] = "10"
    from issuance.infrastructure.api import canvas_routes
    from issuance.infrastructure.adapters.postgres_repository import (
        PostgresIssuanceRepository,
    )

    scenarios = json.loads(
        Path("/verification/contracts/canvas-mixed-roster-scenarios.json").read_text()
    )
    engine = create_async_engine(
        "postgresql+asyncpg://oracle:synthetic-local-only@127.0.0.1:5432/canvas_published_schema_test",
        hide_parameters=True,
    )
    repo = PostgresIssuanceRepository(
        async_sessionmaker(engine, expire_on_commit=False)
    )
    stage = {}
    reads = []

    @asynccontextmanager
    async def client(**_):
        yield None

    async def oauth(**_):
        return "synthetic-unused-token"

    async def assertion(*_, **__):
        return "synthetic-unused-assertion"

    async def token(**_):
        return SimpleNamespace(value="synthetic-unused-token")

    async def users(*_, path, **__):
        assert path == "courses/42/users?enrollment_type%5B%5D=student"
        return [
            {
                "id": user,
                "name": "SYNTHETIC_NAME_MUST_NOT_PERSIST",
                "email": "synthetic-no-retention@example.invalid",
            }
            for user in [8, 7, 7]
        ]

    async def members(*, memberships_url, **_):
        assert (
            memberships_url
            == "https://canvas.example.edu/api/lti/courses/42/memberships"
        )
        return [
            {
                "user_id": "subject-7",
                "status": "Active" if stage["active"] else "Inactive",
            },
            {"user_id": "unlinked-subject", "status": "Active"},
        ]

    async def rest(*, requirement, canvas_user_id, **_):
        reads.append({"source": "rest", "identity": canvas_user_id})
        if stage.get("error"):
            raise canvas_routes.CanvasLtiServiceError("synthetic unavailable")
        return {
            "id": 11,
            "assignment_id": 9,
            "score": 90,
            "workflow_state": "graded",
            "assignment": {"points_possible": 100},
        }, requirement.scope.to_dict()

    async def ags(*, user_id, **_):
        reads.append({"source": "ags", "identity": user_id})
        if stage.get("error"):
            raise canvas_routes.CanvasLtiServiceError("synthetic unavailable")
        return [
            {
                "resultScore": stage["score"],
                "resultMaximum": 100,
                "resultStatus": "FullyGraded",
            }
        ]

    canvas_routes.canvas_http_client = client
    canvas_routes._canvas_oauth_access_token = oauth
    canvas_routes._lti_service_client_assertion = assertion
    canvas_routes.request_lti_access_token = token
    canvas_routes._fetch_canvas_api_collection = users
    canvas_routes.read_nrps_memberships = members
    canvas_routes._read_canvas_rest_evidence = rest
    canvas_routes.read_ags_results = ags
    observations = []
    try:
        async with engine.begin() as connection:
            for statement in scenarios["seed"]:
                await connection.exec_driver_sql(statement)
        for stage in scenarios["stages"]:
            reads.clear()
            if stage.get("action"):
                async with engine.begin() as connection:
                    result = await connection.exec_driver_sql(
                        scenarios["actions"][stage["action"]]
                    )
                    assert result.rowcount == 1
            target = await repo.get_canvas_sync_target_for_org(
                "org-roster", "target-roster"
            )
            result = await canvas_routes.process_authoritative_canvas_sync_target(
                repo, target
            )
            async with engine.connect() as connection:
                snapshot = (
                    await connection.execute(text(scenarios["snapshot_sql"]))
                ).scalar_one()
                stored = (
                    await connection.execute(
                        text(
                            "SELECT jsonb_build_object('candidates',(SELECT jsonb_agg(to_jsonb(c)) FROM issuance_service.canvas_award_candidates c),'observations',(SELECT jsonb_agg(to_jsonb(o)) FROM issuance_service.canvas_candidate_observations o))"
                        )
                    )
                ).scalar_one()
            serialized = json.dumps(stored)
            assert "SYNTHETIC_NAME_MUST_NOT_PERSIST" not in serialized
            assert "synthetic-no-retention@example.invalid" not in serialized
            assert (
                snapshot["applications"]
                == snapshot["credentials"]
                == snapshot["facts"]
                == 0
            )
            observations.append(
                {
                    "name": stage["name"],
                    "result": result,
                    "reads": list(reads),
                    "snapshot": snapshot,
                }
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
