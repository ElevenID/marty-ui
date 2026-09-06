"""Actual published worker, OAuth storage and local HTTP on official migrations."""

import asyncio
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import time

from sqlalchemy import create_engine, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from run_canvas_worker_startup_oracle import (
    DATABASE,
    finish_worker,
    start_blocked_workers,
    start_worker,
)
from canvas_worker_https_fixture import WorkerHttpsFixture


async def seed_oauth(origin, token):
    from issuance.domain.entities import (
        CanvasOAuthConnection,
        OrganizationIntegrationSecret,
    )
    from issuance.infrastructure.adapters.postgres_repository import (
        PostgresIssuanceRepository,
    )

    engine = create_async_engine(
        DATABASE.replace("postgresql:", "postgresql+asyncpg:", 1)
    )
    try:
        repo = PostgresIssuanceRepository(
            async_sessionmaker(engine, expire_on_commit=False)
        )
        await repo.save_integration_secret(
            OrganizationIntegrationSecret(
                id="worker-rest-token",
                organization_id="org-review",
                name="Synthetic REST token",
                provider="canvas",
                secret_value=token,
            )
        )
        await repo.save_canvas_oauth_connection(
            CanvasOAuthConnection(
                id="worker-rest-connection",
                organization_id="org-review",
                platform_id="platform-review",
                canvas_base_url=origin,
                client_id="synthetic-client",
                client_secret_ref="org_secret://org-review/unused-client",
                access_token_secret_ref="org_secret://org-review/worker-rest-token",
            )
        )
    finally:
        await engine.dispose()


def run(scenario="canvas-worker-rest-scenarios.json"):
    spec = json.loads((Path("/verification/contracts") / scenario).read_text())
    if "extends" in spec:
        base = json.loads(
            (Path("/verification/contracts") / spec["extends"]).read_text()
        )
        spec = {**base, **spec}
    shared = json.loads(
        (Path("/verification/contracts") / spec["shared_seed"]).read_text()
    )
    with WorkerHttpsFixture() as https:
        return run_scenarios(spec, shared, https)


def seed_worker_database(engine, origin, spec, shared):
    os.environ["INTEGRATION_SECRET_MASTER_KEY"] = (
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    )
    with engine.begin() as connection:
        for statement in shared["seed"]:
            connection.exec_driver_sql(statement)
        if "requirements" in spec:
            connection.execute(
                text(
                    "UPDATE issuance_service.canvas_program_bindings SET evidence_requirements=CAST(:requirements AS json) WHERE id='binding-review'"
                ),
                {"requirements": json.dumps(spec["requirements"])},
            )
        connection.execute(
            text(
                "UPDATE issuance_service.canvas_platforms SET canvas_base_url=:origin"
            ),
            {"origin": origin},
        )
    asyncio.run(seed_oauth(origin, spec["token"]))
    with engine.connect() as connection:
        preserved = connection.execute(text(shared["preserved_rows_sql"])).scalar_one()
        ciphertext = connection.execute(
            text(
                "SELECT encrypted_secret_value FROM issuance_service.organization_integration_secrets WHERE id='worker-rest-token'"
            )
        ).scalar_one()
    assert ciphertext != spec["token"]
    return preserved, ciphertext


def worker_case(origin, cert, extra=None):
    return {
        "database_scheme": "postgresql+asyncpg",
        "environment": {
            "CANVAS_PORTABLE_INTEGRATION_ENABLED": "true",
            "CANVAS_PILOT_ORGANIZATION_IDS": "org-review",
            "CANVAS_PRIVATE_ORIGIN_ALLOWLIST": origin,
            "MARTY_CANVAS_TEST_CA_FILE": str(cert),
            "PYTHONPATH": "/verification/worker_trust:"
            + os.environ.get("PYTHONPATH", ""),
            **(extra or {}),
        },
    }


def run_scenarios(spec, shared, https):
    origin, cert, requests = https.origin, https.cert, https.requests
    engine = create_engine(DATABASE, hide_parameters=True)
    observations = []
    try:
        preserved, ciphertext = seed_worker_database(engine, origin, spec, shared)
        for index, stage in enumerate(spec["stages"]):
            https.stage = stage
            requests.clear()
            with engine.connect() as connection:
                prior_job_ids = (
                    connection.execute(
                        text(
                            "SELECT id FROM issuance_service.canvas_evidence_sync_jobs ORDER BY created_at,id"
                        )
                    )
                    .scalars()
                    .all()
                )
            if stage.get("retry_existing"):
                assert prior_job_ids
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline:
                    with engine.connect() as connection:
                        due = connection.execute(
                            text(
                                "SELECT status='retry' AND available_at<=clock_timestamp() FROM issuance_service.canvas_evidence_sync_jobs WHERE id=:id"
                            ),
                            {"id": prior_job_ids[-1]},
                        ).scalar_one()
                    if due:
                        break
                    time.sleep(0.05)
                else:
                    raise AssertionError("Actual persisted retry did not become due")
            with engine.begin() as connection:
                if not stage.get("retry_existing"):
                    connection.execute(
                        text(
                            "UPDATE issuance_service.canvas_evidence_sync_targets SET next_run_at=clock_timestamp() WHERE id='target-review'"
                        )
                    )
                connection.execute(
                    text("TRUNCATE issuance_service.canvas_worker_heartbeats")
                )
            race = stage.get("reference_race")
            if race is None:
                child = start_worker(worker_case(origin, cert), "worker-rest")
            else:
                child = start_blocked_workers(
                    engine,
                    worker_case(origin, cert),
                    ["worker-rest"],
                    race["barrier_sql"],
                    text(race["blocked_sql"]),
                    lambda: None,
                    race["release_sql"],
                )["worker-rest"]
            try:
                deadline = time.monotonic() + 25
                while time.monotonic() < deadline:
                    assert child.poll() is None, (
                        "Published worker exited before completing its cycle"
                    )
                    with engine.connect() as connection:
                        jobs = connection.execute(text(spec["jobs_sql"])).scalar_one()
                        heartbeat = connection.execute(
                            text(
                                "SELECT jsonb_build_object('role',role,'metadata',metadata) FROM issuance_service.canvas_worker_heartbeats WHERE worker_id='worker-rest' AND metadata->>'phase'='idle'"
                            )
                        ).scalar_one_or_none()
                    if (
                        len(jobs) == stage.get("expected_jobs", index + 1)
                        and jobs[-1]["attempt_count"]
                        == stage.get("expected_attempts", 1)
                        and jobs[-1]["status"] in {"succeeded", "retry", "dead_letter"}
                        and heartbeat
                    ):
                        break
                    time.sleep(0.025)
                else:
                    raise AssertionError("Published nonempty worker cycle timed out")
                child.send_signal(signal.SIGINT)
                exit_code = child.wait(timeout=10)
                with engine.connect() as connection:
                    if stage.get("retry_existing"):
                        assert (
                            connection.execute(
                                text(
                                    "SELECT id FROM issuance_service.canvas_evidence_sync_jobs ORDER BY created_at,id"
                                )
                            )
                            .scalars()
                            .all()
                            == prior_job_ids
                        )
                    snapshot = connection.execute(
                        text(shared["snapshot_sql"])
                    ).scalar_one()
                    facts = connection.execute(text(spec["facts_sql"])).scalar_one()
                    oauth = connection.execute(text(spec["oauth_sql"])).scalar_one()
                    assert (
                        connection.execute(
                            text(shared["preserved_rows_sql"])
                        ).scalar_one()
                        == preserved
                    )
                    assert (
                        connection.execute(
                            text(
                                "SELECT encrypted_secret_value FROM issuance_service.organization_integration_secrets WHERE id='worker-rest-token'"
                            )
                        ).scalar_one()
                        == ciphertext
                    )
                observations.append(
                    {
                        "name": stage["name"],
                        "requests": list(requests),
                        "jobs": jobs,
                        "heartbeat": heartbeat,
                        "snapshot": snapshot,
                        "facts": facts,
                        "oauth": oauth,
                        "exit_code_after_interrupt": exit_code,
                    }
                )
                if stage.get("retry_existing"):
                    observations[-1]["same_job_ids"] = True
                if race is not None:
                    with engine.connect() as connection:
                        absent = connection.execute(
                            text(race["absent_sql"])
                        ).scalar_one()
                    assert absent is True
                    observations[-1]["reference_race"] = {
                        "blocked_before_release": True,
                        "referenced_row_absent": absent,
                    }
            finally:
                finish_worker(child)
        return {
            "schema": spec.get("oracle_schema", "marty.canvas-worker-rest-oracle/v1"),
            "source_sha256": {
                name: hashlib.sha256(
                    Path(importlib.util.find_spec(name).origin)
                    .read_text(encoding="utf-8")
                    .encode()
                ).hexdigest()
                for name in [
                    "issuance.canvas_worker",
                    "issuance.infrastructure.api.canvas_routes",
                ]
            },
            "observations": observations,
        }
    finally:
        engine.dispose()
