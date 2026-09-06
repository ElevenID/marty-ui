"""Actual published worker processes on the exact-owned published schema.

No worker, database query, clock or processor is patched. Only synthetic inputs
are supplied. Empty queues establish startup/heartbeat, not provider capability.
Child logs are discarded; observations never contain credentials or tracebacks.
"""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

from sqlalchemy import create_engine, text

DATABASE = "postgresql://oracle:synthetic-local-only@127.0.0.1:5432/canvas_published_schema_test"


def observe(engine, case):
    worker_id = f"startup-{case['name']}"
    # The parent is the isolated immutable-image probe, not a host environment.
    environment = {
        key: value for key, value in os.environ.items() if not key.startswith("CANVAS_")
    }
    environment.update(
        DATABASE_URL=DATABASE.replace("postgresql:", f"{case['database_scheme']}:", 1),
        TOKEN_HMAC_KEY="synthetic-startup-hmac-key",
        INTEGRATION_SECRET_MASTER_KEY="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        ISSUANCE_API_KEY="synthetic-startup-api-key",
        SIGNING_KEYS_INTERNAL_API_KEY="synthetic-startup-api-key",
        SIGNING_KEYS_INTERNAL_URL="http://127.0.0.1:1/internal/signing-keys",
        CANVAS_SYNC_PROCESSOR=(
            "issuance.infrastructure.api.canvas_routes:process_authoritative_canvas_sync_target"
        ),
        CANVAS_SYNC_WORKER_ID=worker_id,
        CANVAS_SYNC_WORKER_POLL_SECONDS="60",
        CANVAS_PILOT_ORGANIZATION_IDS="bootstrap-org",
    )
    environment.update(case["environment"])
    with engine.begin() as connection:
        connection.execute(text("TRUNCATE issuance_service.canvas_worker_heartbeats"))
    child = subprocess.Popen(
        [sys.executable, "-m", "issuance.canvas_worker"],
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    heartbeat = None
    try:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if child.poll() is not None:
                break
            with engine.connect() as connection:
                row = (
                    connection.execute(
                        text(
                            "SELECT role, metadata FROM issuance_service.canvas_worker_heartbeats "
                            "WHERE worker_id = :id AND metadata->>'phase' = 'idle'"
                        ),
                        {"id": worker_id},
                    )
                    .mappings()
                    .one_or_none()
                )
            if row is not None:
                heartbeat = dict(row)
                break
            time.sleep(0.025)
        else:
            raise AssertionError("Published startup observation timed out")
        alive = child.poll() is None
        if alive:
            child.send_signal(signal.SIGINT)
        exit_code = child.wait(timeout=10)
        with engine.connect() as connection:
            jobs = connection.execute(
                text("SELECT count(*) FROM issuance_service.canvas_evidence_sync_jobs")
            ).scalar_one()
        return {
            "name": case["name"],
            "heartbeat": heartbeat,
            "alive_after_idle": alive,
            "exit_code_after_interrupt": exit_code,
            "job_count": jobs,
        }
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=10)


def run():
    scenarios = json.loads(
        Path("/verification/contracts/canvas-worker-startup-scenarios.json").read_text()
    )
    engine = create_engine(DATABASE, hide_parameters=True)
    try:
        observations = [observe(engine, case) for case in scenarios["cases"]]
    finally:
        engine.dispose()
    return {
        "schema": "marty.canvas-worker-startup-oracle/v1",
        "python": sys.version.split()[0],
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
        "cases": observations,
    }
