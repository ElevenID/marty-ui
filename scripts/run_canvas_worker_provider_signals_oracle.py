"""Signal only the owned published child while actual provider I/O is pending."""

import hashlib
import importlib.util
import json
from pathlib import Path
import signal

from sqlalchemy import create_engine, text

from canvas_worker_https_fixture import WorkerHttpsFixture
from run_canvas_worker_rest_oracle import seed_worker_database, worker_case
from run_canvas_worker_startup_oracle import DATABASE, finish_worker, start_worker


def snapshot(engine, spec, shared, heartbeat_sql=None):
    with engine.connect() as connection:
        state = {
            key: connection.execute(text(query)).scalar_one()
            for key, query in [
                ("jobs", spec["jobs_sql"]),
                ("facts", spec["facts_sql"]),
                ("oauth", spec["oauth_sql"]),
                ("snapshot", shared["snapshot_sql"]),
                (
                    "heartbeat",
                    heartbeat_sql
                    or "SELECT jsonb_build_object('role',role,'metadata',metadata) FROM issuance_service.canvas_worker_heartbeats WHERE worker_id='worker-rest'",
                ),
            ]
        }
        preserved = connection.execute(text(shared["preserved_rows_sql"])).scalar_one()
        ciphertext = connection.execute(
            text(
                "SELECT encrypted_secret_value FROM issuance_service.organization_integration_secrets WHERE id='worker-rest-token'"
            )
        ).scalar_one()
    return state, preserved, ciphertext


def run(signal_name):
    contracts = Path("/verification/contracts")
    cases = json.loads(
        (contracts / "canvas-worker-provider-signals-scenarios.json").read_text()
    )
    assert signal_name in cases["signals"]
    spec = json.loads((contracts / cases["reference_scenario"]).read_text())
    shared = json.loads((contracts / spec["shared_seed"]).read_text())
    with WorkerHttpsFixture() as https:
        engine = create_engine(DATABASE, hide_parameters=True)
        try:
            preserved, ciphertext = seed_worker_database(
                engine, https.origin, spec, shared
            )
            https.stage = {**spec["stages"][0], "hold_response": True}
            child = start_worker(worker_case(https.origin, https.cert), "worker-rest")
            try:
                assert https.received.wait(15), (
                    "Actual worker did not reach provider I/O"
                )
                assert child.poll() is None
                before, current, encrypted = snapshot(engine, spec, shared)
                assert len(before["jobs"]) == 1
                assert before["jobs"][0]["status"] == "leased"
                assert before["facts"] == []
                assert (current, encrypted) == (preserved, ciphertext)
                child.send_signal(getattr(signal, signal_name))
                exit_code = child.wait(timeout=10)
                assert not https.release.is_set()
                after, current, encrypted = snapshot(engine, spec, shared)
                assert (current, encrypted) == (preserved, ciphertext)
                return {
                    "schema": "marty.canvas-worker-provider-signals-oracle/v1",
                    "signal": signal_name,
                    "requests": list(https.requests),
                    "response_released_after_exit": True,
                    "exit_code": exit_code,
                    "before": before,
                    "after": after,
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
                }
            finally:
                finish_worker(child)
        finally:
            engine.dispose()
