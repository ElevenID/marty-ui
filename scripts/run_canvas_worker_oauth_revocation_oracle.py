"""Observe remote revocation through the actual published worker and owned SQL."""

import hashlib
import importlib.util
import json
from pathlib import Path
import signal
import time

from sqlalchemy import create_engine, text

from canvas_worker_https_fixture import WorkerHttpsFixture
from run_canvas_worker_rest_oracle import seed_worker_database, worker_case
from run_canvas_worker_startup_oracle import (
    DATABASE,
    finish_worker,
    start_worker,
    worker_source_sha256,
)


def run(case_name, kind="oauth-revocation"):
    assert kind in {"oauth-revocation", "oauth-revocation-fence"}
    contracts = Path("/verification/contracts")
    matrix = json.loads(
        (contracts / f"canvas-worker-{kind}-scenarios.json").read_text()
    )
    if "base_scenario" in matrix:
        matrix = {
            **json.loads((contracts / matrix["base_scenario"]).read_text()),
            **matrix,
        }
    cases = [case for case in matrix["cases"] if case["name"] == case_name]
    assert len(cases) == 1, "Unknown or duplicate revocation case"
    case = cases[0]
    spec = json.loads((contracts / matrix["reference_scenario"]).read_text())
    shared = json.loads((contracts / spec["shared_seed"]).read_text())
    with WorkerHttpsFixture() as https:
        engine = create_engine(DATABASE, hide_parameters=True)
        try:
            with engine.begin() as connection:
                connection.exec_driver_sql(matrix["seed"][0])
            preserved, _ = seed_worker_database(
                engine,
                https.origin,
                spec,
                shared,
                additional_secrets=matrix["additional_secrets"],
            )
            with engine.begin() as connection:
                for statement in matrix["seed"][1:]:
                    connection.exec_driver_sql(statement)
                before_secrets = connection.execute(
                    text(matrix["secret_sql"])
                ).scalar_one()
            assert set(before_secrets) == {
                "worker-rest-token",
                "worker-refresh-token",
                "worker-unrelated-token",
            }
            for secret_id, _, plaintext in matrix["additional_secrets"]:
                assert before_secrets[secret_id] != plaintext
            assert before_secrets["worker-rest-token"] != spec["token"]
            https.stage = case
            child = start_worker(
                worker_case(https.origin, https.cert), "worker-revocation"
            )
            try:
                fence = None
                if kind == "oauth-revocation-fence":
                    assert https.received.wait(15), "Actual DELETE was not received"
                    received_at = time.monotonic()
                    assert child.poll() is None and not https.release.is_set()
                    with engine.begin() as connection:
                        before_fence = connection.execute(
                            text(matrix["fence_sql"])
                        ).scalar_one()
                        assert before_fence["owner"] == "worker-revocation"
                        assert before_fence["lease_unexpired"] is True
                        assert (
                            connection.execute(text(matrix["takeover_sql"])).rowcount
                            == 1
                        )
                        replacement = connection.execute(
                            text(matrix["row_sql"])
                        ).scalar_one()
                        replacement_fence = connection.execute(
                            text(matrix["fence_sql"])
                        ).scalar_one()
                    fence = {"before": before_fence, "replacement": replacement_fence}
                    # Release only after the test's explicit competing-owner
                    # transaction commits. The actual worker handles the reply.
                    assert time.monotonic() - received_at < 5, (
                        "Owner transfer exceeded the pre-timeout budget"
                    )
                    https.release.set()
                deadline = time.monotonic() + 25
                while True:
                    assert child.poll() is None, "Published worker exited before idle"
                    with engine.connect() as connection:
                        heartbeat = connection.execute(
                            text(matrix["heartbeat_sql"])
                        ).scalar_one_or_none()
                    if (
                        heartbeat is not None
                        and heartbeat["metadata"]["phase"] == "idle"
                    ):
                        break
                    assert time.monotonic() < deadline, (
                        "Published revocation did not reach idle"
                    )
                    time.sleep(0.025)
                if case.get("hold_response") and fence is None:
                    assert https.received.is_set() and not https.release.is_set()
                child.send_signal(signal.SIGINT)
                assert child.wait(timeout=10) == -signal.SIGINT
                with engine.connect() as connection:
                    if fence is not None:
                        assert (
                            connection.execute(text(matrix["row_sql"])).scalar_one()
                            == replacement
                        )
                        fence["replacement_row_unchanged"] = True
                    connection_state = connection.execute(
                        text(matrix["connection_sql"])
                    ).scalar_one_or_none()
                    secrets = connection.execute(
                        text(matrix["secret_sql"])
                    ).scalar_one()
                    platform = connection.execute(
                        text(matrix["platform_sql"])
                    ).scalar_one()
                    delay = connection.execute(
                        text(matrix["retry_delay_sql"])
                    ).scalar_one_or_none()
                    current = connection.execute(
                        text(shared["preserved_rows_sql"])
                    ).scalar_one()
                    jobs = connection.execute(
                        text(
                            "SELECT count(*) FROM issuance_service.canvas_evidence_sync_jobs"
                        )
                    ).scalar_one()
                assert current == preserved and jobs == 0
                assert (
                    secrets.get("worker-unrelated-token")
                    == before_secrets["worker-unrelated-token"]
                )
                assert all(
                    value == before_secrets[key] for key, value in secrets.items()
                )
                timing = None
                if fence is not None:
                    assert secrets == before_secrets
                    timing = {"kind": "preserved", "matches": True}
                elif "delay_bounds" in case:
                    minimum, maximum = case["delay_bounds"]
                    assert delay is not None and minimum - 0.1 <= delay <= maximum + 0.1
                    timing = {"kind": "bounds", "matches": True}
                else:
                    assert delay is None
                assert https.requests == [
                    {
                        "method": "DELETE",
                        "path": "/login/oauth2/token",
                        "authorization": f"Bearer {spec['token']}",
                        "accept": "application/json",
                    }
                ]
                sources = worker_source_sha256()
                module = "issuance.application.canvas_oauth"
                sources[module] = hashlib.sha256(
                    Path(importlib.util.find_spec(module).origin)
                    .read_text(encoding="utf-8")
                    .encode()
                ).hexdigest()
                observation = {
                    "schema": f"marty.canvas-worker-{kind}-oracle/v1",
                    "name": case_name,
                    "requests": list(https.requests),
                    "connection": connection_state,
                    "platform": platform,
                    "retained_secret_ids": sorted(secrets),
                    "retained_ciphertexts_unchanged": True,
                    "issued_rows_unchanged": True,
                    "job_count": jobs,
                    "heartbeat": heartbeat,
                    "retry_timing": timing,
                    "source_sha256": sources,
                }
                if fence is not None:
                    observation["fence"] = fence
                return observation
            finally:
                finish_worker(child)
        finally:
            engine.dispose()
