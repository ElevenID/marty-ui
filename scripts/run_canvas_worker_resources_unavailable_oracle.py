"""Actual post-validation resource disappearance; only owned table barriers."""

from contextlib import ExitStack
import json
from pathlib import Path
import signal

from sqlalchemy import create_engine, text

from canvas_worker_https_fixture import WorkerHttpsFixture
from run_canvas_worker_provider_recovery_oracle import scalar, wait_for
from run_canvas_worker_provider_signals_oracle import snapshot
from run_canvas_worker_rest_oracle import seed_worker_database, worker_case
from run_canvas_worker_startup_oracle import (
    DATABASE,
    finish_worker,
    start_blocked_workers,
    worker_source_sha256,
)


def _barrier_sql(table):
    assert table in {"applications", "canvas_platforms", "canvas_program_bindings"}
    return f"LOCK TABLE issuance_service.{table} IN ACCESS EXCLUSIVE MODE"


class HookPlatformBarrierNotObserved(AssertionError):
    pass


class HookBindingBarrierNotObserved(AssertionError):
    pass


class HookApplicationBarrierNotObserved(AssertionError):
    pass


class ResourcePlatformBarrierNotObserved(AssertionError):
    pass


def _blocked_query(table, barrier_pid=None):
    # Full ORM SELECTs can exceed pg_stat_activity.query's configured size,
    # truncating the FROM clause. Observe the actual requested relation lock
    # instead, with only a SELECT-prefix check and an exact owning blocker.
    _barrier_sql(table)
    query = (
        "SELECT count(DISTINCT a.pid) FROM pg_stat_activity a "
        "JOIN pg_locks l ON l.pid=a.pid "
        "WHERE a.datname=current_database() AND a.pid<>pg_backend_pid() "
        "AND a.wait_event_type='Lock' AND a.query ILIKE 'SELECT%' "
        "AND l.locktype='relation' AND l.mode='AccessShareLock' AND NOT l.granted "
        f"AND l.relation='issuance_service.{table}'::regclass"
    )
    if barrier_pid is not None:
        return text(
            query + " AND :barrier_pid=ANY(pg_blocking_pids(a.pid))"
        ).bindparams(barrier_pid=barrier_pid)
    return text(query)


def run(case_name):
    contracts = Path("/verification/contracts")
    matrix = json.loads(
        (contracts / "canvas-worker-resources-unavailable-scenarios.json").read_text()
    )
    matching = [case for case in matrix["cases"] if case["name"] == case_name]
    assert len(matching) == 1
    case = matching[0]
    phases = case["barriers"]
    assert [phase["name"] for phase in phases] == [
        "wrapper_application",
        "hook_platform",
        "hook_binding",
        "hook_application",
        "resource_platform",
    ]
    spec = json.loads((contracts / matrix["reference_scenario"]).read_text())
    shared = json.loads((contracts / spec["shared_seed"]).read_text())
    queued = json.loads((contracts / matrix["queued_job_scenario"]).read_text())
    child = None
    with WorkerHttpsFixture() as https:
        engine = create_engine(DATABASE, hide_parameters=True)
        try:
            preserved = seed_worker_database(engine, https.origin, spec, shared)
            with engine.begin() as connection:
                for statement in [*case["seed"], queued["initial_job_seed"]]:
                    assert connection.exec_driver_sql(statement).rowcount == 1

            def observe():
                state, current, encrypted = snapshot(engine, spec, shared)
                assert (current, encrypted) == preserved
                assert https.requests == []
                return state

            # A response exists only as an unexpected-I/O tripwire; reaching
            # the target boundary must not consume even an OAuth credential.
            https.stage = {"status": 500, "body": {}}
            observed_barriers = []
            held = {}
            blocker_pids = {}
            with ExitStack() as barriers:

                def acquire(index):
                    connection = barriers.enter_context(engine.begin())
                    # Bound only fixture lock acquisition, never worker clocks
                    # or sessions. Each repository read closes its own session.
                    connection.exec_driver_sql("SET LOCAL lock_timeout='5s'")
                    connection.exec_driver_sql(_barrier_sql(phases[index]["table"]))
                    held[index] = connection
                    blocker_pids[index] = connection.exec_driver_sql(
                        "SELECT pg_backend_pid()"
                    ).scalar_one()

                workers = start_blocked_workers(
                    engine,
                    worker_case(https.origin, https.cert),
                    ["worker-rest"],
                    _barrier_sql(phases[0]["table"]),
                    _blocked_query(phases[0]["table"]),
                    lambda: acquire(1),
                )
                child = workers["worker-rest"]
                observed_barriers.append(phases[0]["name"])
                for index in range(1, len(phases)):
                    phase = phases[index]

                    def blocked():
                        with engine.connect() as connection:
                            return (
                                connection.execute(
                                    _blocked_query(phase["table"], blocker_pids[index])
                                ).scalar_one()
                                == 1
                            )

                    try:
                        wait_for(blocked, 15, phase["name"], child)
                    except AssertionError:
                        # Sanitized capture errors retain only class/frame
                        # names, so static types identify the failed boundary
                        # without worker logs, query text, or exception detail.
                        failure = {
                            "hook_platform": HookPlatformBarrierNotObserved,
                            "hook_binding": HookBindingBarrierNotObserved,
                            "hook_application": HookApplicationBarrierNotObserved,
                            "resource_platform": ResourcePlatformBarrierNotObserved,
                        }[phase["name"]]
                        raise failure from None
                    observed_barriers.append(phase["name"])
                    assert https.requests == []
                    if index + 1 < len(phases):
                        # Acquire the next table while the worker is still
                        # blocked; this prevents timing-dependent read gaps.
                        acquire(index + 1)
                        held[index].commit()

                final_barrier = held[len(phases) - 1]
                before = observe()
                assert len(before["jobs"]) == 1
                assert before["jobs"][0]["status"] == "leased"
                assert before["jobs"][0]["attempt_count"] == 1
                assert before["oauth"]["secret_used"] is False
                original_job = scalar(engine, matrix["job_row_sql"])
                # Read the locked platform through its owning connection.
                protected = final_barrier.execute(
                    text(matrix["protected_rows_sql"])
                ).scalar_one()
                for statement in case["mutation"]:
                    assert final_barrier.exec_driver_sql(statement).rowcount == 1
                changed_resources = final_barrier.execute(
                    text(matrix["resources_sql"])
                ).scalar_one()
                assert changed_resources["disposable_binding_present"] is False
                assert changed_resources["target"]["binding_id"] == "binding-review"
                assert (
                    final_barrier.execute(text(matrix["job_row_sql"])).scalar_one()
                    == original_job
                )
                final_barrier.commit()

            def completed():
                state = observe()
                if (
                    state["heartbeat"]["metadata"]["phase"] == "idle"
                    and len(state["jobs"]) == 1
                    and state["jobs"][0]["status"] == "dead_letter"
                ):
                    return state
                return None

            after = wait_for(
                completed, 20, "durable unavailable-resource outcome", child
            )
            assert after["jobs"][0]["last_error_code"] == case["code"]
            assert after["jobs"][0]["attempt_count"] == 1
            assert after["facts"] == []
            assert after["oauth"]["secret_used"] is False
            assert scalar(engine, matrix["protected_rows_sql"]) == protected
            final_resources = scalar(engine, matrix["resources_sql"])
            assert final_resources["disposable_binding_present"] is False
            assert final_resources["target"]["binding_id"] == "binding-review"
            assert final_resources["target"]["enabled"] is False
            terminal = scalar(engine, matrix["job_row_sql"])
            assert terminal["id"] == original_job["id"] == "worker-validation-job"
            child.send_signal(signal.SIGINT)
            exit_code = child.wait(timeout=10)
            assert exit_code == -2
            assert observe() == after
            assert scalar(engine, matrix["job_row_sql"]) == terminal
            assert scalar(engine, matrix["resources_sql"]) == final_resources
            assert scalar(engine, matrix["protected_rows_sql"]) == protected
            return {
                "schema": "marty.canvas-worker-resources-unavailable-oracle/v1",
                "source_sha256": worker_source_sha256(),
                "case": case_name,
                "observed_barriers": observed_barriers,
                "before": before,
                "changed_resources": changed_resources,
                "after": after,
                "final_resources": final_resources,
                "same_job": True,
                "protected_rows_unchanged": True,
                "unchanged_after_exit": True,
                "requests": list(https.requests),
                "exit_code_after_interrupt": exit_code,
            }
        finally:
            try:
                if child is not None:
                    finish_worker(child)
            finally:
                engine.dispose()
