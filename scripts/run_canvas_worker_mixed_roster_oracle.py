"""Complete published mixed-roster worker cycles on naturally due schedules."""

import copy
import hashlib
import json
from pathlib import Path
import signal

from sqlalchemy import create_engine, text

from canvas_worker_mixed_roster_https_fixture import (
    AGS_SCOPE,
    EMAIL_SENTINEL,
    ISSUER_DID,
    NAME_SENTINEL,
    NRPS_SCOPE,
    MixedRosterHttpsFixture,
)
from run_canvas_worker_provider_recovery_oracle import scalar, wait_for
from run_canvas_worker_provider_signals_oracle import snapshot
from run_canvas_worker_rest_oracle import seed_worker_database, worker_case
from run_canvas_worker_startup_oracle import (
    DATABASE,
    finish_worker,
    start_worker,
    worker_source_sha256,
)


class MixedRosterFixtureFailed(AssertionError):
    pass


class MixedRosterUnexpectedJobOutcome(AssertionError):
    pass


class MixedRosterScopeInvalid(AssertionError):
    pass


class MixedRosterRequirementsInvalid(AssertionError):
    pass


class MixedRosterResourcesUnavailable(AssertionError):
    pass


class MixedRosterOAuthUnavailable(AssertionError):
    pass


class MixedRosterNrpsUnavailable(AssertionError):
    pass


class MixedRosterAuthoritativeReadFailed(AssertionError):
    pass


class MixedRosterUnexpectedHttpException(AssertionError):
    pass


def _raise_job_failure(job):
    # Expose only fixed class names for known public outcomes; never a job
    # document, exception payload, assertion, token, or provider response.
    failure = {
        "canvas_sync_target_scope_invalid": MixedRosterScopeInvalid,
        "canvas_requirements_invalid": MixedRosterRequirementsInvalid,
        "canvas_sync_resources_unavailable": MixedRosterResourcesUnavailable,
        "canvas_roster_oauth_unavailable": MixedRosterOAuthUnavailable,
        "canvas_nrps_roster_unavailable": MixedRosterNrpsUnavailable,
        "canvas_authoritative_read_failed": MixedRosterAuthoritativeReadFailed,
    }.get(job["last_error_code"], MixedRosterUnexpectedJobOutcome)
    if (
        job["last_error_code"] == "canvas_sync_unexpected_error"
        and job["last_error_summary"] == "Canvas synchronization failed (HTTPException)"
    ):
        failure = MixedRosterUnexpectedHttpException
    raise failure


def _roster_snapshot(engine, mixed):
    # Reuse the established language-neutral candidate/head projection. The
    # new actual-worker target is the existing issued-preservation fixture.
    query = mixed["snapshot_sql"].replace("'target-roster'", "'target-review'")
    assert query != mixed["snapshot_sql"]
    return scalar(engine, query)


def _seed(engine, matrix, case, origin, old_reference):
    source = next(
        stage
        for stage in old_reference["observations"]
        if stage["name"] == matrix["seed_observation_stage"]
    )
    heads = next(
        candidate
        for candidate in source["snapshot"]["candidates"]
        if candidate["user"] == "7"
    )["observations"]
    assert {head["requirement"] for head in heads} == {"rest", "ags"}
    assert all(head["current"] and not head["superseded"] for head in heads)
    requirements = json.loads(
        json.dumps(matrix["requirements"]).replace("{origin}", origin)
    )
    metadata = {
        "verified_binding_id": "binding-review",
        "verified_binding_config_version": 1,
        "nrps_context_memberships_url": origin + "/api/lti/courses/42/memberships",
        "roster_cursor": case["initial_cursor"],
        "synthetic_marker": "preserve",
    }
    with engine.begin() as connection:
        assert (
            connection.execute(
                text(
                    "UPDATE issuance_service.canvas_platforms SET lti_issuer=:origin,"
                    "lti_client_id='synthetic-client',lti_trust_profile='self_managed_same_origin',"
                    "lti_openid_configuration=CAST(:configuration AS json) "
                    "WHERE id='platform-review' AND organization_id='org-review'"
                ),
                {
                    "origin": origin,
                    "configuration": json.dumps(
                        {"token_endpoint": origin + "/login/oauth2/token"}
                    ),
                },
            ).rowcount
            == 1
        )
        assert (
            connection.execute(
                text(
                    "UPDATE issuance_service.canvas_program_bindings SET evidence_requirements=CAST(:requirements AS json) "
                    "WHERE id='binding-review' AND organization_id='org-review'"
                ),
                {"requirements": json.dumps(requirements)},
            ).rowcount
            == 1
        )
        assert (
            connection.execute(
                text(
                    "UPDATE issuance_service.canvas_evidence_sync_targets SET target_type='background_roster',"
                    "application_id=NULL,schedule_seconds=:schedule,metadata=CAST(:metadata AS json) "
                    "WHERE id='target-review' AND organization_id='org-review'"
                ),
                {
                    "schedule": matrix["schedule_seconds"],
                    "metadata": json.dumps(metadata),
                },
            ).rowcount
            == 1
        )
        for identity in matrix["identities"]:
            assert (
                connection.execute(
                    text(
                        "INSERT INTO issuance_service.canvas_learner_identities "
                        "(id,organization_id,platform_id,deployment_id,lti_subject,canvas_user_id,status) "
                        "VALUES (:id,'org-review','platform-review','deployment',:subject,:user,:status)"
                    ),
                    {
                        "id": f"worker-roster-identity-{identity['user']}",
                        "subject": f"subject-{identity['user']}",
                        **identity,
                    },
                ).rowcount
                == 1
            )
        for candidate in matrix["terminal_candidates"]:
            user = candidate["user"]
            candidate_id = f"worker-roster-candidate-{user}"
            key = hashlib.sha256(
                f"platform-review:binding-review:canvas_user:{user}".encode()
            ).hexdigest()
            assert (
                connection.execute(
                    text(
                        "INSERT INTO issuance_service.canvas_award_candidates "
                        "(id,organization_id,platform_id,binding_id,learner_identity_id,candidate_key,"
                        "canvas_user_id,lti_subject,state,observed_at,created_at,updated_at) "
                        "VALUES (:id,'org-review','platform-review','binding-review',:identity,:key,"
                        ":user,:subject,:state,now(),now(),now())"
                    ),
                    {
                        "id": candidate_id,
                        "identity": "identity-review"
                        if user == "7"
                        else f"worker-roster-identity-{user}",
                        "key": key,
                        "subject": f"subject-{user}",
                        **candidate,
                    },
                ).rowcount
                == 1
            )
            for head in heads:
                assert (
                    connection.execute(
                        text(
                            "INSERT INTO issuance_service.canvas_candidate_observations "
                            "(id,organization_id,candidate_id,requirement_id,logical_key,assertion,verification,"
                            "payload_hash,is_current,observed_at,created_at) "
                            "VALUES (:id,'org-review',:candidate,:requirement,:requirement,CAST(:assertion AS json),"
                            "CAST(:verification AS json),:hash,true,now(),now())"
                        ),
                        {
                            "id": f"worker-roster-observation-{user}-{head['requirement']}",
                            "candidate": candidate_id,
                            "requirement": head["requirement"],
                            "assertion": json.dumps(head["assertion"]),
                            "verification": json.dumps(head["verification"]),
                            "hash": head["hash"],
                        },
                    ).rowcount
                    == 1
                )


def _candidate_map(roster):
    values = roster["candidates"]
    assert len({candidate["user"] for candidate in values}) == len(values)
    return {candidate["user"]: candidate for candidate in values}


def _assert_requests(fixture):
    if fixture.failures:
        raise MixedRosterFixtureFailed
    assert fixture.token_scopes in [[NRPS_SCOPE], [NRPS_SCOPE, AGS_SCOPE]]
    assert fixture.signer_operations == [
        "resolve_lti_tool_identity",
        "sign_lti_tool_assertion",
    ] * len(fixture.token_scopes)
    assert len(fixture.signer_requests) == len(fixture.signer_operations)
    for request in fixture.requests:
        path = request["path"]
        if request["method"] == "POST":
            assert path == "/login/oauth2/token"
            assert (
                request["authorization"] is None
                and request["accept"] == "application/json"
            )
        elif path == "/api/lti/courses/42/memberships":
            assert request["method"] == "GET"
            assert request["authorization"] == "Bearer synthetic-nrps-token"
            assert (
                request["accept"]
                == "application/vnd.ims.lti-nrps.v2.membershipcontainer+json"
            )
        elif path.startswith("/api/lti/courses/42/line_items/5/results?"):
            assert request["method"] == "GET"
            assert request["authorization"] == "Bearer synthetic-ags-token"
            assert (
                request["accept"] == "application/vnd.ims.lis.v2.resultcontainer+json"
            )
        else:
            assert request["method"] == "GET" and path.startswith("/api/v1/courses/42/")
            assert request["authorization"] == "Bearer synthetic-worker-rest-token"
            assert request["accept"] == "application/json"


def run(case_name):
    contracts = Path("/verification/contracts")
    matrix = json.loads(
        (contracts / "canvas-worker-mixed-roster-scenarios.json").read_text()
    )
    names = [case["name"] for case in matrix["cases"]]
    assert names and len(names) == len(set(names)) and case_name in names
    case = next(case for case in matrix["cases"] if case["name"] == case_name)
    stages = case["stages"]
    assert len(stages) == 7 and len({stage["name"] for stage in stages}) == 7
    spec = json.loads((contracts / matrix["reference_scenario"]).read_text())
    shared = json.loads((contracts / spec["shared_seed"]).read_text())
    mixed = json.loads((contracts / matrix["roster_scenario"]).read_text())
    old_reference = json.loads((contracts / matrix["roster_reference"]).read_text())
    assert (
        old_reference["source_sha256"]
        == worker_source_sha256()["issuance.infrastructure.api.canvas_routes"]
    )
    child = None
    with MixedRosterHttpsFixture(matrix) as https:
        engine = create_engine(DATABASE, hide_parameters=True)
        try:
            preserved = seed_worker_database(engine, https.origin, spec, shared)
            _seed(engine, matrix, case, https.origin, old_reference)
            initial = _roster_snapshot(engine, mixed)
            assert initial["cursor"] == 3 and len(initial["candidates"]) == 2
            initial_candidates = _candidate_map(initial)
            worker_input = worker_case(
                https.origin,
                https.cert,
                {
                    "CANVAS_BACKGROUND_ROSTER_BATCH_SIZE": str(matrix["batch_size"]),
                    "CANVAS_BACKGROUND_ROSTER_MAX_SIZE": str(matrix["roster_limit"]),
                    "CANVAS_SYNC_WORKER_POLL_SECONDS": "0.1",
                    "CANVAS_SELF_MANAGED_ORIGIN_ALLOWLIST": https.origin,
                    "CANVAS_LTI_TOOL_SIGNING_ORGANIZATION_ID": "org-review",
                    "CANVAS_LTI_TOOL_ISSUER_DID": ISSUER_DID,
                    "SIGNING_KEYS_INTERNAL_URL": https.signer_origin,
                },
            )
            observations = []
            snapshots = {}
            restarts = []

            def observe():
                state, current, encrypted = snapshot(engine, spec, shared)
                assert (current, encrypted) == preserved
                roster = _roster_snapshot(engine, mixed)
                assert roster["applications"] == roster["credentials"] == 1
                assert roster["facts"] == 0
                serialized = json.dumps(scalar(engine, matrix["stored_roster_sql"]))
                assert (
                    NAME_SENTINEL not in serialized and EMAIL_SENTINEL not in serialized
                )
                return state, roster

            for index, stage in enumerate(stages):
                https.set_stage(stage)
                if child is None:
                    child = start_worker(worker_input, "worker-rest")

                def completed():
                    if https.failures:
                        raise MixedRosterFixtureFailed
                    jobs = scalar(engine, spec["jobs_sql"])
                    assert len(jobs) <= index + 1
                    if len(jobs) == index + 1:
                        if jobs[-1]["status"] in {"retry", "dead_letter"}:
                            _raise_job_failure(jobs[-1])
                        if jobs[-1]["status"] == "succeeded":
                            heartbeat = scalar(
                                engine,
                                "SELECT metadata->>'phase' FROM issuance_service.canvas_worker_heartbeats WHERE worker_id='worker-rest'",
                            )
                            if heartbeat == "idle":
                                return observe()
                    return None

                # Natural due times are intentionally not shortened. The
                # configured minute cadence is fixture input before startup.
                state, roster = wait_for(completed, 95, stage["name"], child)
                _assert_requests(https)
                assert all(
                    job["attempt_count"] == 1 and job["status"] == "succeeded"
                    for job in state["jobs"]
                )
                assert (
                    roster["cursor"] == stage["cursor"] and roster["roster_size"] == 6
                )
                candidates = _candidate_map(roster)
                assert candidates["7"]["state"] == "claimed"
                assert candidates["8"]["state"] == "dismissed"
                assert candidates["9"]["state"] == stage["ordinary_state"]
                if stage.get("seeded_heads_reused"):
                    for user in ["7", "8"]:
                        assert (
                            candidates[user]["observations"]
                            == initial_candidates[user]["observations"]
                        )
                if stage.get("preserve_tail_observations_from"):
                    previous = _candidate_map(
                        snapshots[stage["preserve_tail_observations_from"]]
                    )
                    for user in ["7", "8", "9"]:
                        assert (
                            candidates[user]["observations"]
                            == previous[user]["observations"]
                        )
                if stage.get("preserve_head_observations_from"):
                    previous = _candidate_map(
                        snapshots[stage["preserve_head_observations_from"]]
                    )
                    for user in ["10", "11", "12"]:
                        assert (
                            candidates[user]["observations"]
                            == previous[user]["observations"]
                        )
                if index >= 1:
                    assert (
                        candidates["10"]["state"]
                        == candidates["11"]["state"]
                        == "identity_link_required"
                    )
                    assert candidates["12"]["state"] == (
                        "pending_claim" if index >= 3 else "identity_link_required"
                    )
                target = scalar(engine, matrix["target_sql"])
                assert target["enabled"] is True and target["marker"] == "preserve"
                assert target["cycle_completed_at_present"] is (stage["cursor"] == 0)
                snapshots[stage["name"]] = copy.deepcopy(roster)
                observations.append(
                    {
                        "name": stage["name"],
                        "state": state,
                        "roster": roster,
                        "target": target,
                        "requests": copy.deepcopy(https.requests),
                        "token_scopes": list(https.token_scopes),
                        "signer_requests": copy.deepcopy(https.signer_requests),
                        "signer_operations": list(https.signer_operations),
                        "issued_rows_transactions_ciphertext_preserved": True,
                        "roster_name_email_not_retained": True,
                    }
                )
                if stage.get("restart_after_idle"):
                    raw_jobs = scalar(engine, matrix["job_rows_sql"])
                    child.send_signal(signal.SIGINT)
                    assert child.wait(timeout=10) == -2
                    child = None
                    assert observe() == (state, roster)
                    assert scalar(engine, matrix["job_rows_sql"]) == raw_jobs
                    restarts.append(
                        {
                            "after_stage": stage["name"],
                            "cursor": roster["cursor"],
                            "job_count": len(state["jobs"]),
                            "exit_code": -2,
                            "durable_state_unchanged": True,
                        }
                    )

            raw_jobs = scalar(engine, matrix["job_rows_sql"])
            child.send_signal(signal.SIGINT)
            assert child.wait(timeout=10) == -2
            child = None
            assert observe() == (state, roster)
            assert scalar(engine, matrix["job_rows_sql"]) == raw_jobs
            assert len(restarts) == 1 and restarts[0]["cursor"] == 3
            return {
                "schema": "marty.canvas-worker-mixed-roster-oracle/v1",
                "source_sha256": worker_source_sha256(),
                "case": case_name,
                "initial_roster": initial,
                "observations": observations,
                "idle_restarts": restarts,
                "exit_code_after_interrupt": -2,
                "final_durable_state_unchanged_after_exit": True,
                "signer_scope": "Synthetic LTI tool assertion transport only; not remote signing or crypto-service qualification",
            }
        finally:
            try:
                if child is not None:
                    finish_worker(child)
            finally:
                engine.dispose()
