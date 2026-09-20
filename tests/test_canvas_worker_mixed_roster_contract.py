"""Published capture integrity, not native-worker or cryptographic qualification."""

import importlib
from copy import deepcopy
import json
from pathlib import Path
from urllib.parse import urlencode

import pytest

ROOT = Path(__file__).resolve().parents[1]


def contract(name):
    return json.loads((ROOT / "contracts" / name).read_text())


@pytest.fixture
def corpus():
    # Missing reference is an error, never an unconfigured skip or a capture-A
    # fallback. The maintainer freezes only the independently reproduced result.
    return (
        contract("canvas-worker-mixed-roster-scenarios.json"),
        contract("canvas-worker-mixed-roster-oracle.json"),
    )


@pytest.fixture
def fixture_module(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    return importlib.import_module("canvas_worker_mixed_roster_https_fixture")


def candidates(roster):
    values = roster["candidates"]
    assert len(values) == len({candidate["user"] for candidate in values})
    return {candidate["user"]: candidate for candidate in values}


def assert_published_number_types(reference):
    # Python's captured provider assertions use JSON floats, unlike durable
    # counters/cursors. Numeric equality alone misses a lossy JSON roundtrip.
    rosters = [
        reference["initial_roster"],
        *(item["roster"] for item in reference["observations"]),
    ]
    for roster in rosters:
        assert type(roster["cursor"]) is int
        for field in ("applications", "credentials", "facts"):
            assert type(roster[field]) is int
        for candidate in roster["candidates"]:
            for observation in candidate["observations"]:
                for field in ("score", "score_maximum", "score_percent"):
                    assert type(observation["assertion"][field]) is float
    for item in reference["observations"]:
        assert type(item["target"]["cursor"]) is int
        for job in item["state"]["jobs"]:
            assert all(type(value) is int for value in job["result"].values())


def test_reference_preserves_published_float_scores_and_integer_counters(corpus):
    _, reference = corpus
    assert_published_number_types(reference)


@pytest.mark.parametrize(
    "field", ["score", "score_maximum", "score_percent", "cursor", "counter"]
)
def test_numeric_equality_does_not_allow_lossy_reference_rewriting(corpus, field):
    _, reference = corpus
    changed = deepcopy(reference)
    if field == "cursor":
        changed["initial_roster"][field] = float(changed["initial_roster"][field])
    elif field == "counter":
        result = changed["observations"][0]["state"]["jobs"][0]["result"]
        result["candidates_seen"] = float(result["candidates_seen"])
    else:
        assertion = changed["initial_roster"]["candidates"][0]["observations"][0][
            "assertion"
        ]
        assertion[field] = int(assertion[field])
    assert changed == reference, "Control must differ only in numeric representation"
    with pytest.raises(AssertionError):
        assert_published_number_types(changed)


def stages_with_batch(matrix, reference):
    case = matrix["cases"][0]
    ordered = sorted({str(user) for user in matrix["roster_users"]})
    cursor = case["initial_cursor"]
    for stage, observed in zip(case["stages"], reference["observations"], strict=True):
        assert observed["name"] == stage["name"]
        batch = ordered[cursor : cursor + matrix["batch_size"]]
        assert len(batch) == matrix["batch_size"]
        yield stage, observed, batch
        cursor = stage["cursor"]


def test_corpus_is_complete_nonempty_and_pinned_to_published_sources(corpus):
    matrix, reference = corpus
    assert matrix["schema"] == "marty.canvas-worker-mixed-roster-scenarios/v1"
    assert reference["schema"] == "marty.canvas-worker-mixed-roster-oracle/v1"
    cases = matrix["cases"]
    assert len(cases) == 1 and cases[0]["name"] == reference["case"]
    names = [stage["name"] for stage in cases[0]["stages"]]
    assert len(names) == len(set(names)) == 7
    assert [observed["name"] for observed in reference["observations"]] == names
    assert (
        reference["source_sha256"]
        == contract("canvas-worker-rest-oracle.json")["source_sha256"]
    )
    assert (
        reference["source_sha256"]["issuance.infrastructure.api.canvas_routes"]
        == contract(matrix["roster_reference"])["source_sha256"]
    )
    assert (
        reference["signer_scope"]
        == "Synthetic LTI tool assertion transport only; not remote signing or crypto-service qualification"
    )


def test_all_four_durable_counters_match_candidate_and_observation_deltas(corpus):
    matrix, reference = corpus
    previous = reference["initial_roster"]
    prior_jobs = []
    for _, observed, batch in stages_with_batch(matrix, reference):
        roster = observed["roster"]
        current = candidates(roster)
        jobs = observed["state"]["jobs"]
        assert jobs[:-1] == prior_jobs
        assert len(jobs) == len(prior_jobs) + 1
        latest = jobs[-1]
        assert latest["result"] == {
            "candidates_seen": len(batch),
            "identity_link_required": sum(
                current[user]["state"] == "identity_link_required" for user in batch
            ),
            "observations_written": sum(
                len(candidate["observations"]) for candidate in current.values()
            )
            - sum(
                len(candidate["observations"])
                for candidate in candidates(previous).values()
            ),
            "pending_claim": sum(
                current[user]["state"] == "pending_claim" for user in batch
            ),
        }
        assert all(
            type(value) is int and value >= 0 for value in latest["result"].values()
        )
        assert latest["status"] == "succeeded"
        assert latest["attempt_count"] == 1 and latest["max_attempts"] == 8
        assert latest["started"] is latest["completed"] is True
        assert latest["lease_owner_present"] is latest["lease_expires_present"] is False
        assert latest["last_error_code"] is latest["last_error_summary"] is None
        assert (
            latest["retry_scheduled"]
            is latest["retry_delay_matches_37_seconds"]
            is None
        )
        previous, prior_jobs = roster, jobs


def test_actual_cursor_progression_is_bounded_and_wraps_without_losing_candidates(
    corpus,
):
    matrix, reference = corpus
    ordered = sorted({str(user) for user in matrix["roster_users"]})
    assert len(matrix["roster_users"]) > len(ordered), "Retain duplicate roster input"
    assert len(ordered) == 2 * matrix["batch_size"] <= matrix["roster_limit"]
    cursor = reference["initial_roster"]["cursor"]
    assert cursor == matrix["cases"][0]["initial_cursor"] == 3
    seen = set(candidates(reference["initial_roster"]))
    cursors = []
    for stage, observed, batch in stages_with_batch(matrix, reference):
        cursor = (cursor + len(batch)) % len(ordered)
        cursors.append(cursor)
        assert (
            observed["roster"]["cursor"]
            == observed["target"]["cursor"]
            == stage["cursor"]
            == cursor
        )
        assert (
            observed["roster"]["roster_size"]
            == observed["target"]["roster_size"]
            == len(ordered)
        )
        seen.update(batch)
        assert set(candidates(observed["roster"])) == seen
        target = observed["target"]
        assert target["enabled"] is target["last_success_present"] is True
        assert target["marker"] == "preserve"
        assert target["config_version"] == 1
        assert target["schedule_seconds"] == matrix["schedule_seconds"] == 60
        assert target["cycle_completed_at_present"] is (cursor == 0)
        assert target["worker_id"] is None
    assert cursors == [0, 3, 0, 3, 0, 3, 0]


def test_provider_and_synthetic_signer_traces_match_each_selected_identity(
    corpus, fixture_module
):
    matrix, reference = corpus
    identities = {
        identity["user"]: identity["status"] for identity in matrix["identities"]
    }
    for user, candidate in candidates(reference["initial_roster"]).items():
        assert candidate["identity"] and candidate["subject"]
        identities.setdefault(user, "linked")

    def request(method, path, authorization=None, accept="application/json"):
        return {
            "method": method,
            "path": path,
            "authorization": authorization,
            "accept": accept,
        }

    for stage, observed, batch in stages_with_batch(matrix, reference):
        eligible = [
            user
            for user in batch
            if identities.get(user) == "linked" and (user != "12" or stage["active_12"])
        ]
        expected = [
            request(
                "GET",
                f"/api/v1/courses/42/users?enrollment_type%5B%5D=student&per_page={matrix['roster_limit']}",
                "Bearer synthetic-worker-rest-token",
            ),
            request("POST", "/login/oauth2/token"),
            request(
                "GET",
                "/api/lti/courses/42/memberships",
                "Bearer synthetic-nrps-token",
                "application/vnd.ims.lti-nrps.v2.membershipcontainer+json",
            ),
        ]
        for index, user in enumerate(eligible):
            expected.append(
                request(
                    "GET",
                    f"/api/v1/courses/42/assignments/9/submissions/{user}?include%5B%5D=assignment",
                    "Bearer synthetic-worker-rest-token",
                )
            )
            if index == 0:
                expected.append(request("POST", "/login/oauth2/token"))
            expected.append(
                request(
                    "GET",
                    f"/api/lti/courses/42/line_items/5/results?user_id=subject-{user}",
                    "Bearer synthetic-ags-token",
                    "application/vnd.ims.lis.v2.resultcontainer+json",
                )
            )
        assert observed["requests"] == expected
        scopes = [fixture_module.NRPS_SCOPE] + (
            [fixture_module.AGS_SCOPE] if eligible else []
        )
        assert observed["token_scopes"] == scopes
        assert observed["signer_operations"] == [
            "resolve_lti_tool_identity",
            "sign_lti_tool_assertion",
        ] * len(scopes)
        resolve_path = "/internal/signing-keys/resolve-issuer-did?" + urlencode(
            {
                "organization_id": "org-review",
                "issuer_did": fixture_module.ISSUER_DID,
                "credential_format": "lti_tool_jwt",
                "key_purpose": "lti_tool_signing",
                "algorithm": "RS256",
            }
        )
        assert observed["signer_requests"] == [
            request("GET", resolve_path, accept="*/*"),
            request(
                "POST",
                "/internal/signing-keys/issuer-dids/sign?organization_id=org-review",
                accept="*/*",
            ),
        ] * len(scopes)


def test_terminal_identity_and_observation_preservation_matches_scenario(corpus):
    matrix, reference = corpus
    initial = candidates(reference["initial_roster"])
    source = next(
        observed
        for observed in contract(matrix["roster_reference"])["observations"]
        if observed["name"] == matrix["seed_observation_stage"]
    )
    seeded_heads = candidates(source["snapshot"])["7"]["observations"]
    assert {head["requirement"] for head in seeded_heads} == {"rest", "ags"}
    assert all(head["current"] and not head["superseded"] for head in seeded_heads)
    assert set(initial) == {
        terminal["user"] for terminal in matrix["terminal_candidates"]
    }
    for candidate in initial.values():
        assert candidate["observations"] == seeded_heads
    snapshots = {}
    for stage, observed, _ in stages_with_batch(matrix, reference):
        current = candidates(observed["roster"])
        for terminal in matrix["terminal_candidates"]:
            assert current[terminal["user"]]["state"] == terminal["state"]
        assert current["9"]["state"] == stage["ordinary_state"]
        if stage.get("seeded_heads_reused"):
            for user in initial:
                assert current[user]["observations"] == initial[user]["observations"]
        for marker, users in (
            ("preserve_tail_observations_from", ["7", "8", "9"]),
            ("preserve_head_observations_from", ["10", "11", "12"]),
        ):
            if marker in stage:
                for user in users:
                    assert (
                        current[user]["observations"]
                        == snapshots[stage[marker]][user]["observations"]
                    )
                assert (
                    observed["state"]["jobs"][-1]["result"]["observations_written"] == 0
                )
        if "10" in current:
            assert (
                current["10"]["state"]
                == current["11"]["state"]
                == "identity_link_required"
            )
            assert current["10"]["observations"] == current["11"]["observations"] == []
            assert current["12"]["state"] == (
                "pending_claim" if stage["active_12"] else "identity_link_required"
            )
        snapshots[stage["name"]] = current


def test_idle_restart_and_final_interrupt_preserve_completed_durable_state(corpus):
    matrix, reference = corpus
    expected = []
    for index, (stage, observed, _) in enumerate(
        stages_with_batch(matrix, reference), start=1
    ):
        assert observed["state"]["heartbeat"] == {
            "role": "canvas_sync",
            "metadata": {
                "leased_jobs": 0,
                "phase": "idle",
                "process": "standalone",
                "processor_configured": True,
            },
        }
        if stage.get("restart_after_idle"):
            expected.append(
                {
                    "after_stage": stage["name"],
                    "cursor": stage["cursor"],
                    "job_count": index,
                    "exit_code": -2,
                    "durable_state_unchanged": True,
                }
            )
    assert len(expected) == 1 and expected[0]["cursor"] == 3
    assert reference["idle_restarts"] == expected
    assert reference["exit_code_after_interrupt"] == -2
    assert reference["final_durable_state_unchanged_after_exit"] is True


def test_issued_business_state_and_roster_privacy_survive_every_cycle(
    corpus, fixture_module
):
    _, reference = corpus
    baseline = reference["observations"][0]["state"]["snapshot"]
    for observed in reference["observations"]:
        assert observed["issued_rows_transactions_ciphertext_preserved"] is True
        assert observed["roster_name_email_not_retained"] is True
        assert (
            observed["roster"]["applications"] == observed["roster"]["credentials"] == 1
        )
        assert observed["roster"]["facts"] == 0
        assert observed["state"]["facts"] == []
        assert observed["state"]["snapshot"] == baseline
        assert observed["state"]["oauth"] == {
            "reauthorization_required": False,
            "refresh_lease_owner_present": False,
            "secret_enabled": True,
            "secret_used": True,
            "status": "connected",
        }
    assert baseline["credential"] == {"active": True, "count": 1}
    assert baseline["facts"] == 0 and baseline["head_scores"] is None
    assert baseline["application"] == {
        "credential_id": "credential-review",
        "policy_allowed": None,
        "status": "approved",
    }
    assert baseline["events"] == {} and baseline["reviews"] == []
    serialized = json.dumps(reference)
    assert fixture_module.NAME_SENTINEL not in serialized
    assert fixture_module.EMAIL_SENTINEL not in serialized
