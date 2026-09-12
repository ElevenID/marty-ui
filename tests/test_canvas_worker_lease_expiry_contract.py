"""Frozen independent Python lease-expiry evidence, not native fence parity."""

from copy import deepcopy
import hashlib
import importlib
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
ORACLE = ROOT / "contracts/canvas-worker-lease-expiry-oracle.json"
BODY_ORACLE = ROOT / "contracts/canvas-worker-body-timeout-oracle.json"
CAPTURE_SHA256 = "455494bc6be253a73747116734c418c9c13e41d13eac09a1c31f721e5d44499d"
BODY_SHA256 = "e97d7fee361a11d4245876b725c8ac417045254d766693f772da53409c9b50eb"
CASES = ("renewal_lock_early_release", "renewal_lock_crosses_expiry")
PROOFS = (
    "blocked_renewal_observed",
    "first_terminal_observed_separately_from_idle",
    "lease_advanced_after_release",
    "lock_release_within_declared_window",
    "provider_body_pending_at_release",
    "stable_after_final_attempt_join_and_interrupt",
)
OBSERVATION_FIELDS = {
    "before_release",
    "capture_source_sha256",
    "case",
    "chunks",
    "exit_code_after_interrupt",
    "first_terminal_status",
    "initial_held",
    "logs_after_interrupt",
    "logs_before_interrupt",
    "original_lease_expired_at_release",
    "outcome",
    "requests",
    "schema",
    "scope",
    "source_sha256",
    *PROOFS,
}


@pytest.fixture
def corpus():
    # No missing-file skip, capture fallback, or JSON normalization.
    return json.loads(ORACLE.read_bytes())


def observations(reports):
    return [report["worker_lease_expiry"] for report in reports]


def assert_raw_capture(raw):
    assert type(raw) is bytes
    assert len(raw) == 19_575
    assert hashlib.sha256(raw).hexdigest() == CAPTURE_SHA256
    assert b"\r" not in raw and raw.endswith(b"]\n")


def assert_evidence(reports):
    assert type(reports) is list and len(reports) == 2
    assert [item["case"] for item in observations(reports)] == list(CASES)
    for index, report in enumerate(reports):
        assert set(report) == {
            "migration_revisions",
            "organization_dependency",
            "status",
            "worker_lease_expiry",
            "worker_sha256",
        }
        assert report["migration_revisions"] == ["merge_issuance_heads"]
        assert report["organization_dependency"] == "synthetic-minimal"
        assert report["status"] == "passed"
        observed = report["worker_lease_expiry"]
        assert set(observed) == OBSERVATION_FIELDS
        assert observed["schema"] == "marty.canvas-worker-lease-expiry-observation/v1"
        assert observed["scope"] == (
            "Published process with owned renewal row lock and actual incomplete HTTPS body; "
            "post-release outcome observed, not native parity"
        )
        assert (
            report["worker_sha256"]
            == observed["source_sha256"]["issuance.canvas_worker"]
        )
        for key in PROOFS:
            assert observed[key] is True
        assert observed["original_lease_expired_at_release"] is bool(index)
        assert observed["first_terminal_status"] == "succeeded"
        assert type(observed["exit_code_after_interrupt"]) is int
        assert observed["exit_code_after_interrupt"] == -2
        assert observed["requests"] == [
            {
                "method": "GET",
                "path": "/api/v1/courses/42/assignments/9/submissions/7?include%5B%5D=assignment",
                "authorization": "Bearer synthetic-worker-rest-token",
                "accept": "application/json",
            }
        ]
        chunks = observed["chunks"]
        assert len(chunks) == 5
        assert [chunk["scheduled_offset_seconds"] for chunk in chunks] == [
            0,
            8,
            16,
            24,
            34,
        ]
        for position, chunk in enumerate(chunks):
            assert set(chunk) == {
                "index",
                "scheduled_offset_seconds",
                "byte_count",
                "flushed_byte_count",
                "outcome",
                "disconnect_category",
                "write_within_declared_band",
            }
            assert type(chunk["index"]) is int and chunk["index"] == position
            assert type(chunk["scheduled_offset_seconds"]) is float
            assert type(chunk["byte_count"]) is type(chunk["flushed_byte_count"]) is int
            assert chunk["byte_count"] == chunk["flushed_byte_count"] > 0
            assert chunk["outcome"] == "flushed"
            assert chunk["disconnect_category"] is None
            assert chunk["write_within_declared_band"] is True
        for state_name in ("initial_held", "before_release", "outcome"):
            state = observed[state_name]
            leased = state_name != "outcome"
            assert len(state["jobs"]) == 1
            job = state["jobs"][0]
            assert job["status"] == ("leased" if leased else "succeeded")
            assert type(job["attempt_count"]) is type(job["max_attempts"]) is int
            assert job["attempt_count"] == 1 and job["max_attempts"] == 8
            assert job["started"] is True
            assert job["completed"] is (not leased)
            assert job["lease_owner_present"] is leased
            assert job["lease_expires_present"] is leased
            assert job["last_error_code"] is job["last_error_summary"] is None
            assert state["heartbeat"]["metadata"]["phase"] == (
                "processing" if leased else "idle"
            )
            assert state["heartbeat"]["metadata"]["leased_jobs"] == int(leased)
            target = state["target"]
            assert (
                type(target["config_version"]) is int and target["config_version"] == 1
            )
            assert target["enabled"] is True
            assert target["target_type"] == "learner_application"
            assert target["last_success_present"] is (not leased)
            assert target["metadata"] == {"worker_id": "worker-rest"}
            assert target["candidate_count"] == target["observation_count"] == 0
            if leased:
                assert job["result"] == {}
                assert state["facts"] == []
            else:
                result = job["result"]
                assert result["facts_created"] == result["requirements_checked"] == 1
                assert (
                    type(result["facts_created"])
                    is type(result["requirements_checked"])
                    is int
                )
                assert result["policy_allowed"] is True
                assert len(state["facts"]) == 1
                fact = state["facts"][0]
                assert fact["fact_type"] == "canvas.assignment_score"
                for key in ("score", "score_maximum", "score_percent"):
                    assert type(fact["assertion"][key]) is float
                assert state["snapshot"]["head_scores"] == [90.0]
                assert type(state["snapshot"]["head_scores"][0]) is float
                assert state["snapshot"]["events"] == {"evidence_fact_created": 1}
                assert state["snapshot"]["application"]["policy_allowed"] is True
        initial, held, outcome = (
            observed[key] for key in ("initial_held", "before_release", "outcome")
        )
        assert initial["snapshot"] == held["snapshot"]
        assert initial["oauth"] == held["oauth"] == outcome["oauth"]
        assert initial["snapshot"]["credential"] == outcome["snapshot"]["credential"]
        assert initial["snapshot"]["reviews"] == outcome["snapshot"]["reviews"] == []


def test_exact_frozen_raw_bytes_and_lf_checkout():
    assert_raw_capture(ORACLE.read_bytes())
    assert (
        "contracts/canvas-worker-lease-expiry-oracle.json text eol=lf"
        in (ROOT / ".gitattributes").read_text().splitlines()
    )


def test_observed_two_case_evidence_is_not_native_expected_behavior(corpus):
    assert_evidence(corpus)


def test_provenance_keeps_eighteen_capture_inputs_and_four_installed_pins(corpus):
    scenario = json.loads(
        (ROOT / "contracts/canvas-worker-lease-expiry-scenarios.json").read_bytes()
    )
    pins = observations(corpus)[0]["capture_source_sha256"]
    assert len(pins) == 18
    assert len(scenario["source_sha256"]) == 4
    body_raw = BODY_ORACLE.read_bytes()
    assert len(body_raw) == 46_042
    assert hashlib.sha256(body_raw).hexdigest() == BODY_SHA256
    body_pins = json.loads(body_raw)[0]["worker_body_timeout"]["capture_source_sha256"]
    assert len(body_pins) == 16
    assert {key: pins[key] for key in body_pins} == body_pins
    assert set(pins) - set(body_pins) == {
        "run_canvas_worker_lease_expiry_oracle.py",
        "canvas-worker-lease-expiry-scenarios.json",
    }
    for observed in observations(corpus):
        assert observed["capture_source_sha256"] == pins
        assert observed["source_sha256"] == scenario["source_sha256"]
    for name, digest in pins.items():
        assert Path(name).name == name
        directory = "contracts" if name.endswith(".json") else "scripts"
        # Only checkout newlines normalize; numeric spelling/content stays significant.
        source = (ROOT / directory / name).read_text(encoding="utf-8")
        assert hashlib.sha256(source.encode("utf-8")).hexdigest() == digest


def assert_logs(reports, shutdown):
    for observed in observations(reports):
        before = observed["logs_before_interrupt"]
        assert before == {
            "stdout_empty": True,
            "other_output_empty": True,
            "stderr_warning_categories": {
                "missing_credential_template_service_url": 1,
                "missing_revocation_profile_service_url": 1,
            },
        }
        after = observed["logs_after_interrupt"]
        assert set(after) == {
            "pre_interrupt_profile",
            "python_version",
            "shutdown",
            "shutdown_source_sha256",
        }
        assert after["pre_interrupt_profile"] == before
        assert after["python_version"] == shutdown.PYTHON_VERSION == "3.12.13"
        assert after["shutdown_source_sha256"] == shutdown.SOURCE_SHA256
        assert after["shutdown"] == {
            "caret_line_count": 4,
            "exception_chain": [
                "asyncio.exceptions.CancelledError",
                "KeyboardInterrupt",
            ],
            "frame_count": 11,
            "trace_line_count": 31,
            "traceback_count": 2,
            "unexpected_output_empty": True,
        }


@pytest.fixture
def shutdown(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    return importlib.import_module("canvas_worker_shutdown_output")


def test_preinterrupt_and_shutdown_profiles_are_bounded_source_pinned(corpus, shutdown):
    assert_logs(corpus, shutdown)


@pytest.mark.parametrize("proof", (*PROOFS, "original_lease_expired_at_release"))
def test_missing_or_false_natural_expiry_proofs_are_rejected(corpus, proof):
    changed = deepcopy(corpus)
    observed = changed[1]["worker_lease_expiry"]
    observed[proof] = False
    with pytest.raises(AssertionError):
        assert_evidence(changed)
    del observed[proof]
    with pytest.raises((AssertionError, KeyError)):
        assert_evidence(changed)


@pytest.mark.parametrize(
    "field",
    [
        "score",
        "score_maximum",
        "score_percent",
        "head",
        "offset",
        "counter",
        "attempt",
        "proof",
    ],
)
def test_python_numeric_equality_cannot_hide_changed_evidence_types(corpus, field):
    changed = deepcopy(corpus)
    observed = changed[0]["worker_lease_expiry"]
    if field in {"score", "score_maximum", "score_percent"}:
        observed["outcome"]["facts"][0]["assertion"][field] = int(
            observed["outcome"]["facts"][0]["assertion"][field]
        )
    elif field == "head":
        observed["outcome"]["snapshot"]["head_scores"][0] = 90
    elif field == "offset":
        observed["chunks"][0]["scheduled_offset_seconds"] = 0
    elif field == "counter":
        observed["outcome"]["jobs"][0]["result"]["facts_created"] = 1.0
    elif field == "attempt":
        observed["outcome"]["jobs"][0]["attempt_count"] = True
    else:
        observed["lease_advanced_after_release"] = 1
    assert changed == corpus
    with pytest.raises(AssertionError):
        assert_evidence(changed)


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_case",
        "order",
        "name",
        "extra_field",
        "extra_request",
        "lost_fact",
        "early_fact",
        "generation",
        "lost_chunk",
        "attempt_not_flush",
        "retry_invented",
    ],
)
def test_partial_or_reinterpreted_captures_fail(corpus, mutation):
    changed = deepcopy(corpus)
    observed = changed[0]["worker_lease_expiry"]
    if mutation == "missing_case":
        changed.pop()
    elif mutation == "order":
        changed.reverse()
    elif mutation == "name":
        observed["case"] = "invented-case"
    elif mutation == "extra_field":
        observed["raw_private_output"] = "synthetic-private"
    elif mutation == "extra_request":
        observed["requests"].append(deepcopy(observed["requests"][0]))
    elif mutation == "lost_fact":
        observed["outcome"]["facts"] = []
    elif mutation == "early_fact":
        observed["before_release"]["facts"] = deepcopy(observed["outcome"]["facts"])
    elif mutation == "generation":
        observed["before_release"]["target"]["config_version"] = 2
    elif mutation == "lost_chunk":
        observed["chunks"].pop()
    elif mutation == "attempt_not_flush":
        observed["chunks"][-1]["flushed_byte_count"] = None
    else:
        observed["outcome"]["jobs"][0]["status"] = "retry"
    with pytest.raises((AssertionError, KeyError)):
        assert_evidence(changed)


@pytest.mark.parametrize(
    "mutation", ["float_token", "whitespace", "crlf", "truncated", "extra"]
)
def test_raw_capture_rewrite_is_never_accepted(mutation):
    raw = ORACLE.read_bytes()
    if mutation == "float_token":
        changed = raw.replace(b"90.0", b"90", 1)
        assert json.loads(changed) == json.loads(raw)
    elif mutation == "whitespace":
        changed = raw + b" "
    elif mutation == "crlf":
        changed = raw.replace(b"\n", b"\r\n")
    elif mutation == "truncated":
        changed = raw[:-1]
    else:
        changed = raw + b"synthetic-private"
    assert changed != raw
    with pytest.raises(AssertionError):
        assert_raw_capture(changed)


@pytest.mark.parametrize("mutation", ["stdout", "warning", "trace", "extra", "source"])
def test_log_profile_cannot_hide_unknown_output_or_source_drift(
    corpus, shutdown, mutation
):
    changed = deepcopy(corpus)
    observed = changed[0]["worker_lease_expiry"]
    if mutation == "stdout":
        observed["logs_before_interrupt"]["stdout_empty"] = False
    elif mutation == "warning":
        observed["logs_before_interrupt"]["stderr_warning_categories"]["unreviewed"] = 1
    elif mutation == "trace":
        observed["logs_after_interrupt"]["shutdown"]["unexpected_output_empty"] = False
    elif mutation == "extra":
        observed["logs_after_interrupt"]["raw_output"] = "synthetic-private"
    else:
        key = next(iter(observed["logs_after_interrupt"]["shutdown_source_sha256"]))
        observed["logs_after_interrupt"]["shutdown_source_sha256"][key] = "0" * 64
    with pytest.raises(AssertionError):
        assert_logs(changed, shutdown)
