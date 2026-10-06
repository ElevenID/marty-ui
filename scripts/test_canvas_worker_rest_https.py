"""Supply frozen HTTPS responses to actual native worker processes on Linux."""

import hashlib
import json
import os
import ssl
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from email.utils import parsedate_to_datetime
from http.server import ThreadingHTTPServer
from pathlib import Path
from threading import Lock, Thread

from canvas_worker_https_fixture import ObservedRequestHandler, response_headers
from test_canvas_lti_https import create_loopback_certificate

RETRY_AFTER_TIER = "MARTY_CANVAS_WORKER_RETRY_AFTER_TIER"
VALIDATION_TIER = "MARTY_CANVAS_WORKER_VALIDATION_TIER"
RETRY_AFTER_CASES = frozenset(
    {
        "http_date_future",
        "http_date_past",
        "malformed",
        "negative",
        "zero",
        "clamped",
        "huge_integer",
    }
)
ROUTINE_RETRY_AFTER_CASES = frozenset({"http_date_future", "malformed"})
VALIDATION_CASES = frozenset(
    {
        "invalid_roster_batch",
        "invalid_roster_limit",
        "invalid_roster_bounds_do_not_preempt_application",
        "invalid_evidence_requirements",
        "missing_lti_subject",
        "unsupported_award_candidate",
        "template_removed_after_application_read",
        "incomplete_logical_key",
        "prohibited_metadata",
        "binding_platform_mismatch",
        "target_disabled",
        "platform_disabled",
        "platform_archived",
        "binding_disabled",
        "binding_archived",
        "stale_configuration",
        "application_missing",
        "candidate_missing",
        "application_removed_after_target_read",
        "candidate_removed_after_target_read",
    }
)
ROUTINE_VALIDATION_CASES = frozenset(
    {
        "invalid_roster_batch",
        "invalid_roster_limit",
        "invalid_roster_bounds_do_not_preempt_application",
        "invalid_evidence_requirements",
        "missing_lti_subject",
        "unsupported_award_candidate",
        "template_removed_after_application_read",
        "prohibited_metadata",
        "application_removed_after_target_read",
        "candidate_removed_after_target_read",
    }
)
VALIDATION_CORPUS_SHA256 = {
    "scenarios": "4933e2fe4108d2ebb6329233c2a42889155ed2c8c6b948ca2a4b938e6b9290a7",
    "oracle": "927f092c2daf428c37ed3a5e906d13873b10c7f147ea2774c15d9dbd1f245d55",
}


def emit_phase(phase, name, started, status):
    """Emit only a fixed phase, corpus-owned case ID, duration and outcome."""
    print(
        "\nMARTY_CI_PHASE_V1 "
        + json.dumps(
            {
                "phase": phase,
                "name": name,
                "duration_ms": round((time.monotonic() - started) * 1000),
                "status": status,
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
        flush=True,
    )


def validate_validation_corpus_files(scenarios: Path, oracle: Path) -> None:
    """Pin the complete frozen inputs, not just their case-name projections."""
    for kind, path in (("scenarios", scenarios), ("oracle", oracle)):
        # Git may check out CRLF locally; pin the committed LF corpus content.
        if (
            hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()
            != VALIDATION_CORPUS_SHA256[kind]
        ):
            raise AssertionError(f"Native validation {kind} corpus changed")


def selected_retry_after_cases(cases, reference, tier, qualification="0"):
    """Classify the whole frozen matrix before selecting nested native cases."""
    if qualification not in {"0", "1"}:
        raise ValueError(f"Invalid Canvas full qualification mode: {qualification!r}")
    if tier not in {"full", "routine"}:
        raise ValueError(f"Invalid native Retry-After tier: {tier!r}")
    if qualification == "1" and tier != "full":
        raise ValueError("Full qualification requires all native Retry-After cases")
    names = [case["name"] for case in cases]
    if len(names) != len(RETRY_AFTER_CASES) or set(names) != RETRY_AFTER_CASES:
        raise AssertionError("Native Retry-After case inventory changed")
    if set(reference) != RETRY_AFTER_CASES:
        raise AssertionError("Frozen Retry-After oracle inventory changed")
    selected = RETRY_AFTER_CASES if tier == "full" else ROUTINE_RETRY_AFTER_CASES
    if len(selected) != (7 if tier == "full" else 2):
        raise AssertionError("Native Retry-After tier membership changed")
    return [case for case in cases if case["name"] in selected]


def selected_validation_cases(cases, reference, inventory, tier, qualification="0"):
    """Check all 20 declarations and frozen oracles before any native child."""
    if qualification not in {"0", "1"}:
        raise ValueError(f"Invalid Canvas full qualification mode: {qualification!r}")
    if tier not in {"full", "routine"}:
        raise ValueError(f"Invalid native validation tier: {tier!r}")
    if qualification == "1" and tier != "full":
        raise ValueError("Full qualification requires all native validation cases")
    names = [case["name"] for case in cases]
    if (
        len(names) != 20
        or set(names) != VALIDATION_CASES
        or set(reference) != VALIDATION_CASES
    ):
        raise AssertionError("Native validation scenario/oracle inventory changed")
    if (
        set(ROUTINE_VALIDATION_CASES) - VALIDATION_CASES
        or len(ROUTINE_VALIDATION_CASES) != 10
    ):
        raise AssertionError("Native validation routine membership changed")
    declared = inventory.get("native_validation", {})
    routine = declared.get("routine", [])
    full_only = declared.get("full_only", [])
    if (
        declared.get("test") != "worker_validation_matches_frozen_published_process"
        or declared.get("historical_test")
        != "worker_validation_reference_matches_published_process"
        or len(routine) != 10
        or set(routine) != ROUTINE_VALIDATION_CASES
        or len(full_only) != 10
        or {entry.get("case") for entry in full_only}
        != VALIDATION_CASES - ROUTINE_VALIDATION_CASES
        or any(
            entry.get("fast_owners")
            != [
                "worker_validation_repository_matches_frozen_errors",
                "terminal_validation_errors_reach_actual_worker_dead_letter_port",
            ]
            for entry in full_only
        )
    ):
        raise AssertionError("Native validation tier obligation inventory changed")
    selected = VALIDATION_CASES if tier == "full" else ROUTINE_VALIDATION_CASES
    return [case for case in cases if case["name"] in selected]


def run(executable, scenario="rest"):
    assert scenario in {
        "rest",
        "facts",
        "retry",
        "retry-after",
        "validation",
        "roster-failure",
        "resources-unavailable",
    }
    root = Path(__file__).resolve().parents[1]
    if scenario == "validation":
        validate_validation_corpus_files(
            root / "contracts/canvas-worker-validation-scenarios.json",
            root / "contracts/canvas-worker-validation-oracle.json",
        )
    spec = json.loads(
        (root / f"contracts/canvas-worker-{scenario}-scenarios.json").read_text()
    )
    if "extends" in spec:
        base = json.loads((root / "contracts" / spec["extends"]).read_text())
        spec = {**base, **spec}
    reference = json.loads(
        (root / f"contracts/canvas-worker-{scenario}-oracle.json").read_text()
    )
    if scenario in {
        "retry-after",
        "validation",
        "roster-failure",
        "resources-unavailable",
    }:
        names = [case["name"] for case in spec["cases"]]
        assert names, "Worker scenario matrix must not be empty"
        assert len(set(names)) == len(names)
        assert set(names) == set(reference)
        cases = spec["cases"]
        if scenario == "retry-after":
            cases = selected_retry_after_cases(
                cases,
                reference,
                os.environ.get(RETRY_AFTER_TIER, "full"),
                os.environ.get("MARTY_CANVAS_FULL_QUALIFICATION", "0"),
            )
        if scenario == "validation":
            inventory = json.loads(
                (root / "contracts/canvas-worker-tier-obligations.json").read_text()
            )
            cases = selected_validation_cases(
                cases,
                reference,
                inventory,
                os.environ.get(VALIDATION_TIER, "full"),
                os.environ.get("MARTY_CANVAS_FULL_QUALIFICATION", "0"),
            )
        for case in cases:
            stage = {
                **case,
                "status": 429 if scenario == "retry-after" else 500,
                "body": {"error": "synthetic-rate-limit"}
                if scenario == "retry-after"
                else {},
            }
            if scenario == "roster-failure":
                stage = dict(case)
            started = time.monotonic()
            status = "failed"
            try:
                run_scenario(
                    executable,
                    scenario,
                    {"stages": [stage]},
                    reference[case["name"]],
                    case,
                )
                status = "ok"
            finally:
                # The parser accepts only short static scenario IDs and numeric
                # durations; no response, SQL, token or exception enters telemetry.
                emit_phase("scenario", f"{scenario}.{case['name']}", started, status)
    else:
        started = time.monotonic()
        status = "failed"
        try:
            run_scenario(executable, scenario, spec, reference)
            status = "ok"
        finally:
            emit_phase("scenario", scenario, started, status)


def assert_retry_timing(output, case, dates, expected):
    prefix = "CANVAS_WORKER_RETRY_TIMING="
    records = [
        line[len(prefix) :] for line in output.splitlines() if line.startswith(prefix)
    ]
    assert len(records) == 1, "Expected one actual durable retry timing observation"
    timing = json.loads(records[0])
    assert set(timing) == {"available_at", "updated_at"}
    available_at = datetime.fromisoformat(timing["available_at"])
    updated_at = datetime.fromisoformat(timing["updated_at"])
    assert available_at.utcoffset() is not None and updated_at.utcoffset() is not None
    if case["timing"] == "http_date":
        assert len(dates) == 1
        matches = (
            abs((available_at - parsedate_to_datetime(dates[0])).total_seconds()) <= 1.1
        )
    else:
        assert case["timing"] == "bounds"
        minimum, maximum = case["delay_bounds"]
        assert type(minimum) is int and type(maximum) is int
        assert 0 <= minimum <= maximum <= 86400
        delay = (available_at - updated_at).total_seconds()
        matches = minimum - 0.1 <= delay <= maximum + 0.1
    assert {"kind": case["timing"], "matches": matches} == expected, (
        f"Native persisted Retry-After timing differs: {case['name']}"
    )


def run_scenario(executable, scenario, spec, reference, matrix_case=None):
    responses = [
        response
        for stage in spec["stages"]
        for response in (
            stage["responses"].values() if "responses" in stage else [stage]
        )
    ]
    requests = []
    dates = []

    class Handler(ObservedRequestHandler):
        observed_requests = requests
        request_observation_lock = Lock()

        def log_message(self, *_):
            pass

        def do_GET(self):
            index = self.observed_request_index
            # Unexpected extra reads fail the request-count check, never wrap.
            stage = (
                responses[index]
                if index < len(responses)
                else {"status": 500, "body": {}}
            )
            body = json.dumps(stage["body"], separators=(",", ":")).encode()
            self.send_response(stage["status"])
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            headers = response_headers(stage)
            if "retry_after_offset_seconds" in stage:
                dates.append(headers["Retry-After"])
            for key, value in headers.items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(body)

    with tempfile.TemporaryDirectory(prefix="canvas-worker-rest-native-") as directory:
        certificate_root = Path(directory)
        name = scenario if matrix_case is None else f"{scenario}.{matrix_case['name']}"
        fixture_started = time.monotonic()
        fixture_ready = False
        server = None
        thread = None
        try:
            cert, key = create_loopback_certificate(certificate_root)
            server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            fixture_ready = True
            emit_phase("fixture_seed", name, fixture_started, "ok")
            empty_ca_directory = certificate_root / "empty-ca-directory"
            empty_ca_directory.mkdir()
            environment = dict(os.environ)
            environment.update(
                MARTY_CANVAS_WORKER_REST_NATIVE_ORIGIN=f"https://127.0.0.1:{server.server_port}",
                MARTY_CANVAS_WORKER_REST_SCENARIO=scenario,
                SSL_CERT_FILE=str(cert),
                SSL_CERT_DIR=str(empty_ca_directory),
            )
            if matrix_case is not None:
                flag = {
                    "retry-after": "MARTY_CANVAS_WORKER_RETRY_AFTER_CASE",
                    "validation": "MARTY_CANVAS_WORKER_VALIDATION_CASE",
                    "roster-failure": "MARTY_CANVAS_WORKER_ROSTER_FAILURE_CASE",
                    "resources-unavailable": "MARTY_CANVAS_WORKER_RESOURCES_UNAVAILABLE_CASE",
                }[scenario]
                environment[flag] = matrix_case["name"]
            child = subprocess.run(
                [executable, "worker_rest_native_child", "--exact", "--nocapture"],
                env=environment,
                capture_output=True,
                text=True,
                timeout=240,
                check=False,
            )
            # The native child keeps raw diagnostics captured for its existing
            # failure assertion. Forward only timing-shaped lines from the
            # owned fixture; the group relay validates every field again.
            for line in child.stderr.splitlines():
                if line.startswith("MARTY_CI_PHASE_V1 "):
                    print("\n" + line, flush=True)
            assert child.returncode == 0, (
                f"Native worker replay failed: {child.stdout} {child.stderr}"
            )
            expected = (
                reference["requests"]
                if scenario == "resources-unavailable"
                else [
                    request
                    for observation in reference["observations"]
                    for request in observation["requests"]
                ]
            )
            if scenario == "resources-unavailable":
                assert expected == [], (
                    "Resource lookup failure must precede provider I/O"
                )
            assert requests == expected, "Actual worker HTTPS requests differ"
            if scenario == "retry-after":
                assert matrix_case is not None
                assert_retry_timing(
                    child.stdout, matrix_case, dates, reference["retry_timing"]
                )
            label = (
                scenario if matrix_case is None else f"{scenario}/{matrix_case['name']}"
            )
            print(
                f"Native worker {label} replay passed all {len(spec['stages'])} frozen HTTPS stages ({len(requests)} requests)"
            )
        finally:
            if not fixture_ready:
                emit_phase("fixture_seed", name, fixture_started, "failed")
            cleanup_started = time.monotonic()
            cleanup_status = "failed"
            try:
                if thread is not None:
                    server.shutdown()
                    thread.join(timeout=5)
                    assert not thread.is_alive()
                if server is not None:
                    server.server_close()
                cleanup_status = "ok"
            finally:
                emit_phase("cleanup", name, cleanup_started, cleanup_status)


if __name__ == "__main__":
    if len(sys.argv) not in {2, 3}:
        raise SystemExit(
            "Expected the exact compiled published-schema executable [rest|facts|retry|retry-after|validation|roster-failure|resources-unavailable]"
        )
    run(sys.argv[1], sys.argv[2] if len(sys.argv) == 3 else "rest")
