"""Resource-removal fixture integrity, not native Linux process qualification."""

import ast
from http.client import HTTPSConnection
import importlib
import json
from pathlib import Path
import ssl
from urllib.parse import urlsplit

import pytest


ROOT = Path(__file__).resolve().parents[1]
CASE = "binding_removed_after_hook_validation"


def contract(name):
    return json.loads((ROOT / "contracts" / name).read_text())


def corpus():
    return (
        contract("canvas-worker-resources-unavailable-scenarios.json"),
        contract("canvas-worker-resources-unavailable-oracle.json"),
    )


def test_resources_unavailable_corpus_is_nonempty_unique_and_complete():
    matrix, reference = corpus()
    assert matrix["schema"] == "marty.canvas-worker-resources-unavailable-scenarios/v1"
    names = [case["name"] for case in matrix["cases"]]
    assert names == [CASE]
    assert names and len(names) == len(set(names))
    assert set(names) == set(reference)
    assert matrix["reference_scenario"] == "canvas-worker-rest-scenarios.json"
    assert matrix["queued_job_scenario"] == "canvas-worker-validation-scenarios.json"
    assert reference[CASE]["case"] == CASE
    assert (
        reference[CASE]["schema"]
        == "marty.canvas-worker-resources-unavailable-oracle/v1"
    )
    assert (
        reference[CASE]["source_sha256"]
        == contract("canvas-worker-rest-oracle.json")["source_sha256"]
    )


def test_resource_fixture_only_changes_its_exact_disposable_binding_and_reference():
    matrix, _ = corpus()
    case = matrix["cases"][0]
    assert case["seed"] == [
        "INSERT INTO issuance_service.canvas_program_bindings "
        "(id,organization_id,platform_id,application_template_id,credential_template_id,"
        "evidence_requirements,enabled,validated_config_version,activated_at) "
        "SELECT 'binding-resources-race',organization_id,platform_id,application_template_id,"
        "credential_template_id,evidence_requirements,enabled,validated_config_version,activated_at "
        "FROM issuance_service.canvas_program_bindings WHERE id='binding-review' "
        "AND organization_id='org-review'",
        "UPDATE issuance_service.canvas_evidence_sync_targets "
        "SET binding_id='binding-resources-race' WHERE id='target-review' "
        "AND organization_id='org-review' AND binding_id='binding-review'",
    ]
    assert case["mutation"] == [
        "UPDATE issuance_service.canvas_evidence_sync_targets "
        "SET binding_id='binding-review' WHERE id='target-review' "
        "AND organization_id='org-review' AND binding_id='binding-resources-race'",
        "DELETE FROM issuance_service.canvas_program_bindings "
        "WHERE id='binding-resources-race' AND organization_id='org-review'",
    ]
    # No running job, lease, clock, original resource, or constraint is edited.
    for statement in [*case["seed"], *case["mutation"]]:
        assert "canvas_evidence_sync_jobs" not in statement
        assert all(
            prohibited not in statement.upper()
            for prohibited in ("LEASE_", "CLOCK_TIMESTAMP", "ALTER ", "TRUNCATE ")
        )
    queued = contract(matrix["queued_job_scenario"])["initial_job_seed"]
    assert queued == (
        "INSERT INTO issuance_service.canvas_evidence_sync_jobs "
        "(id,organization_id,target_id,status,attempt_count,max_attempts,available_at,"
        "result,created_at,updated_at) VALUES ('worker-validation-job','org-review',"
        "'target-review','queued',0,8,'2026-09-01T00:00:00Z','{}',"
        "'2026-09-01T00:00:00Z','2026-09-01T00:00:00Z')"
    )
    source = ast.parse(
        (ROOT / "scripts/run_canvas_worker_resources_unavailable_oracle.py").read_text()
    )
    run = next(
        node
        for node in source.body
        if isinstance(node, ast.FunctionDef) and node.name == "run"
    )
    starts = [
        node.lineno
        for node in ast.walk(run)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "start_blocked_workers"
    ]
    seeds = [
        node.lineno
        for node in ast.walk(run)
        if isinstance(node, ast.Subscript)
        and isinstance(node.value, ast.Name)
        and node.value.id == "queued"
        and isinstance(node.slice, ast.Constant)
        and node.slice.value == "initial_job_seed"
    ]
    assert len(starts) == len(seeds) == 1
    assert seeds[0] < starts[0], (
        "Only an initial queued seed before worker startup is allowed"
    )


def test_barrier_trace_records_python_instrumentation_not_required_native_read_counts():
    matrix, reference = corpus()
    # These five observed phases identify the published ORM/loader read path.
    # Rust may eliminate redundant reads; only external before/after behavior
    # is cross-language parity. Do not require this instrumentation in Rust.
    assert matrix["cases"][0]["barriers"] == [
        {"name": "wrapper_application", "table": "applications"},
        {"name": "hook_platform", "table": "canvas_platforms"},
        {"name": "hook_binding", "table": "canvas_program_bindings"},
        {"name": "hook_application", "table": "applications"},
        {"name": "resource_platform", "table": "canvas_platforms"},
    ]
    assert reference[CASE]["observed_barriers"] == [
        barrier["name"] for barrier in matrix["cases"][0]["barriers"]
    ]


def test_reference_preserves_external_state_without_provider_or_oauth_use():
    matrix, reference = corpus()
    observed = reference[CASE]
    before, after = observed["before"], observed["after"]
    assert observed["requests"] == []
    assert observed["same_job"] is True
    assert observed["protected_rows_unchanged"] is True
    assert observed["unchanged_after_exit"] is True
    assert observed["exit_code_after_interrupt"] == -2
    assert before["facts"] == after["facts"] == []
    assert (
        before["snapshot"]
        == after["snapshot"]
        == {
            "application": {
                "credential_id": "credential-review",
                "policy_allowed": None,
                "status": "approved",
            },
            "credential": {"active": True, "count": 1},
            "events": {},
            "facts": 0,
            "head_scores": None,
            "reviews": [],
        }
    )
    assert (
        before["oauth"]
        == after["oauth"]
        == {
            "reauthorization_required": False,
            "refresh_lease_owner_present": False,
            "secret_enabled": True,
            "secret_used": False,
            "status": "connected",
        }
    )
    assert before["heartbeat"]["metadata"]["phase"] == "processing"
    assert after["heartbeat"]["metadata"]["phase"] == "idle"
    assert len(before["jobs"]) == len(after["jobs"]) == 1
    initial, terminal = before["jobs"][0], after["jobs"][0]
    assert initial["status"] == "leased" and initial["max_attempts"] == 8
    assert initial["lease_owner_present"] and initial["lease_expires_present"]
    assert initial["attempt_count"] == terminal["attempt_count"] == 1
    assert terminal == {
        "attempt_count": 1,
        "completed": True,
        "last_error_code": matrix["cases"][0]["code"],
        "last_error_summary": "Canvas synchronization resources are unavailable",
        "lease_expires_present": False,
        "lease_owner_present": False,
        "max_attempts": 1,
        "result": {},
        "retry_delay_matches_37_seconds": None,
        "retry_scheduled": None,
        "started": True,
        "status": "dead_letter",
    }
    assert terminal["last_error_code"] == "canvas_sync_resources_unavailable"
    resources = {
        "disposable_binding_present": False,
        "target": {
            "binding_id": "binding-review",
            "config_version": 1,
            "enabled": True,
        },
    }
    assert observed["changed_resources"] == resources
    assert observed["final_resources"] == {
        **resources,
        "target": {**resources["target"], "enabled": False},
    }


def test_native_parent_routes_each_resource_case_without_expected_requests(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    native = importlib.import_module("test_canvas_worker_rest_https")
    calls = []
    monkeypatch.setattr(native, "run_scenario", lambda *args: calls.append(args))
    native.run("synthetic-native-executable", "resources-unavailable")
    matrix, reference = corpus()
    assert len(calls) == len(matrix["cases"]) == 1
    executable, scenario, spec, observed, case = calls[0]
    assert executable == "synthetic-native-executable"
    assert scenario == "resources-unavailable"
    assert case == matrix["cases"][0]
    assert spec["stages"] == [{**case, "status": 500, "body": {}}]
    assert observed == reference[CASE]
    assert observed["requests"] == []


@pytest.mark.parametrize("invalid", ["empty", "duplicate", "missing", "extra"])
def test_native_resource_matrix_rejects_ambiguous_or_empty_cases(monkeypatch, invalid):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    native = importlib.import_module("test_canvas_worker_rest_https")
    matrix, reference = corpus()
    if invalid == "empty":
        matrix["cases"].clear()
        reference.clear()
    elif invalid == "duplicate":
        matrix["cases"].append(dict(matrix["cases"][0]))
    elif invalid == "missing":
        reference.clear()
    else:
        reference["unconfigured-case"] = reference[CASE]
    inputs = iter([json.dumps(matrix), json.dumps(reference)])
    monkeypatch.setattr(Path, "read_text", lambda *_: next(inputs))

    def unexpected_child(*_):
        pytest.fail("Invalid resource matrix must fail before launching a child")

    monkeypatch.setattr(native, "run_scenario", unexpected_child)
    with pytest.raises(AssertionError):
        native.run("must-not-start", "resources-unavailable")


@pytest.mark.parametrize(
    ("failure", "method"),
    [
        (None, "GET"),
        ("unexpected_https", "GET"),
        ("unexpected_https", "POST"),
        ("child_exit", "GET"),
        ("reference_io", "GET"),
    ],
)
def test_parent_checks_actual_zero_requests_and_exact_child_selection(
    monkeypatch, failure, method
):
    # Reuse the actual HTTPS owner; only the native child is simulated. This
    # validates the parent tripwire, not worker/database behavioral parity.
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    native = importlib.import_module("test_canvas_worker_rest_https")
    actual_run = native.subprocess.run
    matrix, references = corpus()
    observed = references[CASE]
    if failure == "reference_io":
        observed["requests"] = [{"method": "GET", "path": "/must-not-read"}]
    calls = []

    def execute(command, **options):
        if command[0] == "openssl":
            return actual_run(command, **options)
        assert command == [
            "synthetic-worker",
            "worker_rest_native_child",
            "--exact",
            "--nocapture",
        ]
        calls.append(command)
        environment = options["env"]
        assert (
            environment["MARTY_CANVAS_WORKER_REST_SCENARIO"] == "resources-unavailable"
        )
        assert environment["MARTY_CANVAS_WORKER_RESOURCES_UNAVAILABLE_CASE"] == CASE
        assert options["timeout"] == 240
        if failure == "unexpected_https":
            origin = urlsplit(environment["MARTY_CANVAS_WORKER_REST_NATIVE_ORIGIN"])
            assert origin.scheme == "https" and origin.hostname == "127.0.0.1"
            connection = HTTPSConnection(
                origin.hostname,
                origin.port,
                context=ssl.create_default_context(cafile=environment["SSL_CERT_FILE"]),
                timeout=5,
            )
            try:
                connection.request(method, "/must-not-read")
                response = connection.getresponse()
                assert response.status == (500 if method == "GET" else 501)
                response.read()
            finally:
                connection.close()
        return native.subprocess.CompletedProcess(
            command, 1 if failure == "child_exit" else 0, stdout="", stderr=""
        )

    monkeypatch.setattr(native.subprocess, "run", execute)
    case = matrix["cases"][0]
    arguments = (
        "synthetic-worker",
        "resources-unavailable",
        {"stages": [{**case, "status": 500, "body": {}}]},
        observed,
        case,
    )
    if failure is None:
        native.run_scenario(*arguments)
    else:
        message = {
            "unexpected_https": "Actual worker HTTPS requests differ",
            "child_exit": "Native worker replay failed",
            "reference_io": "Resource lookup failure must precede provider I/O",
        }[failure]
        with pytest.raises(AssertionError, match=message):
            native.run_scenario(*arguments)
    assert len(calls) == 1


@pytest.mark.parametrize("method", ["POST", "HEAD"])
def test_published_fixture_records_unsupported_requests_without_accepting_them(
    monkeypatch, method
):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    fixture_module = importlib.import_module("canvas_worker_https_fixture")
    with fixture_module.WorkerHttpsFixture() as fixture:
        fixture.stage = {"status": 500, "body": {}}
        assert fixture.requests == []
        connection = HTTPSConnection(
            "127.0.0.1",
            fixture.server.server_port,
            context=ssl.create_default_context(cafile=str(fixture.cert)),
            timeout=5,
        )
        try:
            connection.request(method, "/must-not-read")
            response = connection.getresponse()
            assert response.status == 501
            response.read()
        finally:
            connection.close()
        assert fixture.requests == [
            {
                "method": method,
                "path": "/must-not-read",
                "authorization": None,
                "accept": None,
            }
        ]
    assert not fixture.thread.is_alive()
    assert fixture.server.socket.fileno() == -1
