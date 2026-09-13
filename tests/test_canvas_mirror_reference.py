"""Root-discovered artifact/control guards; no FastAPI/httpx imports required."""

from __future__ import annotations

import ast
import copy
import hashlib
import importlib.util
import io
import json
import math
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CAPTURE = ROOT / "scripts/capture_canvas_mirror_reference.py"
CONTRACT = ROOT / "contracts/issuance-canvas-mirror.json"


@pytest.fixture
def capture():
    # The capture module's top-level imports are stdlib only. Application
    # dependencies are loaded solely inside the explicit observation worker.
    spec = importlib.util.spec_from_file_location("mirror_reference_guards", CAPTURE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    yield module
    module.VIOLATIONS.clear()


@pytest.fixture
def artifact():
    return json.loads(
        (ROOT / "contracts/canvas-mirror-python-reference.json").read_text(
            encoding="utf-8"
        )
    )


def assert_artifact_files(contract, read_bytes, capture):
    for owner in ("reference", "scenarios"):
        assert (
            hashlib.sha256(
                capture.canonical_json_bytes(read_bytes(contract[owner]["path"]))
            ).hexdigest()
            == contract[owner]["sha256"]
        )


def assert_connected(contract, reference, scenarios, capture):
    assert contract["phase"] == "frozen-controlled-reference-only"
    assert contract["source_commit"] == reference["source_commit"] == capture.REVISION
    assert reference["sources"] == {
        name: list(value) for name, value in capture.SOURCES.items()
    }
    assert {route["operation"] for route in contract["routes"]} == set(
        capture.OPERATIONS
    )
    selected = set(reference["selected_definitions"][capture.ROUTES])
    assert set(capture.OPERATIONS) <= selected
    assert {
        "_verify_management_api_key",
        "_require_trusted_organization",
        "run_canvas_mirror_automation_loop",
        "CanvasMirrorAutomationConfig",
    } <= selected
    expected_http = [case["id"] for case in scenarios["http"]] + [
        f"auth_{operation}_{'missing' if key is None else 'wrong'}"
        for operation in scenarios["authentication"]["operations"]
        for key in scenarios["authentication"]["keys"]
    ]
    assert [case["id"] for case in reference["http"]] == expected_http
    assert (
        len(expected_http)
        == len(set(expected_http))
        == contract["observations"]["http"]
    )
    for key, count in (
        ("loop", "controlled_loop"),
        ("provider_cancellation", "provider_cancellation"),
        ("configuration", "configuration"),
    ):
        assert [case["id"] for case in reference[key]] == [
            case["id"] for case in scenarios[key]
        ]
        assert len(reference[key]) == contract["observations"][count]
    assert contract["automation"]["not_the_same_owner_as"] == "CanvasSyncWorker"
    assert contract["native_selection"] == "unchanged"


def require_publication_boundary(contract, capture, read_bytes):
    decoded = {}
    for kind in ("reference", "scenarios"):
        owner = contract[f"publication_boundary_{kind}"]
        raw = capture.canonical_json_bytes(read_bytes(owner["path"]))
        assert hashlib.sha256(raw).hexdigest() == owner["sha256"]
        decoded[kind] = json.loads(raw)
    reference, scenarios = decoded["reference"], decoded["scenarios"]
    assert reference["schema"] == "marty.canvas-publication-boundary-reference/v1"
    assert reference["source_commit"] == scenarios["source_commit"] == capture.REVISION
    assert reference["sources"] == {
        name: list(value) for name, value in capture.SOURCES.items()
    }
    assert (
        reference["scenarios_sha256"]
        == contract["publication_boundary_scenarios"]["sha256"]
    )
    assert contract["publication_boundary_observations"] == {
        "datetime": 10,
        "adapter_cancellation": 2,
        "response_shapes": 3,
    }
    expected_ids = [
        "bridge_milliseconds",
        "badgr_milliseconds",
        "bridge_microseconds",
        "badgr_microseconds",
        "bridge_offset",
        "badgr_offset",
        "bridge_expiry_absent",
        "badgr_expiry_absent",
        "bridge_provider_cancel",
        "badgr_provider_cancel",
        "badgr_empty_result_data_fallback",
        "badgr_first_nonobject_no_fallback",
        "badgr_empty_result_object_no_fallback",
        "bridge_naive_datetime",
        "badgr_naive_datetime",
    ]
    assert [case["id"] for case in reference["adapter"]] == expected_ids
    assert [case["id"] for case in scenarios["adapter"]] == expected_ids
    assert {
        "publish_canvas_credential_mirror",
        "_build_badgr_assertion_payload",
        "_build_canvas_publish_payload",
    } <= set(reference["selected_definitions"][capture.ADAPTER])
    assert reference["infrastructure_controls"] == [
        "missing-global-fatal",
        "caught-unowned-origin-fatal",
    ]
    for index, case in enumerate(reference["adapter"]):
        assert case["entrypoint"] == "direct_adapter"
        assert case["before"] == case["after"]
        assert case["before"]["snapshot_sha256"] in reference["snapshots"]
        requests = [call for call in case["trace"] if call["kind"] == "http"]
        assert len(requests) == 1 and requests[0]["method"] == "POST"
        response = case["responses"][0]
        if index in (8, 9):
            assert response == {"outcome": "CancelledError"}
        elif index in (11, 12):
            assert response == {
                "exception": "RuntimeError",
                "detail": "Canvas Credentials assertion publish response did not include an assertion id",
            }
        else:
            assert response["result_encoding"] == "python-json-text"
        body = json.loads(requests[0]["body"])
        if index < 6:
            issued = body["issuedOn"] if index % 2 else body["credential"]["issued_at"]
            expected = [
                "2026-08-31T23:59:58.123000+00:00",
                "2026-08-31T23:59:58.123456+00:00",
                "2026-08-31T23:59:58.123000-06:00",
            ][index // 2]
            assert issued == expected
        if index == 6:
            assert body["credential"]["expires_at"] is None
        if index in (13, 14):
            issued = (
                body["credential"]["issued_at"] if index == 13 else body["issuedOn"]
            )
            expiry = (
                body["credential"]["expires_at"] if index == 13 else body["expires"]
            )
            assert issued == "2026-08-31T23:59:58.123000"
            assert expiry == "2027-08-31T23:59:58.123456"
        if index == 7:
            assert "expires" not in body
        if index == 10:
            assert (
                json.loads(response["result_json"])["external_credential_id"]
                == "data-id"
            )


def test_additive_publication_boundary_hashes_sources_and_complete_observations(
    capture,
):
    contract = json.loads(CONTRACT.read_text(encoding="utf-8"))

    def read(path):
        return (ROOT / path).read_bytes()

    require_publication_boundary(contract, capture, read)
    require_publication_boundary(
        contract,
        capture,
        lambda path: capture.canonical_json_bytes(read(path)).replace(b"\n", b"\r\n"),
    )
    for key in ("publication_boundary_reference", "publication_boundary_scenarios"):
        target = contract[key]["path"]
        with pytest.raises(AssertionError):
            require_publication_boundary(
                contract,
                capture,
                lambda path: read(path) + b" " if path == target else read(path),
            )
    changed = copy.deepcopy(contract)
    changed["publication_boundary_observations"]["adapter_cancellation"] = 0
    with pytest.raises(AssertionError):
        require_publication_boundary(changed, capture, read)


@pytest.mark.parametrize(
    "modes",
    [
        {"audit": True, "adapter_reference": True},
        {"audit": True, "publication_boundary": True},
        {"adapter_reference": True, "publication_boundary": True},
        {"audit": True, "adapter_reference": True, "publication_boundary": True},
    ],
)
def test_conflicting_reference_modes_cannot_spawn_or_execute(capture, modes):
    for entrypoint in (capture.bounded_observation_child, capture.observe_sources):
        with pytest.raises(ValueError, match="mutually exclusive"):
            entrypoint({}, **modes)


def test_boundary_cancellation_keeps_original_owned_task_sequence(capture):
    tree = ast.parse(CAPTURE.read_text(encoding="utf-8"))
    functions = {
        node.name: node for node in tree.body if isinstance(node, ast.AsyncFunctionDef)
    }
    cancellation = ast.unparse(functions["cancel_provider_action"])
    assert "asyncio.create_task(action)" in cancellation
    assert "await asyncio.wait_for(provider_entered.wait(), 2)" in cancellation
    assert "task.cancel()" in cancellation
    assert "await task" in cancellation
    assert "await asyncio.gather(task, return_exceptions=True)" in cancellation
    assert "except asyncio.CancelledError" in cancellation
    assert "Provider cancellation was swallowed" in cancellation
    # Both direct adapter and prior ASGI/loop branches use this owner. The
    # bounded complete child remains the final cancellation-swallowing fence.
    assert (
        ast.unparse(functions["observe_http"]).count("await cancel_provider_action(")
        == 2
    )


def test_contract_artifact_hashes_and_source_coverage(capture, artifact):
    contract = json.loads(CONTRACT.read_text())
    scenarios = json.loads(
        (ROOT / contract["scenarios"]["path"]).read_text(encoding="utf-8")
    )
    assert_artifact_files(contract, lambda path: (ROOT / path).read_bytes(), capture)
    assert contract["artifact_identity"] == "UTF-8; CRLF normalized to LF only"
    assert_connected(contract, artifact, scenarios, capture)
    coverage = json.loads(
        (ROOT / "contracts/issuance-native-coverage.json").read_text()
    )
    assert coverage["upstream"]["sha256"] == contract["upstream_surface_sha256"]
    assert artifact["scenarios_sha256"] == contract["scenarios"]["sha256"]


@pytest.mark.parametrize("owner", ["reference", "scenarios"])
def test_changed_artifact_is_rejected(owner, capture):
    contract = json.loads(CONTRACT.read_text())
    target = contract[owner]["path"]
    original = (ROOT / target).read_bytes()
    mutated = original.replace(b'"id":', b'"changed_id":', 1)
    assert mutated != original

    def changed(path):
        return mutated if path == target else (ROOT / path).read_bytes()

    with pytest.raises(AssertionError):
        assert_artifact_files(contract, changed, capture)


def test_crlf_artifacts_preserve_exact_identity(capture):
    contract = json.loads(CONTRACT.read_text())

    def crlf(path):
        raw = capture.canonical_json_bytes((ROOT / path).read_bytes())
        assert b"\n" in raw
        return raw.replace(b"\n", b"\r\n")

    assert_artifact_files(contract, crlf, capture)


def test_canonical_json_identity_has_no_other_normalization(capture):
    raw = '{"value":"é", "space": 1}\r\n'.encode("utf-8")
    assert capture.canonical_json_bytes(raw) == raw.replace(b"\r\n", b"\n")
    assert capture.canonical_json_bytes(b"{\r}") == b"{\r}"
    with pytest.raises(UnicodeDecodeError):
        capture.canonical_json_bytes(b"\xff")


@pytest.fixture
def adapter_artifact():
    def reject_nonfinite(value):
        raise ValueError(f"Nonstandard outer JSON constant: {value}")

    return json.loads(
        (ROOT / "contracts/canvas-mirror-adapter-reference.json").read_text(
            encoding="utf-8"
        ),
        parse_constant=reject_nonfinite,
    )


def test_adapter_artifact_hashes_and_closed_source(capture, adapter_artifact):
    contract = json.loads(CONTRACT.read_text())
    owners = {key: contract[f"adapter_{key}"] for key in ("reference", "scenarios")}
    assert_artifact_files(owners, lambda path: (ROOT / path).read_bytes(), capture)
    assert_artifact_files(
        owners,
        lambda path: capture.canonical_json_bytes((ROOT / path).read_bytes()).replace(
            b"\n", b"\r\n"
        ),
        capture,
    )
    scenarios = json.loads(
        (ROOT / owners["scenarios"]["path"]).read_text(encoding="utf-8")
    )
    assert adapter_artifact["schema"] == "marty.canvas-mirror-adapter-reference/v1"
    assert (
        adapter_artifact["source_commit"]
        == scenarios["source_commit"]
        == capture.REVISION
    )
    assert adapter_artifact["sources"] == {
        key: list(value) for key, value in capture.SOURCES.items()
    }
    assert adapter_artifact["scenarios_sha256"] == owners["scenarios"]["sha256"]
    assert [case["id"] for case in adapter_artifact["adapter"]] == [
        case["id"] for case in scenarios["adapter"]
    ]
    assert len(adapter_artifact["adapter"]) == contract["adapter_observations"] == 51
    assert (
        "publish_canvas_credential_mirror"
        in adapter_artifact["selected_definitions"][
            "issuance.infrastructure.adapters.canvas_credentials_adapter"
        ]
    )
    assert contract["adapter_result_encoding"] == "python-json-text"


@pytest.mark.parametrize("owner", ["reference", "scenarios"])
def test_adapter_content_mutation_is_rejected(capture, owner):
    contract = json.loads(CONTRACT.read_text())
    owners = {key: contract[f"adapter_{key}"] for key in ("reference", "scenarios")}
    path = owners[owner]["path"]
    original = (ROOT / path).read_bytes()
    changed = original.replace(b"bridge_base", b"changed_base", 1)
    assert original != changed
    with pytest.raises(AssertionError):
        assert_artifact_files(
            owners,
            lambda current: (
                changed if current == path else (ROOT / current).read_bytes()
            ),
            capture,
        )


def test_adapter_observations_preserve_input_state_and_owned_effects(adapter_artifact):
    snapshots = adapter_artifact["snapshots"]
    referenced = set()
    for case in adapter_artifact["adapter"]:
        assert case["entrypoint"] == "direct_adapter"
        assert case["request"] is None
        assert case["before"] == case["after"]
        referenced.add(case["before"]["snapshot_sha256"])
        assert all(call["kind"] != "repository" for call in case["trace"])
        if case["id"].startswith("ownership_"):
            assert case["trace"] == []
            assert case["responses"] == [
                {
                    "exception": "RuntimeError",
                    "detail": "Canvas delivery resources are unavailable",
                }
            ]
    assert referenced == set(snapshots)
    for digest, value in snapshots.items():
        assert (
            hashlib.sha256(
                json.dumps(
                    value, ensure_ascii=True, sort_keys=True, separators=(",", ":")
                ).encode()
            ).hexdigest()
            == digest
        )


def test_adapter_portable_gate_precedes_aggregate_ownership(adapter_artifact):
    case = next(
        case
        for case in adapter_artifact["adapter"]
        if case["id"] == "portable_foreign_organization"
    )
    assert case["trace"] == []
    assert case["responses"] == [
        {
            "exception": "RuntimeError",
            "detail": "Portable Canvas delivery is not enabled for this organization",
        }
    ]


def test_adapter_result_text_preserves_numeric_nan_string_and_surrogate(
    adapter_artifact,
):
    cases = {case["id"]: case for case in adapter_artifact["adapter"]}

    def result(name):
        response = cases[name]["responses"][0]
        assert response["result_encoding"] == "python-json-text"
        return json.loads(response["result_json"])

    finite = result("bridge_response_scalar_id")
    assert finite["external_credential_id"] == "17"
    assert finite["metadata"]["publish_response"]["id"] == 17
    numeric = result("bridge_response_nonfinite_id")
    assert numeric["external_credential_id"] == "nan"
    assert math.isnan(numeric["metadata"]["publish_response"]["id"])
    text = result("bridge_response_string_nan_id")
    assert (
        text["external_credential_id"]
        == text["metadata"]["publish_response"]["id"]
        == "NaN"
    )
    surrogate = result("bridge_response_surrogate_id")
    assert (
        surrogate["external_credential_id"]
        == surrogate["metadata"]["publish_response"]["id"]
        == "\ud800"
    )
    assert (
        "\\ud800"
        in cases["bridge_response_surrogate_id"]["responses"][0]["result_json"]
    )
    assert result("bridge_utf16_json")["external_credential_id"] == "encoded-id"


def test_adapter_delivery_secret_policy_is_not_validation_policy(adapter_artifact):
    cases = {case["id"]: case for case in adapter_artifact["adapter"]}
    ordered = cases["secret_ordered_sources"]["trace"]
    assert [call for call in ordered if call["kind"] == "secret"] == [
        {"kind": "secret", "organization": "org-1", "identifier": "empty"},
        {"kind": "secret", "organization": "org-1", "identifier": "selected"},
    ]
    for name, case in cases.items():
        if name.startswith("secret_alias_"):
            assert case["trace"][0] == {
                "kind": "secret",
                "organization": "org-1",
                "identifier": "selected-secret",
            }
            assert (
                next(call for call in case["trace"] if call["kind"] == "http")[
                    "headers"
                ]["authorization"]
                == "Bearer synthetic-selected-token"
            )
    fallback = next(
        call
        for call in cases["secret_operator_fallback"]["trace"]
        if call["kind"] == "http"
    )
    assert fallback["headers"]["authorization"] == "Bearer synthetic-provider-token"
    sanitized = json.loads(
        next(
            call
            for call in cases["bridge_metadata_sanitization"]["trace"]
            if call["kind"] == "http"
        )["body"]
    )["metadata"]
    assert sanitized == {
        "canvas_credentials": {"issuer_id": "metadata-issuer"},
        "public_custom": {"value": "kept"},
    }


@pytest.mark.parametrize("mutation", ["route", "auth", "loop", "case", "source"])
def test_disconnected_reference_is_rejected(capture, artifact, mutation):
    contract = json.loads(CONTRACT.read_text())
    scenarios = json.loads(
        (ROOT / contract["scenarios"]["path"]).read_text(encoding="utf-8")
    )
    changed = copy.deepcopy(artifact)
    if mutation == "route":
        changed["selected_definitions"][capture.ROUTES].remove(capture.OPERATIONS[0])
    elif mutation == "auth":
        changed["selected_definitions"][capture.ROUTES].remove(
            "_verify_management_api_key"
        )
    elif mutation == "loop":
        changed["loop"].pop()
    elif mutation == "case":
        changed["http"].pop()
    else:
        changed["sources"][capture.ROUTES][1] = "0" * 40
    with pytest.raises(AssertionError):
        assert_connected(contract, changed, scenarios, capture)


def test_lossless_snapshot_references_are_complete(artifact):
    snapshots = artifact["snapshots"]
    referenced = set()

    def visit(value):
        if isinstance(value, dict):
            if set(value) == {"snapshot_sha256"}:
                referenced.add(value["snapshot_sha256"])
            else:
                for nested in value.values():
                    visit(nested)
        elif isinstance(value, list):
            for nested in value:
                visit(nested)

    visit(artifact["http"])
    visit(artifact["provider_cancellation"])
    assert referenced == set(snapshots)
    for digest, value in snapshots.items():
        encoded = json.dumps(
            value, ensure_ascii=True, sort_keys=True, separators=(",", ":")
        ).encode()
        assert hashlib.sha256(encoded).hexdigest() == digest


def test_positive_replay_and_denial_side_effects(artifact):
    cases = {case["id"]: case for case in artifact["http"]}
    for name in ("bridge_publish", "badgr_publish"):
        case = cases[name]
        assert [response["status"] for response in case["responses"]] == [200, 200]
        assert case["responses"][0] == case["responses"][1]
        assert sum(call["kind"] == "http" for call in case["trace"]) == 1
    for case in artifact["http"]:
        if case["id"].startswith("auth_"):
            assert case["responses"][0]["status"] == 401
            assert case["before"] == case["after"]
            assert case["trace"] == []
    assert cases["publish_foreign_context"]["responses"][0]["status"] == 404
    assert cases["provenance_context_mismatch"]["responses"][0]["status"] == 403
    # Frozen management health/batch handlers do not impose the provenance
    # header restriction. Do not silently turn this into gateway proof.
    assert cases["health_foreign_context"]["responses"][0]["status"] == 200


def test_provider_cancellation_is_not_only_a_stubbed_loop(artifact):
    for case in artifact["provider_cancellation"]:
        assert case["responses"] == [{"outcome": "CancelledError"}]
        assert sum(call["kind"] == "http" for call in case["trace"]) == 1
        assert not any(
            call["kind"] == "repository" and call["method"] == "save_delivery_record"
            for call in case["trace"]
        )
    assert {case["entrypoint"] for case in artifact["provider_cancellation"]} == {
        "ASGI",
        "automation_loop",
    }


def test_loop_timing_and_exception_continuation(artifact):
    loops = {case["id"]: case for case in artifact["loop"]}
    assert loops["disabled"]["outcome"] == "returned"
    assert loops["disabled"]["trace"] == []
    delayed = [call for call in loops["delayed_start"]["trace"] if "phase" in call]
    assert [(call["phase"], call["at"]) for call in delayed] == [
        ("sleep", 0.0),
        ("publish", 5.0),
        ("sleep", 5.0),
        ("sync", 7.0),
        ("sleep", 7.0),
    ]
    relative = [
        call for call in loops["completion_relative"]["trace"] if "phase" in call
    ]
    assert [(call["phase"], call["at"]) for call in relative] == [
        ("publish", 0.0),
        ("sync", 4.0),
        ("sleep", 11.0),
        ("publish", 12.0),
        ("sleep", 16.0),
        ("sync", 18.0),
        ("sleep", 25.0),
    ]
    failed = loops["publish_exception_continues"]["trace"]
    assert any(call.get("exception") == "RuntimeError" for call in failed)
    assert any(call.get("phase") == "sync" for call in failed)
    assert all(
        case["outcome"] == "CancelledError"
        for name, case in loops.items()
        if name != "disabled"
    )


def test_infrastructure_failure_cannot_be_swallowed(capture):
    try:
        capture.denied_network()
    except AssertionError:
        pass
    with pytest.raises(AssertionError, match="infrastructure"):
        capture.require_clean_capture()


def test_unowned_dns_is_fatal_even_if_caught(capture):
    with pytest.raises(AssertionError):
        capture.controlled_dns("unowned.example", 443)
    with pytest.raises(AssertionError):
        capture.require_clean_capture()


def test_missing_ast_global_is_fatal(capture, monkeypatch):
    monkeypatch.setattr(
        capture, "SOURCES", {"guard_example": ("guard_example.py", "not-used")}
    )
    loader = capture.PinnedDefinitions(
        {"guard_example": "def run():\n    return missing_dependency()\n"}
    )
    try:
        loader.load("guard_example", ["run"])
        with pytest.raises(ValueError, match="missing_dependency"):
            loader.validate_bindings()
    finally:
        loader.close()


def test_source_input_hash_mismatch_is_fatal(capture):
    with pytest.raises(ValueError, match="Incomplete"):
        capture.verify_sources({})
    wrong = {name: "" for name in capture.SOURCES}
    with pytest.raises(ValueError, match="Untrusted"):
        capture.verify_sources(wrong)


@pytest.mark.parametrize(
    "mode", ["deadline", "flood", "failed", "partial", "reader", "startup"]
)
def test_observation_child_failures_never_return_corpus(
    capture, artifact, monkeypatch, mode
):
    monkeypatch.setattr(capture, "verify_sources", lambda _sources: None)
    monkeypatch.setattr(capture.time, "sleep", lambda _seconds: None)
    ticks = iter([0.0, 31.0, 32.0])
    monkeypatch.setattr(capture.time, "monotonic", lambda: next(ticks, 33.0))

    class Child:
        returncode = (
            None if mode in {"deadline", "startup"} else (1 if mode == "failed" else 0)
        )
        stdout = io.BytesIO(
            b'{"partial":' if mode == "partial" else json.dumps(artifact).encode()
        )
        stderr = io.BytesIO(
            b" " * (4 * 1024 * 1024 + 1) if mode == "flood" else b"controlled failure"
        )
        killed = False
        waited = False

        def poll(self):
            return self.returncode

        def kill(self):
            self.killed = True
            self.returncode = -1

        def wait(self, timeout):
            assert timeout == 5
            self.waited = True
            return self.returncode

    child = Child()
    if mode == "reader":

        class FailedReader(io.BytesIO):
            def read(self, _size=-1):
                raise OSError("controlled reader failure")

        child.stderr = FailedReader()
    if mode == "startup":

        class FailedThread(capture.threading.Thread):
            def start(self):
                raise RuntimeError("controlled thread startup failure")

        monkeypatch.setattr(capture.threading, "Thread", FailedThread)
    monkeypatch.setattr(capture.subprocess, "Popen", lambda *_args, **_kwargs: child)
    if mode == "partial":
        expected_type, reason = json.JSONDecodeError, "Expecting value"
    else:
        expected_type, reason = (
            RuntimeError,
            {
                "deadline": "30-second deadline",
                "flood": "output collection failed",
                "reader": "output collection failed",
                "failed": "Observation child failed",
                "startup": "controlled thread startup failure",
            }[mode],
        )
    with pytest.raises(expected_type, match=reason):
        capture.bounded_observation_child({})
    assert child.waited
    assert child.killed == (mode in {"deadline", "startup"})


@pytest.mark.parametrize("mode", ["reader", "flood", "nonzero"])
def test_child_failure_controls_have_otherwise_acceptable_output(
    capture, artifact, monkeypatch, mode
):
    """Mutation control: suppress only the relevant signal, not JSON validation."""
    monkeypatch.setattr(capture, "verify_sources", lambda _sources: None)
    original_event = capture.threading.Event
    first_event = True

    class SuppressedSignal(original_event):
        def set(self):
            pass

    def event():
        nonlocal first_event
        if first_event:
            first_event = False
            return SuppressedSignal()
        return original_event()

    if mode != "nonzero":
        monkeypatch.setattr(capture.threading, "Event", event)

    class FailedReader(io.BytesIO):
        def read(self, _size=-1):
            raise OSError("controlled reader failure")

    class Child:
        # For nonzero mode, changing precisely the exit status is the mutation.
        returncode = 0
        stdout = io.BytesIO(json.dumps(artifact).encode())
        stderr = (
            FailedReader()
            if mode == "reader"
            else io.BytesIO(
                b" " * (4 * 1024 * 1024 + 1)
                if mode == "flood"
                else b"controlled failure"
            )
        )

        def poll(self):
            return 0

        def wait(self, timeout):
            return 0

    monkeypatch.setattr(capture.subprocess, "Popen", lambda *_args, **_kwargs: Child())
    _, actual = capture.bounded_observation_child({})
    assert actual == artifact


def test_imports_are_inert_and_worker_does_not_read_git():
    tree = ast.parse(CAPTURE.read_text())
    for node in tree.body:
        if isinstance(node, ast.Import):
            assert all(
                alias.name.split(".")[0]
                not in {"fastapi", "httpx", "pydantic", "issuance"}
                for alias in node.names
            )
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] not in {
                "fastapi",
                "httpx",
                "pydantic",
                "issuance",
            }
    main = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "main"
    )
    worker = next(
        node
        for node in main.body
        if isinstance(node, ast.If) and ast.unparse(node.test) == "args.worker"
    )
    assert "read_sources" not in ast.unparse(worker)
    assert "observe_sources(json.load(sys.stdin)" in ast.unparse(worker)


@pytest.mark.parametrize("future", [False, True])
def test_loader_preserves_original_annotation_semantics(capture, monkeypatch, future):
    prefix = "from __future__ import annotations\n" if future else ""
    name = "annotation_guard"
    monkeypatch.setattr(capture, "SOURCES", {name: ("annotation_guard.py", "unused")})
    loader = capture.PinnedDefinitions(
        {name: prefix + "def run(value: int) -> int:\n    return value\n"}
    )
    try:
        module = loader.load(name, ["run"])
        assert module.run.__annotations__ == {
            "value": "int" if future else int,
            "return": "int" if future else int,
        }
    finally:
        loader.close()
