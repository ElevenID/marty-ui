"""Root-discovered artifact/control guards; no FastAPI/httpx imports required."""

from __future__ import annotations

import ast
import copy
import hashlib
import importlib.util
import io
import json
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


def assert_artifact_files(contract, read_bytes):
    for owner in ("reference", "scenarios"):
        assert (
            hashlib.sha256(read_bytes(contract[owner]["path"])).hexdigest()
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


def test_contract_artifact_hashes_and_source_coverage(capture, artifact):
    contract = json.loads(CONTRACT.read_text())
    scenarios = json.loads(
        (ROOT / contract["scenarios"]["path"]).read_text(encoding="utf-8")
    )
    assert_artifact_files(contract, lambda path: (ROOT / path).read_bytes())
    assert_connected(contract, artifact, scenarios, capture)
    coverage = json.loads(
        (ROOT / "contracts/issuance-native-coverage.json").read_text()
    )
    assert coverage["upstream"]["sha256"] == contract["upstream_surface_sha256"]
    assert artifact["scenarios_sha256"] == contract["scenarios"]["sha256"]


@pytest.mark.parametrize("owner", ["reference", "scenarios"])
def test_changed_artifact_is_rejected(owner):
    contract = json.loads(CONTRACT.read_text())

    def changed(path):
        raw = (ROOT / path).read_bytes()
        return raw + b" " if path == contract[owner]["path"] else raw

    with pytest.raises(AssertionError):
        assert_artifact_files(contract, changed)


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
