"""Dispatch corpus/controlled-hook integrity; not native runtime qualification."""

import asyncio
from copy import deepcopy
import hashlib
import importlib
import inspect
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_compiler_contract_documentation_is_a_packaged_source_dependency():
    source_root = ROOT / "rust/services/issuance/src"
    source = (source_root / "canvas_sync_worker.rs").read_text(encoding="utf-8")
    contract = source_root / "canvas_sync_processor_contract.md"
    assert '#[doc = include_str!("canvas_sync_processor_contract.md")]' in source
    assert "../tests/compile/" not in source
    documentation = contract.read_text(encoding="utf-8")
    assert documentation.count("```compile_fail") == 4
    assert documentation.count("```no_run") == 1
    image_inputs = (
        (ROOT / "rust/services/Dockerfile.ci.dockerignore")
        .read_text(encoding="utf-8")
        .splitlines()
    )
    # Image builds deliberately exclude integration tests. Compiler-consumed
    # rustdoc must stay in the packaged source tree, not that excluded directory.
    assert "!rust/**" in image_inputs
    assert "rust/services/*/tests" in image_inputs
    assert not any("src" in rule for rule in image_inputs if not rule.startswith("#"))


@pytest.fixture
def matrix():
    return json.loads(
        (ROOT / "contracts/canvas-worker-dispatch-scenarios.json").read_text()
    )


@pytest.fixture
def owner(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    return importlib.import_module("run_canvas_worker_dispatch_oracle")


def test_all_three_legacy_dispatch_paths_and_both_controls_are_explicit(owner, matrix):
    contract = json.loads(
        (ROOT / "contracts/issuance-canvas-sync-worker.json").read_text()
    )
    cases = {
        case["name"]: owner.select_case(matrix, case["name"])
        for case in matrix["cases"]
    }
    assert len(cases) == 5
    for name, expected in [
        ("missing_processor", contract["processor_dispatch"]["missing_processor"]),
        ("nonawaitable_result", contract["processor_dispatch"]["invalid_shape"]),
        ("nonmapping_result", contract["processor_dispatch"]["invalid_shape"]),
    ]:
        assert {key: cases[name][key] for key in expected} == expected
    assert (
        cases["nonawaitable_result"]["summary"] != cases["nonmapping_result"]["summary"]
    )
    assert (
        cases["valid_mapping"]["status"]
        == cases["rollout_closed_missing"]["status"]
        == "succeeded"
    )
    assert contract["legacy_python_wiring"]["normative_for_replacement"] is False


@pytest.mark.parametrize(
    "mutation", ["missing", "duplicate", "renamed", "unknown_hook"]
)
def test_invalid_dispatch_selection_fails_before_startup(owner, matrix, mutation):
    if mutation == "missing":
        matrix["cases"].pop()
    elif mutation == "duplicate":
        matrix["cases"].append(deepcopy(matrix["cases"][0]))
    elif mutation == "renamed":
        matrix["cases"][0]["name"] = "not-a-dispatch-case"
    else:
        matrix["cases"][0]["hook"] = "not-a-synthetic-hook"
    with pytest.raises(AssertionError):
        owner.select_case(matrix, "missing_processor")


def test_callbacks_supply_shapes_without_database_or_provider_dependencies(owner):
    hooks = importlib.import_module("canvas_worker_dispatch_hooks")
    ordinary = hooks.nonawaitable_result(None, None)
    assert isinstance(ordinary, dict) and not inspect.isawaitable(ordinary)
    assert isinstance(asyncio.run(hooks.nonmapping_result(None, None)), list)
    result = asyncio.run(hooks.valid_mapping(None, None))
    assert result == {
        "facts_changed": 1,
        "no_change": False,
        "synthetic_discarded": "synthetic-operational-result-tripwire",
    }


def test_dispatch_environment_preserves_tls_and_only_selects_named_fixture_hooks(
    owner, matrix
):
    for case in matrix["cases"]:
        selected = owner.select_case(matrix, case["name"])
        result = owner.dispatch_input(
            "https://127.0.0.1:1", Path("synthetic-ca"), matrix, selected
        )
        env = result["environment"]
        assert env["PYTHONPATH"].startswith("/verification/worker_trust:")
        assert env["PYTHONPATH"].endswith(":/verification/scripts")
        assert env["MARTY_CANVAS_TEST_CA_FILE"] == "synthetic-ca"
        assert env["CANVAS_SYNC_PROCESSOR"] == (
            ""
            if case["hook"] is None
            else f"canvas_worker_dispatch_hooks:{case['hook']}"
        )
        assert (
            env["CANVAS_PORTABLE_INTEGRATION_ENABLED"]
            == str(case["rollout_enabled"]).lower()
        )
        assert "observe_cycle_result" not in result


def test_frozen_dispatch_reference_keeps_all_outcomes_and_preservation(owner, matrix):
    reference = json.loads(
        (ROOT / "contracts/canvas-worker-dispatch-oracle.json").read_text()
    )
    assert reference["schema"] == "marty.canvas-worker-dispatch-corpus/v1"
    retained = json.loads(
        (ROOT / "contracts/canvas-worker-rest-oracle.json").read_text()
    )
    hook_hash = hashlib.sha256(
        (ROOT / "scripts/canvas_worker_dispatch_hooks.py")
        .read_text(encoding="utf-8")
        .encode()
    ).hexdigest()
    assert [item["case"] for item in reference["observations"]] == [
        case["name"] for case in matrix["cases"]
    ]
    for case, observed in zip(matrix["cases"], reference["observations"], strict=True):
        assert observed["schema"] == "marty.canvas-worker-dispatch-oracle/v1"
        assert observed["case"] == case["name"]
        owner.assert_outcome(observed["state"], case)
        assert observed["requests"] == []
        assert observed["same_job"] is observed["unchanged_after_exit"] is True
        assert observed["issued_rows_transactions_ciphertext_preserved"] is True
        assert observed["synthetic_result_detail_not_retained"] is True
        assert "synthetic-operational-result-tripwire" not in json.dumps(observed)
        assert observed["hook_sha256"] == hook_hash
        for module, digest in retained["source_sha256"].items():
            assert observed["source_sha256"][module] == digest
        assert observed["exit_code_after_interrupt"] == -2
        assert set(observed["source_sha256"]) == {
            "issuance.canvas_worker",
            "issuance.infrastructure.api.canvas_routes",
            "issuance.application.canvas_sync_service",
        }


@pytest.mark.parametrize(
    "actual,expected_class",
    [
        (
            "Canvas synchronization processor must be asynchronous",
            "DispatchObservedAsyncRequiredSummary",
        ),
        (
            "Canvas synchronization processor returned an invalid result",
            "DispatchObservedInvalidResultSummary",
        ),
        (
            "Authoritative Canvas synchronization processor is not configured",
            "DispatchObservedMissingProcessorSummary",
        ),
        (None, "DispatchObservedAbsentSummary"),
        ("synthetic-private-provider-detail", "DispatchObservedUnknownSummary"),
    ],
)
def test_diagnostic_summary_classification_never_retains_observed_text(
    owner, actual, expected_class
):
    owner.assert_summary(actual, actual)
    with pytest.raises(getattr(owner, expected_class)) as failure:
        owner.assert_summary(actual, "different expected summary")
    assert str(failure.value) == ""


@pytest.mark.parametrize("name", ["nonawaitable_result", "nonmapping_result"])
def test_terminal_dispatch_requires_exhaustion_without_changing_attempt_fence(
    owner, matrix, name
):
    case = owner.select_case(matrix, name)
    retained = json.loads(
        (ROOT / "contracts/canvas-worker-validation-oracle.json").read_text()
    )
    state = deepcopy(retained["invalid_roster_batch"]["observations"][0])
    state["jobs"][0]["last_error_code"] = case["code"]
    state["jobs"][0]["last_error_summary"] = case["summary"]
    owner.assert_outcome(state, case)
    assert state["jobs"][0]["max_attempts"] == state["jobs"][0]["attempt_count"] == 1
    state["jobs"][0]["max_attempts"] = 8
    with pytest.raises(AssertionError):
        owner.assert_outcome(state, case)


@pytest.mark.parametrize(
    "field,value",
    [
        ("status", "leased"),
        ("attempt_count", 2),
        ("max_attempts", 9),
        ("result", {"facts_changed": 99}),
        ("last_error_code", "wrong-code"),
        ("last_error_summary", "wrong-summary"),
        ("started", False),
        ("completed", False),
        ("lease_owner_present", True),
        ("lease_expires_present", True),
        ("retry_scheduled", True),
    ],
)
def test_durable_dispatch_checks_reject_mutated_job_fields(owner, matrix, field, value):
    case = owner.select_case(matrix, "valid_mapping")
    state = {
        "jobs": [
            {
                "status": "succeeded",
                "attempt_count": 1,
                "max_attempts": 8,
                "result": case["result"],
                "last_error_code": None,
                "last_error_summary": None,
                "started": True,
                "completed": True,
                "lease_owner_present": False,
                "lease_expires_present": False,
                "retry_scheduled": None,
            }
        ],
        "heartbeat": {
            "role": "canvas_sync",
            "metadata": {
                "phase": "idle",
                "leased_jobs": 0,
                "process": "standalone",
                "processor_configured": True,
            },
        },
        "facts": [],
        "oauth": {
            "status": "connected",
            "reauthorization_required": False,
            "refresh_lease_owner_present": False,
            "secret_enabled": True,
            "secret_used": False,
        },
    }
    owner.assert_outcome(state, case)
    state["jobs"][0][field] = value
    with pytest.raises(AssertionError):
        owner.assert_outcome(state, case)
