"""The published JSON oracle keeps its observations and deadline while naming timeouts."""

import asyncio
import importlib.util
import json
import runpy
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

SOURCE = Path(__file__).resolve().parents[1] / "scripts/run_canvas_json_consumer_oracle.py"


def load_oracle(monkeypatch):
    for name in (
        "canvas_observation_values",
        "run_canvas_status_provider_oracle",
        "run_canvas_validation_boundary_oracle",
    ):
        monkeypatch.setitem(sys.modules, name, ModuleType(name))
    sys.modules["canvas_observation_values"].encode_observation = lambda value: value
    spec = importlib.util.spec_from_file_location("json_consumer_phase_probe", SOURCE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    ("phase", "expected"),
    [
        ("setup", "JsonConsumerSetupTimeout"),
        ("validation", "JsonConsumerValidationTimeout"),
        ("provider", "JsonConsumerProviderTimeout"),
    ],
)
def test_outer_deadline_reports_only_fixed_phase(monkeypatch, phase, expected):
    oracle = load_oracle(monkeypatch)
    assert oracle.DEFAULT_TIMEOUT_SECONDS == 120
    cleaned = []

    async def stalled(current):
        current["name"] = phase
        try:
            await asyncio.Future()
        finally:
            cleaned.append(phase)

    with pytest.raises(getattr(oracle, expected)) as failure:
        asyncio.run(oracle.observe_with_deadline(0.01, stalled))
    assert str(failure.value) == ""
    assert cleaned == [phase]


def test_inner_timeout_is_not_reclassified(monkeypatch):
    oracle = load_oracle(monkeypatch)

    async def inner_timeout(current):
        current["name"] = "provider"
        raise TimeoutError("controlled inner deadline")

    with pytest.raises(TimeoutError, match="controlled inner deadline") as failure:
        asyncio.run(oracle.observe_with_deadline(1, inner_timeout))
    assert type(failure.value) is TimeoutError


def test_success_preserves_validation_then_provider_observations(monkeypatch):
    oracle = load_oracle(monkeypatch)
    calls = []
    cases = {
        "validation": [{"name": "validation_case", "payload": "private"}],
        "provider": [{"name": "provider_case", "payload": "private"}],
    }
    monkeypatch.setattr(
        oracle,
        "Path",
        lambda _path: SimpleNamespace(read_text=lambda: json.dumps(cases)),
    )

    async def validation_observe(values, *, capture_diagnostics):
        calls.append(("validation", list(values), capture_diagnostics))
        return {"validation-result": True}

    async def provider_observe(values, *, delivery_lifecycle, credential_routes):
        calls.append(("provider", list(values), delivery_lifecycle, credential_routes))
        return {"provider-result": True}

    oracle.validation.observe = validation_observe
    oracle.provider.observe = provider_observe
    result = asyncio.run(oracle.observe_with_deadline(1))
    assert calls == [
        ("validation", cases["validation"], True),
        ("provider", cases["provider"], True, True),
    ]
    assert result == {
        "schema": "marty.canvas-json-consumers/v1",
        "normalization": "post-observation codepoint/non-finite/object-entry markers; reserved marker keys are escaped as object entries; application values unchanged",
        "validation": {"validation-result": True},
        "provider": {"provider-result": True},
    }
    assert [row["name"] for row in oracle.CASE_TIMINGS] == [
        "json_consumer.validation.validation_case",
        "json_consumer.provider.provider_case",
    ]
    assert all(set(row) == {"name", "duration_ms"} for row in oracle.CASE_TIMINGS)
    assert "private" not in str(oracle.CASE_TIMINGS)


def test_checked_in_json_consumer_case_inventory_remains_132() -> None:
    scenarios = json.loads(
        (SOURCE.parents[1] / "contracts/canvas-json-consumer-scenarios.json").read_text()
    )
    assert len(scenarios["validation"]) == 66
    assert len(scenarios["provider"]) == 66


def test_probe_runpy_namespace_exposes_separate_case_timings(monkeypatch) -> None:
    load_oracle(monkeypatch)
    module = runpy.run_path(str(SOURCE))
    globals_ = module["run"].__globals__
    globals_["Path"] = lambda _path: SimpleNamespace(
        read_text=lambda: json.dumps(
            {"validation": [{"name": "one"}], "provider": [{"name": "two"}]}
        )
    )

    async def observe(values, **_kwargs):
        return {"cases": [case["name"] for case in values]}

    globals_["validation"].observe = observe
    globals_["provider"].observe = observe
    result = module["run"]()
    assert result["oracle"]["validation"] == {"cases": ["one"]}
    assert result["oracle"]["provider"] == {"cases": ["two"]}
    assert [row["name"] for row in result["ci_case_timing"]] == [
        "json_consumer.validation.one",
        "json_consumer.provider.two",
    ]
