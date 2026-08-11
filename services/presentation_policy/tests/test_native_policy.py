"""Contract tests for the Rust presentation-policy binding adapter."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from common.native_backend import NativeBackendUnavailable
from services.presentation_policy.native_policy import (
    NativePolicyEvaluationError,
    NativePresentationPolicyEvaluator,
)


def _valid_result() -> dict[str, object]:
    return {
        "result": "passed",
        "decision": "allow",
        "decision_reason": "All required credentials and claims satisfied",
        "policy_id": "policy-1",
        "policy_name": "Login",
        "credential_results": [],
        "alternative_results": [],
        "total_requirements": 1,
        "satisfied_requirements": 1,
        "required_satisfied": 1,
        "required_total": 1,
        "verified_claims": {"email": "member@example.com"},
        "errors": [],
        "warnings": [],
        "evaluation_time_epoch_seconds": 1_000,
    }


def _backend(**values: object) -> SimpleNamespace:
    return SimpleNamespace(
        normalize_presentation_credential_format=lambda value: value.upper(),
        **values,
    )


def test_adapter_calls_the_single_native_function_with_canonical_json() -> None:
    requests: list[dict[str, object]] = []

    def evaluate(request_json: str) -> str:
        requests.append(json.loads(request_json))
        return json.dumps(_valid_result())

    adapter = NativePresentationPolicyEvaluator(
        _backend(evaluate_service_presentation_policy=evaluate)
    )

    result = adapter.evaluate({"z": 1, "a": {"value": True}})

    assert requests == [{"a": {"value": True}, "z": 1}]
    assert result["decision"] == "allow"
    assert adapter.normalize_credential_format("sd-jwt") == "SD-JWT"


def test_missing_native_policy_function_fails_closed() -> None:
    with pytest.raises(NativeBackendUnavailable, match="does not expose"):
        NativePresentationPolicyEvaluator(SimpleNamespace())


@pytest.mark.parametrize(
    "native_output",
    [
        "not-json",
        "[]",
        json.dumps({**_valid_result(), "decision": "maybe"}),
        json.dumps({**_valid_result(), "required_total": True}),
    ],
)
def test_malformed_native_result_is_typed(native_output: str) -> None:
    adapter = NativePresentationPolicyEvaluator(
        _backend(
            evaluate_service_presentation_policy=lambda _request: native_output
        )
    )

    with pytest.raises(NativePolicyEvaluationError):
        adapter.evaluate({"policy": {}})


def test_invalid_request_json_is_typed_before_native_call() -> None:
    adapter = NativePresentationPolicyEvaluator(
        _backend(
            evaluate_service_presentation_policy=lambda _request: pytest.fail(
                "native function must not be called"
            )
        )
    )

    with pytest.raises(NativePolicyEvaluationError, match="not valid JSON"):
        adapter.evaluate({"value": float("nan")})


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("sd_jwt_vc", "SD_JWT_VC"),
        ("dc+sd-jwt", "SD_JWT_VC"),
        ("JSON_LD", "W3C_VCDM_V2_DI"),
        ("ldp_vc", "W3C_VCDM_V2_DI"),
        ("w3c_vcdm_v2_jwt_vc", "VC_JWT"),
        ("jwt_vc_json", "VC_JWT"),
    ],
)
def test_python_adapter_uses_canonical_rust_format_vectors(
    value: str,
    expected: str,
) -> None:
    adapter = NativePresentationPolicyEvaluator()

    assert adapter.normalize_credential_format(value) == expected


def test_python_adapter_matches_shared_rust_golden_vector() -> None:
    fixture_path = (
        Path(__file__).resolve().parents[3]
        / "tests"
        / "vectors"
        / "presentation_policy_service.json"
    )
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    adapter = NativePresentationPolicyEvaluator()

    for vector in fixture["format_vectors"]:
        assert (
            adapter.normalize_credential_format(vector["input"])
            == vector["expected"]
        )

    result = adapter.evaluate(fixture["request"])
    expected = fixture["expected"]
    assert result["result"] == expected["result"]
    assert result["decision"] == expected["decision"]
    assert result["required_total"] == expected["required_total"]
    assert result["required_satisfied"] == expected["required_satisfied"]
    assert result["verified_claims"] == expected["verified_claims"]
    assert [error["code"] for error in result["errors"]] == expected["error_codes"]
