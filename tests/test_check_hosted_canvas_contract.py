from __future__ import annotations

import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "check-hosted-canvas-contract.py"
CONTRACT_PATH = ROOT / "deploy-config" / "catalog" / "hosted-canvas-acceptance.json"


def load_checker_module():
    spec = importlib.util.spec_from_file_location("check_hosted_canvas_contract", SCRIPT_PATH)
    assert spec
    assert spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def configured_values() -> dict[str, str]:
    return {
        "HOSTED_CANVAS_MARTY_ORIGIN": "https://marty.example.test",
        "HOSTED_CANVAS_PLATFORM_ID": "platform-123",
        "HOSTED_CANVAS_MARTY_API_KEY": "marty-api-key-value",
        "HOSTED_CANVAS_ORIGIN": "https://canvas.example.test",
        "HOSTED_CANVAS_API_TOKEN": "canvas-api-token-value",
        "HOSTED_CANVAS_COURSE_ID": "42",
        "HOSTED_CANVAS_EXTERNAL_TOOL_ID": "84",
        "HOSTED_CANVAS_LTI_CLIENT_ID": "client-123",
        "HOSTED_CANVAS_EXPECTED_ACTIVE_KID": "active-kid",
        "HOSTED_CANVAS_EXPECTED_RETIRING_KID": "retiring-kid",
    }


class FakeClient:
    def __init__(self, checker, *, private_jwk: bool = False):
        self.checker = checker
        self.private_jwk = private_jwk
        self.calls: list[tuple[str, dict[str, str]]] = []

    def get(self, url: str, headers: dict[str, str] | None = None):
        self.calls.append((url, headers or {}))
        response = self.checker.ApiResponse
        if url.endswith("/v1/integrations/canvas/platforms"):
            return response(401, {"error": "unauthorized"})
        if url.endswith("/v1/integrations/canvas/lti/jwks"):
            active = {
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "kid": "active-kid",
                "n": "active-modulus",
                "e": "AQAB",
            }
            if self.private_jwk:
                active["d"] = "private-material"
            return response(
                200,
                {
                    "keys": [
                        active,
                        {
                            "kty": "RSA",
                            "alg": "RS256",
                            "use": "sig",
                            "kid": "retiring-kid",
                            "n": "retiring-modulus",
                            "e": "AQAB",
                        },
                    ]
                },
            )
        if url.endswith("/registration-config"):
            return response(
                200,
                {
                    "developer_key_configuration": {
                        "oidc_initiation_url": "https://marty.example.test/v1/integrations/canvas/lti/login",
                        "target_link_uri": "https://marty.example.test/v1/integrations/canvas/lti/launch",
                    }
                },
            )
        if url.endswith("/readiness"):
            return response(200, {"ready": True, "checks": [{"blocking": True, "status": "pass"}]})
        if url.endswith("/api/v1/courses/42"):
            return response(200, {"id": 42})
        if url.endswith("/api/v1/courses/42/external_tools/84"):
            return response(200, {"id": 84, "workflow_state": "public", "client_id": "client-123"})
        if "/api/v1/courses/42/external_tools/sessionless_launch?" in url:
            return response(200, {"url": "https://canvas.example.test/api/lti/sessionless_launch/opaque"})
        raise AssertionError(f"Unexpected URL in fake client: {url}")


def test_contract_configuration_declares_portable_non_mutating_suite():
    checker = load_checker_module()

    contract = checker.load_contract(CONTRACT_PATH)

    assert [case["id"] for case in contract["automated_cases"]] == list(checker.AUTOMATED_CASE_IDS)
    assert all(case["mutates_tenant"] is False for case in contract["automated_cases"])
    assert checker.REQUIRED_PORTABILITY_EXCLUSIONS.issubset(contract["portability_exclusions"])


def test_missing_tenant_configuration_is_a_redacted_successful_skip():
    checker = load_checker_module()
    contract = checker.load_contract(CONTRACT_PATH)
    now = datetime(2026, 7, 14, tzinfo=timezone.utc)

    result = checker.run_contract(contract, {}, now=now)
    checker.verify_redacted_result(result, contract, {})

    assert result["status"] == "skipped"
    assert result["missing_configuration"] == list(checker.REQUIRED_CONFIGURATION)
    assert {case["status"] for case in result["cases"]} == {"skipped"}
    assert "example.test" not in str(result)


def test_protected_lane_fails_closed_when_configuration_is_missing():
    checker = load_checker_module()
    contract = checker.load_contract(CONTRACT_PATH)
    skipped = checker.run_contract(contract, {})

    assert checker.contract_exit_code(skipped, require_config=False) == 0
    assert checker.contract_exit_code(skipped, require_config=True) == 1
    assert "--require-config" in (ROOT / ".github/workflows/hosted-canvas-contract.yml").read_text(
        encoding="utf-8"
    )


def test_configured_contract_passes_without_emitting_tenant_material():
    checker = load_checker_module()
    contract = checker.load_contract(CONTRACT_PATH)
    values = configured_values()
    client = FakeClient(checker)

    result = checker.run_contract(contract, values, client=client)
    checker.verify_redacted_result(result, contract, values)

    assert result["status"] == "passed"
    assert {case["status"] for case in result["cases"]} == {"passed"}
    serialized = json.dumps(result, sort_keys=True)
    for value in values.values():
        assert json.dumps(value) not in serialized

    readiness_call = next(call for call in client.calls if call[0].endswith("/readiness"))
    assert readiness_call[1] == {"X-API-Key": values["HOSTED_CANVAS_MARTY_API_KEY"]}
    canvas_calls = [call for call in client.calls if "/api/v1/" in call[0]]
    assert canvas_calls
    assert all(
        call[1] == {"Authorization": f"Bearer {values['HOSTED_CANVAS_API_TOKEN']}"}
        for call in canvas_calls
    )


def test_private_jwk_material_fails_without_entering_the_result():
    checker = load_checker_module()
    contract = checker.load_contract(CONTRACT_PATH)
    values = configured_values()

    result = checker.run_contract(
        contract,
        values,
        client=FakeClient(checker, private_jwk=True),
    )
    checker.verify_redacted_result(result, contract, values)

    jwks_case = next(case for case in result["cases"] if case["id"] == "marty_lti_jwks_rs256")
    assert result["status"] == "failed"
    assert jwks_case == {
        "id": "marty_lti_jwks_rs256",
        "status": "failed",
        "reason_code": "private_material_present",
    }
    assert "private-material" not in str(result)


def test_artifact_verifier_rejects_schema_expansion_and_secret_values():
    checker = load_checker_module()
    contract = checker.load_contract(CONTRACT_PATH)
    values = configured_values()
    result = checker.run_contract(contract, values, client=FakeClient(checker))

    expanded = {**result, "response_body": {"token": values["HOSTED_CANVAS_API_TOKEN"]}}
    with pytest.raises(checker.ContractConfigError, match="fixed schema"):
        checker.verify_redacted_result(expanded, contract, values)

    leaked = {**result, "started_at": values["HOSTED_CANVAS_API_TOKEN"]}
    with pytest.raises(checker.ContractConfigError, match="tenant material"):
        checker.verify_redacted_result(leaked, contract, values)
