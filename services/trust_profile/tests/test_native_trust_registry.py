from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import HTTPException

from common.native_backend import NativeBackendUnavailable, NativeOperationError
from trust_profile import native
from trust_profile import main as trust_profile


def test_native_diagnostics_require_trust_registry_capability() -> None:
    result = native.diagnostics()

    assert result["available"] is True
    assert result["backend"] == "_marty_rs"
    assert "trust_registry_sync" in result["capabilities"]


@pytest.mark.asyncio
async def test_native_diagnostics_are_exposed_for_health_checks() -> None:
    app = trust_profile.create_app()
    endpoint = next(
        route.endpoint
        for route in app.routes
        if getattr(route, "path", None) == "/health/native-backend"
    )
    with pytest.raises(HTTPException) as unavailable:
        await endpoint()
    assert unavailable.value.status_code == 503

    app.state.native_backend_diagnostics = native.diagnostics()
    result = await endpoint()
    assert result["status"] == "ready"
    assert "trust_registry_sync" in result["capabilities"]


def test_missing_native_backend_fails_without_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unavailable(**_kwargs: object) -> Any:
        raise NativeBackendUnavailable("native backend unavailable")

    monkeypatch.setattr(native, "load_marty_rs", unavailable)

    with pytest.raises(NativeBackendUnavailable, match="native backend unavailable"):
        native.validate_url("https://registry.example/sync")


def test_missing_native_operation_fails_without_python_implementation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(native, "load_marty_rs", lambda **_kwargs: SimpleNamespace())

    with pytest.raises(NativeBackendUnavailable, match="does not expose"):
        native.validate_url("https://registry.example/sync")


def test_malformed_native_result_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    backend = SimpleNamespace(trust_registry_catalog_json=lambda _framework: "{}")
    monkeypatch.setattr(native, "load_marty_rs", lambda **_kwargs: backend)

    with pytest.raises(NativeOperationError, match="result is malformed"):
        native.registry_catalog()


def test_python_adapter_consumes_the_embedded_behavior_vectors() -> None:
    fixture = native.behavior_fixture()
    now = fixture["now"]

    for case in fixture["catalog_cases"]:
        result = native.registry_catalog(case["framework"])
        assert [entry["registry_type"] for entry in result] == case["expected_types"]

    for case in fixture["import_cases"]:
        if "error_contains" in case:
            with pytest.raises(NativeOperationError, match=case["error_contains"]):
                native.import_decision(
                    case["registry_type"],
                    now,
                    case["formats"],
                    case["interval"],
                )
        else:
            result = native.import_decision(
                case["registry_type"],
                now,
                case["formats"],
                case["interval"],
            )
            assert result["formats"] == case["expected_formats"]
            assert result["next_sync_at"] == case["expected_next_sync_at"]

    for case in fixture["public_sync_query_cases"]:
        if "error_contains" in case:
            with pytest.raises(NativeOperationError, match=case["error_contains"]):
                native.public_sync_query(case["since"])
        else:
            result = native.public_sync_query(case["since"])
            assert result["since_sequence"] == case["expected_since_sequence"]
            assert result["current_only"] == case["expected_current_only"]

    for case in fixture["schedule_cases"]:
        assert (
            native.sync_is_due(case["interval"], now, case["last_synchronized_at"])
            == case["expected_due"]
        )

    metadata = native.public_sync_metadata(42, now)
    assert metadata["sync_token"] == "42"
    assert metadata["sequence"] == 42
    assert metadata["has_more"] is False

    for case in fixture["url_cases"]:
        if case["valid"]:
            assert native.validate_url(case["url"]) == case["url"]
        else:
            with pytest.raises(NativeOperationError, match=case["error_contains"]):
                native.validate_url(case["url"])

    for case in fixture["destination_cases"]:
        if "error_contains" in case:
            with pytest.raises(NativeOperationError, match=case["error_contains"]):
                native.destination_decision(
                    case["url"], case["addresses"], case["allowlist"]
                )
        else:
            result = native.destination_decision(
                case["url"], case["addresses"], case["allowlist"]
            )
            assert result["address"] == case["expected_address"]

    for case in fixture["allowlist_cases"]:
        if "error_contains" in case:
            with pytest.raises(NativeOperationError, match=case["error_contains"]):
                native.validate_private_host_allowlist(case["configured"])
        else:
            assert (
                native.validate_private_host_allowlist(case["configured"])
                == case["expected"]
            )

    for case in fixture["request_cases"]:
        result = native.request_plan(case["url"], case["token"], case["address"])
        assert result["request_url"] == case["expected_request_url"]
        assert result["host_header"] == case["expected_host_header"]
        assert result["sni_hostname"] == case["expected_sni_hostname"]

    for case in fixture["evaluation_cases"]:
        if "error_contains" in case:
            with pytest.raises(NativeOperationError, match=case["error_contains"]):
                native.evaluate_pages(case["previous"], case["pages"], now)
        else:
            result = native.evaluate_pages(case["previous"], case["pages"], now)
            assert result["complete"] == case["expected_complete"]
            assert result["pages"] == case["expected_pages"]
            assert result["next_token"] == case["expected_token"]
            assert result["state"]["sequence"] == case["expected_sequence"]
