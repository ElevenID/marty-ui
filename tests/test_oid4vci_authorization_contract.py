from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "contracts" / "issuance-oid4vci-authorization.json"
REFERENCE_PATH = (
    ROOT / "contracts" / "issuance-oid4vci-authorization-python-reference.json"
)


def _json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _normalized_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def _observations() -> dict[str, dict]:
    return {case["name"]: case for case in _json(REFERENCE_PATH)["observations"]}


def test_frozen_oid4vci_authorization_source_and_reference_are_immutable() -> None:
    contract = _json(CONTRACT_PATH)
    reference = _json(REFERENCE_PATH)

    assert contract["schema"] == "marty.issuance-oid4vci-authorization/v1"
    assert reference["schema"] == (
        "marty.issuance-oid4vci-authorization-python-reference/v1"
    )
    assert contract["source"]["protected_main_commit"] == (
        "aaa6a9b8e31e62cd0ab087eef5fc1f4835048e26"
    )
    assert contract["source"]["protected_main_tree"] == (
        "819b7458a31c75d28043a4660643b029c5ec4567"
    )
    assert reference["source"]["commit"] == contract["source"]["protected_main_commit"]
    assert reference["source"]["tree"] == contract["source"]["protected_main_tree"]
    assert reference["source"]["repository"] == "ElevenID/marty-credentials"
    assert reference["source"]["files"] == {
        "services/issuance/domain/entities.py": (
            "4c8ed38c8c587d86526400b013fd3254e4099392c4b9ffac07f3a373a77e55b5"
        ),
        "services/issuance/infrastructure/adapters/memory_repository.py": (
            "5ff57d51d8d443ae2b1efd5897fed6ed7ec56f688820e756b04957c80c0beead"
        ),
        "services/issuance/infrastructure/adapters/postgres_repository.py": (
            "9e900c3171863cf8e15e8ab4dc9d82b257d3ad1d7318aab243f97f4039fa7c96"
        ),
        "services/issuance/infrastructure/api/routes.py": (
            "daf2f4be1d8043ff237e2b6be36fbd671712a097ca2c0ccee209ae9ab0ef166f"
        ),
    }
    assert (
        contract["source"]["route_source_sha256"]
        == reference["source"]["files"][
            "services/issuance/infrastructure/api/routes.py"
        ]
    )
    assert (
        _normalized_sha256(REFERENCE_PATH) == contract["source"]["reference"]["sha256"]
    )


def test_slice_has_all_seven_operations_and_real_authentication_boundaries() -> None:
    contract = _json(CONTRACT_PATH)
    routes = {route["operation"]: route for route in contract["routes"]}
    expected = {
        "authorize": ("GET", "/v1/issuance/authorize"),
        "pushed_authorization_request": ("POST", "/v1/issuance/par"),
        "deferred_credential": ("POST", "/v1/issuance/deferred-credential"),
        "notification_endpoint": ("POST", "/v1/issuance/notification"),
        "put_oid4vci_registered_client": ("PUT", "/v1/issuance/oid4vci-clients"),
        "revoke_transaction": (
            "POST",
            "/v1/issuance/transactions/{tx_id}/revoke",
        ),
        "list_credentials": ("GET", "/v1/issuance/credentials"),
    }
    assert {
        operation: (route["method"], route["path"])
        for operation, route in routes.items()
    } == expected

    components = {
        component["id"]: set(component["operations"])
        for component in contract["ownership"]["components"]
    }
    assert components == {
        "public-oid4vci-protocol": {
            "authorize",
            "pushed_authorization_request",
            "deferred_credential",
            "notification_endpoint",
        },
        "tenant-oid4vci-management": {
            "put_oid4vci_registered_client",
            "revoke_transaction",
            "list_credentials",
        },
    }
    assert set(contract["authentication_and_tenant_order"]) == {
        "authorize",
        "pushed_authorization_request",
        "deferred_credential_legacy",
        "notification_endpoint_legacy",
        "put_oid4vci_registered_client_legacy",
        "revoke_transaction",
        "list_credentials",
    }
    assert contract["ownership"]["estimated_python_route_body_lines"] >= 490


def test_public_protocol_is_native_while_management_remains_legacy() -> None:
    contract = _json(CONTRACT_PATH)
    coverage = _json(ROOT / "contracts" / "issuance-native-coverage.json")
    native = {route["operation"] for route in coverage["native_http"]}
    operations = {route["operation"] for route in contract["routes"]}

    assert operations & native == {
        "authorize",
        "pushed_authorization_request",
        "deferred_credential",
        "notification_endpoint",
    }
    assert operations - native == {
        "put_oid4vci_registered_client",
        "revoke_transaction",
        "list_credentials",
    }
    assert coverage["remaining"]["http"] == 20

    surface = _json(ROOT / "contracts" / "issuance-runtime-surface.json")
    frozen_surface = {
        route["operation"]: (route["method"], route["path"])
        for route in surface["http"]["routes"]
        if route["operation"] in operations
    }
    assert frozen_surface == {
        route["operation"]: (route["method"], route["path"])
        for route in contract["routes"]
    }


def test_every_captured_whole_response_is_named_once_and_has_complete_shape() -> None:
    contract = _json(CONTRACT_PATH)
    reference = _json(REFERENCE_PATH)
    names = [case["name"] for case in reference["observations"]]

    assert len(names) == len(set(names)) == 38
    assert names == contract["whole_response_reference_cases"]
    for case in reference["observations"]:
        response = case["response"]
        assert set(response) == {"status_code", "headers", "body"}
        assert isinstance(response["status_code"], int)
        assert isinstance(response["headers"], dict)
        assert "repository_calls" in case or "operation_trace" in case


def test_each_route_has_success_and_representative_authentication_or_error_evidence() -> (
    None
):
    observations = _observations()
    cases = {
        "authorize": (
            "authorize_json_success_persists_session",
            "authorize_requires_response_type_and_client_id",
        ),
        "pushed_authorization_request": (
            "par_success_issuer_query_precedes_form",
            "par_failed_store_is_sanitized",
        ),
        "deferred_credential": (
            "deferred_empty_bearer_currently_reaches_pending_transaction",
            "deferred_requires_bearer_prefix",
        ),
        "notification_endpoint": (
            "notification_valid_shape_has_no_legacy_effect",
            "notification_missing_bearer_has_nested_error",
        ),
        "put_oid4vci_registered_client": (
            "put_registered_client_uses_body_tenant",
            "put_registered_client_missing_management_key",
        ),
        "revoke_transaction": (
            "revoke_transaction_canonical_then_local_order",
            "revoke_transaction_missing_management_key",
        ),
        "list_credentials": (
            "list_credentials_exact_status_projection",
            "list_credentials_missing_management_key",
        ),
    }
    assert set(cases) == {
        route["operation"] for route in _json(CONTRACT_PATH)["routes"]
    }
    for success_name, error_name in cases.values():
        assert 200 <= observations[success_name]["response"]["status_code"] < 400
        assert observations[error_name]["response"]["status_code"] >= 400

    for name in (
        "put_registered_client_missing_management_key",
        "revoke_transaction_missing_management_key",
        "list_credentials_missing_management_key",
    ):
        assert observations[name]["response"]["status_code"] == 401
        assert observations[name]["response"]["body"] == {
            "detail": "X-API-Key header is missing"
        }
        assert observations[name]["repository_calls"] == []


def test_authentication_and_tenant_failures_precede_protected_reads() -> None:
    observations = _observations()

    assert observations["list_credentials_missing_management_key"] == {
        "name": "list_credentials_missing_management_key",
        "repository_calls": [],
        "response": {
            "status_code": 401,
            "headers": {
                "content-length": "40",
                "content-type": "application/json",
            },
            "body": {"detail": "X-API-Key header is missing"},
        },
    }
    assert observations["list_credentials_missing_tenant"]["repository_calls"] == []
    assert observations["list_credentials_missing_tenant"]["response"]["body"] == {
        "detail": "Trusted organization context is required"
    }
    assert (
        observations["list_credentials_rejects_foreign_tenant_before_read"][
            "repository_calls"
        ]
        == []
    )
    assert observations["revoke_transaction_hides_foreign_resource_after_lookup"][
        "repository_calls"
    ] == [{"method": "get_transaction", "tx_id": "tx-foreign"}]
    assert observations["revoke_transaction_hides_foreign_resource_after_lookup"][
        "response"
    ]["body"] == {"detail": "Resource not found"}


def test_par_capture_freezes_tenant_precedence_store_and_consume_semantics() -> None:
    contract = _json(CONTRACT_PATH)
    observations = _observations()
    success = observations["par_success_issuer_query_precedes_form"]

    assert success["response"] == {
        "status_code": 201,
        "headers": {
            "content-length": "104",
            "content-type": "application/json",
        },
        "body": {
            "expires_in": 90,
            "request_uri": "urn:ietf:params:oauth:request_uri:<uuid>",
        },
    }
    saved = success["repository_calls"]
    assert len(saved) == 1
    assert saved[0]["method"] == "save_pushed_authorization_request"
    assert saved[0]["ttl_seconds"] == contract["par"]["ttl_seconds"] == 90
    assert saved[0]["params"]["organization_id"] == "org-a"
    assert set(saved[0]["params"]) == set(contract["par"]["encoded_shape_in_order"])

    authorized = observations["authorize_consumes_par_and_preserves_registered_query"]
    assert [call["method"] for call in authorized["repository_calls"]] == [
        "consume_pushed_authorization_request",
        "get_oid4vci_client",
        "save_authorization_session",
    ]
    assert authorized["persistent_authorization_sessions"] == 1
    assert authorized["response"]["status_code"] == 307
    assert authorized["response"]["headers"]["location"] == (
        "https://wallet.example/callback?channel=one&code=<authorization-code>"
        "&iss=https%3A%2F%2Fissuer.example%2Forg%2Forg-a&state=state-a"
    )

    replay = observations["authorize_rejects_replayed_par"]
    assert replay["persistent_authorization_sessions"] == 1
    assert (
        replay["response"]["body"]
        == contract["par"]["storage"]["expired_or_replayed"]["body"]
    )
    assert (
        observations["par_rejects_oversized_encoded_payload_before_store"][
            "repository_calls"
        ]
        == []
    )
    assert (
        observations["par_failed_store_is_sanitized"]["response"]["body"]
        == (contract["par"]["storage"]["unavailable"]["body"])
    )


def test_authorization_redirects_preserve_query_state_errors_and_persistence_order() -> (
    None
):
    contract = _json(CONTRACT_PATH)
    observations = _observations()
    json_success = observations["authorize_json_success_persists_session"]
    assert json_success["response"]["status_code"] == 200
    assert json_success["response"]["body"] == {
        "code": "<authorization-code>",
        "state": "state-json",
    }
    assert json_success["persistent_authorization_sessions"] == 1
    assert [call["method"] for call in json_success["repository_calls"]] == [
        "get_oid4vci_client",
        "save_authorization_session",
    ]
    saved_session = json_success["repository_calls"][-1]
    assert contract["authorization"]["native_engine_lifetime_seconds"] == 600
    assert contract["authorization"]["persisted_session_lifetime"] == {
        "environment_variable": "ISSUANCE_AUTH_SESSION_TTL_MINUTES",
        "unit": "minutes",
        "default_minutes": 60,
        "default_seconds": 3600,
        "configuration_read_timing": "process-import",
        "legacy_composition": (
            "The route asks the native engine for a 600-second session, then creates "
            "and persists a Python AuthorizationSession without copying the engine "
            "expiry. The entity therefore owns the effective configured lifetime."
        ),
    }
    assert saved_session["persisted_lifetime_seconds"] == 3600

    error = observations["authorize_native_error_redirect_preserves_query_and_state"]
    assert error["response"] == {
        "status_code": 307,
        "headers": {
            "content-length": "0",
            "location": (
                "https://wallet.example/callback?channel=one&error=invalid_request"
                "&error_description=response_type+must+be+code&state=state-a"
            ),
        },
        "body": None,
    }
    assert [call["method"] for call in error["repository_calls"]] == [
        "get_oid4vci_client"
    ]
    assert observations["authorize_sanitizes_par_store_failure"]["response"] == {
        "status_code": 503,
        "headers": {
            "content-length": "102",
            "content-type": "application/json",
        },
        "body": {
            "error": "temporarily_unavailable",
            "error_description": "Authorization request storage is unavailable",
        },
    }
    unregistered_redirect = observations[
        "authorize_rejects_unregistered_client_redirect"
    ]
    assert unregistered_redirect["response"]["status_code"] == 400
    assert unregistered_redirect["response"]["body"] == {
        "error": "invalid_request",
        "error_description": "redirect_uri is not registered for this client",
    }


def test_management_projection_and_client_persistence_are_not_silently_reduced() -> (
    None
):
    contract = _json(CONTRACT_PATH)
    observations = _observations()
    listing = observations["list_credentials_exact_status_projection"]

    assert set(listing["response"]["body"][0]) == set(
        contract["credential_listing"]["projection_fields"]
    )
    assert listing["response"]["body"][0]["status"] == "active"
    assert (
        observations["list_credentials_status_is_case_sensitive"]["response"]["body"]
        == []
    )
    failure = observations["list_credentials_repository_failure"]["response"]
    assert failure == {
        "status_code": 500,
        "headers": {
            "content-length": "21",
            "content-type": "text/plain; charset=utf-8",
        },
        "body": "Internal Server Error",
    }

    registration = observations["put_registered_client_uses_body_tenant"]
    assert [call["method"] for call in registration["repository_calls"]] == [
        "save_oid4vci_client",
        "get_oid4vci_client",
    ]
    assert set(registration["response"]["body"]) == set(
        contract["registered_client"]["response_fields"]
    )
    assert registration["response"]["body"]["token_endpoint_auth_method"] == (
        "private_key_jwt"
    )
    assert observations["put_registered_client_requires_read_after_write"]["response"][
        "body"
    ] == {"detail": "Registered client was not persisted"}


def test_deferred_and_notification_security_gaps_are_captured_not_normalized_away() -> (
    None
):
    observations = _observations()
    assert observations["deferred_requires_transaction_id"]["response"]["body"] == {
        "error": "invalid_request",
        "error_description": "transaction_id is required",
    }
    assert observations["deferred_rejects_unknown_transaction"]["response"]["body"] == {
        "error": "invalid_transaction_id",
        "error_description": "No transaction found for the given ID",
    }
    deferred = observations[
        "deferred_empty_bearer_currently_reaches_pending_transaction"
    ]
    assert deferred["response"] == {
        "status_code": 202,
        "headers": {
            "content-length": "25",
            "content-type": "application/json",
            "retry-after": "5",
        },
        "body": {"transaction_id": "tx-a"},
    }
    leaked = observations["deferred_unbound_bearer_currently_reads_issued_credential"]
    assert leaked["response"]["status_code"] == 200
    assert leaked["response"]["body"] == {"credential": "credential.jwt.value"}
    assert [call["method"] for call in leaked["repository_calls"]] == [
        "get_transaction",
        "get_credential_by_transaction_id",
    ]
    assert observations["deferred_issued_without_credential_is_terminal_error"][
        "response"
    ]["body"] == {
        "error": "invalid_transaction_id",
        "error_description": "Transaction is in issued state",
    }
    assert observations["deferred_reports_terminal_state"]["response"]["body"] == {
        "error": "invalid_transaction_id",
        "error_description": "Transaction is in failed state",
    }
    assert observations["deferred_malformed_json_is_unhandled"]["response"] == {
        "status_code": 500,
        "headers": {
            "content-length": "21",
            "content-type": "text/plain; charset=utf-8",
        },
        "body": "Internal Server Error",
    }

    missing = observations["notification_missing_bearer_has_nested_error"]
    assert missing["response"]["body"] == {
        "detail": {
            "error": "invalid_token",
            "error_description": "Bearer token required",
        }
    }
    acknowledged = observations[
        "notification_empty_bearer_and_unread_body_currently_acknowledged"
    ]
    assert acknowledged["response"]["status_code"] == 204
    assert acknowledged["response"]["body"] is None
    valid_shape = observations["notification_valid_shape_has_no_legacy_effect"]
    assert valid_shape["response"]["status_code"] == 204
    assert valid_shape["repository_calls"] == []


def test_transaction_revocation_freezes_all_side_effects_and_failure_atomicity() -> (
    None
):
    observations = _observations()
    success = observations["revoke_transaction_canonical_then_local_order"]
    assert [effect["method"] for effect in success["operation_trace"]] == [
        "get_transaction",
        "get_credential_by_transaction_id",
        "delegate_revocation_profile",
        "save_credential",
        "sync_canvas_lifecycle_delivery_records",
        "save_transaction",
    ]
    assert success["response"]["body"] == {
        "id": "tx-revoke",
        "status": "revoked",
        "revoked_at": "<timestamp>",
        "revocation_reason": "holder request",
    }

    failure = observations["revoke_transaction_fails_closed_before_local_mutation"]
    assert failure["response"]["body"] == {
        "detail": "Revocation service rejected the status change"
    }
    assert failure["stored"] == {
        "transaction_status": "issued",
        "credential_status": "active",
    }
    assert not any(
        call["method"] in {"save_credential", "save_transaction"}
        for call in failure["repository_calls"]
    )
    assert observations["revoke_transaction_missing_transaction"]["response"][
        "body"
    ] == {"detail": "Transaction not found"}
    mismatch = observations["revoke_transaction_rejects_credential_tenant_mismatch"]
    assert mismatch["response"]["status_code"] == 409
    assert mismatch["response"]["body"] == {
        "detail": "Issued credential organization does not match its transaction"
    }
    assert [call["method"] for call in mismatch["repository_calls"]] == [
        "get_transaction",
        "get_credential_by_transaction_id",
    ]


def test_every_intentional_correction_preserves_a_valid_capability() -> None:
    contract = _json(CONTRACT_PATH)
    corrections = {
        correction["id"]: correction
        for correction in contract["intentional_native_corrections"]
    }
    assert set(corrections) == {
        "OID4VCI-AUTH-002:validate-and-bind-bearer",
        "OID4VCI-NOTIFY-001:validate-notification-request",
        "OID4VCI-MGMT-001:registered-client-tenant-binding",
        "OID4VCI-ERROR-001:structured-sanitized-internal-errors",
        "SECURITY-ACCESS-TOKEN-001:exact-1800-second-expiry",
        "OID4VCI-REDIRECT-002:http-or-https-only-localhost",
    }
    for correction in corrections.values():
        assert correction["legacy"]
        assert correction["native"]
        assert correction["preserved_capability"]
        assert correction["required_errors"]

    bearer_error = corrections["OID4VCI-AUTH-002:validate-and-bind-bearer"][
        "required_errors"
    ]["missing_invalid_or_unbound_token"]
    assert bearer_error == {
        "status_code": 401,
        "headers": {"WWW-Authenticate": "Bearer"},
        "body": {
            "error": "invalid_token",
            "error_description": "Client authentication failed",
        },
    }

    expiry_error = corrections["SECURITY-ACCESS-TOKEN-001:exact-1800-second-expiry"][
        "required_errors"
    ]["expired_token"]
    assert expiry_error == bearer_error

    redirect_error = corrections["OID4VCI-REDIRECT-002:http-or-https-only-localhost"][
        "required_errors"
    ]["unsafe_redirect_uri"]
    assert redirect_error == {
        "status_code": 400,
        "body": {
            "error": "invalid_request",
            "error_description": "redirect_uri must use HTTPS",
        },
    }
    notification = contract["notification"]["native_correction"]
    assert notification["specification"] == {
        "name": "OpenID for Verifiable Credential Issuance 1.0 Final",
        "published": "2025-09-16",
        "section": "11 Notification Endpoint",
        "url": (
            "https://openid.net/specs/"
            "openid-4-verifiable-credential-issuance-1_0-final.html"
            "#name-notification-endpoint"
        ),
    }
    assert notification["fields"][1]["values"] == [
        "credential_accepted",
        "credential_failure",
        "credential_deleted",
    ]
    assert notification["persistence"] == {
        "notification_binding_committed_with_credential_response": True,
        "events_are_durable_and_auditable": True,
        "identical_retries_are_idempotent": True,
        "multiple_distinct_supported_events_per_notification_id": True,
    }


def test_capture_script_is_replayable_but_not_a_runtime_dependency() -> None:
    script = (
        ROOT / "scripts" / "capture_oid4vci_authorization_reference.py"
    ).read_text(encoding="utf-8")
    assert 'SOURCE_COMMIT = "aaa6a9b8e31e62cd0ab087eef5fc1f4835048e26"' in script
    assert 'SOURCE_TREE = "819b7458a31c75d28043a4660643b029c5ec4567"' in script
    assert "ASGITransport(app=app, raise_app_exceptions=False)" in script
    assert "--verify" in script
    assert (
        "unchanged route composition executed through FastAPI ASGI transport" in script
    )
    assert "repo.calls[:2]" not in script
    assert "lifecycle_calls" not in script
    assert "capture_oid4vci_authorization_reference" not in (
        ROOT / "rust" / "services" / "issuance" / "Cargo.toml"
    ).read_text(encoding="utf-8")
