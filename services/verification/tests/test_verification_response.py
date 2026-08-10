from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from services.verification import main as verification

# Protocol-allowed top-level keys (verification-session.json schema)
PROTOCOL_KEYS = {
    "id",
    "flow_id",
    "flow_instance_id",
    "presentation_policy_id",
    "deployment_profile_id",
    "verifier_nonce",
    "holder_id",
    "status",
    "result",
    "expires_at",
    "created_at",
    "completed_at",
    "updated_at",
    "error",
}

# Operational keys allowed only on the start response
START_EXTRA_KEYS = {"request_uri", "qr_code_data"}


def _build_client(store: verification.SessionStore) -> TestClient:
    app = FastAPI()
    app.include_router(verification.router)
    verification._store = store
    return TestClient(app)


def test_get_session_returns_protocol_shape_only() -> None:
    store = verification.SessionStore()
    session = verification.VerificationSession(
        organization_id="org-1",
        presentation_policy_id="policy-1",
        deployment_profile_id="deploy-1",
        external_reference="case-123",
        purpose="Age verification",
    )
    store.save(session)
    client = _build_client(store)

    response = client.get(f"/v1/verify/{session.session_id}")

    assert response.status_code == 200
    body = response.json()

    # Only protocol keys (None values omitted)
    assert set(body.keys()) <= PROTOCOL_KEYS, f"Extra keys: {set(body.keys()) - PROTOCOL_KEYS}"

    # Required protocol fields present
    assert body["id"] == session.session_id
    assert body["flow_id"] == session.flow_id
    assert body["presentation_policy_id"] == "policy-1"
    assert body["deployment_profile_id"] == "deploy-1"
    assert body["verifier_nonce"] == session.nonce
    assert body["status"] == "PENDING"

    # Legacy fields must NOT appear
    for legacy_key in (
        "session_id", "organization_id", "response_type", "request_uri",
        "qr_code_data", "nonce", "external_reference", "purpose",
        "result_code", "decision", "decision_reason", "verified_claims",
        "credential_results", "inspection_performed", "inspection_result",
        "runtime_status",
    ):
        assert legacy_key not in body, f"Legacy key {legacy_key!r} must not appear"


def test_start_session_includes_operational_fields() -> None:
    store = verification.SessionStore()
    client = _build_client(store)

    response = client.post(
        "/v1/verify",
        json={
            "organization_id": "org-1",
            "presentation_policy_id": "policy-1",
        },
    )

    assert response.status_code == 200
    body = response.json()

    # Start response allows protocol keys + operational keys
    allowed = PROTOCOL_KEYS | START_EXTRA_KEYS
    assert set(body.keys()) <= allowed, f"Extra keys: {set(body.keys()) - allowed}"

    # Operational fields present
    assert "request_uri" in body
    assert "qr_code_data" in body
    assert body["request_uri"].endswith("/request")


def test_start_session_rejects_standalone_callback_destinations() -> None:
    store = verification.SessionStore()
    client = _build_client(store)

    response = client.post(
        "/v1/verify",
        json={
            "organization_id": "org-1",
            "presentation_policy_id": "policy-1",
            "callback_url": "https://attacker.example/collect",
        },
    )

    assert response.status_code == 400
    assert "Flow service transactional callback outbox" in response.json()["detail"]
    assert store._fallback == {}


def test_submit_presentation_returns_protocol_result() -> None:
    store = verification.SessionStore()
    session = verification.VerificationSession(
        organization_id="org-1",
        presentation_policy_id="policy-1",
    )
    store.save(session)
    client = _build_client(store)

    async def _fake_evaluate_via_grpc(*, policy_id: str, vp_token: str, nonce: str | None, context_json: str = "{}"):
        return {
            "result": "passed",
            "decision": "allow",
            "decision_reason": "All checks passed",
            "verified_claims": {"given_name": "Marty", "age_over_18": True},
            "credential_results": [
                {
                    "claims_missing": ["family_name"],
                    "revocation_checked": True,
                }
            ],
            "holder_binding_evidence": {
                "required": True,
                "validated": True,
                "binding_method": "SESSION_BINDING",
                "proof_profile": "OID4VP_VERIFIABLE_PRESENTATION",
                "challenge_validated": True,
                "audience_validated": True,
                "replay_checked": True,
            },
        }

    verification._evaluate_via_grpc = _fake_evaluate_via_grpc

    response = client.post(
        f"/v1/verify/{session.session_id}/submit",
        json={"vp_token": "vp.jwt.token"},
    )

    assert response.status_code == 200
    body = response.json()

    # Protocol shape only
    assert set(body.keys()) <= PROTOCOL_KEYS, f"Extra keys: {set(body.keys()) - PROTOCOL_KEYS}"

    assert body["status"] == "PASSED"
    assert body["result"] == {
        "passed": True,
        "claims_satisfied": ["age_over_18", "given_name"],
        "claims_missing": ["family_name"],
        "trust_validated": True,
        "revocation_checked": True,
        "holder_binding_evidence": {
            "required": True,
            "validated": True,
            "binding_method": "SESSION_BINDING",
            "proof_profile": "OID4VP_VERIFIABLE_PRESENTATION",
            "challenge_validated": True,
            "audience_validated": True,
            "replay_checked": True,
        },
    }
    assert body["completed_at"] is not None
    assert body["updated_at"] == body["completed_at"]
    stored = store._fallback[session.session_id]
    assert stored.vp_token_sha256 == hashlib.sha256(b"vp.jwt.token").hexdigest()
    assert not hasattr(stored, "vp_token")
    assert stored.verified_claims == {"age_over_18": True, "given_name": True}
    assert "Marty" not in json.dumps(verification._session_to_redis_dict(stored))


def test_terminal_session_projection_excludes_raw_identity_material() -> None:
    session = verification.VerificationSession(
        organization_id="org-1",
        presentation_policy_id="policy-1",
    )
    session.status = verification.SessionStatus.COMPLETED
    session.result = "passed"
    session.decision = "allow"
    session.completed_at = datetime.now(timezone.utc)
    session.vp_token_sha256 = verification._sha256_text("raw-vp-token")
    session.verified_claims = {
        "email": "alice@example.com",
        "given_name": "Alice",
    }
    session.credential_results = [
        {
            "credential_template_id": "template-1",
            "satisfied": True,
            "revocation_checked": True,
            "claim_results": [
                {
                    "claim_name": "email",
                    "satisfied": True,
                    "presented_value": "alice@example.com",
                }
            ],
        }
    ]
    session.inspection_performed = True
    raw_inspection_result = json.dumps(
        {"document_number": "SECRET-123", "result": "verified"}
    )
    session.inspection_result = raw_inspection_result

    stored = verification._session_to_redis_dict(session)
    encoded = json.dumps(stored)

    assert "vp_token" not in stored
    assert stored["vp_token_sha256"] == hashlib.sha256(b"raw-vp-token").hexdigest()
    assert stored["verified_claims"] == {"email": True, "given_name": True}
    assert stored["inspection_result"] == "verified"
    assert stored["inspection_result_sha256"] == verification._sha256_text(
        raw_inspection_result
    )
    assert "alice@example.com" not in encoded
    assert "SECRET-123" not in encoded
    assert "presented_value" not in encoded


def test_legacy_terminal_session_is_redacted_when_deserialized() -> None:
    session = verification.VerificationSession(
        organization_id="org-1",
        presentation_policy_id="policy-1",
    )
    session.status = verification.SessionStatus.COMPLETED
    session.completed_at = datetime.now(timezone.utc)
    stored = verification._session_to_redis_dict(session)
    stored["vp_token"] = "legacy-raw-token"
    stored.pop("vp_token_sha256", None)
    stored["verified_claims"] = {"email": "legacy@example.com"}

    loaded = verification._session_from_dict(stored)

    assert loaded.vp_token_sha256 == hashlib.sha256(b"legacy-raw-token").hexdigest()
    assert loaded.verified_claims == {"email": True}
    assert not hasattr(loaded, "vp_token")


@pytest.mark.asyncio
async def test_legacy_redis_record_is_rewritten_without_raw_material() -> None:
    class FakeRedis:
        def __init__(self) -> None:
            self.values: dict[str, str] = {}

        async def get(self, key: str) -> str | None:
            return self.values.get(key)

        async def set(self, key: str, value: str, **_kwargs) -> None:
            self.values[key] = value

        async def sadd(self, *_args) -> None:
            return None

        async def expire(self, *_args) -> None:
            return None

    session = verification.VerificationSession(
        organization_id="org-1",
        presentation_policy_id="policy-1",
    )
    stored = verification._session_to_redis_dict(session)
    stored.update(
        {
            "status": "completed",
            "result": "passed",
            "decision": "allow",
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "vp_token": "legacy-raw-token",
            "verified_claims": {"email": "legacy@example.com"},
        }
    )
    stored.pop("vp_token_sha256", None)
    redis = FakeRedis()
    key = f"{verification.SESSION_PREFIX}{session.session_id}"
    redis.values[key] = json.dumps(stored)
    store = verification.SessionStore(redis_client=redis)

    loaded = await store.get(session.session_id)
    rewritten = json.loads(redis.values[key])

    assert loaded is not None
    assert "vp_token" not in rewritten
    assert rewritten["vp_token_sha256"] == hashlib.sha256(
        b"legacy-raw-token"
    ).hexdigest()
    assert rewritten["verified_claims"] == {"email": True}
    assert "legacy@example.com" not in json.dumps(rewritten)


def test_expired_session_exposes_protocol_error_field() -> None:
    store = verification.SessionStore()
    session = verification.VerificationSession(
        organization_id="org-1",
        presentation_policy_id="policy-1",
        expiry_minutes=1,
    )
    session.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    store.save(session)
    client = _build_client(store)

    response = client.get(f"/v1/verify/{session.session_id}")

    assert response.status_code == 200
    body = response.json()
    assert set(body.keys()) <= PROTOCOL_KEYS
    assert body["status"] == "EXPIRED"
    assert body["error"] == "Session expired before presentation was submitted"


def test_get_request_object_returns_dcql_only() -> None:
    store = verification.SessionStore()
    session = verification.VerificationSession(
        organization_id="org-1",
        presentation_policy_id="policy-1",
    )
    store.save(session)
    client = _build_client(store)

    original_builder = verification._build_presentation_definition

    async def _fake_build_presentation_definition(_session: verification.VerificationSession) -> dict:
        return {
            "id": "pd-1",
            "input_descriptors": [
                {
                    "id": "req-member-credential",
                    "format": {"dc+sd-jwt": {"sd-jwt_alg_values": ["ES256"]}},
                    "constraints": {
                        "fields": [
                            {
                                "path": ["$.vct"],
                                "filter": {
                                    "type": "string",
                                    "const": "https://example.test/credentials/member",
                                },
                            },
                            {
                                "path": [
                                    "$.vc.credentialSubject.email",
                                    "$.credentialSubject.email",
                                    "$.email",
                                ],
                            },
                        ]
                    },
                }
            ],
        }

    verification._build_presentation_definition = _fake_build_presentation_definition
    try:
        response = client.get(f"/v1/verify/{session.session_id}/request")
    finally:
        verification._build_presentation_definition = original_builder

    assert response.status_code == 200
    body = response.json()
    assert "presentation_definition" not in body
    assert body["dcql_query"] == {
        "credentials": [
            {
                "id": "req-member-credential",
                "format": "dc+sd-jwt",
                "meta": {"vct_values": ["https://example.test/credentials/member"]},
                "claims": [{"id": "claim_email", "path": ["email"]}],
            }
        ]
    }
