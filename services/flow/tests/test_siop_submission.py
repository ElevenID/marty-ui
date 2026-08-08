from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from jwcrypto import jwk, jwt

from flow.main import (
    FlowInstance,
    FlowInstanceStatus,
    InMemoryFlowRepository,
    SiopSubmitRequest,
    submit_siop_id_token,
)


SIOP_SUBJECT_PREFIX = "urn:ietf:params:oauth:jwk-thumbprint"


def _key_for_algorithm(algorithm: str) -> jwk.JWK:
    if algorithm == "ES256":
        return jwk.JWK.generate(kty="EC", crv="P-256")
    if algorithm == "EdDSA":
        return jwk.JWK.generate(kty="OKP", crv="Ed25519")
    raise AssertionError(f"Unsupported test algorithm: {algorithm}")


def _signed_id_token(
    *,
    signing_key: jwk.JWK,
    algorithm: str,
    nonce: str,
    audience: str,
    claims_override: dict | None = None,
    subject_key: jwk.JWK | None = None,
) -> str:
    subject_key = subject_key or signing_key
    public_jwk = json.loads(subject_key.export_public())
    subject = f"{SIOP_SUBJECT_PREFIX}:sha-256:{subject_key.thumbprint()}"
    now = int(datetime.now(timezone.utc).timestamp())
    claims = {
        "iss": subject,
        "sub": subject,
        "aud": audience,
        "nonce": nonce,
        "iat": now,
        "exp": now + 300,
        "sub_jwk": public_jwk,
    }
    claims.update(claims_override or {})
    token = jwt.JWT(header={"alg": algorithm, "typ": "JWT"}, claims=claims)
    token.make_signed_token(signing_key)
    return token.serialize()


def _unsigned_id_token(*, nonce: str, audience: str) -> str:
    def _segment(value: dict) -> str:
        return (
            base64.urlsafe_b64encode(
                json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
            )
            .rstrip(b"=")
            .decode()
        )

    return (
        f"{_segment({'alg': 'none', 'typ': 'JWT'})}."
        f"{_segment({'aud': audience, 'nonce': nonce})}."
    )


async def _pending_siop_instance(
    repo: InMemoryFlowRepository,
    *,
    nonce: str = "siop-nonce",
    audience: str = "https://verifier.example/client",
) -> FlowInstance:
    instance = FlowInstance(
        flow_definition_id="__siop_v2__",
        organization_id="org-1",
        status=FlowInstanceStatus.AWAITING_WALLET,
        context={
            "flow_type": "siop_v2",
            "nonce": nonce,
            "siop_client_id": audience,
        },
        started_at=datetime.now(timezone.utc) - timedelta(seconds=5),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )
    await repo.save_instance(instance)
    return instance


@pytest.mark.asyncio
@pytest.mark.parametrize("algorithm", ["ES256", "EdDSA"])
async def test_siop_submission_verifies_supported_signatures(algorithm: str) -> None:
    repo = InMemoryFlowRepository()
    instance = await _pending_siop_instance(repo)
    key = _key_for_algorithm(algorithm)
    token = _signed_id_token(
        signing_key=key,
        algorithm=algorithm,
        nonce=instance.context["nonce"],
        audience=instance.context["siop_client_id"],
    )

    response = await submit_siop_id_token(
        SiopSubmitRequest(id_token=token, instance_id=instance.id),
        repo,
    )

    assert response["status"] == "verified"
    assert response["sub"] == instance.subject_id
    assert instance.status == FlowInstanceStatus.COMPLETED
    assert instance.result["signing_algorithm"] == algorithm
    assert instance.result["claims_trust"] == "self_attested"
    assert "id_token" not in instance.context
    assert token not in json.dumps(instance.result)


@pytest.mark.asyncio
async def test_identical_siop_retry_returns_immutable_result() -> None:
    repo = InMemoryFlowRepository()
    instance = await _pending_siop_instance(repo)
    key = _key_for_algorithm("ES256")
    token = _signed_id_token(
        signing_key=key,
        algorithm="ES256",
        nonce=instance.context["nonce"],
        audience=instance.context["siop_client_id"],
    )
    request = SiopSubmitRequest(id_token=token, instance_id=instance.id)

    first = await submit_siop_id_token(request, repo)
    second = await submit_siop_id_token(request, repo)

    assert second == first
    assert len(repo._consumed_nonce_digests) == 1


@pytest.mark.asyncio
async def test_conflicting_siop_retry_is_rejected() -> None:
    repo = InMemoryFlowRepository()
    instance = await _pending_siop_instance(repo)
    tokens = [
        _signed_id_token(
            signing_key=key,
            algorithm="ES256",
            nonce=instance.context["nonce"],
            audience=instance.context["siop_client_id"],
        )
        for key in (_key_for_algorithm("ES256"), _key_for_algorithm("ES256"))
    ]

    await submit_siop_id_token(
        SiopSubmitRequest(id_token=tokens[0], instance_id=instance.id),
        repo,
    )
    with pytest.raises(HTTPException) as conflict:
        await submit_siop_id_token(
            SiopSubmitRequest(id_token=tokens[1], instance_id=instance.id),
            repo,
        )

    assert conflict.value.status_code == 409
    assert conflict.value.detail["error"] == "verification_replay_conflict"
    assert len(repo._consumed_nonce_digests) == 1


@pytest.mark.asyncio
async def test_siop_submission_rejects_unsigned_token() -> None:
    repo = InMemoryFlowRepository()
    instance = await _pending_siop_instance(repo)

    with pytest.raises(HTTPException) as exc_info:
        await submit_siop_id_token(
            SiopSubmitRequest(
                id_token=_unsigned_id_token(
                    nonce=instance.context["nonce"],
                    audience=instance.context["siop_client_id"],
                ),
                instance_id=instance.id,
            ),
            repo,
        )

    assert exc_info.value.status_code == 400
    assert exc_info.value.detail["error"] == "invalid_id_token"
    assert instance.status == FlowInstanceStatus.AWAITING_WALLET


@pytest.mark.asyncio
async def test_invalid_signature_does_not_consume_siop_nonce() -> None:
    repo = InMemoryFlowRepository()
    instance = await _pending_siop_instance(repo)
    trusted_key = _key_for_algorithm("ES256")
    attacker_key = _key_for_algorithm("ES256")
    invalid_token = _signed_id_token(
        signing_key=attacker_key,
        subject_key=trusted_key,
        algorithm="ES256",
        nonce=instance.context["nonce"],
        audience=instance.context["siop_client_id"],
    )

    with pytest.raises(HTTPException) as exc_info:
        await submit_siop_id_token(
            SiopSubmitRequest(id_token=invalid_token, instance_id=instance.id),
            repo,
        )
    assert exc_info.value.detail["error"] == "invalid_id_token"

    valid_token = _signed_id_token(
        signing_key=trusted_key,
        algorithm="ES256",
        nonce=instance.context["nonce"],
        audience=instance.context["siop_client_id"],
    )
    response = await submit_siop_id_token(
        SiopSubmitRequest(id_token=valid_token, instance_id=instance.id),
        repo,
    )
    assert response["status"] == "verified"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("claims_override", "expected_description"),
    [
        ({"nonce": "wrong-nonce"}, "nonce"),
        ({"aud": "https://attacker.example/client"}, "audience"),
        ({"exp": 1}, "expired"),
        ({"iss": "did:example:other"}, "iss"),
    ],
)
async def test_siop_submission_rejects_invalid_transaction_claims(
    claims_override: dict,
    expected_description: str,
) -> None:
    repo = InMemoryFlowRepository()
    instance = await _pending_siop_instance(repo)
    key = _key_for_algorithm("ES256")
    token = _signed_id_token(
        signing_key=key,
        algorithm="ES256",
        nonce=instance.context["nonce"],
        audience=instance.context["siop_client_id"],
        claims_override=claims_override,
    )

    with pytest.raises(HTTPException) as exc_info:
        await submit_siop_id_token(
            SiopSubmitRequest(id_token=token, instance_id=instance.id),
            repo,
        )

    assert expected_description in exc_info.value.detail["error_description"].lower()
    assert instance.status == FlowInstanceStatus.AWAITING_WALLET


@pytest.mark.asyncio
async def test_siop_submission_requires_jwk_thumbprint_subject() -> None:
    repo = InMemoryFlowRepository()
    instance = await _pending_siop_instance(repo)
    key = _key_for_algorithm("EdDSA")
    token = _signed_id_token(
        signing_key=key,
        algorithm="EdDSA",
        nonce=instance.context["nonce"],
        audience=instance.context["siop_client_id"],
        claims_override={"iss": "did:key:holder", "sub": "did:key:holder"},
    )

    with pytest.raises(HTTPException) as exc_info:
        await submit_siop_id_token(
            SiopSubmitRequest(id_token=token, instance_id=instance.id),
            repo,
        )

    assert exc_info.value.detail["error"] == "subject_syntax_types_not_supported"
    assert instance.status == FlowInstanceStatus.AWAITING_WALLET


@pytest.mark.asyncio
async def test_siop_submission_requires_live_siop_instance() -> None:
    repo = InMemoryFlowRepository()
    key = _key_for_algorithm("ES256")
    token = _signed_id_token(
        signing_key=key,
        algorithm="ES256",
        nonce="orphan-nonce",
        audience="https://verifier.example/client",
    )

    with pytest.raises(HTTPException) as exc_info:
        await submit_siop_id_token(
            SiopSubmitRequest(id_token=token, instance_id="missing"),
            repo,
        )

    assert exc_info.value.detail["error"] == "invalid_request"
