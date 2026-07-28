"""Narrow VC-API adapter used only by the pinned W3C VCDM v2 test suite.

This router intentionally has no production registration.  A disposable
interop stack may enable it with ``W3C_VC_TEST_ADAPTER=1`` and must provide
separate active credential and presentation policies. Requests are forwarded to Marty’s
normal presentation-policy evaluator; this module does not validate a
credential itself or turn a failed verification into a success.
"""

from __future__ import annotations

import json
import os
from typing import Any
from urllib.parse import unquote_to_bytes

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from gateway.models import IssuanceCreate
from gateway.proxy import get_http_client, get_registry, proxy_request
from gateway.routes.issuance import create_issuance
from pydantic import BaseModel, Field, ValidationError

router = APIRouter(prefix="/__test__/vc-api", tags=["test-only-w3c-vc-api"])


class VerifyCredentialRequest(BaseModel):
    verifiableCredential: str | dict[str, Any]
    options: dict[str, Any] = Field(default_factory=dict)


class VerifyPresentationRequest(BaseModel):
    verifiablePresentation: str | dict[str, Any]
    options: dict[str, Any] = Field(default_factory=dict)


class IssueCredentialRequest(BaseModel):
    credential: dict[str, Any]
    options: dict[str, Any] = Field(default_factory=dict)


def _enabled_policy_id(*, presentation: bool) -> str:
    if os.environ.get("W3C_VC_TEST_ADAPTER") != "1":
        raise HTTPException(status_code=404, detail="W3C VC test adapter is disabled")
    variable = (
        "W3C_VC_TEST_PRESENTATION_POLICY_ID"
        if presentation
        else "W3C_VC_TEST_CREDENTIAL_POLICY_ID"
    )
    policy_id = os.environ.get(variable, "").strip()
    if not policy_id:
        raise HTTPException(
            status_code=503, detail=f"W3C VC test adapter requires {variable}"
        )
    return policy_id


def _issuance_fixture_configuration() -> tuple[str, str, str]:
    """Return the disposable organization, template, and public issuer DID."""
    _enabled_policy_id(presentation=False)
    organization_id = os.environ.get("W3C_VC_TEST_ORGANIZATION_ID", "").strip()
    template_id = os.environ.get("W3C_VC_TEST_TEMPLATE_ID", "").strip()
    issuer_did = os.environ.get("W3C_VC_TEST_ISSUER_DID", "").strip()
    if not organization_id or not template_id or not issuer_did:
        raise HTTPException(
            status_code=503,
            detail=(
                "W3C VC issuer adapter requires W3C_VC_TEST_ORGANIZATION_ID "
                "W3C_VC_TEST_TEMPLATE_ID, and W3C_VC_TEST_ISSUER_DID"
            ),
        )
    return organization_id, template_id, issuer_did


def _create_oid4vci_proof(issuer_url: str, nonce: str) -> str:
    """Generate a real, one-off holder proof using the released Rust binding."""
    try:
        from marty_rs import _marty_rs as binding
    except Exception as exc:  # pragma: no cover - release image invariant
        raise HTTPException(
            status_code=503, detail="Marty OID4VCI proof binding is unavailable"
        ) from exc
    try:
        return str(binding.oid4vci_create_proof_jwt(issuer_url, nonce))
    except Exception as exc:
        raise HTTPException(
            status_code=503, detail="could not generate OID4VCI holder proof"
        ) from exc


def _token_or_unsupported(
    value: str | dict[str, Any], field: str
) -> str | dict[str, Any]:
    if isinstance(value, str) and value.strip():
        return value
    if isinstance(value, dict):
        proof = value.get("proof")
        proofs = proof if isinstance(proof, list) else [proof]
        if any(
            isinstance(item, dict) and item.get("type") == "DataIntegrityProof"
            for item in proofs
        ):
            # Keep the document structured. The ordinary presentation-policy
            # service sends it to the released Rust verifier and fails closed.
            return value
        return _extract_jose_envelope(value, field)
    raise HTTPException(
        status_code=422,
        detail={
            "error": "unsupported_serialization",
            "error_description": (
                f"{field} must use a supported JWT, SD-JWT, mdoc, "
                "or VCDM Data Integrity serialization"
            ),
        },
    )


def _extract_jose_envelope(value: dict[str, Any], field: str) -> str:
    """Extract a JWT from the VCDM v2 JOSE envelope representation.

    This is deliberately a representation adapter only.  The extracted token
    is still sent to the ordinary Marty evaluator; the adapter neither trusts
    nor verifies the JWS itself.  JSON-LD Data Integrity objects remain
    explicitly unsupported.
    """
    context = value.get("@context")
    contexts = context if isinstance(context, list) else [context]
    types = value.get("type")
    identifier = value.get("id")
    expected_type = (
        "EnvelopedVerifiableCredential"
        if field == "verifiableCredential"
        else "EnvelopedVerifiablePresentation"
    )
    if (
        not contexts
        or contexts[0] != "https://www.w3.org/ns/credentials/v2"
        or not isinstance(types, (list, str))
        or expected_type not in (types if isinstance(types, list) else [types])
        or not isinstance(identifier, str)
    ):
        raise HTTPException(
            status_code=422, detail={"error": "unsupported_serialization"}
        )

    prefix = "data:application/"
    if not identifier.startswith(prefix) or "," not in identifier:
        raise HTTPException(status_code=422, detail={"error": "invalid_envelope"})
    media_type, encoded_token = identifier[5:].split(",", 1)
    allowed_media_types = (
        {"application/vc+jwt", "application/jwt"}
        if field == "verifiableCredential"
        else {"application/vp+jwt", "application/jwt"}
    )
    try:
        normalized_media_type = unquote_to_bytes(media_type).decode("ascii").lower()
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=422, detail={"error": "invalid_envelope"}
        ) from None
    if normalized_media_type not in allowed_media_types:
        raise HTTPException(
            status_code=422, detail={"error": "unsupported_serialization"}
        )
    try:
        token = unquote_to_bytes(encoded_token).decode("ascii")
    except (UnicodeDecodeError, ValueError):
        raise HTTPException(
            status_code=422, detail={"error": "invalid_envelope"}
        ) from None
    if token.count(".") != 2 or not all(token.split(".")):
        raise HTTPException(status_code=422, detail={"error": "invalid_envelope"})
    return token


async def _evaluate(
    token: str | dict[str, Any],
    options: dict[str, Any],
    request: Request,
    *,
    presentation: bool,
) -> Response:
    policy_id = _enabled_policy_id(presentation=presentation)
    registry = get_registry()
    service_url = registry.get_service_url("presentation-policies")
    if not service_url:
        raise HTTPException(
            status_code=503, detail="Presentation policy service unavailable"
        )
    response = await proxy_request(
        request,
        service_url,
        f"/v1/presentation-policies/{policy_id}/evaluate",
        body_override=json.dumps(
            {
                "vp_token": token,
                "nonce": options.get("challenge"),
                "audience": options.get("domain"),
            }
        ).encode("utf-8"),
        inject_headers={"Content-Type": "application/json"},
    )
    if response.status_code >= 400:
        return response
    try:
        evaluation = json.loads(bytes(response.body))
    except (AttributeError, TypeError, ValueError, json.JSONDecodeError):
        raise HTTPException(
            status_code=502, detail="Presentation policy returned an invalid response"
        ) from None
    if not isinstance(evaluation, dict):
        raise HTTPException(
            status_code=502, detail="Presentation policy returned an invalid response"
        )
    if evaluation.get("decision") != "allow" or evaluation.get("result") != "passed":
        return JSONResponse(
            status_code=422,
            content={"verified": False, "errors": ["verification_failed"]},
        )
    return JSONResponse(
        {
            "verified": True,
            "results": evaluation,
            "problemDetails": [],
        }
    )


async def _issue_data_integrity_credential(
    credential: dict[str, Any],
    request: Request,
) -> dict[str, Any]:
    """Issue through Marty's ordinary OID4VCI service path.

    The W3C endpoint is only a shape adapter.  It still resolves the template
    issuer identity, creates a pre-authorized transaction, redeems a token,
    obtains a fresh nonce, and submits a cryptographically valid holder proof.
    """
    organization_id, template_id, issuer_did = _issuance_fixture_configuration()
    try:
        body = IssuanceCreate(
            organization_id=organization_id,
            credential_template_id=template_id,
            issuer_did=issuer_did,
            credential_document=json.loads(json.dumps(credential)),
        )
    except ValidationError as exc:
        # This model is constructed inside the VC-API shape adapter, after
        # FastAPI has validated the outer request. Translate production
        # issuance validation failures into the same controlled 422 boundary
        # a direct /v1/issuance request would expose, without logging the
        # submitted credential or leaking an internal traceback.
        raise HTTPException(
            status_code=422,
            detail={
                "error": "invalid_credential",
                "validation_errors": exc.errors(
                    include_url=False,
                    include_context=False,
                    include_input=False,
                ),
            },
        ) from None
    initiated = await create_issuance(body, request)
    if initiated.status_code >= 400:
        raise HTTPException(
            status_code=initiated.status_code,
            detail=bytes(initiated.body)[:300].decode("utf-8", errors="replace"),
        )
    try:
        transaction = json.loads(bytes(initiated.body))
    except (AttributeError, TypeError, ValueError, json.JSONDecodeError):
        raise HTTPException(
            status_code=502,
            detail="Marty general issuance API returned an invalid response",
        ) from None
    pre_auth_code = transaction.get("pre_auth_code")
    if not isinstance(pre_auth_code, str) or not pre_auth_code:
        raise HTTPException(
            status_code=502,
            detail="Marty issuance did not return a pre-authorized code",
        )

    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    if not service_url:
        raise HTTPException(status_code=503, detail="Issuance service unavailable")
    client = get_http_client()

    token_response = await client.post(
        f"{service_url}/v1/issuance/token",
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            "pre-authorized_code": pre_auth_code,
        },
        timeout=30.0,
    )
    if token_response.status_code >= 400:
        raise HTTPException(
            status_code=token_response.status_code, detail=token_response.text[:300]
        )
    access_token = token_response.json().get("access_token")
    if not isinstance(access_token, str) or not access_token:
        raise HTTPException(
            status_code=502, detail="Marty issuance did not return an access token"
        )

    nonce_response = await client.post(
        f"{service_url}/v1/issuance/nonce", json={}, timeout=30.0
    )
    if nonce_response.status_code >= 400:
        raise HTTPException(
            status_code=nonce_response.status_code, detail=nonce_response.text[:300]
        )
    nonce = nonce_response.json().get("c_nonce")
    if not isinstance(nonce, str) or not nonce:
        raise HTTPException(
            status_code=502, detail="Marty issuance did not return a proof nonce"
        )
    issuer_base_url = os.environ.get("ISSUER_BASE_URL", "http://gateway:8000").rstrip(
        "/"
    )
    proof = _create_oid4vci_proof(f"{issuer_base_url}/org/{organization_id}", nonce)

    issued = await client.post(
        f"{service_url}/v1/issuance/credential",
        headers={"Authorization": f"Bearer {access_token}"},
        json={"format": "ldp_vc", "proofs": {"jwt": [proof]}},
        timeout=30.0,
    )
    if issued.status_code >= 400:
        raise HTTPException(status_code=issued.status_code, detail=issued.text[:300])
    response = issued.json()
    credentials = response.get("credentials") if isinstance(response, dict) else None
    result = (
        credentials[0]
        if isinstance(credentials, list) and len(credentials) == 1
        else None
    )
    document = result.get("credential") if isinstance(result, dict) else None
    document_issuer = document.get("issuer") if isinstance(document, dict) else None
    document_issuer_id = (
        document_issuer.get("id")
        if isinstance(document_issuer, dict)
        else document_issuer
    )
    if (
        not isinstance(result, dict)
        or result.get("format") != "ldp_vc"
        or not isinstance(document, dict)
        or document_issuer_id != issuer_did
        or not isinstance(document.get("proof"), dict)
        or document["proof"].get("type") != "DataIntegrityProof"
        or document["proof"].get("cryptosuite") != "eddsa-rdfc-2022"
    ):
        raise HTTPException(
            status_code=502,
            detail="Marty issuance did not return a native Data Integrity credential",
        )
    return document


@router.post("/credentials/verify")
async def verify_credential(
    body: VerifyCredentialRequest, request: Request
) -> Response:
    """VC-API-shaped entry point backed by the actual Marty verifier."""
    return await _evaluate(
        _token_or_unsupported(body.verifiableCredential, "verifiableCredential"),
        body.options,
        request,
        presentation=False,
    )


@router.post("/presentations/verify")
async def verify_presentation(
    body: VerifyPresentationRequest, request: Request
) -> Response:
    """VC-API-shaped VP entry point backed by the actual Marty verifier."""
    return await _evaluate(
        _token_or_unsupported(body.verifiablePresentation, "verifiablePresentation"),
        body.options,
        request,
        presentation=True,
    )


@router.post("/credentials/issue")
async def issue_credential(body: IssueCredentialRequest, request: Request) -> Response:
    """VC-API issuer boundary backed by a full Marty OID4VCI issuance flow."""
    credential = await _issue_data_integrity_credential(body.credential, request)
    return JSONResponse({"verifiableCredential": credential})
