"""Narrow VC-API adapter used only by the pinned W3C VCDM v2 test suite.

This router intentionally has no production registration.  A disposable
interop stack may enable it with ``W3C_VC_TEST_ADAPTER=1`` and must provide an
active, fixture-only presentation policy.  Requests are forwarded to Marty’s
normal presentation-policy evaluator; this module does not validate a
credential itself or turn a failed verification into a success.
"""

from __future__ import annotations

import os
import json
from typing import Any
from urllib.parse import unquote_to_bytes

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field

from gateway.proxy import get_registry, proxy_request


router = APIRouter(prefix="/__test__/vc-api", tags=["test-only-w3c-vc-api"])


class VerifyCredentialRequest(BaseModel):
    verifiableCredential: str | dict[str, Any]
    options: dict[str, Any] = Field(default_factory=dict)


class VerifyPresentationRequest(BaseModel):
    verifiablePresentation: str | dict[str, Any]
    options: dict[str, Any] = Field(default_factory=dict)


def _enabled_policy_id() -> str:
    if os.environ.get("W3C_VC_TEST_ADAPTER") != "1":
        raise HTTPException(status_code=404, detail="W3C VC test adapter is disabled")
    policy_id = os.environ.get("W3C_VC_TEST_POLICY_ID", "").strip()
    if not policy_id:
        raise HTTPException(status_code=503, detail="W3C VC test adapter requires W3C_VC_TEST_POLICY_ID")
    return policy_id


def _token_or_unsupported(value: str | dict[str, Any], field: str) -> str:
    if isinstance(value, str) and value.strip():
        return value
    if isinstance(value, dict):
        return _extract_jose_envelope(value, field)
    # The current Marty production verifier accepts JWT VC/VP, SD-JWT VC, and
    # mdoc encodings. It does not claim support for JSON-LD Data Integrity
    # proofs, including the W3C suite's eddsa-rdfc-2022 fixtures.
    raise HTTPException(
        status_code=422,
        detail={
            "error": "unsupported_serialization",
            "error_description": (
                f"{field} must use a Marty-supported JWT, SD-JWT, or mdoc serialization; "
                "JSON-LD Data Integrity proof verification is not implemented"
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
    types = value.get("type")
    identifier = value.get("id")
    expected_type = (
        "EnvelopedVerifiableCredential"
        if field == "verifiableCredential"
        else "EnvelopedVerifiablePresentation"
    )
    if (
        not isinstance(context, list)
        or not context
        or context[0] != "https://www.w3.org/ns/credentials/v2"
        or not isinstance(types, (list, str))
        or expected_type not in (types if isinstance(types, list) else [types])
        or not isinstance(identifier, str)
    ):
        raise HTTPException(status_code=422, detail={"error": "unsupported_serialization"})

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
        raise HTTPException(status_code=422, detail={"error": "invalid_envelope"}) from None
    if normalized_media_type not in allowed_media_types:
        raise HTTPException(status_code=422, detail={"error": "unsupported_serialization"})
    try:
        token = unquote_to_bytes(encoded_token).decode("ascii")
    except (UnicodeDecodeError, ValueError):
        raise HTTPException(status_code=422, detail={"error": "invalid_envelope"}) from None
    if token.count(".") != 2 or not all(token.split(".")):
        raise HTTPException(status_code=422, detail={"error": "invalid_envelope"})
    return token


async def _evaluate(token: str, options: dict[str, Any], request: Request) -> Response:
    policy_id = _enabled_policy_id()
    registry = get_registry()
    service_url = registry.get_service_url("presentation-policies")
    if not service_url:
        raise HTTPException(status_code=503, detail="Presentation policy service unavailable")
    return await proxy_request(
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


@router.post("/credentials/verify")
async def verify_credential(body: VerifyCredentialRequest, request: Request) -> Response:
    """VC-API-shaped entry point backed by the actual Marty verifier."""
    return await _evaluate(_token_or_unsupported(body.verifiableCredential, "verifiableCredential"), body.options, request)


@router.post("/presentations/verify")
async def verify_presentation(body: VerifyPresentationRequest, request: Request) -> Response:
    """VC-API-shaped VP entry point backed by the actual Marty verifier."""
    return await _evaluate(_token_or_unsupported(body.verifiablePresentation, "verifiablePresentation"), body.options, request)
