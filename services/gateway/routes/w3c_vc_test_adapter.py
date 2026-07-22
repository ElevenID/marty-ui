"""Narrow VC-API adapter used only by the pinned W3C VCDM v2 test suite.

This router intentionally has no production registration.  A disposable
interop stack may enable it with ``W3C_VC_TEST_ADAPTER=1`` and must provide
separate active credential and presentation policies. Requests are forwarded to Marty’s
normal presentation-policy evaluator; this module does not validate a
credential itself or turn a failed verification into a success.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
from datetime import datetime
from typing import Any
from urllib.parse import unquote_to_bytes

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

from gateway.models import IssuanceCreate
from gateway.proxy import get_http_client, get_registry, proxy_request
from gateway.routes.issuance import (
    _ISSUANCE_HEADERS,
    _load_credential_template,
    _resolve_issuer_identity,
    _select_issuer_profile_id,
)


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


def _issuance_fixture_configuration() -> tuple[str, str]:
    """Return the explicit disposable organization and JWT-VC template IDs."""
    _enabled_policy_id(presentation=False)
    organization_id = os.environ.get("W3C_VC_TEST_ORGANIZATION_ID", "").strip()
    template_id = os.environ.get("W3C_VC_TEST_TEMPLATE_ID", "").strip()
    if not organization_id or not template_id:
        raise HTTPException(
            status_code=503,
            detail=(
                "W3C VC issuer adapter requires W3C_VC_TEST_ORGANIZATION_ID "
                "and W3C_VC_TEST_TEMPLATE_ID"
            ),
        )
    return organization_id, template_id


def _claims_from_w3c_credential(
    credential: dict[str, Any],
) -> dict[str, Any] | list[dict[str, Any]]:
    """Validate the supported VC-JWT input subset before real issuance.

    The W3C suite is broad enough to include JSON-LD-only structures.  This
    adapter deliberately accepts the VCDM fields Marty can carry in a JWT VC;
    it never converts an invalid document into a signed credential.
    """
    _validate_w3c_vcdm_credential(credential)
    subject = credential.get("credentialSubject")
    if isinstance(subject, list):
        return [dict(item) for item in subject]
    if not isinstance(subject, dict) or not subject:
        raise HTTPException(status_code=422, detail={"error": "invalid_credential"})
    # The credential template controls issuer identity and credential type.
    # The exact subject object/set crosses the boundary separately from flat
    # claims so the production JWT-VC builder cannot collapse a subject set.
    return dict(subject)


_ABSOLUTE_URI = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:[^\s]+$")
_RFC3339_DATETIME = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)
_BASE_CONTEXT = "https://www.w3.org/ns/credentials/v2"
_EXAMPLES_CONTEXT = "https://www.w3.org/ns/credentials/examples/v2"
_PROTECTED_VCDM_TERMS = frozenset(
    {
        "VerifiableCredential",
        "VerifiablePresentation",
        "credentialSubject",
        "issuer",
        "proof",
        "type",
        "id",
        "@context",
    }
)


def _is_absolute_uri(value: Any) -> bool:
    return isinstance(value, str) and bool(_ABSOLUTE_URI.fullmatch(value))


def _context_term_map(context: list[Any]) -> dict[str, str]:
    terms: dict[str, str] = {}
    for item in context[1:]:
        if isinstance(item, str):
            if not _is_absolute_uri(item):
                raise HTTPException(
                    status_code=422, detail={"error": "invalid_context"}
                )
            # This pinned W3C context defines an @vocab mapping. Resolve the
            # term exercised by the official suite without accepting arbitrary
            # unmapped compact terms.
            if item == _EXAMPLES_CONTEXT:
                terms["RelationshipCredential"] = (
                    "https://www.w3.org/ns/credentials/examples#RelationshipCredential"
                )
            continue
        if not isinstance(item, dict):
            raise HTTPException(status_code=422, detail={"error": "invalid_context"})
        for term, target in item.items():
            if term in _PROTECTED_VCDM_TERMS or not _is_absolute_uri(target):
                raise HTTPException(
                    status_code=422, detail={"error": "invalid_context"}
                )
            terms[term] = target
    return terms


def _validate_type(
    value: Any, terms: dict[str, str], required: str | None = None
) -> None:
    values = value if isinstance(value, list) else [value]
    if not values or not all(isinstance(item, str) and item for item in values):
        raise HTTPException(status_code=422, detail={"error": "invalid_type"})
    if required and required not in values:
        raise HTTPException(status_code=422, detail={"error": "invalid_type"})
    for item in values:
        if (
            not _is_absolute_uri(item)
            and item not in _PROTECTED_VCDM_TERMS
            and item not in terms
        ):
            raise HTTPException(status_code=422, detail={"error": "invalid_type"})


def _validate_typed_resource(
    value: Any, terms: dict[str, str], *, require_id: bool = False
) -> None:
    values = value if isinstance(value, list) else [value]
    if not values or not all(isinstance(item, dict) for item in values):
        raise HTTPException(status_code=422, detail={"error": "invalid_resource"})
    for item in values:
        _validate_type(item.get("type"), terms)
        if require_id and not _is_absolute_uri(item.get("id")):
            raise HTTPException(status_code=422, detail={"error": "invalid_resource"})


def _validate_language_value(value: Any) -> bool:
    if isinstance(value, str):
        return True
    if isinstance(value, list):
        return bool(value) and all(
            not isinstance(item, list) and _validate_language_value(item)
            for item in value
        )
    if not isinstance(value, dict) or not isinstance(value.get("@value"), str):
        return False
    return all(
        key in {"@value", "@language", "@direction"}
        and (key == "@value" or isinstance(entry, str))
        for key, entry in value.items()
    )


async def _validate_related_resource_digests(credential: dict[str, Any]) -> None:
    """Retrieve allowlisted related resources and validate their digests."""
    resources = credential.get("relatedResource")
    if resources is None:
        return
    values = resources if isinstance(resources, list) else [resources]
    allowed = {
        value.strip()
        for value in os.environ.get(
            "W3C_VC_TEST_RELATED_RESOURCE_URLS", _BASE_CONTEXT
        ).split(",")
        if value.strip()
    }
    client = get_http_client()
    documents: dict[str, bytes] = {}
    for resource in values:
        resource_id = resource["id"]
        if resource_id not in allowed:
            raise HTTPException(
                status_code=422, detail={"error": "related_resource_not_allowlisted"}
            )
        if resource_id not in documents:
            response = await client.get(resource_id, timeout=10.0)
            if response.status_code != 200 or len(response.content) > 2_000_000:
                raise HTTPException(
                    status_code=422, detail={"error": "related_resource_unavailable"}
                )
            documents[resource_id] = bytes(response.content)
        content = documents[resource_id]
        digest_sri = resource.get("digestSRI")
        if digest_sri:
            try:
                algorithm, expected = digest_sri.split("-", 1)
                if algorithm not in {"sha256", "sha384", "sha512"}:
                    raise ValueError("unsupported SRI digest")
                digest = hashlib.new(algorithm, content).digest()
            except (ValueError, TypeError):
                raise HTTPException(
                    status_code=422, detail={"error": "invalid_related_resource"}
                ) from None
            actual = base64.b64encode(digest).decode("ascii")
            if not hmac.compare_digest(actual, expected):
                raise HTTPException(
                    status_code=422,
                    detail={"error": "related_resource_digest_mismatch"},
                )
        digest_multibase = resource.get("digestMultibase")
        if digest_multibase:
            actual = "u" + base64.urlsafe_b64encode(
                hashlib.sha256(content).digest()
            ).decode("ascii").rstrip("=")
            if not hmac.compare_digest(actual, digest_multibase):
                raise HTTPException(
                    status_code=422,
                    detail={"error": "related_resource_digest_mismatch"},
                )


def _is_rfc3339_datetime(value: Any) -> bool:
    if not isinstance(value, str) or not _RFC3339_DATETIME.fullmatch(value):
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


def _validate_w3c_vcdm_credential(credential: dict[str, Any]) -> None:
    """Enforce the structural VCDM v2 rules exercised by the official suite.

    This is a narrow input gate for the disposable VC-API adapter. It does not
    verify a proof or issue a synthetic credential: valid input continues into
    Marty's ordinary OID4VCI remote-signing path.
    """
    context = credential.get("@context")
    if not isinstance(context, list) or not context or context[0] != _BASE_CONTEXT:
        raise HTTPException(status_code=422, detail={"error": "invalid_context"})
    terms = _context_term_map(context)
    _validate_type(credential.get("type"), terms, "VerifiableCredential")
    if "id" in credential and not _is_absolute_uri(credential["id"]):
        raise HTTPException(status_code=422, detail={"error": "invalid_id"})
    # An issuer request may omit issuer and let the configured production
    # issuer inject it (the official suite's baseline fixture does this).
    # Explicit issuer values still have to be valid even though the fixture
    # cannot override Marty's configured issuer identity.
    if "issuer" in credential:
        issuer = credential.get("issuer")
        if isinstance(issuer, dict):
            issuer = issuer.get("id")
        if not _is_absolute_uri(issuer):
            raise HTTPException(status_code=422, detail={"error": "invalid_issuer"})
    subjects = credential.get("credentialSubject")
    subject_values = subjects if isinstance(subjects, list) else [subjects]
    if not subject_values or not all(
        isinstance(subject, dict) and subject for subject in subject_values
    ):
        raise HTTPException(status_code=422, detail={"error": "invalid_subject"})
    for subject in subject_values:
        if "id" in subject and not _is_absolute_uri(subject["id"]):
            raise HTTPException(status_code=422, detail={"error": "invalid_subject"})
    for key in ("validFrom", "validUntil"):
        if key in credential and not _is_rfc3339_datetime(credential[key]):
            raise HTTPException(status_code=422, detail={"error": "invalid_validity"})
    if "validFrom" in credential and "validUntil" in credential:
        if datetime.fromisoformat(
            credential["validFrom"].replace("Z", "+00:00")
        ) > datetime.fromisoformat(credential["validUntil"].replace("Z", "+00:00")):
            raise HTTPException(status_code=422, detail={"error": "invalid_validity"})
    if "credentialStatus" in credential:
        _validate_typed_resource(credential["credentialStatus"], terms)
        for status in (
            credential["credentialStatus"]
            if isinstance(credential["credentialStatus"], list)
            else [credential["credentialStatus"]]
        ):
            if "id" in status and not _is_absolute_uri(status["id"]):
                raise HTTPException(status_code=422, detail={"error": "invalid_status"})
    if "credentialSchema" in credential:
        _validate_typed_resource(credential["credentialSchema"], terms, require_id=True)
    for key in ("termsOfUse", "refreshService", "evidence"):
        if key in credential:
            _validate_typed_resource(credential[key], terms)
    if "relatedResource" in credential:
        resources = credential["relatedResource"]
        resources = resources if isinstance(resources, list) else [resources]
        seen_resource_ids: set[str] = set()
        if not resources or not all(
            isinstance(resource, dict) for resource in resources
        ):
            raise HTTPException(
                status_code=422, detail={"error": "invalid_related_resource"}
            )
        for resource in resources:
            resource_id = resource.get("id")
            if not _is_absolute_uri(resource_id) or resource_id in seen_resource_ids:
                raise HTTPException(
                    status_code=422, detail={"error": "invalid_related_resource"}
                )
            if not isinstance(
                resource.get("digestSRI") or resource.get("digestMultibase"), str
            ):
                raise HTTPException(
                    status_code=422, detail={"error": "invalid_related_resource"}
                )
            seen_resource_ids.add(resource_id)
    for key in ("name", "description"):
        if key in credential and not _validate_language_value(credential[key]):
            raise HTTPException(
                status_code=422, detail={"error": "invalid_language_value"}
            )
    if isinstance(credential.get("issuer"), dict):
        for key in ("name", "description"):
            if key in credential["issuer"] and not _validate_language_value(
                credential["issuer"][key]
            ):
                raise HTTPException(
                    status_code=422, detail={"error": "invalid_language_value"}
                )


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


def _jose_vc_envelope(credential: dict[str, Any], token: str) -> dict[str, Any]:
    """Wrap an actual JWT VC in the VCDM v2 JOSE envelope representation."""
    if token.count(".") != 2 or not all(token.split(".")):
        raise HTTPException(
            status_code=502, detail="Marty issuance did not return a JWT VC"
        )
    return {
        "@context": credential["@context"],
        # The pinned official suite identifies an enveloped credential by the
        # scalar VCDM envelope type before extracting the signed JWT payload.
        # A one-element array is schema-valid in other contexts, but the
        # suite's envelope branch intentionally uses scalar equality.
        "type": "EnvelopedVerifiableCredential",
        "id": f"data:application/vc+jwt,{token}",
    }


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


async def _issue_jwt_vc(credential: dict[str, Any], request: Request) -> str:
    """Issue through Marty's ordinary OID4VCI service path.

    The W3C endpoint is only a shape adapter.  It still resolves the template
    issuer identity, creates a pre-authorized transaction, redeems a token,
    obtains a fresh nonce, and submits a cryptographically valid holder proof.
    """
    credential_subject = _claims_from_w3c_credential(credential)
    await _validate_related_resource_digests(credential)
    organization_id, template_id = _issuance_fixture_configuration()
    body = IssuanceCreate(
        organization_id=organization_id,
        credential_template_id=template_id,
        claims={},
        credential_subject=credential_subject,
    )
    template = await _load_credential_template(template_id, request)
    if template.get("organization_id") != organization_id:
        raise HTTPException(
            status_code=403,
            detail="W3C fixture template belongs to another organization",
        )
    credential_format = template.get("credential_payload_format")
    if str(credential_format or "").strip().lower() not in {
        "jwt_vc_json",
        "vc_jwt",
        "w3c_vcdm_v2_jwt_vc",
    }:
        raise HTTPException(
            status_code=422,
            detail="W3C fixture template must issue JWT VC, not SD-JWT, mdoc, or JSON-LD",
        )
    issuer_profile_id = _select_issuer_profile_id(body, template)
    issuer_identity = await _resolve_issuer_identity(
        request,
        organization_id,
        issuer_profile_id,
        credential_format=credential_format,
    )
    if issuer_identity is None:
        raise HTTPException(
            status_code=422, detail="W3C fixture template has no active issuer identity"
        )

    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    if not service_url:
        raise HTTPException(status_code=503, detail="Issuance service unavailable")
    headers = dict(_ISSUANCE_HEADERS or {})
    headers["X-Issuer-Profile-Id"] = issuer_profile_id
    headers["X-Issuer-Did"] = issuer_identity["issuer_did"]
    client = get_http_client()

    initiated = await client.post(
        f"{service_url}/v1/issuance/initiate",
        headers=headers,
        json=body.model_dump(),
        timeout=30.0,
    )
    if initiated.status_code >= 400:
        raise HTTPException(
            status_code=initiated.status_code, detail=initiated.text[:300]
        )
    transaction = initiated.json()
    pre_auth_code = transaction.get("pre_auth_code")
    if not isinstance(pre_auth_code, str) or not pre_auth_code:
        raise HTTPException(
            status_code=502,
            detail="Marty issuance did not return a pre-authorized code",
        )

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
        json={"format": "jwt_vc_json", "proofs": {"jwt": [proof]}},
        timeout=30.0,
    )
    if issued.status_code >= 400:
        raise HTTPException(status_code=issued.status_code, detail=issued.text[:300])
    token = issued.json().get("credential")
    if not isinstance(token, str):
        raise HTTPException(
            status_code=502, detail="Marty issuance did not return a credential"
        )
    return token


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
    token = await _issue_jwt_vc(body.credential, request)
    return JSONResponse(
        {"verifiableCredential": _jose_vc_envelope(body.credential, token)}
    )
