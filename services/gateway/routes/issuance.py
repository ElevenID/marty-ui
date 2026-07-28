"""Issuance, issued credentials, OID4VCI wallet endpoints, and Application Templates."""

from __future__ import annotations

import logging
import os
import json
import httpx
from fastapi import APIRouter, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse

from gateway.models import (
    ApplicationTemplateCreate,
    ApplicationTemplatePatch,
    ApplicationTemplateResponse,
    DidcommDeliverRequest,
    DidcommDeliveryResponse,
    IssuanceCreate,
    IssuanceResponse,
    IssuedCredentialRecordResponse,
)
from gateway.proxy import _resource_org_id, get_http_client, get_registry, proxy_request

logger = logging.getLogger(__name__)

passport_router = APIRouter(prefix="/v1/passport", tags=["Physical Documents"])


def _read_secret_value(name: str) -> str:
    direct = os.environ.get(name)
    if direct:
        return direct
    file_path = os.environ.get(f"{name}_FILE")
    if not file_path:
        return ""
    try:
        with open(file_path, "r", encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError:
        return ""


_ISSUANCE_API_KEY = _read_secret_value("ISSUANCE_API_KEY")

_ISSUANCE_HEADERS: dict[str, str] | None = (
    {"X-API-Key": _ISSUANCE_API_KEY} if _ISSUANCE_API_KEY else None
)

# Credential format → key purpose mapping used for KMS service resolution.
_FORMAT_KEY_PURPOSE: dict[str, str] = {
    "jwt_vc_json": "vc_jwt_issuer",
    "vc+sd-jwt": "vc_jwt_issuer",
    "spruce-vc+sd-jwt": "vc_jwt_issuer",
    "dc+sd-jwt": "vc_jwt_issuer",
    "w3c_vcdm_v2_sd_jwt": "vc_jwt_issuer",
    "w3c_vcdm_v2_di": "vc_jwt_issuer",
    "ldp_vc": "vc_jwt_issuer",
    "json_ld": "vc_jwt_issuer",
    "sd_jwt_vc": "vc_jwt_issuer",
    "mso_mdoc": "mdoc_dsc",
    "mdoc": "mdoc_dsc",
    "zk_mdoc": "mdoc_dsc",
    "vds_nc": "vdsnc_signing",
    "vdsnc": "vdsnc_signing",
}

_PUBLIC_SIGNING_FORMAT_ALIASES: dict[str, str] = {
    "w3c_vcdm_v2_sd_jwt": "dc+sd-jwt",
    "ietf_sd_jwt": "dc+sd-jwt",
    "sd_jwt_vc": "dc+sd-jwt",
    "vc+sd_jwt": "dc+sd-jwt",
    "vc+sd-jwt": "dc+sd-jwt",
    "dc+sd_jwt": "dc+sd-jwt",
    "dc+sd-jwt": "dc+sd-jwt",
    "w3c_vcdm_v2_jwt_vc": "jwt_vc_json",
    "vc_jwt": "jwt_vc_json",
    "jwt_vc": "jwt_vc_json",
    "jwt_vc_json": "jwt_vc_json",
    "w3c_vcdm_v2_di": "ldp_vc",
    "json_ld": "ldp_vc",
    "json-ld": "ldp_vc",
    "ldp_vc": "ldp_vc",
    "mdoc": "mso_mdoc",
    "mso_mdoc": "mso_mdoc",
}


def _public_signing_credential_format(
    credential_payload_format: str | None,
    supported_formats: object = None,
) -> str | None:
    """Return the wire format used by issuer-profile capability resolution.

    Credential templates store a Marty payload-shape name while signing
    services advertise protocol wire formats. Keeping this conversion in one
    place prevents a template that was valid at creation time from becoming
    unresolvable during issuance.
    """
    explicit = (credential_payload_format or "").strip().lower()
    if explicit:
        return _PUBLIC_SIGNING_FORMAT_ALIASES.get(explicit, explicit)

    candidates: set[str] = set()
    if isinstance(supported_formats, list):
        for value in supported_formats:
            if not isinstance(value, str) or not value.strip():
                continue
            normalized = value.strip().lower()
            candidates.add(
                _PUBLIC_SIGNING_FORMAT_ALIASES.get(normalized, normalized)
            )
    if len(candidates) == 1:
        return candidates.pop()
    return None


def _normalize_credential_format(value: str | None) -> str | None:
    normalized = (value or "").strip().lower()
    return normalized.replace("-", "_") if normalized else None


def _key_purpose_for_format(value: str | None) -> str | None:
    normalized = _normalize_credential_format(value)
    if not normalized:
        return "vc_jwt_issuer"
    if normalized in {"vc+sd_jwt", "spruce_vc+sd_jwt", "dc+sd_jwt"}:
        return "vc_jwt_issuer"
    return _FORMAT_KEY_PURPOSE.get(normalized)


async def _resolve_issuer_identity(
    request: Request,
    organization_id: str | None,
    issuer_did: str | None,
    credential_format: str | None = None,
    key_purpose: str | None = None,
    algorithm: str | None = None,
) -> dict[str, str] | None:
    """Resolve a public DID to exactly one org-owned active issuer profile."""
    if not issuer_did:
        return None
    if not organization_id:
        raise HTTPException(
            status_code=422,
            detail="organization_id is required to resolve issuer_did.",
        )

    try:
        from gateway.routes.signing_keys import (  # noqa: PLC0415
            internal_resolve_issuer_did,
        )
    except ImportError:
        raise HTTPException(
            status_code=503,
            detail="Signing-keys issuer profile resolver is unavailable.",
        )

    try:
        response = await internal_resolve_issuer_did(
            request=request,
            organization_id=organization_id,
            issuer_did=issuer_did,
            verification_method_id=None,
            credential_format=credential_format,
            key_purpose=key_purpose or _key_purpose_for_format(credential_format),
            algorithm=algorithm,
            x_api_key=_read_secret_value("SIGNING_KEYS_INTERNAL_API_KEY")
            or _read_secret_value("ISSUANCE_API_KEY"),
        )
    except HTTPException:
        # Preserve the resolver's fail-closed 404/409/422 distinction so an
        # ambiguous or cross-tenant identity can never degrade to a fallback.
        raise

    try:
        payload = json.loads(response.body)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=503,
            detail="Signing-keys issuer profile resolver returned an invalid response.",
        ) from exc

    profile = (
        payload.get("issuer_profile")
        if isinstance(payload.get("issuer_profile"), dict)
        else {}
    )
    service = (
        payload.get("signing_service")
        if isinstance(payload.get("signing_service"), dict)
        else {}
    )
    resolved_profile_id = _clean_optional_id(profile.get("id"))
    resolved_issuer_did = _clean_optional_id(payload.get("issuer_did"))
    resolved_organization_id = _clean_optional_id(payload.get("organization_id"))
    if (
        not payload.get("ok")
        or not resolved_profile_id
        or not resolved_issuer_did
        or not service.get("id")
    ):
        return None
    if resolved_organization_id != organization_id or resolved_issuer_did != issuer_did:
        raise HTTPException(
            status_code=409,
            detail="Issuer DID resolver returned an identity outside the requested organization scope.",
        )
    algorithm_value = profile.get("algorithm") or ""
    return {
        "issuer_profile_id": resolved_profile_id,
        "issuer_did": resolved_issuer_did,
        "signing_service_id": str(service["id"]),
        "signing_key_reference": str(profile.get("signing_key_reference") or ""),
        "verification_method_id": str(payload.get("verification_method_id") or ""),
        "key_purpose": str(
            profile.get("key_purpose")
            or key_purpose
            or _key_purpose_for_format(credential_format)
            or "vc_jwt_issuer"
        ),
        "algorithm": str(algorithm_value),
    }


async def _load_credential_template(template_id: str, request: Request) -> dict:
    registry = get_registry()
    client = get_http_client()
    url = f"{registry.get_service_url('credential-templates')}/v1/credential-templates/{template_id}"
    headers: dict[str, str] = {}
    if getattr(request.state, "user_id", None):
        headers["X-User-Id"] = request.state.user_id
    if getattr(request.state, "user_email", None):
        headers["X-User-Email"] = request.state.user_email
    auth = request.headers.get("authorization")
    if auth:
        headers["Authorization"] = auth
    response = await client.get(url, timeout=10.0, headers=headers)
    if response.status_code == 404:
        raise HTTPException(
            status_code=404, detail=f"Credential template not found: {template_id}"
        )
    if response.status_code >= 400:
        raise HTTPException(
            status_code=response.status_code, detail=response.text[:300]
        )
    data = response.json()
    return data if isinstance(data, dict) else {}


def _clean_optional_id(value: object) -> str | None:
    if value is None:
        return None
    cleaned = str(value).strip()
    return cleaned or None


def _select_issuer_identity_request(
    body: IssuanceCreate, credential_template: dict
) -> str:
    """Select the public DID without exposing internal profile selectors."""
    template_issuer_did = _clean_optional_id(credential_template.get("issuer_did"))
    body_issuer_did = _clean_optional_id(body.issuer_did)
    claim_issuer_profile_id = (
        _clean_optional_id(body.claims.get("issuer_profile_id"))
        if isinstance(body.claims, dict)
        else None
    )

    if claim_issuer_profile_id:
        raise HTTPException(
            status_code=422,
            detail=(
                "claims.issuer_profile_id is not a supported public signing "
                "identity input; use issuer_did."
            ),
        )

    if credential_template:
        if not template_issuer_did:
            raise HTTPException(
                status_code=422,
                detail=(
                    "credential_template_id must reference a template with an "
                    "issuer_did; migrate this legacy template before issuance."
                ),
            )
        if (
            body_issuer_did
            and body_issuer_did != template_issuer_did
        ):
            raise HTTPException(
                status_code=422,
                detail="issuer_did cannot override the credential template issuer DID.",
            )
        return template_issuer_did

    if not body_issuer_did:
        raise HTTPException(
            status_code=422,
            detail="issuer_did is required for direct issuance without a credential template.",
        )
    return body_issuer_did


issuance_router = APIRouter(prefix="/v1/issuance", tags=["Issuance"])
issued_credential_router = APIRouter(
    prefix="/v1/issued-credentials", tags=["Issued Credentials"]
)


def _issuance_service_url() -> str:
    return get_registry().get_service_url("issuance")


async def _register_oid4vci_authorized_client(
    body: IssuanceCreate,
    service_url: str,
) -> None:
    """Persist a public wallet key through the normal authenticated API path."""

    if body.authorized_client is None:
        return
    try:
        response = await get_http_client().put(
            f"{service_url}/v1/issuance/oid4vci-clients",
            headers=_ISSUANCE_HEADERS,
            json={
                "organization_id": body.organization_id,
                "client_id": body.authorized_client.client_id,
                "jwks": body.authorized_client.jwks.model_dump(exclude_none=True),
                "redirect_uris": [],
                "active": True,
            },
            timeout=10.0,
        )
    except (httpx.TimeoutException, httpx.TransportError) as exc:
        raise HTTPException(
            status_code=503,
            detail="OID4VCI client registration is temporarily unavailable",
        ) from exc
    if response.status_code >= 400:
        logger.warning(
            "OID4VCI client registration failed for org=%s status=%s",
            body.organization_id,
            response.status_code,
        )
        raise HTTPException(
            status_code=response.status_code,
            detail="Unable to register the authorized wallet client",
        )


@passport_router.get("/capabilities", summary="Get Physical Document Capabilities")
async def get_passport_capabilities(request: Request) -> Response:
    service_url = _issuance_service_url()
    response = await get_http_client().get(
        f"{service_url}/v1/passport/capabilities",
        headers=_ISSUANCE_HEADERS,
        timeout=10.0,
    )
    if response.status_code == 404:
        return JSONResponse(
            {
                "supported": False,
                "state": "UNSUPPORTED",
                "code": "PHYSICAL_DOCUMENTS_UNSUPPORTED",
                "message": "Physical document issuance is not installed in this deployment.",
            }
        )
    if response.status_code in {402, 403}:
        try:
            error_payload = response.json()
        except ValueError:
            error_payload = {}
        code = str(
            error_payload.get("code") or error_payload.get("error") or ""
        ).upper()
        if "PLAN" in code or "ENTITLEMENT" in code:
            return JSONResponse(
                {
                    "supported": True,
                    "state": "ENTITLEMENT_REQUIRED",
                    "code": code or "PHYSICAL_DOCUMENT_ENTITLEMENT_REQUIRED",
                    "message": "This capability is available but is not included in the current entitlement.",
                }
            )
    if response.status_code >= 500:
        raise HTTPException(
            status_code=503,
            detail="Physical document capabilities are temporarily unavailable",
        )
    if response.status_code >= 400:
        raise HTTPException(
            status_code=response.status_code,
            detail="Unable to load physical document capabilities",
        )
    payload = response.json()
    if not isinstance(payload, dict):
        raise HTTPException(
            status_code=503, detail="Physical document capability response is malformed"
        )
    payload.setdefault("supported", True)
    payload.setdefault("state", "AVAILABLE")
    return JSONResponse(payload)


@passport_router.post("/applications", summary="Create Physical Document Application")
async def create_passport_application(request: Request) -> Response:
    return await proxy_request(
        request,
        _issuance_service_url(),
        "/v1/passport/applications",
        inject_headers=_ISSUANCE_HEADERS,
    )


@passport_router.post(
    "/applications/{application_id}/generate-sod", summary="Sign Physical Document SOD"
)
async def generate_passport_sod(application_id: str, request: Request) -> Response:
    return await proxy_request(
        request,
        _issuance_service_url(),
        f"/v1/passport/applications/{application_id}/generate-sod",
        inject_headers=_ISSUANCE_HEADERS,
    )


@passport_router.post(
    "/applications/{application_id}/generate-data-groups",
    summary="Generate Physical Document Data Groups",
)
async def generate_passport_data_groups(
    application_id: str, request: Request
) -> Response:
    return await proxy_request(
        request,
        _issuance_service_url(),
        f"/v1/passport/applications/{application_id}/generate-data-groups",
        inject_headers=_ISSUANCE_HEADERS,
    )


@passport_router.post(
    "/applications/{application_id}/submit-personalization",
    summary="Submit Physical Document Production",
)
async def submit_passport_personalization(
    application_id: str, request: Request
) -> Response:
    return await proxy_request(
        request,
        _issuance_service_url(),
        f"/v1/passport/applications/{application_id}/submit-personalization",
        inject_headers=_ISSUANCE_HEADERS,
    )


@passport_router.get(
    "/applications/{application_id}/production-status",
    summary="Get Physical Document Production Status",
)
async def get_passport_production_status(
    application_id: str, request: Request
) -> Response:
    return await proxy_request(
        request,
        _issuance_service_url(),
        f"/v1/passport/applications/{application_id}/production-status",
        inject_headers=_ISSUANCE_HEADERS,
    )


@passport_router.post(
    "/applications/{application_id}/quality-verify",
    summary="Record Physical Document Quality Result",
)
async def verify_passport_quality(application_id: str, request: Request) -> Response:
    return await proxy_request(
        request,
        _issuance_service_url(),
        f"/v1/passport/applications/{application_id}/quality-verify",
        inject_headers=_ISSUANCE_HEADERS,
    )


@passport_router.post(
    "/applications/{application_id}/activate", summary="Activate Physical Document"
)
async def activate_passport(application_id: str, request: Request) -> Response:
    return await proxy_request(
        request,
        _issuance_service_url(),
        f"/v1/passport/applications/{application_id}/activate",
        inject_headers=_ISSUANCE_HEADERS,
    )


application_template_router = APIRouter(
    prefix="/v1/application-templates", tags=["Application Templates"]
)


# ── Issuance ─────────────────────────────────────────────────────────


@issuance_router.post("", response_model=IssuanceResponse, summary="Create Issuance")
async def create_issuance(body: IssuanceCreate, request: Request) -> Response:
    """Initiate credential issuance for a subject (directly or via Application).

    The gateway forwards only the canonical DID identity. The issuance service
    resolves the authorized issuer profile and signs through that profile's
    managed custody configuration.
    """
    credential_template: dict = {}
    if body.credential_template_id:
        credential_template = await _load_credential_template(
            body.credential_template_id, request
        )
        owner_org = credential_template.get("organization_id")
        if owner_org != body.organization_id:
            raise HTTPException(
                status_code=403,
                detail="Access denied: credential template belongs to another organization",
            )

    # Resolve the public DID to exactly one active profile. Internal profile and
    # custody details are used only to validate the mapping and never cross the
    # public request boundary.
    credential_format = _public_signing_credential_format(
        credential_template.get("credential_payload_format"),
        credential_template.get("supported_formats"),
    ) or _public_signing_credential_format(
        body.claims.get("credential_format")
        if isinstance(body.claims, dict)
        else None
    )
    issuer_did = _select_issuer_identity_request(body, credential_template)
    issuer_identity = await _resolve_issuer_identity(
        request,
        body.organization_id,
        issuer_did,
        credential_format=credential_format,
    )
    if issuer_identity is None:
        raise HTTPException(
            status_code=422,
            detail=(
                "issuer_did must resolve to exactly one active KMS-backed issuer "
                "profile for this organization."
            ),
        )
    inject_headers: dict[str, str] = dict(_ISSUANCE_HEADERS or {})
    logger.debug(
        "Resolved issuer DID for org=%s format=%s",
        body.organization_id,
        credential_format,
    )
    # The downstream issuance service enforces the same DID-only boundary.
    # Propagate the canonical resolver result in the request body, never by a
    # profile/key header that could act as a hidden selector.
    downstream_body = body.model_dump(exclude_none=True)
    if not body.claims:
        downstream_body.pop("claims", None)
    downstream_body["issuer_did"] = issuer_identity["issuer_did"]

    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    if body.authorized_client is not None:
        await _register_oid4vci_authorized_client(body, service_url)
        authorized_client = downstream_body.pop("authorized_client")
        downstream_body["authorized_client_id"] = authorized_client["client_id"]
        return await proxy_request(
            request,
            service_url,
            "/v1/issuance/initiate",
            body_override=json.dumps(downstream_body, separators=(",", ":")).encode("utf-8"),
            inject_headers=inject_headers or None,
        )
    return await proxy_request(
        request,
        service_url,
        "/v1/issuance/initiate",
        body_override=json.dumps(downstream_body, separators=(",", ":")).encode("utf-8"),
        inject_headers=inject_headers or None,
    )


@issuance_router.get(
    "", response_model=list[IssuanceResponse], summary="List Issuances"
)
async def list_issuances(
    organization_id: str = Query(..., description="Organization ID"),
    request: Request = None,
) -> Response:
    """List issuance records for an organization."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        "/v1/issuance/transactions",
        inject_headers=_ISSUANCE_HEADERS,
    )


@issuance_router.get("/authorize", summary="OID4VCI Authorization Endpoint")
async def authorize_issuance(request: Request) -> Response:
    """Proxy the public OAuth authorization-code entry point to issuance.

    This is deliberately unauthenticated: the authorization endpoint validates
    the PAR request and redirect URI itself. It must be declared before the
    ``/{issuance_id}`` route so FastAPI does not interpret ``authorize`` as a
    transaction identifier.
    """
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/issuance/authorize")


@issuance_router.get(
    "/{issuance_id}", response_model=IssuanceResponse, summary="Get Issuance"
)
async def get_issuance(issuance_id: str, request: Request) -> Response:
    """Get an issuance record by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        f"/v1/issuance/transactions/{issuance_id}",
        inject_headers=_ISSUANCE_HEADERS,
    )


@issuance_router.post("/{issuance_id}/revoke", summary="Revoke Issuance")
async def revoke_issuance(issuance_id: str, request: Request) -> Response:
    """Revoke a credential issuance transaction."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        f"/v1/issuance/transactions/{issuance_id}/revoke",
        inject_headers=_ISSUANCE_HEADERS,
    )


@issuance_router.get(
    "/{issuance_id}/revocation-status", summary="Get Revocation Status"
)
async def get_issuance_revocation_status(
    issuance_id: str, request: Request
) -> Response:
    """Get the revocation status of an issuance transaction."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        f"/v1/issuance/transactions/{issuance_id}/revocation-status",
        inject_headers=_ISSUANCE_HEADERS,
    )


# ── DIDComm v2 delivery ─────────────────────────────────────────────


@issuance_router.post(
    "/didcomm/deliver",
    response_model=DidcommDeliveryResponse,
    summary="DIDComm V2 Deliver",
)
async def didcomm_deliver(body: DidcommDeliverRequest, request: Request) -> Response:
    """Deliver a credential to a holder via DIDComm v2 push.

    Signs the credential, wraps it in a DIDComm v2 issue-credential/3.0
    message, resolves the holder's DID Document for their service endpoint,
    and POSTs the message.
    """
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        "/v1/issuance/didcomm/deliver",
        inject_headers=_ISSUANCE_HEADERS,
    )


@issuance_router.post("/didcomm/receive", summary="DIDComm V2 Receive")
async def didcomm_receive(request: Request) -> Response:
    """Receive inbound DIDComm v2 messages (acks, problem-reports, etc.).

    This is the public-facing DIDComm endpoint that other agents POST to.
    No authentication required — DIDComm agents use DID-based trust.
    """
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/issuance/didcomm/receive")


# ── Issued Credentials ──────────────────────────────────────────────


@issued_credential_router.get(
    "",
    response_model=list[IssuedCredentialRecordResponse],
    summary="List Issued Credentials",
)
async def list_issued_credentials(
    organization_id: str = Query(..., description="Organization ID"),
    status: str | None = Query(None),
    request: Request = None,
) -> Response:
    """List issued credential lifecycle records for an organization."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request, service_url, "/v1/issued-credentials", inject_headers=_ISSUANCE_HEADERS
    )


@issued_credential_router.get("/mine", summary="List My Issued Credentials")
async def list_my_issued_credentials(request: Request) -> Response:
    """Return the authenticated holder's privacy-filtered credential inventory."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, "/v1/issued-credentials/mine")


@issued_credential_router.get(
    "/{credential_id}",
    response_model=IssuedCredentialRecordResponse,
    summary="Get Issued Credential",
)
async def get_issued_credential(credential_id: str, request: Request) -> Response:
    """Get an issued credential lifecycle record by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        f"/v1/issued-credentials/{credential_id}",
        inject_headers=_ISSUANCE_HEADERS,
    )


@issued_credential_router.post(
    "/{credential_id}/revoke",
    response_model=IssuedCredentialRecordResponse,
    summary="Revoke Issued Credential",
)
async def revoke_issued_credential(credential_id: str, request: Request) -> Response:
    """Revoke an issued credential lifecycle record."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        f"/v1/issued-credentials/{credential_id}/revoke",
        inject_headers=_ISSUANCE_HEADERS,
    )


@issued_credential_router.post(
    "/{credential_id}/suspend",
    response_model=IssuedCredentialRecordResponse,
    summary="Suspend Issued Credential",
)
async def suspend_issued_credential(credential_id: str, request: Request) -> Response:
    """Suspend an issued credential lifecycle record."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        f"/v1/issued-credentials/{credential_id}/suspend",
        inject_headers=_ISSUANCE_HEADERS,
    )


@issued_credential_router.post(
    "/{credential_id}/reinstate",
    response_model=IssuedCredentialRecordResponse,
    summary="Reinstate Issued Credential",
)
async def reinstate_issued_credential(credential_id: str, request: Request) -> Response:
    """Reinstate a suspended issued credential lifecycle record."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        f"/v1/issued-credentials/{credential_id}/reinstate",
        inject_headers=_ISSUANCE_HEADERS,
    )


@issued_credential_router.post(
    "/{credential_id}/renew", summary="Renew Issued Credential"
)
async def renew_issued_credential(credential_id: str, request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        f"/v1/issued-credentials/{credential_id}/renew",
        inject_headers=_ISSUANCE_HEADERS,
    )


@issuance_router.get(
    "/delivery-records/canvas-credentials/provenance",
    summary="Resolve Canvas Mirror Provenance",
)
async def get_canvas_mirror_provenance(request: Request) -> Response:
    """Resolve a Canvas mirror record to its canonical ElevenID issuance context."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        "/v1/issuance/delivery-records/canvas-credentials/provenance",
    )


@issuance_router.post(
    "/delivery-records/canvas-credentials/process-pending",
    summary="Process Pending Canvas Mirror Deliveries",
)
async def process_pending_canvas_mirror_deliveries(request: Request) -> Response:
    """Process pending Canvas mirror delivery records through issuance."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        "/v1/issuance/delivery-records/canvas-credentials/process-pending",
        inject_headers=_ISSUANCE_HEADERS,
    )


@issuance_router.post(
    "/delivery-records/canvas-credentials/process-status-sync-failures",
    summary="Process Canvas Mirror Status Sync Failures",
)
async def process_canvas_mirror_status_sync_failures(request: Request) -> Response:
    """Retry failed Canvas mirror lifecycle status syncs through issuance."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        "/v1/issuance/delivery-records/canvas-credentials/process-status-sync-failures",
        inject_headers=_ISSUANCE_HEADERS,
    )


@issuance_router.post(
    "/delivery-records/canvas-credentials/run-automation-cycle",
    summary="Run Canvas Mirror Automation Cycle",
)
async def run_canvas_mirror_automation_cycle(request: Request) -> Response:
    """Run one Canvas mirror automation cycle through issuance."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        "/v1/issuance/delivery-records/canvas-credentials/run-automation-cycle",
        inject_headers=_ISSUANCE_HEADERS,
    )


@issuance_router.get(
    "/organizations/{organization_id}/canvas-mirror-health",
    summary="Get Canvas Mirror Health",
)
async def get_canvas_mirror_health(organization_id: str, request: Request) -> Response:
    """Return Canvas mirror publish and lifecycle sync health for an organization."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        f"/v1/issuance/organizations/{organization_id}/canvas-mirror-health",
        inject_headers=_ISSUANCE_HEADERS,
    )


# ── OID4VCI Wallet-facing Endpoints ─────────────────────────────────


@issuance_router.get("/offers/{tx_id}", summary="Get Credential Offer")
async def get_credential_offer(tx_id: str, request: Request) -> Response:
    """
    Get OID4VCI credential offer for wallet integration.

    This endpoint is called by wallets when resolving a credential_offer_uri.
    No authentication required as the pre-authorized code serves as the auth token.
    """
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        f"/v1/issuance/offers/{tx_id}",
        inject_headers=_ISSUANCE_HEADERS,
    )


@issuance_router.post("/token", summary="Exchange Token")
async def exchange_token(request: Request) -> Response:
    """
    OID4VCI Token Endpoint.

    Exchange pre-authorized code for access token. This is called by wallets
    during the credential issuance flow.
    """
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request, service_url, "/v1/issuance/token", inject_headers=_ISSUANCE_HEADERS
    )


@issuance_router.post("/credential", summary="Issue Credential")
async def issue_credential(request: Request) -> Response:
    """
    OID4VCI Credential Endpoint.

    Issue a credential after successful token exchange. This is called by wallets
    to receive the actual credential.
    """
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        "/v1/issuance/credential",
        inject_headers=_ISSUANCE_HEADERS,
    )


@issuance_router.post("/par", summary="Pushed Authorization Request")
async def pushed_authorization_request(request: Request) -> Response:
    """
    RFC 9126 — Pushed Authorization Request (PAR).

    Wallet POSTs authorization parameters and receives a request_uri
    that can be used at the /authorize endpoint.
    """
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request, service_url, "/v1/issuance/par", inject_headers=_ISSUANCE_HEADERS
    )


@issuance_router.post("/nonce", summary="Get Fresh Nonce")
async def get_nonce(request: Request) -> Response:
    """
    OID4VCI Nonce Endpoint.

    Returns a fresh c_nonce for use in credential proof JWTs. Called by wallets
    after token exchange to refresh the nonce. No authentication required.
    """
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request, service_url, "/v1/issuance/nonce", inject_headers=_ISSUANCE_HEADERS
    )


@issuance_router.post("/notification", summary="Credential Notification")
async def credential_notification(request: Request) -> Response:
    """OID4VCI-1FINAL §11 — Wallet notifies issuer of credential lifecycle event."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        "/v1/issuance/notification",
        inject_headers=_ISSUANCE_HEADERS,
    )


@issuance_router.post("/deferred-credential", summary="Deferred Credential")
async def deferred_credential(request: Request) -> Response:
    """OID4VCI-1FINAL §9.1 — Poll for a deferred credential using a transaction_id."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        "/v1/issuance/deferred-credential",
        inject_headers=_ISSUANCE_HEADERS,
    )


# ── Application Templates ───────────────────────────────────────────


async def _validate_application_template_dependencies(
    body: ApplicationTemplateCreate,
    request: Request,
) -> None:
    """Ensure referenced credential templates stay within the same org boundary."""
    if not body.credential_template_id:
        return

    owner_org = await _resource_org_id(
        "credential-templates",
        f"/v1/credential-templates/{body.credential_template_id}",
        request,
    )
    if owner_org is None:
        raise HTTPException(
            status_code=422,
            detail=f"Credential template not found: {body.credential_template_id}",
        )
    if owner_org != body.organization_id:
        raise HTTPException(
            status_code=403,
            detail="Access denied: credential template belongs to another organization",
        )


@application_template_router.post(
    "",
    response_model=ApplicationTemplateResponse,
    summary="Create Application Template",
)
async def create_application_template(
    body: ApplicationTemplateCreate, request: Request
) -> Response:
    """Create an Application Template defining how users apply for credentials."""
    await _validate_application_template_dependencies(body, request)
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        "/v1/application-templates",
        inject_headers=_ISSUANCE_HEADERS,
    )


@application_template_router.get(
    "",
    response_model=list[ApplicationTemplateResponse],
    summary="List Application Templates",
)
async def list_application_templates(
    organization_id: str = Query(..., description="Organization ID"),
    request: Request = None,
) -> Response:
    """List Application Templates for an organization."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        "/v1/application-templates",
        inject_headers=_ISSUANCE_HEADERS,
    )


@application_template_router.get(
    "/{template_id}",
    response_model=ApplicationTemplateResponse,
    summary="Get Application Template",
)
async def get_application_template(template_id: str, request: Request) -> Response:
    """Get an Application Template by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        f"/v1/application-templates/{template_id}",
        inject_headers=_ISSUANCE_HEADERS,
    )


@application_template_router.patch(
    "/{template_id}",
    response_model=ApplicationTemplateResponse,
    summary="Update draft Application Template",
)
async def update_application_template(
    template_id: str, body: ApplicationTemplatePatch, request: Request
) -> Response:
    """Patch mutable fields on a draft Application Template."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        f"/v1/application-templates/{template_id}",
        inject_headers=_ISSUANCE_HEADERS,
    )


@application_template_router.delete(
    "/{template_id}", summary="Delete Application Template"
)
async def delete_application_template(template_id: str, request: Request) -> Response:
    """Delete a draft Application Template."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        f"/v1/application-templates/{template_id}",
        inject_headers=_ISSUANCE_HEADERS,
    )


@application_template_router.post(
    "/{template_id}/validate", summary="Validate Application Template"
)
async def validate_application_template(template_id: str, request: Request) -> Response:
    """Return section-scoped validation errors without changing lifecycle state."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        f"/v1/application-templates/{template_id}/validate",
        inject_headers=_ISSUANCE_HEADERS,
    )


@application_template_router.post(
    "/{template_id}/activate",
    response_model=ApplicationTemplateResponse,
    summary="Activate Application Template",
)
async def activate_application_template(template_id: str, request: Request) -> Response:
    """Validate and activate a draft Application Template."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        f"/v1/application-templates/{template_id}/activate",
        inject_headers=_ISSUANCE_HEADERS,
    )


@application_template_router.post(
    "/{template_id}/deprecate",
    response_model=ApplicationTemplateResponse,
    summary="Deprecate Application Template",
)
async def deprecate_application_template(
    template_id: str, request: Request
) -> Response:
    """Deprecate an active Application Template while preserving history."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        f"/v1/application-templates/{template_id}/deprecate",
        inject_headers=_ISSUANCE_HEADERS,
    )
