"""Issuance, Issued Credentials, OID4VCI wallet endpoints, Application Templates, and Applications."""
from __future__ import annotations

import logging
import os
import json
from fastapi import APIRouter, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse

from gateway.models import (
    ApplicationCreate,
    ApplicationResponse,
    ApplicationTemplateCreate,
    ApplicationTemplatePatch,
    ApplicationTemplateResponse,
    DidcommDeliverRequest,
    DidcommDeliveryResponse,
    EvidenceSubmission,
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
    "sd_jwt_vc": "vc_jwt_issuer",
    "mso_mdoc": "mdoc_dsc",
    "mdoc": "mdoc_dsc",
    "zk_mdoc": "mdoc_dsc",
    "vds_nc": "vdsnc_signing",
    "vdsnc": "vdsnc_signing",
}


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
    issuer_profile_id: str | None,
    credential_format: str | None = None,
    key_purpose: str | None = None,
    algorithm: str | None = None,
) -> dict[str, str] | None:
    """Return the explicitly selected active DID issuer identity."""
    if not issuer_profile_id:
        return None
    if not organization_id:
        raise HTTPException(status_code=422, detail="organization_id is required to resolve issuer profile.")

    try:
        from gateway.routes.signing_keys import (  # noqa: PLC0415
            internal_resolve_issuer_context,
        )
    except ImportError:
        raise HTTPException(
            status_code=503,
            detail="Signing-keys issuer profile resolver is unavailable.",
        )

    try:
        response = await internal_resolve_issuer_context(
            request=request,
            organization_id=organization_id,
            issuer_profile_id=issuer_profile_id,
            issuer_mode="org_managed",
            credential_format=credential_format,
            key_purpose=key_purpose or _key_purpose_for_format(credential_format),
            algorithm=algorithm,
            x_api_key=_read_secret_value("SIGNING_KEYS_INTERNAL_API_KEY") or _read_secret_value("ISSUANCE_API_KEY"),
        )
    except HTTPException as exc:
        if exc.status_code in {404, 409, 422}:
            return None
        raise

    try:
        payload = json.loads(response.body)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=503, detail="Signing-keys issuer profile resolver returned an invalid response.") from exc

    if not payload.get("ok") or not payload.get("issuer_did") or not payload.get("signing_service_id"):
        return None

    service = payload.get("service") if isinstance(payload.get("service"), dict) else {}
    algorithm_value = service.get("algorithm") or ""
    return {
        "issuer_did": str(payload["issuer_did"]),
        "signing_service_id": str(payload["signing_service_id"]),
        "signing_key_reference": str(payload.get("signing_key_reference") or ""),
        "verification_method_id": str(payload.get("verification_method_id") or ""),
        "key_purpose": str(payload.get("key_purpose") or key_purpose or _key_purpose_for_format(credential_format) or "vc_jwt_issuer"),
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
        raise HTTPException(status_code=404, detail=f"Credential template not found: {template_id}")
    if response.status_code >= 400:
        raise HTTPException(status_code=response.status_code, detail=response.text[:300])
    data = response.json()
    return data if isinstance(data, dict) else {}


def _clean_optional_id(value: object) -> str | None:
    if value is None:
        return None
    cleaned = str(value).strip()
    return cleaned or None


def _select_issuer_profile_id(body: IssuanceCreate, credential_template: dict) -> str:
    template_issuer_profile_id = _clean_optional_id(credential_template.get("issuer_profile_id"))
    body_issuer_profile_id = _clean_optional_id(body.issuer_profile_id)
    claim_issuer_profile_id = (
        _clean_optional_id(body.claims.get("issuer_profile_id"))
        if isinstance(body.claims, dict)
        else None
    )

    if credential_template:
        if not template_issuer_profile_id:
            raise HTTPException(
                status_code=422,
                detail="credential_template_id must reference a template bound to an active KMS-backed issuer profile.",
            )
        if body_issuer_profile_id and body_issuer_profile_id != template_issuer_profile_id:
            raise HTTPException(
                status_code=422,
                detail="issuer_profile_id cannot override the credential template issuer profile.",
            )
        if claim_issuer_profile_id and claim_issuer_profile_id != template_issuer_profile_id:
            raise HTTPException(
                status_code=422,
                detail="claims.issuer_profile_id cannot override the credential template issuer profile.",
            )
        return template_issuer_profile_id

    if not body_issuer_profile_id:
        raise HTTPException(
            status_code=422,
            detail="issuer_profile_id is required for direct issuance without a credential template.",
        )
    if claim_issuer_profile_id and claim_issuer_profile_id != body_issuer_profile_id:
        raise HTTPException(
            status_code=422,
            detail="claims.issuer_profile_id cannot override the request issuer profile.",
        )
    return body_issuer_profile_id


issuance_router = APIRouter(prefix="/v1/issuance", tags=["Issuance"])
issued_credential_router = APIRouter(prefix="/v1/issued-credentials", tags=["Issued Credentials"])


def _issuance_service_url() -> str:
    return get_registry().get_service_url("issuance")


@passport_router.get("/capabilities", summary="Get Physical Document Capabilities")
async def get_passport_capabilities(request: Request) -> Response:
    service_url = _issuance_service_url()
    response = await get_http_client().get(
        f"{service_url}/v1/passport/capabilities",
        headers=_ISSUANCE_HEADERS,
        timeout=10.0,
    )
    if response.status_code == 404:
        return JSONResponse({
            "supported": False,
            "state": "UNSUPPORTED",
            "code": "PHYSICAL_DOCUMENTS_UNSUPPORTED",
            "message": "Physical document issuance is not installed in this deployment.",
        })
    if response.status_code in {402, 403}:
        try:
            error_payload = response.json()
        except ValueError:
            error_payload = {}
        code = str(error_payload.get("code") or error_payload.get("error") or "").upper()
        if "PLAN" in code or "ENTITLEMENT" in code:
            return JSONResponse({
                "supported": True,
                "state": "ENTITLEMENT_REQUIRED",
                "code": code or "PHYSICAL_DOCUMENT_ENTITLEMENT_REQUIRED",
                "message": "This capability is available but is not included in the current entitlement.",
            })
    if response.status_code >= 500:
        raise HTTPException(status_code=503, detail="Physical document capabilities are temporarily unavailable")
    if response.status_code >= 400:
        raise HTTPException(status_code=response.status_code, detail="Unable to load physical document capabilities")
    payload = response.json()
    if not isinstance(payload, dict):
        raise HTTPException(status_code=503, detail="Physical document capability response is malformed")
    payload.setdefault("supported", True)
    payload.setdefault("state", "AVAILABLE")
    return JSONResponse(payload)


@passport_router.post("/applications", summary="Create Physical Document Application")
async def create_passport_application(request: Request) -> Response:
    return await proxy_request(request, _issuance_service_url(), "/v1/passport/applications", inject_headers=_ISSUANCE_HEADERS)


@passport_router.post("/applications/{application_id}/generate-sod", summary="Sign Physical Document SOD")
async def generate_passport_sod(application_id: str, request: Request) -> Response:
    return await proxy_request(request, _issuance_service_url(), f"/v1/passport/applications/{application_id}/generate-sod", inject_headers=_ISSUANCE_HEADERS)


@passport_router.post("/applications/{application_id}/generate-data-groups", summary="Generate Physical Document Data Groups")
async def generate_passport_data_groups(application_id: str, request: Request) -> Response:
    return await proxy_request(request, _issuance_service_url(), f"/v1/passport/applications/{application_id}/generate-data-groups", inject_headers=_ISSUANCE_HEADERS)


@passport_router.post("/applications/{application_id}/submit-personalization", summary="Submit Physical Document Production")
async def submit_passport_personalization(application_id: str, request: Request) -> Response:
    return await proxy_request(request, _issuance_service_url(), f"/v1/passport/applications/{application_id}/submit-personalization", inject_headers=_ISSUANCE_HEADERS)


@passport_router.get("/applications/{application_id}/production-status", summary="Get Physical Document Production Status")
async def get_passport_production_status(application_id: str, request: Request) -> Response:
    return await proxy_request(request, _issuance_service_url(), f"/v1/passport/applications/{application_id}/production-status", inject_headers=_ISSUANCE_HEADERS)


@passport_router.post("/applications/{application_id}/quality-verify", summary="Record Physical Document Quality Result")
async def verify_passport_quality(application_id: str, request: Request) -> Response:
    return await proxy_request(request, _issuance_service_url(), f"/v1/passport/applications/{application_id}/quality-verify", inject_headers=_ISSUANCE_HEADERS)


@passport_router.post("/applications/{application_id}/activate", summary="Activate Physical Document")
async def activate_passport(application_id: str, request: Request) -> Response:
    return await proxy_request(request, _issuance_service_url(), f"/v1/passport/applications/{application_id}/activate", inject_headers=_ISSUANCE_HEADERS)
application_template_router = APIRouter(prefix="/v1/application-templates", tags=["Application Templates"])
application_router = APIRouter(prefix="/v1/applications", tags=["Applications"])


# ── Issuance ─────────────────────────────────────────────────────────

@issuance_router.post("", response_model=IssuanceResponse, summary="Create Issuance")
async def create_issuance(body: IssuanceCreate, request: Request) -> Response:
    """Initiate credential issuance for a subject (directly or via Application).

    The gateway forwards the active DID issuer identity and its bound KMS
    signing service so downstream issuance signs with the key published for
    that DID.
    """
    credential_template: dict = {}
    if body.credential_template_id:
        credential_template = await _load_credential_template(body.credential_template_id, request)
        owner_org = credential_template.get("organization_id")
        if owner_org != body.organization_id:
            raise HTTPException(status_code=403, detail="Access denied: credential template belongs to another organization")

    # Resolve the DID issuer identity and its bound remote signing service as a
    # pair. A format-only KMS resolver can select a key that is not published in
    # the DID document, which breaks BYOK issuer identity guarantees.
    credential_format: str | None = (
        credential_template.get("credential_payload_format")
        or (body.claims.get("credential_format") if isinstance(body.claims, dict) else None)
    )
    issuer_profile_id = _select_issuer_profile_id(body, credential_template)
    issuer_identity = await _resolve_issuer_identity(
        request,
        body.organization_id,
        issuer_profile_id,
        credential_format=credential_format,
    )
    if issuer_identity is None:
        raise HTTPException(
            status_code=422,
            detail="issuer_profile_id must reference an active KMS-backed issuer profile for this organization.",
        )
    signing_service_id = issuer_identity.get("signing_service_id") if issuer_identity else None

    inject_headers: dict[str, str] = dict(_ISSUANCE_HEADERS or {})
    if signing_service_id:
        inject_headers["X-Signing-Service-Id"] = signing_service_id
        logger.debug(
            "Resolved signing service %s for org=%s format=%s",
            signing_service_id,
            body.organization_id,
            credential_format,
        )

    issuer_did = issuer_identity.get("issuer_did") if issuer_identity else None
    if issuer_did:
        inject_headers["X-Issuer-Did"] = issuer_did
        logger.debug("Resolved issuer DID %s for org=%s", issuer_did, body.organization_id)

    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/issuance/initiate", inject_headers=inject_headers or None)


@issuance_router.get("", response_model=list[IssuanceResponse], summary="List Issuances")
async def list_issuances(
    organization_id: str = Query(..., description="Organization ID"),
    request: Request = None,
) -> Response:
    """List issuance records for an organization."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/issuance/transactions", inject_headers=_ISSUANCE_HEADERS)


@issuance_router.get("/{issuance_id}", response_model=IssuanceResponse, summary="Get Issuance")
async def get_issuance(issuance_id: str, request: Request) -> Response:
    """Get an issuance record by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/issuance/transactions/{issuance_id}", inject_headers=_ISSUANCE_HEADERS)


@issuance_router.post("/{issuance_id}/revoke", summary="Revoke Issuance")
async def revoke_issuance(issuance_id: str, request: Request) -> Response:
    """Revoke a credential issuance transaction."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/issuance/transactions/{issuance_id}/revoke", inject_headers=_ISSUANCE_HEADERS)


@issuance_router.get("/{issuance_id}/revocation-status", summary="Get Revocation Status")
async def get_issuance_revocation_status(issuance_id: str, request: Request) -> Response:
    """Get the revocation status of an issuance transaction."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/issuance/transactions/{issuance_id}/revocation-status", inject_headers=_ISSUANCE_HEADERS)


# ── DIDComm v2 delivery ─────────────────────────────────────────────

@issuance_router.post("/didcomm/deliver", response_model=DidcommDeliveryResponse, summary="DIDComm V2 Deliver")
async def didcomm_deliver(body: DidcommDeliverRequest, request: Request) -> Response:
    """Deliver a credential to a holder via DIDComm v2 push.

    Signs the credential, wraps it in a DIDComm v2 issue-credential/3.0
    message, resolves the holder's DID Document for their service endpoint,
    and POSTs the message.
    """
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/issuance/didcomm/deliver", inject_headers=_ISSUANCE_HEADERS)


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

@issued_credential_router.get("", response_model=list[IssuedCredentialRecordResponse], summary="List Issued Credentials")
async def list_issued_credentials(
    organization_id: str = Query(..., description="Organization ID"),
    status: str | None = Query(None),
    request: Request = None,
) -> Response:
    """List issued credential lifecycle records for an organization."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/issued-credentials", inject_headers=_ISSUANCE_HEADERS)


@issued_credential_router.get("/mine", summary="List My Issued Credentials")
async def list_my_issued_credentials(request: Request) -> Response:
    """Return the authenticated holder's privacy-filtered credential inventory."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, "/v1/issued-credentials/mine")


@issued_credential_router.get("/{credential_id}", response_model=IssuedCredentialRecordResponse, summary="Get Issued Credential")
async def get_issued_credential(credential_id: str, request: Request) -> Response:
    """Get an issued credential lifecycle record by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/issued-credentials/{credential_id}", inject_headers=_ISSUANCE_HEADERS)


@issued_credential_router.post("/{credential_id}/revoke", response_model=IssuedCredentialRecordResponse, summary="Revoke Issued Credential")
async def revoke_issued_credential(credential_id: str, request: Request) -> Response:
    """Revoke an issued credential lifecycle record."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/issued-credentials/{credential_id}/revoke", inject_headers=_ISSUANCE_HEADERS)


@issued_credential_router.post("/{credential_id}/suspend", response_model=IssuedCredentialRecordResponse, summary="Suspend Issued Credential")
async def suspend_issued_credential(credential_id: str, request: Request) -> Response:
    """Suspend an issued credential lifecycle record."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/issued-credentials/{credential_id}/suspend", inject_headers=_ISSUANCE_HEADERS)


@issued_credential_router.post("/{credential_id}/reinstate", response_model=IssuedCredentialRecordResponse, summary="Reinstate Issued Credential")
async def reinstate_issued_credential(credential_id: str, request: Request) -> Response:
    """Reinstate a suspended issued credential lifecycle record."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/issued-credentials/{credential_id}/reinstate", inject_headers=_ISSUANCE_HEADERS)


@issuance_router.get("/delivery-records/canvas-credentials/provenance", summary="Resolve Canvas Mirror Provenance")
async def get_canvas_mirror_provenance(request: Request) -> Response:
    """Resolve a Canvas mirror record to its canonical ElevenID issuance context."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/issuance/delivery-records/canvas-credentials/provenance")


@issuance_router.post("/delivery-records/canvas-credentials/process-pending", summary="Process Pending Canvas Mirror Deliveries")
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


@issuance_router.get("/organizations/{organization_id}/canvas-mirror-health", summary="Get Canvas Mirror Health")
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
    return await proxy_request(request, service_url, f"/v1/issuance/offers/{tx_id}", inject_headers=_ISSUANCE_HEADERS)


@issuance_router.post("/token", summary="Exchange Token")
async def exchange_token(request: Request) -> Response:
    """
    OID4VCI Token Endpoint.

    Exchange pre-authorized code for access token. This is called by wallets
    during the credential issuance flow.
    """
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/issuance/token", inject_headers=_ISSUANCE_HEADERS)


@issuance_router.post("/credential", summary="Issue Credential")
async def issue_credential(request: Request) -> Response:
    """
    OID4VCI Credential Endpoint.

    Issue a credential after successful token exchange. This is called by wallets
    to receive the actual credential.
    """
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/issuance/credential", inject_headers=_ISSUANCE_HEADERS)


@issuance_router.post("/par", summary="Pushed Authorization Request")
async def pushed_authorization_request(request: Request) -> Response:
    """
    RFC 9126 — Pushed Authorization Request (PAR).

    Wallet POSTs authorization parameters and receives a request_uri
    that can be used at the /authorize endpoint.
    """
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/issuance/par", inject_headers=_ISSUANCE_HEADERS)


@issuance_router.post("/nonce", summary="Get Fresh Nonce")
async def get_nonce(request: Request) -> Response:
    """
    OID4VCI Nonce Endpoint.

    Returns a fresh c_nonce for use in credential proof JWTs. Called by wallets
    after token exchange to refresh the nonce. No authentication required.
    """
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/issuance/nonce", inject_headers=_ISSUANCE_HEADERS)


@issuance_router.post("/notification", summary="Credential Notification")
async def credential_notification(request: Request) -> Response:
    """OID4VCI-1FINAL §11 — Wallet notifies issuer of credential lifecycle event."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/issuance/notification", inject_headers=_ISSUANCE_HEADERS)


@issuance_router.post("/deferred-credential", summary="Deferred Credential")
async def deferred_credential(request: Request) -> Response:
    """OID4VCI-1FINAL §9.1 — Poll for a deferred credential using a transaction_id."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/issuance/deferred-credential", inject_headers=_ISSUANCE_HEADERS)


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

@application_template_router.post("", response_model=ApplicationTemplateResponse, summary="Create Application Template")
async def create_application_template(body: ApplicationTemplateCreate, request: Request) -> Response:
    """Create an Application Template defining how users apply for credentials."""
    await _validate_application_template_dependencies(body, request)
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/application-templates", inject_headers=_ISSUANCE_HEADERS)


@application_template_router.get("", response_model=list[ApplicationTemplateResponse], summary="List Application Templates")
async def list_application_templates(
    organization_id: str = Query(..., description="Organization ID"),
    request: Request = None,
) -> Response:
    """List Application Templates for an organization."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/application-templates", inject_headers=_ISSUANCE_HEADERS)


@application_template_router.get("/{template_id}", response_model=ApplicationTemplateResponse, summary="Get Application Template")
async def get_application_template(template_id: str, request: Request) -> Response:
    """Get an Application Template by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/application-templates/{template_id}", inject_headers=_ISSUANCE_HEADERS)


@application_template_router.patch("/{template_id}", response_model=ApplicationTemplateResponse, summary="Update draft Application Template")
async def update_application_template(template_id: str, body: ApplicationTemplatePatch, request: Request) -> Response:
    """Patch mutable fields on a draft Application Template."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/application-templates/{template_id}", inject_headers=_ISSUANCE_HEADERS)


@application_template_router.delete("/{template_id}", summary="Delete Application Template")
async def delete_application_template(template_id: str, request: Request) -> Response:
    """Delete a draft Application Template."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/application-templates/{template_id}", inject_headers=_ISSUANCE_HEADERS)


@application_template_router.post("/{template_id}/validate", summary="Validate Application Template")
async def validate_application_template(template_id: str, request: Request) -> Response:
    """Return section-scoped validation errors without changing lifecycle state."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/application-templates/{template_id}/validate", inject_headers=_ISSUANCE_HEADERS)


@application_template_router.post("/{template_id}/activate", response_model=ApplicationTemplateResponse, summary="Activate Application Template")
async def activate_application_template(template_id: str, request: Request) -> Response:
    """Validate and activate a draft Application Template."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/application-templates/{template_id}/activate", inject_headers=_ISSUANCE_HEADERS)


@application_template_router.post("/{template_id}/deprecate", response_model=ApplicationTemplateResponse, summary="Deprecate Application Template")
async def deprecate_application_template(template_id: str, request: Request) -> Response:
    """Deprecate an active Application Template while preserving history."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/application-templates/{template_id}/deprecate", inject_headers=_ISSUANCE_HEADERS)


# ── Applications ─────────────────────────────────────────────────────

@application_router.post("", response_model=ApplicationResponse, summary="Create Application")
async def create_application(body: ApplicationCreate, request: Request) -> Response:
    """Create an Application from an Application Template."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/applications", inject_headers=_ISSUANCE_HEADERS)


@application_router.get("", response_model=list[ApplicationResponse], summary="List Applications")
async def list_applications(
    organization_id: str = Query(..., description="Organization ID"),
    status: str | None = Query(None, description="Filter by status"),
    request: Request = None,
) -> Response:
    """List Applications for an organization."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/applications", inject_headers=_ISSUANCE_HEADERS)


@application_router.get("/{application_id}", response_model=ApplicationResponse, summary="Get Application")
async def get_application(application_id: str, request: Request) -> Response:
    """Get an Application by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/applications/{application_id}", inject_headers=_ISSUANCE_HEADERS)


@application_router.get("/{application_id}/evidence-facts", summary="List Application Evidence Facts")
async def list_application_evidence_facts(application_id: str, request: Request) -> Response:
    """List normalized MIP evidence facts for an application."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        f"/v1/applications/{application_id}/evidence-facts",
        inject_headers=_ISSUANCE_HEADERS,
    )


@application_router.get("/{application_id}/evidence-summary", summary="Get Application Evidence Summary")
async def get_application_evidence_summary(application_id: str, request: Request) -> Response:
    """Get evidence facts, policy decision, and issuance transition metadata."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        f"/v1/applications/{application_id}/evidence-summary",
        inject_headers=_ISSUANCE_HEADERS,
    )


@application_router.post("/{application_id}/evidence/api-checks/{check_id}/run", summary="Run External Evidence API Check")
async def run_external_evidence_api_check(application_id: str, check_id: str, request: Request) -> Response:
    """Run a configured external evidence API check for an application."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        f"/v1/applications/{application_id}/evidence/api-checks/{check_id}/run",
        inject_headers=_ISSUANCE_HEADERS,
    )


@application_router.post("/evidence/reconcile", summary="Reconcile Canvas Evidence")
async def reconcile_application_evidence(request: Request) -> Response:
    """Recover Canvas evidence policy and approval-to-issuance transitions."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        "/v1/applications/evidence/reconcile",
        inject_headers=_ISSUANCE_HEADERS,
    )


@application_router.get("/evidence/reconciliation-report", summary="Canvas Evidence Reconciliation Report")
async def get_application_evidence_reconciliation_report(request: Request) -> Response:
    """Return a dry-run Canvas evidence reconciliation report."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        "/v1/applications/evidence/reconciliation-report",
        inject_headers=_ISSUANCE_HEADERS,
    )


@application_router.post("/{application_id}/submit-evidence", response_model=ApplicationResponse, summary="Submit Evidence")
async def submit_application_evidence(application_id: str, body: EvidenceSubmission, request: Request) -> Response:
    """Submit evidence for an Application."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/applications/{application_id}/submit-evidence", inject_headers=_ISSUANCE_HEADERS)


@application_router.post("/{application_id}/approve", response_model=ApplicationResponse, summary="Approve Application")
async def approve_application(application_id: str, request: Request) -> Response:
    """Approve an Application for credential issuance."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/applications/{application_id}/approve", inject_headers=_ISSUANCE_HEADERS)


@application_router.post("/{application_id}/reject", response_model=ApplicationResponse, summary="Reject Application")
async def reject_application(application_id: str, request: Request) -> Response:
    """Reject an Application."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/applications/{application_id}/reject", inject_headers=_ISSUANCE_HEADERS)


@application_router.post("/{application_id}/issuance-offer", summary="Generate Wallet Invite")
async def generate_issuance_offer(application_id: str, request: Request) -> Response:
    """Generate (or refresh) a wallet credential offer for an approved application.

    Returns offer_url, qr_payload, wallets deep-link list, email_payload, and expires_at.
    """
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/applications/{application_id}/issuance-offer", inject_headers=_ISSUANCE_HEADERS)


@application_router.get("/{application_id}/issuance-offer", summary="Get Wallet Invite (Applicant)")
async def get_issuance_offer(application_id: str, request: Request) -> Response:
    """Retrieve the current wallet credential offer for an application (applicant-facing).

    Returns 404 until an admin has generated the offer via POST.
    """
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/applications/{application_id}/issuance-offer", inject_headers=_ISSUANCE_HEADERS)


@application_router.get("/{application_id}/issuance-events", summary="List Issuance Events (Admin)")
async def get_application_issuance_events(application_id: str, request: Request) -> Response:
    """List all lifecycle events for an application (admin audit timeline).

    Returns events in chronological order covering the full issuance lifecycle:
    offer_generated, offer_viewed, offer_expired, credential_issued.
    """
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/applications/{application_id}/issuance-events", inject_headers=_ISSUANCE_HEADERS)
