"""Issuance, Issued Credentials, OID4VCI wallet endpoints, Application Templates, and Applications."""
from __future__ import annotations

import os
from fastapi import APIRouter, HTTPException, Query, Request, Response

from gateway.models import (
    ApplicationCreate,
    ApplicationResponse,
    ApplicationTemplateCreate,
    ApplicationTemplateResponse,
    DidcommDeliverRequest,
    DidcommDeliveryResponse,
    EvidenceSubmission,
    IssuanceCreate,
    IssuanceResponse,
    IssuedCredentialRecordResponse,
)
from gateway.proxy import _resource_org_id, get_registry, proxy_request

_ISSUANCE_API_KEY = os.environ.get("ISSUANCE_API_KEY", "")

_ISSUANCE_HEADERS: dict[str, str] | None = (
    {"X-API-Key": _ISSUANCE_API_KEY} if _ISSUANCE_API_KEY else None
)

issuance_router = APIRouter(prefix="/v1/issuance", tags=["Issuance"])
issued_credential_router = APIRouter(prefix="/v1/issued-credentials", tags=["Issued Credentials"])
application_template_router = APIRouter(prefix="/v1/application-templates", tags=["Application Templates"])
application_router = APIRouter(prefix="/v1/applications", tags=["Applications"])


# ── Issuance ─────────────────────────────────────────────────────────

@issuance_router.post("", response_model=IssuanceResponse, summary="Create Issuance")
async def create_issuance(body: IssuanceCreate, request: Request) -> Response:
    """Initiate credential issuance for a subject (directly or via Application)."""
    if body.credential_template_id:
        owner_org = await _resource_org_id("credential-templates", f"/v1/credential-templates/{body.credential_template_id}", request)
        if owner_org is None:
            raise HTTPException(status_code=404, detail=f"Credential template not found: {body.credential_template_id}")
        if owner_org != body.organization_id:
            raise HTTPException(status_code=403, detail="Access denied: credential template belongs to another organization")
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/issuance/initiate", inject_headers=_ISSUANCE_HEADERS)


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


@application_template_router.put("/{template_id}", response_model=ApplicationTemplateResponse, summary="Update Application Template")
async def update_application_template(template_id: str, body: ApplicationTemplateCreate, request: Request) -> Response:
    """Update an Application Template."""
    await _validate_application_template_dependencies(body, request)
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/application-templates/{template_id}", inject_headers=_ISSUANCE_HEADERS)


@application_template_router.delete("/{template_id}", summary="Delete Application Template")
async def delete_application_template(template_id: str, request: Request) -> Response:
    """Delete an Application Template."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/application-templates/{template_id}", inject_headers=_ISSUANCE_HEADERS)


@application_template_router.post("/{template_id}/activate", response_model=ApplicationTemplateResponse, summary="Activate Application Template")
async def activate_application_template(template_id: str, request: Request) -> Response:
    """Activate an Application Template."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/application-templates/{template_id}/activate", inject_headers=_ISSUANCE_HEADERS)


@application_template_router.post("/validate-artifacts", summary="Validate Issuer Artifacts")
async def validate_application_artifacts(request: Request) -> Response:
    """Validate issuer artifacts (keys, certificates, DIDs) for an Application Template."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/application-templates/validate-artifacts", inject_headers=_ISSUANCE_HEADERS)


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
