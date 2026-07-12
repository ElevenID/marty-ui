"""MIP 0.3 applicant self-service and organization review routes."""
from __future__ import annotations

import os

from fastapi import APIRouter, Request, Response

from gateway.proxy import get_registry, proxy_request


applicant_router = APIRouter(tags=["Applicants"])


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
_ISSUANCE_HEADERS = {"X-API-Key": _ISSUANCE_API_KEY} if _ISSUANCE_API_KEY else None


def _applicant_url() -> str:
    return get_registry().get_service_url("applicant")


def _issuance_url() -> str:
    return get_registry().get_service_url("issuance")


def _self_service_headers(request: Request) -> dict[str, str] | None:
    organization_id = str(getattr(request.state, "session_organization_id", "") or "").strip()
    return {"X-Organization-ID": organization_id} if organization_id else None


# Holder-owned profile and applications.

@applicant_router.get("/v1/me/applicant-profile", summary="Get My Applicant Profile")
async def get_my_applicant_profile(request: Request) -> Response:
    return await proxy_request(
        request,
        _applicant_url(),
        "/v1/me/applicant-profile",
        inject_headers=_self_service_headers(request),
    )


@applicant_router.patch("/v1/me/applicant-profile", summary="Update My Applicant Profile")
async def update_my_applicant_profile(request: Request) -> Response:
    return await proxy_request(
        request,
        _applicant_url(),
        "/v1/me/applicant-profile",
        inject_headers=_self_service_headers(request),
    )


@applicant_router.post("/v1/me/applicant-profile/biometrics", summary="Enroll My Biometric")
async def enroll_my_biometric(request: Request) -> Response:
    return await proxy_request(
        request,
        _applicant_url(),
        "/v1/me/applicant-profile/biometrics",
        inject_headers=_self_service_headers(request),
    )


@applicant_router.get("/v1/me/applications", summary="List My Applications")
async def list_my_applications(request: Request) -> Response:
    return await proxy_request(request, _applicant_url(), "/v1/me/applications")


@applicant_router.post("/v1/me/applications", summary="Create My Application")
async def create_my_application(request: Request) -> Response:
    return await proxy_request(request, _applicant_url(), "/v1/me/applications")


@applicant_router.get("/v1/me/applications/{application_id}", summary="Get My Application")
async def get_my_application(application_id: str, request: Request) -> Response:
    return await proxy_request(request, _applicant_url(), f"/v1/me/applications/{application_id}")


@applicant_router.post("/v1/me/applications/{application_id}/submit", summary="Submit My Application")
async def submit_my_application(application_id: str, request: Request) -> Response:
    return await proxy_request(request, _applicant_url(), f"/v1/me/applications/{application_id}/submit")


@applicant_router.post("/v1/me/applications/{application_id}/withdraw", summary="Withdraw My Application")
async def withdraw_my_application(application_id: str, request: Request) -> Response:
    return await proxy_request(request, _applicant_url(), f"/v1/me/applications/{application_id}/withdraw")


@applicant_router.post("/v1/me/applications/{application_id}/claim", summary="Claim My Credential")
async def claim_my_application(application_id: str, request: Request) -> Response:
    return await proxy_request(request, _applicant_url(), f"/v1/me/applications/{application_id}/claim")


# Organization-scoped reviewer and operator routes.

@applicant_router.get("/v1/organizations/{organization_id}/applicants", summary="List Organization Applicants")
async def list_organization_applicants(organization_id: str, request: Request) -> Response:
    return await proxy_request(
        request,
        _applicant_url(),
        f"/v1/organizations/{organization_id}/applicants",
    )


@applicant_router.get("/v1/organizations/{organization_id}/applicants/{application_id}", summary="Get Organization Applicant")
async def get_organization_applicant(organization_id: str, application_id: str, request: Request) -> Response:
    return await proxy_request(
        request,
        _applicant_url(),
        f"/v1/organizations/{organization_id}/applicants/{application_id}",
    )


async def _proxy_application_action(
    organization_id: str,
    application_id: str,
    action: str,
    request: Request,
) -> Response:
    return await proxy_request(
        request,
        _applicant_url(),
        f"/v1/organizations/{organization_id}/applicants/{application_id}/{action}",
    )


@applicant_router.post("/v1/organizations/{organization_id}/applicants/{application_id}/approve")
async def approve_organization_applicant(organization_id: str, application_id: str, request: Request) -> Response:
    return await _proxy_application_action(organization_id, application_id, "approve", request)


@applicant_router.post("/v1/organizations/{organization_id}/applicants/{application_id}/reject")
async def reject_organization_applicant(organization_id: str, application_id: str, request: Request) -> Response:
    return await _proxy_application_action(organization_id, application_id, "reject", request)


@applicant_router.post("/v1/organizations/{organization_id}/applicants/{application_id}/request-information")
async def request_organization_applicant_information(organization_id: str, application_id: str, request: Request) -> Response:
    return await _proxy_application_action(organization_id, application_id, "request-information", request)


@applicant_router.post("/v1/organizations/{organization_id}/applicants/{application_id}/withdraw")
async def withdraw_organization_applicant(organization_id: str, application_id: str, request: Request) -> Response:
    return await _proxy_application_action(organization_id, application_id, "withdraw", request)


@applicant_router.post("/v1/organizations/{organization_id}/applicants/{application_id}/issue")
async def issue_organization_applicant(organization_id: str, application_id: str, request: Request) -> Response:
    return await _proxy_application_action(organization_id, application_id, "issue", request)


@applicant_router.post("/v1/organizations/{organization_id}/applicants/{application_id}/lock")
async def acquire_organization_applicant_lock(organization_id: str, application_id: str, request: Request) -> Response:
    return await _proxy_application_action(organization_id, application_id, "lock", request)


@applicant_router.get("/v1/organizations/{organization_id}/applicants/{application_id}/lock")
async def get_organization_applicant_lock(organization_id: str, application_id: str, request: Request) -> Response:
    return await _proxy_application_action(organization_id, application_id, "lock", request)


@applicant_router.delete("/v1/organizations/{organization_id}/applicants/{application_id}/lock")
async def release_organization_applicant_lock(organization_id: str, application_id: str, request: Request) -> Response:
    return await _proxy_application_action(organization_id, application_id, "lock", request)


@applicant_router.get("/v1/organizations/{organization_id}/applicants/{application_id}/checks")
async def list_organization_applicant_checks(organization_id: str, application_id: str, request: Request) -> Response:
    return await _proxy_application_action(organization_id, application_id, "checks", request)


@applicant_router.post("/v1/organizations/{organization_id}/applicants/{application_id}/checks/{check_id}/start")
async def start_organization_applicant_check(organization_id: str, application_id: str, check_id: str, request: Request) -> Response:
    return await _proxy_application_action(organization_id, application_id, f"checks/{check_id}/start", request)


@applicant_router.post("/v1/organizations/{organization_id}/applicants/{application_id}/checks/{check_id}/complete")
async def complete_organization_applicant_check(organization_id: str, application_id: str, check_id: str, request: Request) -> Response:
    return await _proxy_application_action(organization_id, application_id, f"checks/{check_id}/complete", request)


@applicant_router.get("/v1/organizations/{organization_id}/applicants/{application_id}/evidence-summary")
async def get_organization_applicant_evidence_summary(organization_id: str, application_id: str, request: Request) -> Response:
    return await proxy_request(
        request,
        _issuance_url(),
        f"/v1/applications/{application_id}/evidence-summary",
        inject_headers=_ISSUANCE_HEADERS,
    )


@applicant_router.get("/v1/organizations/{organization_id}/applicants/{application_id}/evidence-facts")
async def list_organization_applicant_evidence_facts(organization_id: str, application_id: str, request: Request) -> Response:
    return await proxy_request(
        request,
        _issuance_url(),
        f"/v1/applications/{application_id}/evidence-facts",
        inject_headers=_ISSUANCE_HEADERS,
    )


@applicant_router.post("/v1/organizations/{organization_id}/applicants/{application_id}/evidence/api-checks/{check_id}/run")
async def run_organization_applicant_evidence_check(organization_id: str, application_id: str, check_id: str, request: Request) -> Response:
    return await proxy_request(
        request,
        _issuance_url(),
        f"/v1/applications/{application_id}/evidence/api-checks/{check_id}/run",
        inject_headers=_ISSUANCE_HEADERS,
    )
