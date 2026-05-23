"""Applicant profile and application management routes."""
from __future__ import annotations

import os

from fastapi import APIRouter, Query, Request, Response

from gateway.proxy import get_registry, proxy_request

applicant_router = APIRouter(prefix="/v1/applicants", tags=["Applicants"])


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


@applicant_router.post("", summary="Create Applicant")
async def create_applicant(request: Request) -> Response:
    """Create an applicant profile."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, "/v1/applicants")


@applicant_router.get("/by-user/{user_id}", summary="Get Applicant by User ID")
async def get_applicant_by_user(user_id: str, request: Request) -> Response:
    """Get an applicant profile by user ID."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, f"/v1/applicants/by-user/{user_id}")


@applicant_router.get("/profiles/{applicant_id}", summary="Get Applicant")
async def get_applicant(applicant_id: str, request: Request) -> Response:
    """Get an applicant profile by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, f"/v1/applicants/profiles/{applicant_id}")


@applicant_router.patch("/profiles/{applicant_id}", summary="Update Applicant")
async def update_applicant(applicant_id: str, request: Request) -> Response:
    """Update an applicant profile."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, f"/v1/applicants/profiles/{applicant_id}")


@applicant_router.get("", summary="List Applicants")
async def list_applicants(
    organization_id: str = Query(None, description="Filter by organization"),
    request: Request = None,
) -> Response:
    """List applicant profiles."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, "/v1/applicants")


@applicant_router.post("/applications", summary="Create Application")
async def create_applicant_application(request: Request) -> Response:
    """Create an application for a credential."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, "/v1/applicants/applications")


@applicant_router.get("/org-applications", summary="List Organization Applications")
async def list_applicant_applications(request: Request) -> Response:
    """List applications for an organization queue."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, "/v1/applicants/org-applications")


@applicant_router.get("/applications/{application_id}", summary="Get Application")
async def get_applicant_application(application_id: str, request: Request) -> Response:
    """Get an application by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, f"/v1/applicants/applications/{application_id}")


@applicant_router.get("/applications/{application_id}/evidence-summary", summary="Get Application Evidence Summary")
async def get_applicant_application_evidence_summary(application_id: str, request: Request) -> Response:
    """Get MIP evidence facts and policy metadata for a Canvas-backed application."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        f"/v1/applications/{application_id}/evidence-summary",
        inject_headers=_ISSUANCE_HEADERS,
    )


@applicant_router.get("/applications/{application_id}/evidence-facts", summary="List Application Evidence Facts")
async def list_applicant_application_evidence_facts(application_id: str, request: Request) -> Response:
    """List normalized MIP evidence facts for a Canvas-backed application."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        f"/v1/applications/{application_id}/evidence-facts",
        inject_headers=_ISSUANCE_HEADERS,
    )


@applicant_router.post("/applications/{application_id}/evidence/api-checks/{check_id}/run", summary="Run Application Evidence API Check")
async def run_applicant_application_evidence_api_check(application_id: str, check_id: str, request: Request) -> Response:
    """Run a configured MIP external evidence API check for an application."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        f"/v1/applications/{application_id}/evidence/api-checks/{check_id}/run",
        inject_headers=_ISSUANCE_HEADERS,
    )


@applicant_router.post("/applications/{application_id}/submit", summary="Submit Application")
async def submit_applicant_application(application_id: str, request: Request) -> Response:
    """Submit an application for review."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, f"/v1/applicants/applications/{application_id}/submit")


@applicant_router.patch("/applications/{application_id}", summary="Update Application")
async def update_applicant_application(application_id: str, request: Request) -> Response:
    """Update application fields (admin)."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, f"/v1/applicants/applications/{application_id}")


@applicant_router.post("/applications/{application_id}/review", summary="Review Application")
async def review_applicant_application(application_id: str, request: Request) -> Response:
    """Review (approve/reject) an application."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, f"/v1/applicants/applications/{application_id}/review")


@applicant_router.post("/applications/{application_id}/supersede", summary="Supersede Application")
async def supersede_applicant_application(application_id: str, request: Request) -> Response:
    """Retire an active application before creating a replacement."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, f"/v1/applicants/applications/{application_id}/supersede")


@applicant_router.post("/applications/{application_id}/issue", summary="Issue Application")
async def issue_applicant_application(application_id: str, request: Request) -> Response:
    """Issue a credential for an approved application."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, f"/v1/applicants/applications/{application_id}/issue")


@applicant_router.post("/applications/{application_id}/auto-issue", summary="Auto-Issue Application")
async def auto_issue_applicant_application(application_id: str, request: Request) -> Response:
    """Atomically submit, approve, and issue a credential for an auto-approve application."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, f"/v1/applicants/applications/{application_id}/auto-issue")


@applicant_router.post("/applications/{application_id}/request-info", summary="Request More Info")
async def request_applicant_info(application_id: str, request: Request) -> Response:
    """Request additional information from an applicant."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, f"/v1/applicants/applications/{application_id}/request-info")


@applicant_router.get("/applications/{application_id}/checks", summary="Get Vetting Checks")
async def get_applicant_checks(application_id: str, request: Request) -> Response:
    """Get vetting checks for an application."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, f"/v1/applicants/applications/{application_id}/checks")


@applicant_router.get("/checks/pending", summary="Get Pending Checks")
async def get_pending_checks(request: Request) -> Response:
    """List pending vetting checks across all applications."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, "/v1/applicants/checks/pending")


@applicant_router.post("/checks/{check_id}/start", summary="Start Check")
async def start_applicant_check(check_id: str, request: Request) -> Response:
    """Start a vetting check."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, f"/v1/applicants/checks/{check_id}/start")


@applicant_router.post("/checks/{check_id}/complete", summary="Complete Check")
async def complete_applicant_check(check_id: str, request: Request) -> Response:
    """Complete a vetting check."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, f"/v1/applicants/checks/{check_id}/complete")


@applicant_router.post("/applications/{application_id}/lock", summary="Acquire Reviewer Lock")
async def acquire_applicant_lock(application_id: str, request: Request) -> Response:
    """Acquire a reviewer lock on an application."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, f"/v1/applicants/applications/{application_id}/lock")


@applicant_router.get("/applications/{application_id}/lock", summary="Get Lock Status")
async def get_applicant_lock(application_id: str, request: Request) -> Response:
    """Get the current reviewer lock status for an application."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, f"/v1/applicants/applications/{application_id}/lock")


@applicant_router.delete("/applications/{application_id}/lock", summary="Release Reviewer Lock")
async def release_applicant_lock(application_id: str, request: Request) -> Response:
    """Release a reviewer lock on an application."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, f"/v1/applicants/applications/{application_id}/lock")


@applicant_router.post("/profiles/{applicant_id}/biometrics", summary="Enroll Biometric")
async def enroll_applicant_biometric(applicant_id: str, request: Request) -> Response:
    """Enroll biometric data for an applicant."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, f"/v1/applicants/profiles/{applicant_id}/biometrics")


@applicant_router.get("/profiles/{applicant_id}/applications", summary="Get Applicant Applications")
async def get_applicant_applications(applicant_id: str, request: Request) -> Response:
    """Get applications for a specific applicant."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, f"/v1/applicants/profiles/{applicant_id}/applications")
