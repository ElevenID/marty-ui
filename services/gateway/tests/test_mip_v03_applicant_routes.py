from __future__ import annotations

from gateway.routes.applicants import applicant_router


def test_gateway_exposes_only_mip_v03_applicant_routes() -> None:
    paths = {route.path for route in applicant_router.routes}
    assert "/v1/me/applicant-profile" in paths
    assert "/v1/me/applications" in paths
    assert "/v1/organizations/{organization_id}/applicants" in paths
    assert "/v1/applicants/applications" not in paths
    assert "/v1/applicants/org-applications" not in paths
    assert all(not path.startswith("/v1/applicants/profiles") for path in paths)
