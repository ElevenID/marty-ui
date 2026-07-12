from __future__ import annotations

from applicant.main import app


def test_only_mip_v03_applicant_routes_are_registered() -> None:
    paths = {route.path for route in app.routes}
    assert "/v1/me/applicant-profile" in paths
    assert "/v1/me/applications" in paths
    assert "/v1/organizations/{organization_id}/applicants/{application_id}/lock" in paths
    assert "/v1/applicants/applications" not in paths
    assert "/v1/applicants/org-applications" not in paths
    assert "/v1/applicants/profiles/{applicant_id}" not in paths
    assert "/v1/applicants/by-user/{user_id}" not in paths
