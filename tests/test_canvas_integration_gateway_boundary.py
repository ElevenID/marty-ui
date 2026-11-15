import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / "contracts/canvas-integration-gateway-boundary.json"
GATEWAY_ROUTES = ROOT / "contracts/gateway-routes.json"
AUTHORIZATION = ROOT / "rust/services/gateway/src/authorization.rs"


def test_canvas_gateway_boundary_matrix_matches_current_route_inventory():
    matrix = json.loads(MATRIX.read_text(encoding="utf-8"))
    gateway = json.loads(GATEWAY_ROUTES.read_text(encoding="utf-8"))
    actual = {
        (route["method"], route["path"])
        for route in gateway["routes"]
        if route["path"].startswith("/v1/integrations/canvas/")
    }
    actual.update(
        {
            ("GET", "/v1/issuance/delivery-records/canvas-credentials/provenance"),
            ("POST", "/v1/issuance/delivery-records/canvas-credentials/process-pending"),
            ("POST", "/v1/issuance/delivery-records/canvas-credentials/process-status-sync-failures"),
            ("POST", "/v1/issuance/delivery-records/canvas-credentials/run-automation-cycle"),
            ("GET", "/v1/issuance/organizations/{organization_id}/canvas-mirror-health"),
        }
    )
    rows = matrix["routes"]
    observed = {(row["method"], row["path"]) for row in rows}
    assert len(observed) == len(rows), "matrix must not contain duplicate method/path pairs"
    assert observed == actual
    assert matrix["route_count"] == len(rows)


def test_canvas_gateway_boundary_scope_mapping_is_fail_closed():
    matrix = json.loads(MATRIX.read_text(encoding="utf-8"))
    authorization = AUTHORIZATION.read_text(encoding="utf-8")
    assert "pub fn resolve_action" in authorization
    assert "pub fn authorize_api_key" in authorization
    assert "pub fn skips_tenant_authorization" in authorization

    for row in matrix["routes"]:
        if row["target_owner"] == "canvas-integration public protocol edge":
            # These callbacks terminate at the connector; they are not API-key
            # exemptions for connector-to-core calls.
            assert row["current_api_key_scope"] is None
            assert "any core request uses API key" in row["target_auth"]
            continue

        permission = row["current_permission"]
        scope = row["current_api_key_scope"]
        assert permission is not None, row
        if permission == "integration-connector:view":
            assert scope == "integrations:read", row
        elif permission in {
            "integration-connector:create",
            "integration-connector:edit",
            "integration-connector:delete",
        }:
            assert scope == "integrations:write", row
        else:
            raise AssertionError(f"Unexpected Canvas integration permission: {permission}")

    assert sum(
        row["target_owner"] == "canvas-integration public protocol edge"
        for row in matrix["routes"]
    ) == 17
