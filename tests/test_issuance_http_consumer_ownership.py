import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_inventory_freezes_native_and_legacy_consumer_ownership():
    contract = json.loads(
        (ROOT / "contracts/issuance-http-consumer-ownership.json").read_text()
    )
    assert contract["schema"] == "marty.issuance-http-consumer-ownership/v1"
    assert contract["native_environment"] == "ISSUANCE_NATIVE_SERVICE_URL"
    assert contract["legacy_environment"] == "ISSUANCE_SERVICE_URL"
    assert set(contract["consumers"]) == {
        "auth",
        "applicant",
        "presentation-policy",
        "flow",
    }
    flow_legacy = set(contract["consumers"]["flow"]["legacy"])
    assert "GET /health" in flow_legacy
    universal = json.loads(
        (ROOT / "contracts/issuance-universal-ownership.json").read_text()
    )
    canonical_passport_operations = {
        f"{operation['method']} {operation['path']}"
        for operation in universal["retained_legacy_http"]
        if operation["path"].startswith("/v1/passport/applications")
    }
    assert flow_legacy - {"GET /health"} == canonical_passport_operations
    assert all(
        owner["authentication"] in {"bearer", "x-api-key"}
        for owner in contract["consumers"].values()
    )
    assert all(owner["tenant_binding"] for owner in contract["consumers"].values())


def test_source_wiring_keeps_native_reads_off_the_legacy_owner():
    auth = (ROOT / "rust/services/auth/src/config.rs").read_text()
    applicant = (ROOT / "rust/services/applicant/src/main.rs").read_text()
    policy = (ROOT / "rust/services/presentation-policy/src/config.rs").read_text()
    flow_config = (ROOT / "rust/services/flow/src/config.rs").read_text()
    flow_connections = (ROOT / "rust/services/flow/src/connections.rs").read_text()
    applicant_http = (ROOT / "rust/services/applicant/src/http.rs").read_text()
    policy_control = (
        ROOT / "rust/services/presentation-policy/src/control_plane.rs"
    ).read_text()
    flow_http = (ROOT / "rust/services/flow/src/http_providers.rs").read_text()

    assert "issuance_native_service_url" in auth
    assert "ISSUANCE_SERVICE_URL" not in auth
    assert (
        'env_value("ISSUANCE_NATIVE_SERVICE_URL", "http://issuance-native:8005")'
        in applicant
    )
    assert 'value(&values, "ISSUANCE_NATIVE_SERVICE_URL")' in policy
    assert '"ISSUANCE_NATIVE_SERVICE_URL"' in flow_config
    assert "&config.issuance_native_url" in flow_connections
    assert (
        "HttpPhysicalDocumentProvider::new(\n        &config.issuance_url"
        in flow_connections
    )
    assert applicant_http.count('.header("x-organization-id"') >= 2
    assert '.header("x-organization-id", organization_id.to_string())' in policy_control
    assert '"organization_id".into(),' in flow_http
    assert 'format!("v1/passport/applications/{application_id}/{suffix}")' in flow_http


def test_canvas_manual_routes_use_gateway_not_direct_native_or_legacy_ports():
    guide = (ROOT / "docs/CANVAS_LTI_LOGIN_SETUP.md").read_text()
    assert "dev-issuance-api-key" not in guide
    assert "localhost:8005/v1/integrations/canvas" not in guide
    assert (
        "${MARTY_API_BASE_URL:-http://localhost:8000}/v1/integrations/canvas" in guide
    )
    assert (
        '"${MARTY_API_BASE_URL:-http://localhost:8000}/v1/integrations/canvas/ags'
        not in guide
    )
    assert "CANVAS_LEGACY_EVENT_INGEST_ENABLED=true" in guide
    assert "CANVAS_DEMO_EVIDENCE_EVENT_ENABLED=true" in guide
