from __future__ import annotations

import inspect
import json
from pathlib import Path

import yaml

from scripts import conformance_stack


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = json.loads(
    (ROOT / "contracts/issuance-universal-ownership.json").read_text(encoding="utf-8")
)


def _json(path: str) -> dict:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def _route_keys(routes: list[dict]) -> set[tuple[str, str]]:
    return {(route["method"], route["path"]) for route in routes}


def test_exact_runtime_remainder_stays_on_python_without_hiding_migrated_routes() -> (
    None
):
    coverage = _json(CONTRACT["native_coverage"])
    surface = _json(CONTRACT["runtime_surface"])
    native = _route_keys(coverage["native_http"])
    complete = _route_keys(surface["http"]["routes"])
    retained = _route_keys(CONTRACT["retained_legacy_http"])

    assert len(complete) == 131
    assert len(native) == 120
    assert retained == complete - native
    assert len(retained) == coverage["remaining"]["http"] == 11
    runtime_grpc = {row["method"] for row in surface["grpc"]["methods"]}
    assert set(coverage["native_grpc"]) == runtime_grpc
    assert len(coverage["native_grpc"]) == len(surface["grpc"]["methods"]) == 12
    assert len(runtime_grpc) == surface["grpc"]["method_count"] == 12
    assert coverage["remaining"]["grpc"] == 0


def test_default_compose_selects_native_and_keeps_only_the_explicit_legacy_owner() -> (
    None
):
    model = yaml.safe_load(
        (ROOT / CONTRACT["default_compositions"]["compose"]).read_text()
    )
    services = model["services"]
    assert {CONTRACT["default_owner"], CONTRACT["retained_legacy_owner"]} <= set(
        services
    )
    assert services["gateway"]["environment"]["ISSUANCE_NATIVE_SERVICE_URL"] == (
        "http://issuance-native:8005"
    )
    assert services["flow"]["environment"]["ISSUANCE_GRPC_TARGET"] == (
        "issuance-native:9005"
    )
    assert services["issuance"]["environment"]["DIDCOMM_DELIVERY_OWNER"] == "native"


def test_default_conformance_kubernetes_and_envoy_select_native() -> None:
    signature = inspect.signature(conformance_stack.compose_command)
    assert signature.parameters["issuance_owner"].default == "native"

    kubernetes = (ROOT / CONTRACT["default_compositions"]["kubernetes"]).read_text(
        encoding="utf-8"
    )
    assert (
        'K8S_ISSUANCE_NATIVE_ENABLED="${K8S_ISSUANCE_NATIVE_ENABLED-true}"'
        in kubernetes
    )

    envoy = yaml.safe_load(
        (ROOT / CONTRACT["default_compositions"]["envoy"]).read_text()
    )
    clusters = {
        cluster["name"]: cluster for cluster in envoy["static_resources"]["clusters"]
    }
    native = clusters["issuance_native_grpc"]
    endpoint = native["load_assignment"]["endpoints"][0]["lb_endpoints"][0]["endpoint"]
    assert endpoint["address"]["socket_address"] == {
        "address": "issuance-native",
        "port_value": 9005,
    }
    routes = envoy["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][
        0
    ]["typed_config"]["route_config"]["virtual_hosts"][0]["routes"]
    issuance = [
        route
        for route in routes
        if route["match"]
        .get("prefix", "")
        .startswith(("/marty.ui.issuance.v1.IssuanceService/", "/v1/issuance/"))
    ]
    assert len(issuance) == 2
    assert {route["route"]["cluster"] for route in issuance} == {"issuance_native_grpc"}


def test_direct_first_party_clients_use_gateway_not_a_python_host_port() -> None:
    for relative in [
        "scripts/check_template_wallets.py",
        "scripts/debug_issuance_response.py",
        "scripts/test_credential_format.py",
        "scripts/seed_canvas_real.py",
    ]:
        source = (ROOT / relative).read_text(encoding="utf-8")
        assert "localhost:8005" not in source, relative
    assert CONTRACT["direct_client_boundary"] == "gateway"


def test_credential_format_diagnostic_authenticates_gateway_initiation() -> None:
    source = (ROOT / "scripts/test_credential_format.py").read_text(encoding="utf-8")
    assert "resolve_gateway_actor" in source
    assert 'headers={"X-API-Key": api_key}' in source
    assert 'f"{api_base_url}/v1/issuance/initiate"' in source


def test_all_moved_diagnostics_use_the_shared_gateway_actor_boundary() -> None:
    for relative in [
        "scripts/test_credential_format.py",
        "scripts/debug_issuance_response.py",
        "scripts/seed_canvas_real.py",
    ]:
        source = (ROOT / relative).read_text(encoding="utf-8")
        assert "resolve_gateway_actor" in source, relative
        assert '"dev-issuance-api-key"' not in source, relative
    helper = (ROOT / "scripts/operator_gateway.py").read_text(encoding="utf-8")
    assert 'values.get("MARTY_API_KEY", "").strip()' in helper
    assert 'values.get("ISSUANCE_API_KEY"' not in helper


def test_production_and_kms_boundaries_remain_explicit() -> None:
    production = yaml.safe_load((ROOT / CONTRACT["production_composition"]).read_text())
    services = production["services"]
    issuance_environment = services["issuance"]["environment"]
    assert "DIDCOMM_DELIVERY_OWNER" not in issuance_environment
    assert "ISSUANCE_NATIVE_SERVICE_URL" not in issuance_environment

    # Universal native ownership is a beta/default-composition change.  Keep
    # every production HTTP consumer on its previously selected legacy owner;
    # checking only the issuance service itself would miss a consumer cutover.
    for service_name in ("auth", "applicant", "presentation-policy", "flow"):
        environment = services[service_name]["environment"]
        assert environment["ISSUANCE_SERVICE_URL"] == "http://issuance:8005"
        assert "ISSUANCE_NATIVE_SERVICE_URL" not in environment

    presentation_environment = services["presentation-policy"]["environment"]
    assert presentation_environment["MIP_CREDENTIAL_STATUS_URL_TEMPLATE"] == (
        "${MIP_CREDENTIAL_STATUS_URL_TEMPLATE:-http://issuance:8005/v1/issuance/"
        "credentials/{credential_id}/status}"
    )
    assert services["flow"]["environment"]["ISSUANCE_GRPC_TARGET"] == (
        "issuance-native:9005"
    )
    for service_name in ("auth", "applicant", "presentation-policy"):
        assert "issuance-native" not in services[service_name].get("depends_on", {})
    assert {"issuance", "issuance-native"}.isdisjoint(
        services["flow"].get("depends_on", {})
    )

    assert CONTRACT["production_unchanged"] is True
    assert CONTRACT["production_http_owner"] == {
        "consumers": ["auth", "applicant", "presentation-policy", "flow"],
        "selected_environment_variable": "ISSUANCE_SERVICE_URL",
        "runtime_precedence": [
            "ISSUANCE_NATIVE_SERVICE_URL",
            "ISSUANCE_SERVICE_URL",
            "development_native_default",
        ],
        "flow_grpc_owner": "issuance-native",
    }
    assert CONTRACT["python_deletion_authorized"] is False
    retirement = CONTRACT["rust_owned_python_retirement"]
    assert retirement == {
        "authorized": True,
        "scope": [
            "oid4vci-public-and-management-http",
            "canvas-mirror-http",
            "canvas-mirror-automation-loop",
        ],
        "retained_http_route_count": 11,
        "packaged_main_lifecycle_gate": (
            "canvas_mirror_worker_enabled_packaged_main_runs_and_shuts_down_cleanly"
        ),
        "full_python_service_deletion_authorized": False,
    }
    published = (
        ROOT
        / "rust/services/issuance/tests/canvas_published_schema_contract.rs"
    ).read_text(encoding="utf-8")
    lifecycle = (
        ROOT
        / "rust/services/issuance/tests/support/canvas_status_runtime_contract.rs"
    ).read_text(encoding="utf-8")
    assert retirement["packaged_main_lifecycle_gate"] in published
    for evidence in (
        'env("CANVAS_MIRROR_WORKER_ENABLED", "true")',
        'args(["-TERM", &child.0.id().to_string()])',
        'external_credential_id=\'automation-external\'',
        'stderr.contains("Issuance shutdown requested")',
    ):
        assert evidence in lifecycle
    assert CONTRACT["deferred"] == ["DIDCOMM-KMS-001"]
