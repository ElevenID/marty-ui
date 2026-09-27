"""Source checks for the opt-in passport route consumer handoff."""

import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = json.loads(
    (ROOT / "contracts/passport-supported-consumer-routing.json").read_text()
)


def compose_environment(file: str, service: str) -> dict:
    if file == "docker-compose.base.yml" and service == "issuance-native":
        file = "docker-compose.profile.issuance-native.yml"
    model = yaml.safe_load((ROOT / file).read_text())
    return model["services"][service]["environment"]


def k8s_resources(file: str) -> list[dict]:
    return [item for item in yaml.safe_load_all((ROOT / file).read_text()) if item]


def k8s_container(file: str, name: str) -> dict:
    resource = next(
        item
        for item in k8s_resources(file)
        if item["kind"] == "Deployment" and item["metadata"]["name"] == name
    )
    return resource["spec"]["template"]["spec"]["containers"][0]


def test_route_fixture_matches_native_contract_and_gateway_declaration() -> None:
    assert CONTRACT["state"] == "opt_in_source_only_pending_acceptance"
    declared = {(route["method"], route["path"]) for route in CONTRACT["routes"]}
    native = json.loads((ROOT / "contracts/issuance-physical-passport-native.json").read_text())
    gateway = json.loads((ROOT / "contracts/gateway-routes.json").read_text())
    assert len(declared) == 9
    assert declared == {(route["method"], route["path"]) for route in native["routes"]}
    assert declared <= {
        (route["method"], route["path"])
        for route in gateway["routes"]
    }


def test_compose_consumers_keep_selectors_off_and_share_token_source() -> None:
    for file in ("docker-compose.base.yml", "docker-compose.selfhost.prod.yml"):
        gateway = compose_environment(file, "gateway")
        flow = compose_environment(file, "flow")
        owner = compose_environment(file, "issuance-native")
        assert gateway["PASSPORT_NATIVE_GATEWAY_ENABLED"] == "${PASSPORT_NATIVE_GATEWAY_ENABLED:-false}"
        assert flow["PASSPORT_NATIVE_FLOW_ENABLED"] == "${PASSPORT_NATIVE_FLOW_ENABLED:-false}"
        assert owner["PASSPORT_NATIVE_HTTP_ENABLED"] == "${PASSPORT_NATIVE_HTTP_ENABLED:-false}"
        assert all(
            env["PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED"]
            == "${PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED:-false}"
            for env in (gateway, flow, owner)
        )
        assert gateway["ISSUANCE_NATIVE_SERVICE_URL"] == "http://issuance-native:8005"
        if file == "docker-compose.selfhost.prod.yml":
            assert flow["ISSUANCE_NATIVE_SERVICE_URL"] == "${ISSUANCE_NATIVE_SERVICE_URL:-http://issuance:8005}"
            assert all(
                env["GRPC_SERVICE_TOKEN_FILE"] == "/run/secrets/grpc_service_token"
                for env in (gateway, flow, owner)
            )
            model = yaml.safe_load((ROOT / file).read_text())
            assert model["secrets"]["grpc_service_token"]["file"]
            assert all("grpc_service_token" in model["services"][name]["secrets"] for name in ("gateway", "flow", "issuance-native"))
        else:
            assert flow["ISSUANCE_NATIVE_SERVICE_URL"] == "http://issuance-native:8005"
            assert all(env["GRPC_SERVICE_TOKEN"] == "${GRPC_SERVICE_TOKEN:-dev-grpc-service-token-change-before-production}" for env in (gateway, flow, owner))


def test_selfhost_flow_reference_catalog_keeps_legacy_default_until_explicit_override() -> None:
    flow = compose_environment("docker-compose.selfhost.prod.yml", "flow")
    setting = flow["ISSUANCE_NATIVE_SERVICE_URL"]
    prefix, fallback = setting.removeprefix("${").removesuffix("}").split(":-", 1)
    assert prefix == "ISSUANCE_NATIVE_SERVICE_URL"
    assert fallback == flow["ISSUANCE_SERVICE_URL"] == "http://issuance:8005"
    assert flow["PASSPORT_NATIVE_FLOW_ENABLED"] == "${PASSPORT_NATIVE_FLOW_ENABLED:-false}"
    assert "http://issuance-native:8005" != fallback
    connections = (ROOT / "rust/services/flow/src/connections.rs").read_text()
    assert "HttpFlowReferenceProvider::new(\n        &config.issuance_native_url," in connections
    assert "HttpPhysicalDocumentProvider::new_tenant_bound(&config.issuance_native_url, keys)" in connections
    assert "HttpPhysicalDocumentProvider::new(\n            &config.issuance_url," in connections
    config = (ROOT / "rust/services/flow/src/config.rs").read_text()
    assert "if passport_native_flow_enabled && issuance_native_url == issuance_url" in config
    # Setting ISSUANCE_NATIVE_SERVICE_URL to the native DNS is the explicit
    # post-acceptance override; the Flow config rejects a selected legacy URL.
    assert "http://issuance-native:8005" != fallback


def test_kubernetes_consumers_default_off_and_use_exact_token_secret() -> None:
    common = k8s_resources("k8s/oracle/01-configmap.yaml")[0]["data"]
    for flag in (
        "PASSPORT_NATIVE_GATEWAY_ENABLED",
        "PASSPORT_NATIVE_FLOW_ENABLED",
        "PASSPORT_NATIVE_HTTP_ENABLED",
        "PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED",
        "PASSPORT_MANAGED_ISSUER_SIGNING_ENABLED",
        "PASSPORT_KMS_ARTIFACTS_ENABLED",
        "PASSPORT_KMS_CALLBACKS_ENABLED",
    ):
        assert common[flag] == "false"
    gateway = k8s_container("k8s/oracle/07-microservices.yaml", "gateway")
    flow = k8s_container("k8s/oracle/07-microservices.yaml", "flow")
    owner = k8s_container("k8s/oracle/07a-issuance-native.yaml", "issuance-native")
    for consumer in (gateway, flow, owner):
        token = next(item for item in consumer["env"] if item["name"] == "GRPC_SERVICE_TOKEN")
        assert token["valueFrom"]["secretKeyRef"] == {
            "name": "marty-secrets",
            "key": "GRPC_SERVICE_TOKEN",
        }
    assert {"configMapRef": {"name": "marty-config"}} in gateway["envFrom"]
    assert {"configMapRef": {"name": "marty-config"}} in flow["envFrom"]
    inherited = (ROOT / "rust/crates/release-evidence/src/kubernetes_native.rs").read_text()
    for flag in (
        "PASSPORT_NATIVE_HTTP_ENABLED",
        "PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED",
        "PASSPORT_MANAGED_ISSUER_SIGNING_ENABLED",
        "PASSPORT_KMS_ARTIFACTS_ENABLED",
        "PASSPORT_KMS_CALLBACKS_ENABLED",
    ):
        assert f'"{flag}",' in inherited.split("pub const INHERITED_SETTINGS", 1)[1].split("];", 1)[0]
