"""Source checks for the opt-in passport route consumer handoff."""

import json
import os
from pathlib import Path
import re
import shutil
import subprocess

import pytest
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


def named_k8s_container(resources: list[dict], name: str) -> dict:
    deployments = [
        item
        for item in resources
        if item["kind"] == "Deployment" and item["metadata"]["name"] == name
    ]
    assert len(deployments) == 1, f"Expected one {name} Deployment"
    deployment = deployments[0]
    assert deployment["metadata"]["namespace"] == "marty-prod", f"Wrong {name} namespace"
    containers = [
        item
        for item in deployment["spec"]["template"]["spec"]["containers"]
        if item["name"] == name
    ]
    assert len(containers) == 1, f"Expected one {name} container"
    return containers[0]


def k8s_container(file: str, name: str) -> dict:
    return named_k8s_container(k8s_resources(file), name)


@pytest.mark.parametrize(
    "mutation", ["duplicate-deployment", "wrong-namespace", "missing-container", "duplicate-container"]
)
def test_k8s_consumer_requires_unique_deployment_and_named_container(mutation: str) -> None:
    resources = k8s_resources("k8s/oracle/07-microservices.yaml")
    assert named_k8s_container(resources, "flow")["name"] == "flow"
    deployment = next(
        item
        for item in resources
        if item["kind"] == "Deployment" and item["metadata"]["name"] == "flow"
    )
    if mutation == "duplicate-deployment":
        resources.append(deployment.copy())
    elif mutation == "wrong-namespace":
        deployment["metadata"]["namespace"] = "other-synthetic-namespace"
    elif mutation == "missing-container":
        deployment["spec"]["template"]["spec"]["containers"][0]["name"] = "other"
    else:
        deployment["spec"]["template"]["spec"]["containers"].append(
            deployment["spec"]["template"]["spec"]["containers"][0].copy()
        )
    expected = {
        "duplicate-deployment": "Expected one flow Deployment",
        "wrong-namespace": "Wrong flow namespace",
        "missing-container": "Expected one flow container",
        "duplicate-container": "Expected one flow container",
    }[mutation]
    with pytest.raises(AssertionError, match=expected):
        named_k8s_container(resources, "flow")


def test_k8s_consumer_selects_named_container_after_unrelated_sidecar() -> None:
    resources = k8s_resources("k8s/oracle/07-microservices.yaml")
    deployment = next(
        item
        for item in resources
        if item["kind"] == "Deployment" and item["metadata"]["name"] == "flow"
    )
    containers = deployment["spec"]["template"]["spec"]["containers"]
    selected = containers[0]
    containers.insert(0, {"name": "unrelated-synthetic-sidecar", "env": []})
    assert named_k8s_container(resources, "flow") is selected


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
    acceptance = CONTRACT["software_route_acceptance"]
    assert acceptance["provider_kind"] == "simulator"
    assert acceptance["physical_claim"] == "not_claimed"
    assert acceptance["bureau_profile_id"] == "passport-beta-bureau"
    assert acceptance["physical_booklet_required"] is False


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
            assert flow["ISSUANCE_NATIVE_SERVICE_URL"] == CONTRACT["consumers"]["selfhost_compose"]["native_url_default"]
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


def test_selfhost_flow_uses_native_owner_while_passport_routes_remain_opt_in() -> None:
    flow = compose_environment("docker-compose.selfhost.prod.yml", "flow")
    assert flow["ISSUANCE_NATIVE_SERVICE_URL"] == "http://issuance-native:8005"
    assert flow["ISSUANCE_SERVICE_URL"] == "http://issuance:8005"
    assert flow["PASSPORT_NATIVE_FLOW_ENABLED"] == "${PASSPORT_NATIVE_FLOW_ENABLED:-false}"
    for profile in ("docker-compose.profile.passport-native-beta.yml",
                    "docker-compose.profile.passport-native-physical-beta.yml"):
        beta_flow = compose_environment(profile, "flow")
        assert beta_flow["ISSUANCE_NATIVE_SERVICE_URL"] == "http://issuance-native:8005"
        assert beta_flow["PASSPORT_NATIVE_FLOW_ENABLED"] == "true"
    connections = (ROOT / "rust/services/flow/src/connections.rs").read_text()
    assert "HttpFlowReferenceProvider::new(\n        &config.issuance_native_url," in connections
    assert "HttpPhysicalDocumentProvider::new_tenant_bound(&config.issuance_native_url, keys)" in connections
    assert "HttpPhysicalDocumentProvider::new(\n            &config.issuance_url," in connections
    config = (ROOT / "rust/services/flow/src/config.rs").read_text()
    assert "if passport_native_flow_enabled && issuance_native_url == issuance_url" in config
    assert "else if environment == Environment::Production" in config
    assert "issuance_url.clone()" in config


@pytest.mark.parametrize(
    ("native_url", "enabled", "expected"),
    [
        (None, "false", "http://issuance-native:8005"),
        ("http://issuance-native:8005", "true", "http://issuance-native:8005"),
    ],
)
def test_standalone_selfhost_compose_renders_native_flow_override(
    tmp_path: Path, native_url: str | None, enabled: str, expected: str
) -> None:
    if shutil.which("docker") is None:
        pytest.skip("Docker Compose is unavailable")
    source = (ROOT / "docker-compose.selfhost.prod.yml").read_text(encoding="utf-8")
    environment = os.environ.copy()
    environment.pop("ISSUANCE_NATIVE_SERVICE_URL", None)
    for name in re.findall(r"\$\{([A-Z][A-Z0-9_]*):\?", source):
        environment.setdefault(name, "synthetic-contract-value")
    environment.update(
        SELFHOST_STATE_DIR=str(tmp_path / "state"),
        SELFHOST_SECRET_DIR=str(tmp_path / "secrets"),
        KEYCLOAK_SOCIAL_LOGIN_ENABLED="false",
        PASSPORT_NATIVE_GATEWAY_ENABLED=enabled,
        PASSPORT_NATIVE_FLOW_ENABLED=enabled,
        PASSPORT_NATIVE_HTTP_ENABLED=enabled,
    )
    if native_url is not None:
        environment["ISSUANCE_NATIVE_SERVICE_URL"] = native_url
    rendered = subprocess.run(
        ["docker", "compose", "-f", "docker-compose.selfhost.prod.yml", "config", "--format", "json"],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=True,
    )
    services = json.loads(rendered.stdout)["services"]
    flow = services["flow"]["environment"]
    assert flow["ISSUANCE_SERVICE_URL"] == "http://issuance:8005"
    assert flow["ISSUANCE_NATIVE_SERVICE_URL"] == expected
    assert flow["PASSPORT_NATIVE_FLOW_ENABLED"] == enabled
    assert services["gateway"]["environment"]["PASSPORT_NATIVE_GATEWAY_ENABLED"] == enabled
    assert services["issuance-native"]["environment"]["PASSPORT_NATIVE_HTTP_ENABLED"] == enabled


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
    assert common["PERSONALIZATION_BUREAU_URL"] == ""
    bureau_url = next(item for item in owner["env"] if item["name"] == "PERSONALIZATION_BUREAU_URL")
    assert bureau_url["valueFrom"]["configMapKeyRef"] == {
        "name": "marty-config",
        "key": "PERSONALIZATION_BUREAU_URL",
    }
    bureau_key = next(item for item in owner["env"] if item["name"] == "PERSONALIZATION_BUREAU_API_KEY")
    assert bureau_key["valueFrom"]["secretKeyRef"] == {
        "name": "marty-secrets",
        "key": "PERSONALIZATION_BUREAU_API_KEY",
        "optional": True,
    }
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
