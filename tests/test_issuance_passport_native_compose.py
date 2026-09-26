"""Source guards for default-off native passport cutover inputs."""

import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def _environment(path: str, service: str) -> dict[str, str]:
    source = yaml.safe_load((ROOT / path).read_text(encoding="utf-8"))
    return source["services"][service]["environment"]


def test_compose_exposes_both_passport_selectors_without_enabling_them() -> None:
    flow = _environment("docker-compose.base.yml", "flow")
    development = _environment(
        "docker-compose.profile.issuance-native.yml", "issuance-native"
    )
    beta = _environment("docker-compose.service.issuance-native.yml", "issuance-native")
    selfhost = _environment("docker-compose.selfhost.prod.yml", "issuance-native")
    selfhost_gateway = _environment("docker-compose.selfhost.prod.yml", "gateway")
    selfhost_flow = _environment("docker-compose.selfhost.prod.yml", "flow")
    assert (
        flow["PASSPORT_NATIVE_FLOW_ENABLED"] == "${PASSPORT_NATIVE_FLOW_ENABLED:-false}"
    )
    assert flow["PASSPORT_TENANT_API_KEYS"] == "${PASSPORT_TENANT_API_KEYS:-}"
    assert flow["PASSPORT_TENANT_API_KEYS_FILE"] == "${PASSPORT_TENANT_API_KEYS_FILE:-}"
    assert (
        selfhost_gateway["PASSPORT_NATIVE_GATEWAY_ENABLED"]
        == "${PASSPORT_NATIVE_GATEWAY_ENABLED:-false}"
    )
    assert (
        selfhost_flow["PASSPORT_NATIVE_FLOW_ENABLED"]
        == "${PASSPORT_NATIVE_FLOW_ENABLED:-false}"
    )
    assert "ISSUANCE_NATIVE_SERVICE_URL" not in selfhost_flow
    assert (
        selfhost_gateway["ISSUANCE_NATIVE_SERVICE_URL"] == "http://issuance-native:8005"
    )
    for consumer in (selfhost_gateway, selfhost_flow, selfhost):
        assert consumer["PASSPORT_TENANT_API_KEYS"] == flow["PASSPORT_TENANT_API_KEYS"]
        assert (
            consumer["PASSPORT_TENANT_API_KEYS_FILE"]
            == flow["PASSPORT_TENANT_API_KEYS_FILE"]
        )
    for native in (development, beta, selfhost):
        assert (
            native["PASSPORT_NATIVE_HTTP_ENABLED"]
            == "${PASSPORT_NATIVE_HTTP_ENABLED:-false}"
        )
        assert (
            native["PASSPORT_MANAGED_ISSUER_SIGNING_ENABLED"]
            == "${PASSPORT_MANAGED_ISSUER_SIGNING_ENABLED:-false}"
        )
        assert native["PASSPORT_KMS_ARTIFACTS_ENABLED"] == "${PASSPORT_KMS_ARTIFACTS_ENABLED:-false}"
        assert native["PASSPORT_KMS_CALLBACKS_ENABLED"] == "${PASSPORT_KMS_CALLBACKS_ENABLED:-false}"
        for key in (
            "PASSPORT_TENANT_API_KEYS",
            "PASSPORT_TENANT_API_KEYS_FILE",
            "PHYSICAL_DOCUMENT_ARTIFACT_KEY",
            "ICAO_DOCUMENT_SIGNER_URL",
            "ICAO_DOCUMENT_SIGNER_API_KEY",
            "PHYSICAL_DOCUMENT_ALLOW_SELF_SIGNED",
            "PERSONALIZATION_BUREAU_URL",
            "PERSONALIZATION_BUREAU_API_KEY",
            "PERSONALIZATION_BUREAU_WEBHOOK_SECRET",
        ):
            assert key in native
        assert native["PASSPORT_TENANT_API_KEYS"] == flow["PASSPORT_TENANT_API_KEYS"]
        assert (
            native["PASSPORT_TENANT_API_KEYS_FILE"]
            == flow["PASSPORT_TENANT_API_KEYS_FILE"]
        )
    assert (
        development["PHYSICAL_DOCUMENT_ALLOW_SELF_SIGNED"]
        == "${PHYSICAL_DOCUMENT_ALLOW_SELF_SIGNED:-false}"
    )
    assert (
        beta["PHYSICAL_DOCUMENT_ALLOW_SELF_SIGNED"]
        == "${PHYSICAL_DOCUMENT_ALLOW_SELF_SIGNED:-false}"
    )


def test_gateway_stays_legacy_until_tenant_key_boundary_is_qualified() -> None:
    contract = json.loads(
        (ROOT / "contracts/issuance-physical-passport-native.json").read_text(
            encoding="utf-8"
        )
    )
    coverage = json.loads(
        (ROOT / "contracts/issuance-native-coverage.json").read_text(encoding="utf-8")
    )
    routes = [
        route
        for route in coverage["native_http"]
        if route["path"].startswith("/v1/passport/")
    ]
    assert len(routes) == contract["gateway_cutover"]["native_route_count"] == 0
    gateway = json.loads(
        (ROOT / "contracts/gateway-routes.json").read_text(encoding="utf-8")
    )
    created = [
        route
        for route in gateway["routes"]
        if route["method"] == "POST" and route["path"] == "/v1/passport/applications"
    ]
    assert len(created) == 1 and created[0]["status_code"] == 201
    declared = {
        (route["method"], route["path"])
        for route in gateway["routes"]
        if route["path"].startswith("/v1/passport/")
    }
    webhook = contract["gateway_cutover"]["signed_webhook_path"]
    frozen = {(route["method"], route["path"]) for route in contract["routes"]}
    assert (
        len(declared)
        == contract["gateway_cutover"]["declared_gateway_route_count"]
        == 9
    )
    assert declared == frozen
    assert ("POST", webhook) in declared
    gateway_source = (ROOT / "rust/services/gateway/src/contract.rs").read_text(
        encoding="utf-8"
    )
    assert '("/v1/passport", "issuance")' in gateway_source
    assert contract["gateway_cutover"]["current_owner"] == "issuance"


def test_self_signed_test_image_is_explicit_opt_in() -> None:
    dockerfile = (ROOT / "services/Dockerfile").read_text(encoding="utf-8")
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    contract = json.loads(
        (ROOT / "contracts/issuance-physical-passport-native.json").read_text(
            encoding="utf-8"
        )
    )
    assert "ARG PASSPORT_SELF_SIGNED_TEST=false" in dockerfile
    assert (
        "true) set -- --features marty-issuance-service/passport-self-signed-test"
        in dockerfile
    )
    assert "PASSPORT_SELF_SIGNED_TEST must be true or false" in dockerfile
    assert "Verify opt-in passport test-mode image boundary" in workflow
    assert "--build-arg PASSPORT_SELF_SIGNED_TEST=true" in workflow
    assert (
        "PASSPORT_SELF_SIGNED_TEST=true"
        in contract["self_signed_test_signer"]["packaged_image_build_arg"]
    )
