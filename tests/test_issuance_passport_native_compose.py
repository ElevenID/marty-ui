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
    assert (
        flow["PASSPORT_NATIVE_FLOW_ENABLED"] == "${PASSPORT_NATIVE_FLOW_ENABLED:-false}"
    )
    assert flow["PASSPORT_TENANT_API_KEYS"] == "${PASSPORT_TENANT_API_KEYS:-}"
    assert flow["PASSPORT_TENANT_API_KEYS_FILE"] == "${PASSPORT_TENANT_API_KEYS_FILE:-}"
    for native in (development, beta):
        assert (
            native["PASSPORT_NATIVE_HTTP_ENABLED"]
            == "${PASSPORT_NATIVE_HTTP_ENABLED:-false}"
        )
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
        == 8
    )
    assert declared == frozen - {("POST", webhook)}
    assert ("POST", webhook) not in declared
    gateway_source = (ROOT / "rust/services/gateway/src/contract.rs").read_text(
        encoding="utf-8"
    )
    assert '("/v1/passport", "issuance")' in gateway_source
    assert contract["gateway_cutover"]["current_owner"] == "issuance"
