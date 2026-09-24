"""Source guards for default-off native passport cutover inputs."""

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
