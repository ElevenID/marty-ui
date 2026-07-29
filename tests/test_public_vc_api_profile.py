"""Keep the public VC-API free of the retired test-only deployment switch."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_legacy_w3c_test_overlay_is_removed() -> None:
    assert not (ROOT / "docker-compose.profile.w3c-vc.yml").exists()
    oidf = (ROOT / "docker-compose.profile.oidf.yml").read_text(encoding="utf-8")
    assert 'W3C_VC_TEST_ADAPTER: "1"' not in oidf


def test_gateway_has_no_test_only_vc_api_switch() -> None:
    gateway = ROOT / "services" / "gateway"
    sources = "\n".join(
        path.read_text(encoding="utf-8")
        for path in gateway.rglob("*.py")
        if "__pycache__" not in path.parts
    )
    assert "W3C_VC_TEST_ADAPTER" not in sources
    assert "/__test__/vc-api" not in sources


def test_marty_conformance_stack_does_not_embed_the_eudi_reference_services() -> None:
    """EUDI references run in their own Compose project over the TLS bridge."""
    assert not (ROOT / "docker-compose.profile.eudi.yml").exists()
    assert not (ROOT / "docker-compose.profile.conformance-eudi.yml").exists()
