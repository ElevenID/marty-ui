"""Keep the W3C VC test adapter unavailable outside its disposable overlay."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_w3c_profile_enables_only_the_fixture_adapter() -> None:
    profile = (ROOT / "docker-compose.profile.w3c-vc.yml").read_text(encoding="utf-8")

    assert 'W3C_VC_TEST_ADAPTER: "1"' in profile
    assert "W3C_VC_TEST_POLICY_ID" in profile
    assert "disposable fixture policy" in profile


def test_standard_oidf_profile_does_not_enable_w3c_adapter() -> None:
    oidf = (ROOT / "docker-compose.profile.oidf.yml").read_text(encoding="utf-8")

    assert 'W3C_VC_TEST_ADAPTER: "1"' not in oidf


def test_marty_conformance_stack_does_not_embed_the_eudi_reference_services() -> None:
    """EUDI references run in their own Compose project over the TLS bridge."""
    assert not (ROOT / "docker-compose.profile.eudi.yml").exists()
    assert not (ROOT / "docker-compose.profile.conformance-eudi.yml").exists()
