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


def test_eudi_verifier_declares_https_at_its_public_boundary() -> None:
    profile = (ROOT / "docker-compose.profile.eudi.yml").read_text(encoding="utf-8")
    proxy = (ROOT / "services" / "eudi-verifier-tls" / "nginx.conf").read_text(encoding="utf-8")

    assert "eudi-verifier-tls:" in profile
    assert "EUDI_VERIFIER_TLS_HOST_PORT" in profile
    assert "proxy_pass http://eudi-verifier:8080" in proxy
    verifier_block = profile.split("  eudi-verifier-tls:", maxsplit=1)[0]
    assert "EUDI_VERIFIER_HOST_PORT" not in verifier_block
