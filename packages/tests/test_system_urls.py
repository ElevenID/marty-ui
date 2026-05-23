from marty_common.system_urls import (
    build_marty_status_list_base_url,
    resolve_marty_issuer_base_url,
    resolve_marty_issuer_did,
    resolve_marty_public_domain,
)


def test_resolve_marty_issuer_base_url_prefers_explicit_envs(monkeypatch) -> None:
    monkeypatch.setenv("PUBLIC_API_URL", "https://public.example")
    monkeypatch.setenv("ISSUER_BASE_URL", "https://issuer.example")
    monkeypatch.setenv("MARTY_ISSUER_BASE_URL", "https://marty.example/")

    assert resolve_marty_issuer_base_url() == "https://marty.example"


def test_resolve_marty_public_domain_falls_back_to_issuer_base_url(monkeypatch) -> None:
    monkeypatch.delenv("PUBLIC_DOMAIN", raising=False)
    monkeypatch.setenv("ISSUER_BASE_URL", "https://issuer.example")
    monkeypatch.delenv("MARTY_ISSUER_BASE_URL", raising=False)
    monkeypatch.delenv("PUBLIC_API_URL", raising=False)

    assert resolve_marty_public_domain() == "issuer.example"


def test_resolve_marty_issuer_did_and_status_list_base_url_follow_runtime_conventions(monkeypatch) -> None:
    monkeypatch.delenv("MARTY_ISSUER_DID", raising=False)
    monkeypatch.setenv("PUBLIC_DOMAIN", "issuer.example")
    monkeypatch.setenv("MARTY_ORG_SLUG", "marty-prod")
    monkeypatch.setenv("ISSUER_BASE_URL", "https://issuer.example")
    monkeypatch.delenv("MARTY_ISSUER_BASE_URL", raising=False)
    monkeypatch.delenv("PUBLIC_API_URL", raising=False)

    assert resolve_marty_issuer_did() == "did:web:issuer.example:orgs:marty-prod"
    assert build_marty_status_list_base_url() == (
        "https://issuer.example/v1/organizations/00000000-0000-0000-0000-000000000001"
        "/revocation-profiles/70000000-0000-0000-0000-000000000001/status-lists/{mechanism}/{purpose}"
    )