import base64
import json

import pytest

from services.auth.domain.entities import AuthenticatedUser
from services.auth.infrastructure.adapters.http_adapter import (
    _CREDENTIAL_LOGIN_JS,
    _build_credential_login_wallet_options,
    _render_credential_login_page,
    get_current_user,
)
from services.auth.infrastructure.adapters.oidc_adapter import build_oidc_user_info


def _encode_base64url(payload: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8").rstrip("=")


def _build_jwt(claims: dict) -> str:
    return ".".join([
        _encode_base64url({"alg": "none", "typ": "JWT"}),
        _encode_base64url(claims),
        "signature",
    ])


def test_build_oidc_user_info_merges_keycloak_roles_and_org_claims():
    id_token = _build_jwt({
        "sub": "kc-user-1",
        "email": "alice@example.com",
        "given_name": "Alice",
        "family_name": "Smith",
        "preferred_username": "alice",
        "organization": {
            "org-1": {"name": "Acme"},
            "org-2": {"name": "Beta"},
        },
    })
    access_token = _build_jwt({
        "realm_access": {"roles": ["vendor"]},
        "resource_access": {
            "marty-ui": {"roles": ["organization-admin"]},
            "marty-api": {"roles": ["api-user"]},
        },
        "roles": ["administrator"],
    })

    oidc_user = build_oidc_user_info(id_token=id_token, access_token=access_token)

    assert oidc_user.sub == "kc-user-1"
    assert oidc_user.organization == {
        "org-1": {"name": "Acme"},
        "org-2": {"name": "Beta"},
    }
    assert oidc_user.organization_id == "org-1"
    assert oidc_user.organization_name == "Acme"
    assert oidc_user.roles == ["administrator", "vendor", "organization-admin", "api-user"]


@pytest.mark.asyncio
async def test_get_current_user_includes_raw_keycloak_organization_claim():
    user = AuthenticatedUser(
        user_id="user-1",
        email="alice@example.com",
        roles=["applicant"],
        organization_id="org-1",
        organization_name="Acme",
        organization={"org-1": {"name": "Acme"}},
    )

    response = await get_current_user(user)

    assert response.authenticated is True
    assert response.user is not None
    assert response.user.organization == {"org-1": {"name": "Acme"}}


def test_build_credential_login_wallet_options_defaults_to_protocol_sprucekit_then_lissi(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("CREDENTIAL_LOGIN_LISSI_DEEP_LINK_TEMPLATE", raising=False)
    monkeypatch.delenv("CREDENTIAL_LOGIN_LISSI_ANDROID_DEEP_LINK_TEMPLATE", raising=False)
    monkeypatch.delenv("CREDENTIAL_LOGIN_LISSI_IOS_DEEP_LINK_TEMPLATE", raising=False)
    monkeypatch.delenv("CREDENTIAL_LOGIN_LISSI_IOS_UNIVERSAL_LINK_TEMPLATE", raising=False)
    monkeypatch.delenv("CREDENTIAL_LOGIN_LISSI_ANDROID_PACKAGE", raising=False)
    monkeypatch.delenv("CREDENTIAL_LOGIN_SPRUCEKIT_DEEP_LINK_TEMPLATE", raising=False)
    monkeypatch.delenv("CREDENTIAL_LOGIN_SPRUCEKIT_ANDROID_DEEP_LINK_TEMPLATE", raising=False)
    monkeypatch.delenv("CREDENTIAL_LOGIN_SPRUCEKIT_IOS_DEEP_LINK_TEMPLATE", raising=False)
    monkeypatch.delenv("CREDENTIAL_LOGIN_SPRUCEKIT_IOS_UNIVERSAL_LINK_TEMPLATE", raising=False)
    monkeypatch.delenv("CREDENTIAL_LOGIN_SPRUCEKIT_ANDROID_PACKAGE", raising=False)
    monkeypatch.delenv("CREDENTIAL_LOGIN_LUCY_DEEP_LINK_TEMPLATE", raising=False)

    options = _build_credential_login_wallet_options(
        oid4vp_uri="openid4vp://authorize?request_uri=https://issuer.example/request/1",
        request_uri="openid4vp://authorize?request_uri=https://issuer.example/request/1",
    )

    assert options == [
        {
            "id": "sprucekit",
            "label": "SpruceKit",
            "description": "Selected wallet: SpruceKit.",
            "href": "openid4vp://authorize?request_uri=https%3A%2F%2Fissuer.example%2Frequest%2F1",
            "android_href": "intent://authorize?request_uri=https%3A%2F%2Fissuer.example%2Frequest%2F1#Intent;scheme=openid4vp;package=com.spruceid.mobilesdkexample;end",
            "ios_href": "openid4vp://authorize?request_uri=https%3A%2F%2Fissuer.example%2Frequest%2F1",
        },
        {
            "id": "lissi",
            "label": "LISSI Wallet",
            "description": "Selected wallet: LISSI Wallet.",
            "href": "openid4vp://authorize?request_uri=https%3A%2F%2Fissuer.example%2Frequest%2F1%3Fcompat%3Dlissi",
            "android_href": "intent://authorize?request_uri=https%3A%2F%2Fissuer.example%2Frequest%2F1%3Fcompat%3Dlissi#Intent;scheme=openid4vp;end",
            "ios_href": "openid4vp://authorize?request_uri=https%3A%2F%2Fissuer.example%2Frequest%2F1%3Fcompat%3Dlissi",
        },
    ]


def test_build_credential_login_wallet_options_honors_sprucekit_template_override(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv(
        "CREDENTIAL_LOGIN_SPRUCEKIT_DEEP_LINK_TEMPLATE",
        "walletapp://authorize?request_uri={request_uri}",
    )
    monkeypatch.setenv(
        "CREDENTIAL_LOGIN_SPRUCEKIT_ANDROID_DEEP_LINK_TEMPLATE",
        "intent://custom?request_uri={request_uri_encoded}#Intent;scheme=openid4vp;end",
    )
    monkeypatch.setenv("CREDENTIAL_LOGIN_SPRUCEKIT_ANDROID_PACKAGE", "com.example.wallet")

    options = _build_credential_login_wallet_options(
        oid4vp_uri="openid4vp://authorize?request_uri=https://issuer.example/request/1",
        request_uri="https://issuer.example/request/1",
    )

    assert options[0]["href"] == "walletapp://authorize?request_uri=https://issuer.example/request/1"
    assert options[0]["android_href"] == "intent://custom?request_uri=https%3A%2F%2Fissuer.example%2Frequest%2F1#Intent;scheme=openid4vp;end"


def test_build_credential_login_wallet_options_renders_android_package_placeholder(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv(
        "CREDENTIAL_LOGIN_SPRUCEKIT_ANDROID_DEEP_LINK_TEMPLATE",
        "intent://authorize?request_uri={request_uri_encoded}#Intent;scheme=openid4vp;{android_package_param}end",
    )
    monkeypatch.setenv("CREDENTIAL_LOGIN_SPRUCEKIT_ANDROID_PACKAGE", "com.example.wallet")

    options = _build_credential_login_wallet_options(
        oid4vp_uri="openid4vp://authorize?request_uri=https://issuer.example/request/1",
        request_uri="https://issuer.example/request/1",
    )

    assert options[0]["android_href"] == "intent://authorize?request_uri=https%3A%2F%2Fissuer.example%2Frequest%2F1#Intent;scheme=openid4vp;package=com.example.wallet;end"


def test_build_credential_login_wallet_options_honors_ios_universal_link_templates(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv(
        "CREDENTIAL_LOGIN_LISSI_IOS_DEEP_LINK_TEMPLATE",
        "lissi://unused?request_uri={request_uri_encoded}",
    )
    monkeypatch.setenv(
        "CREDENTIAL_LOGIN_LISSI_IOS_UNIVERSAL_LINK_TEMPLATE",
        "https://lissi.example/openid4vp?request_uri={request_uri_encoded}",
    )
    monkeypatch.setenv(
        "CREDENTIAL_LOGIN_SPRUCEKIT_IOS_DEEP_LINK_TEMPLATE",
        "spruceid://unused?request_uri={request_uri_encoded}",
    )
    monkeypatch.setenv(
        "CREDENTIAL_LOGIN_SPRUCEKIT_IOS_UNIVERSAL_LINK_TEMPLATE",
        "https://spruceid.example/openid4vp?request_uri={request_uri_encoded}",
    )

    options = _build_credential_login_wallet_options(
        oid4vp_uri="openid4vp://authorize?request_uri=https://issuer.example/request/1",
        request_uri="openid4vp://authorize?request_uri=https://issuer.example/request/1",
    )

    assert options[0]["ios_href"] == "https://spruceid.example/openid4vp?request_uri=https%3A%2F%2Fissuer.example%2Frequest%2F1"
    assert options[1]["ios_href"] == "https://lissi.example/openid4vp?request_uri=https%3A%2F%2Fissuer.example%2Frequest%2F1%3Fcompat%3Dlissi"


def test_render_credential_login_page_includes_wallet_selector():
    html = _render_credential_login_page(
        nonce="nonce-123",
        flow_instance_id="flow-123",
        qr_encoded="openid4vp%3A%2F%2Fauthorize",
        oid4vp_uri="openid4vp://authorize?request_uri=https://issuer.example/request/1",
        request_uri="openid4vp://authorize?request_uri=https://issuer.example/request/1",
    )

    assert 'Select wallet app' in html
    assert '/v1/auth/credential-login/assets/styles.css?v=' in html
    assert '/v1/auth/credential-login/assets/app.js?v=' in html
    assert 'id="platform-select"' in html
    assert 'Auto-detect' in html
    assert 'Android' in html
    assert 'iOS' in html
    assert 'value="lissi"' in html
    assert 'value="sprucekit"' in html
    assert html.index('value="sprucekit"') < html.index('value="lissi"')
    assert 'data-link="openid4vp://authorize?request_uri=https%3A%2F%2Fissuer.example%2Frequest%2F1"' in html
    assert 'data-android-link="intent://authorize?request_uri=https%3A%2F%2Fissuer.example%2Frequest%2F1#Intent;scheme=openid4vp;package=com.spruceid.mobilesdkexample;end"' in html
    assert 'data-ios-link="openid4vp://authorize?request_uri=https%3A%2F%2Fissuer.example%2Frequest%2F1"' in html
    assert 'data-link="openid4vp://authorize?request_uri=https%3A%2F%2Fissuer.example%2Frequest%2F1%3Fcompat%3Dlissi"' in html
    assert 'data-android-link="intent://authorize?request_uri=https%3A%2F%2Fissuer.example%2Frequest%2F1%3Fcompat%3Dlissi#Intent;scheme=openid4vp;end"' in html
    assert 'data-ios-link="openid4vp://authorize?request_uri=https%3A%2F%2Fissuer.example%2Frequest%2F1%3Fcompat%3Dlissi"' in html
    assert 'href="openid4vp://authorize?request_uri=https%3A%2F%2Fissuer.example%2Frequest%2F1"' in html
    assert 'spruceid://credential-offer' not in html
    assert 'lissi://openid4vp' not in html
    assert 'id="wallet-select"' in html
    assert 'Open wallet' in html
    assert 'Open Lucy' not in html
    assert 'data-dc-api-request-url="/v1/flows/instances/flow-123/request?transport=dc_api"' in html
    assert 'data-dc-api-submit-url="/v1/flows/instances/flow-123/submit/dc-api"' in html
    assert 'data-dc-api-protocol="openid4vp-v1-signed"' in html
    assert html.index('id="wallet-select"') < html.index('id="mobile-section"')


def test_credential_login_js_persists_wallet_and_platform_preferences():
    js = _CREDENTIAL_LOGIN_JS
    assert "marty.credential_login.wallet" in js
    assert "marty.credential_login.platform" in js
    assert "restoreWalletPreference" in js
    assert "persistPlatformPreference" in js


def test_build_credential_login_wallet_options_uses_ios_universal_link_when_env_set(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv(
        "CREDENTIAL_LOGIN_SPRUCEKIT_IOS_UNIVERSAL_LINK_TEMPLATE",
        "https://wallet.spruceid.example/openid4vp?request_uri={request_uri_encoded}",
    )

    options = _build_credential_login_wallet_options(
        oid4vp_uri="openid4vp://authorize?request_uri=https://issuer.example/request/1",
        request_uri="openid4vp://authorize?request_uri=https://issuer.example/request/1",
    )

    spruce = options[0]
    assert spruce["id"] == "sprucekit"
    assert spruce["ios_href"] == (
        "https://wallet.spruceid.example/openid4vp?request_uri=https%3A%2F%2Fissuer.example%2Frequest%2F1"
    )
    # Generic + Android still use the protocol scheme so that other transports stay intact.
    assert spruce["href"].startswith("openid4vp://")
    assert spruce["android_href"].startswith("intent://")