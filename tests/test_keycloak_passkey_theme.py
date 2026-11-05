"""Render native passkey integration without replacing the branded login options."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import urllib.request
import urllib.parse

import pytest

from tests import test_keycloak_email_layout as email_contract

email_renderer = email_contract.renderer


ROOT = Path(__file__).resolve().parents[1]
PARENT_URL = "https://raw.githubusercontent.com/keycloak/keycloak/26.8.0/themes/src/main/resources/theme/base/login/passkeys.ftl"
PARENT_SHA256 = "64acd32cc34fa1e4537912f0c54e1730bb8b7b29d04640804c8bf7a6029a2f01"


@pytest.fixture(scope="module")
def passkey_renderer(email_renderer):
    classpath = email_renderer[3]
    working = Path(classpath.split(os.pathsep)[0])
    parent = working / "parent"
    parent.mkdir()
    # Use the real upstream macro, pinned by tag AND bytes. It remains inherited
    # at runtime, so this test catches changes in its required attributes.
    opener = urllib.request.build_opener(email_contract.NoRedirect())
    with opener.open(PARENT_URL, timeout=30) as response:
        assert response.status == 200 and response.url == PARENT_URL
        data = response.read(65537)
    assert len(data) <= 65536 and hashlib.sha256(data).hexdigest() == PARENT_SHA256
    (parent / "passkeys.ftl").write_bytes(data)
    empty = working / "no-passkey-parent"
    empty.mkdir()
    subprocess.run([shutil.which("javac"), "-J-Xmx128m", "-cp", classpath,
                    "-d", str(working), str(ROOT / "tests/java/KeycloakPasskeyThemeContract.java")],
                   check=True, capture_output=True, text=True, timeout=30)
    return ([email_renderer[0], "-Xmx96m", "-cp", classpath,
             "KeycloakPasskeyThemeContract", str(ROOT / "config/keycloak/themes/11id/login")],
            parent, empty)


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("template,mode", [
    ("login.ftl", "normal"), ("login.ftl", "reauth"), ("login-username.ftl", "normal"),
])
def test_native_passkeys_preserve_password_google_badge_and_recovery(passkey_renderer, enabled, template, mode):
    command, parent, empty = passkey_renderer
    result = subprocess.run([*command, str(parent if enabled else empty), template,
                             "enabled" if enabled else "disabled", mode],
                            capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    html = result.stdout
    assert html.count('id="kc-form-login"') == 1
    assert html.count('id="social-google"') == 1
    assert html.count('id="credential-login"') == 1
    assert 'href="/custom-badge-login"' in html
    assert 'Present Open Badge Credential' in html
    assert '"rfc4648":"/resources/common/vendor/rfc4648/rfc4648.js"' in html
    if mode == "reauth":
        assert '/broker/google/login?client_id=marty-ui&amp;tab_id=synthetic' in html
    else:
        assert '/broker/google/login?state=synthetic' in html
        assert 'href="/register"' in html
        assert ('autocomplete="username webauthn"' in html) == enabled
    if template == "login.ftl":
        assert 'data-testid="password-input"' in html
        assert 'href="/reset"' in html
    assert ('id="authenticateWebAuthnButton"' in html) == enabled
    assert ('id="webauth"' in html) == enabled
    assert ('/js/passkeysConditionalAuth.js' in html) == enabled
    if enabled:
        assert 'userVerification : "required"' in html
        assert 'rpId : "example.invalid"' in html
        assert 'mediation : "conditional"' in html  # missing optional attribute defaults
        assert html.count('name="userHandle"') == 1
        assert ('name="authn_use_chk"' in html) == (mode == "reauth")


@pytest.mark.parametrize("restart", ["automatic", "keyboard"])
def test_error_restart_preserves_client_and_tab_context_in_browser(passkey_renderer, restart):
    from playwright.sync_api import sync_playwright

    command, _, empty = passkey_renderer
    result = subprocess.run([*command, str(empty), "error.ftl", "disabled", "normal"],
                            capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel="chrome", headless=True)
        try:
            page = browser.new_page()
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            def serve(route):
                if urllib.parse.urlparse(route.request.url).path == "/failure":
                    route.fulfill(content_type="text/html", body=result.stdout)
                else:
                    route.fulfill(content_type="text/plain", body="Synthetic restart destination")
            page.route("**/*", serve)
            page.goto("https://theme.example.invalid/failure")
            assert page.locator("#kc-error-message .instruction").inner_text() == "Synthetic authentication failure"
            if restart == "keyboard":
                page.locator("#kc-error-restart-link").focus()
                page.keyboard.press("Enter")
            page.wait_for_url("**/login-actions/authenticate?**", timeout=10000)
            assert urllib.parse.parse_qs(urllib.parse.urlparse(page.url).query) == {
                "client_id": ["marty-ui"], "tab_id": ["synthetic"], "client_data": ["value&value=test"]}
            assert errors == []
        finally:
            browser.close()
