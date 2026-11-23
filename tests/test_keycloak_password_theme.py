"""Render the actual FreeMarker forms and exercise them in isolated Chromium.

Uses the JDK, pytest, and Playwright already installed by the Python CI job.
This verifies password-manager DOM/event compatibility, not a live Bitwarden vault.
"""
from __future__ import annotations

from functools import lru_cache
import os
from pathlib import Path
import shutil
import subprocess

import pytest
from playwright.sync_api import sync_playwright

from tests.keycloak_freemarker import load_freemarker_jar

ROOT = Path(__file__).resolve().parents[1]
THEME = ROOT / "config/keycloak/themes/11id/login"
USERNAME = 'fixture"<user>&@example.invalid'
PASSWORD = "Fixture!Password42"


@pytest.fixture(scope="module")
def render(tmp_path_factory):
    java, javac = shutil.which("java"), shutil.which("javac")
    assert java and javac, "A JDK is required for the Keycloak login rendering contract"
    working = tmp_path_factory.mktemp("keycloak-password-theme")
    data = load_freemarker_jar("KEYCLOAK_LOGIN_FREEMARKER_JAR", "KEYCLOAK_EMAIL_FREEMARKER_JAR")
    jar = working / "freemarker.jar"
    jar.write_bytes(data)
    subprocess.run([javac, "-J-Xmx128m", "-cp", str(jar), "-d", str(working),
                    str(ROOT / "tests/java/KeycloakLoginThemeContract.java")],
                   check=True, capture_output=True, text=True, timeout=30)

    @lru_cache(maxsize=None)
    def rendered(scenario, locale="en"):
        result = subprocess.run([java, "-Xmx96m", "-cp", str(working) + os.pathsep + str(jar),
                                 "KeycloakLoginThemeContract", str(THEME), scenario, locale],
                                capture_output=True, text=True, timeout=20)
        assert result.returncode == 0, result.stderr
        return result.stdout

    return rendered


@pytest.fixture(scope="module")
def browser():
    with sync_playwright() as playwright:
        instance = playwright.chromium.launch(headless=True)
        yield instance
        instance.close()


@pytest.fixture
def load_page(browser, render):
    context = browser.new_context(viewport={"width": 800, "height": 1000})
    # Rendered fixtures contain only synthetic credentials and cannot contact services.
    context.route("**/*", lambda route: route.abort())
    page = context.new_page()
    errors = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    css = "\n".join((THEME / "resources/css" / name).read_text(encoding="utf-8")
                    for name in ("auth-layout.css", "marty.css"))

    def load(scenario, locale="en", *, extra_fields="", prefilled=False):
        html = render(scenario, locale).replace("</head>", "<style>" + css + "</style></head>")
        if extra_fields:
            html = html.replace("</form>", extra_fields + "</form>", 1)
        if prefilled:
            field = "password-new" if scenario.startswith("update") else "password"
            html = html.replace('id="' + field + '"', 'value="' + PASSWORD + '" id="' + field + '"', 1)
        page.set_content(html, wait_until="domcontentloaded")
        return page

    yield load
    context.close()
    assert errors == [], errors


@pytest.mark.parametrize("scenario", ["update", "update-aia"])
def test_update_password_has_intact_username_and_new_password_semantics(load_page, scenario):
    page = load_page(scenario)
    assert page.locator("#username").input_value() == USERNAME
    assert page.locator("#username").get_attribute("autocomplete") == "username"
    assert page.locator("#username").evaluate("input => input.form.id") == "kc-passwd-update-form"
    for field in ["password-new", "password-confirm"]:
        element = page.locator("#" + field)
        assert element.get_attribute("name") == field
        assert element.get_attribute("autocomplete") == "new-password"
        assert element.is_editable()
        assert element.evaluate("input => input.form.id") == "kc-passwd-update-form"
    assert not page.locator("#password").is_visible()
    assert page.locator(".kc-password-toggle-btn").count() == 2
    assert page.locator(".kc-password-toggle-btn[aria-controls=password]").count() == 0
    assert page.locator("button[name=cancel-aia]").count() == (scenario == "update-aia")


@pytest.mark.parametrize("scenario", ["login", "reauth", "username"])
def test_login_steps_preserve_username_association(load_page, scenario):
    page = load_page(scenario)
    username = page.locator("#username")
    assert username.count() == 1
    assert username.input_value() == USERNAME
    assert username.get_attribute("autocomplete") == "username"
    assert username.evaluate("input => input.form.id") == "kc-form-login"
    if scenario == "reauth":
        assert username.get_attribute("name") is None
        assert not username.is_visible()
    if scenario != "username":
        assert page.locator("#password").get_attribute("autocomplete") == "current-password"
        assert page.locator(".kc-password-toggle-btn").count() == 1


@pytest.mark.parametrize("reset_available", [True, False])
def test_login_error_has_one_card_and_only_available_recovery(load_page, reset_available):
    page = load_page("login-error" if reset_available else "login-error-reset-disabled")
    error = page.get_by_role("alert")
    assert error.count() == 1
    assert error.inner_text().strip() == "Invalid sign-in credentials"
    for field in ["username", "password"]:
        assert page.locator("#" + field).get_attribute("aria-describedby") == "input-error"
    assert page.get_by_test_id("set-password-email-link").count() == int(reset_available)
    assert page.get_by_test_id("forgot-password-link").count() == 0
    for width in [320, 1280]:
        page.set_viewport_size({"width": width, "height": 1000})
        wrapper = page.locator("#kc-form > #kc-form-wrapper")
        assert wrapper.evaluate("el => getComputedStyle(el).boxShadow") == "none"
        assert wrapper.evaluate("el => getComputedStyle(el).padding") == "0px"
        assert page.locator("#kc-form").evaluate("el => getComputedStyle(el).boxShadow") != "none"
        assert page.evaluate("document.documentElement.scrollWidth === innerWidth")


@pytest.mark.parametrize("scenario", ["register", "register-email"])
def test_registration_identifies_username_and_both_new_passwords(load_page, scenario):
    page = load_page(scenario)
    username = page.locator("#email" if scenario == "register-email" else "#username")
    assert username.get_attribute("autocomplete") == "username"
    assert username.input_value() == USERNAME
    for field in ["password", "password-confirm"]:
        element = page.locator("#" + field)
        assert element.get_attribute("autocomplete") == "new-password"
        assert element.is_editable()
        assert element.evaluate("input => input.form.id") == "kc-register-form"
    assert page.locator(".kc-password-toggle-btn").count() == 2
    assert page.locator("#kc-register").evaluate("input => input.form.id") == "kc-register-form"


@pytest.mark.parametrize("locale", ["en", "de", "nl", "ja", "es", "fr"])
def test_update_password_instruction_resolves_in_each_supported_locale(load_page, locale):
    page = load_page("update", locale)
    hint = page.locator(".elevenid-context-hint").inner_text().strip()
    assert hint and "updatePasswordBody" not in hint


def test_toggles_skip_hidden_and_native_controls_and_are_idempotent(load_page):
    page = load_page("update", extra_fields="""
        <div hidden><input type="password" id="hidden-parent"></div>
        <div style="visibility:hidden"><input type="password" id="invisible-parent"></div>
        <input type="password" id="hidden-field" hidden>
        <div><input type="password" id="native-password">
          <button type="button" data-password-toggle aria-controls="native-password">Native</button>
        </div>
    """)
    assert page.locator(".kc-password-toggle-btn").count() == 2
    assert page.locator("[data-password-toggle]").count() == 1
    page.evaluate("document.dispatchEvent(new Event('DOMContentLoaded'))")
    assert page.locator(".kc-password-toggle-btn").count() == 2
    assert page.locator(".kc-password-toggle-wrap .kc-password-toggle-wrap").count() == 0


@pytest.mark.parametrize("width", [360, 800])
def test_visibility_toggle_preserves_the_autofilled_control_and_does_not_cover_it(load_page, width):
    page = load_page("update")
    page.set_viewport_size({"width": width, "height": 1000})
    field = page.locator("#password-new")
    field.fill(PASSWORD)
    page.evaluate("window.originalPasswordField = document.getElementById('password-new')")
    page.evaluate("document.querySelector('form').addEventListener('submit', event => { event.preventDefault(); window.submitted = true; })")
    toggle = page.locator('.kc-password-toggle-btn[aria-controls="password-new"]')
    field_box, toggle_box = field.bounding_box(), toggle.bounding_box()
    assert field_box and toggle_box
    assert toggle_box["x"] >= field_box["x"] + field_box["width"]
    assert toggle_box["x"] + toggle_box["width"] <= width
    assert toggle.get_attribute("aria-pressed") == "false"
    toggle.click()
    assert field.get_attribute("type") == "text"
    assert toggle.get_attribute("aria-pressed") == "true"
    toggle.click()
    assert field.get_attribute("type") == "password"
    assert toggle.get_attribute("aria-pressed") == "false"
    assert field.input_value() == PASSWORD
    assert field.get_attribute("name") == "password-new"
    assert field.get_attribute("autocomplete") == "new-password"
    assert page.evaluate("window.originalPasswordField === document.getElementById('password-new')")
    assert not page.evaluate("Boolean(window.submitted)")


@pytest.mark.parametrize("scenario", ["update", "register"])
@pytest.mark.parametrize("event", ["input", "change", "pageshow"])
def test_password_requirements_follow_password_manager_events(load_page, scenario, event):
    page = load_page(scenario)
    field = "password-new" if scenario == "update" else "password"
    page.locator("#" + field).evaluate("""(input, args) => {
        input.value = args.password;
        if (args.event === 'pageshow') window.dispatchEvent(new Event('pageshow'));
        else input.dispatchEvent(new Event(args.event, { bubbles: true }));
    }""", {"password": PASSWORD, "event": event})
    assert page.locator("#password-requirements .pwd-req.met").count() == 5
    assert page.locator("#password-requirements .unmet-active").count() == 0
    page.locator("#password-confirm").evaluate("""(input, password) => {
        input.value = password;
        input.dispatchEvent(new Event('input', { bubbles: true }));
        input.dispatchEvent(new Event('change', { bubbles: true }));
    }""", PASSWORD)
    submitted = page.locator("form").evaluate("""form => {
        let submitted;
        form.addEventListener('submit', event => {
            event.preventDefault();
            submitted = Object.fromEntries(new FormData(form));
        }, { once: true });
        form.requestSubmit();
        return submitted;
    }""")
    assert submitted[field] == PASSWORD
    assert submitted["password-confirm"] == PASSWORD


@pytest.mark.parametrize("scenario", ["update", "register"])
def test_password_requirements_read_an_initially_prefilled_value(load_page, scenario):
    page = load_page(scenario, prefilled=True)
    assert page.locator("#password-requirements .pwd-req.met").count() == 5


def test_bundled_helm_login_theme_matches_the_source():
    bundled = ROOT / "deploy/helm/marty/files/keycloak/themes/11id/login"
    expected = {path.relative_to(THEME): path.read_bytes() for path in THEME.rglob("*") if path.is_file()}
    actual = {path.relative_to(bundled): path.read_bytes() for path in bundled.rglob("*") if path.is_file()}
    assert actual == expected


def test_configured_identity_navigation_uses_the_application_and_website_origins(load_page):
    page = load_page("login-external")
    assert page.locator(".elevenid-home-btn").get_attribute("href") == "https://website.example.invalid/"
    assert page.locator("#credential-login").get_attribute("href") == "https://console.example.invalid/v1/auth/credential-login"


def test_same_origin_navigation_keeps_its_existing_defaults(load_page):
    page = load_page("login")
    assert page.locator(".elevenid-home-btn").get_attribute("href") == "/"
    assert page.locator("#credential-login").get_attribute("href") == "/v1/auth/credential-login"


@pytest.mark.parametrize("scenario", ["login-no-credential", "login-empty-credential"])
def test_unavailable_credential_login_does_not_leave_an_empty_alternative_section(load_page, scenario):
    page = load_page(scenario)
    assert page.locator("#credential-login").count() == 0
    assert page.locator("#kc-social-providers").count() == 0
    assert page.locator("#kc-form-login").is_visible()


def test_disabling_credential_login_preserves_the_configured_social_provider(load_page):
    page = load_page("login-google-no-credential")
    assert page.locator("#credential-login").count() == 0
    assert page.locator("#social-google").get_attribute("href") == "/realms/fixture/broker/google/login"


@pytest.mark.parametrize("scenario,target", [
    ("info-success", "https://console.example.invalid/v1/auth/callback?code=synthetic-code&state=synthetic-state"),
    ("info-local", "http://127.0.0.1:9999/callback"),
])
def test_completed_native_action_returns_to_its_explicit_web_destination(browser, render, scenario, target):
    context = browser.new_context()
    navigations = []

    def route_request(route):
        if route.request.is_navigation_request():
            assert route.request.url == target
            navigations.append(route.request.url)
            route.fulfill(status=200, content_type="text/html", body="<main>Application return observed</main>")
        else:
            route.abort()

    context.route("**/*", route_request)
    try:
        page = context.new_page()
        page.set_content(render(scenario), wait_until="domcontentloaded")
        page.wait_for_url(target)
        assert page.locator("main").inner_text() == "Application return observed"
        assert navigations == [target]
    finally:
        context.close()


@pytest.mark.parametrize("scenario", [
    "info-action", "info-action-with-destination", "info-pending", "info-hidden",
    "info-error", "info-no-destination", "info-native", "info-remote-http",
])
def test_native_action_confirmation_pending_factors_errors_and_nonweb_returns_stay_explicit(load_page, scenario):
    page = load_page(scenario)
    assert page.url == "about:blank"
    assert page.locator(".elevenid-inherited-card").count() == 1
    assert page.locator("h1#kc-page-title").count() == 1
    if scenario == "info-hidden":
        assert page.locator("#kc-info-message a").count() == 0
    else:
        assert page.locator("#kc-info-message a").is_visible()


@pytest.mark.parametrize("width", [320, 1280])
def test_native_completion_retains_a_styled_accessible_return_without_javascript(browser, render, width):
    context = browser.new_context(java_script_enabled=False, viewport={"width": width, "height": 900})
    context.route("**/*", lambda route: route.abort())
    try:
        page = context.new_page()
        css = "\n".join((THEME / "resources/css" / name).read_text(encoding="utf-8")
                        for name in ("auth-layout.css", "marty.css"))
        page.set_content(render("info-success").replace("</head>", "<style>" + css + "</style></head>"),
                         wait_until="domcontentloaded")
        assert page.locator("h1#kc-page-title").is_visible()
        assert page.locator("#kc-info-message a").get_attribute("href") == (
            "https://console.example.invalid/v1/auth/callback?code=synthetic-code&state=synthetic-state")
        assert page.locator(".elevenid-inherited-card").evaluate(
            "node => getComputedStyle(node).borderTopWidth") == "1px"
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
    finally:
        context.close()


@pytest.mark.parametrize("width", [320, 1280])
@pytest.mark.parametrize("scenario", ["otp", "otp-error", "otp-multiple"])
def test_native_otp_has_one_card_a_clear_heading_and_intact_code_input(load_page, width, scenario):
    page = load_page(scenario)
    page.set_viewport_size({"width": width, "height": 900})
    assert page.locator("h1#kc-page-title").inner_text() == "Verify it's you"
    assert page.locator(".elevenid-inherited-card").count() == 1
    assert page.locator("#otp").get_attribute("autocomplete") == "one-time-code"
    assert page.locator("#kc-login").is_enabled()
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
    if scenario == "otp-error":
        assert page.locator("#input-error-otp-code").inner_text() == "Invalid authenticator code"


@pytest.mark.parametrize("locale", ["en", "de", "nl", "ja", "es", "fr"])
def test_native_otp_heading_and_hint_resolve_for_each_supported_locale(load_page, locale):
    page = load_page("otp", locale)
    assert "mfaVerificationTitle" not in page.locator("h1#kc-page-title").inner_text()
    assert "mfaAuthenticatorHint" not in page.locator(".elevenid-context-hint").inner_text()
