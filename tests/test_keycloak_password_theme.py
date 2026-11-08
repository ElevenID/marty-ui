"""Render the actual FreeMarker forms and exercise them in isolated Chromium.

Uses the JDK, pytest, and Playwright already installed by the Python CI job.
This verifies password-manager DOM/event compatibility, not a live Bitwarden vault.
"""
from __future__ import annotations

from functools import lru_cache
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import urllib.request

import pytest
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
THEME = ROOT / "config/keycloak/themes/11id/login"
USERNAME = 'fixture"<user>&@example.invalid'
PASSWORD = "Fixture!Password42"
JAR_URL = "https://repo.maven.apache.org/maven2/org/freemarker/freemarker/2.3.35/freemarker-2.3.35.jar"
JAR_SHA256 = "0fac87dddd78f1223139e8ef88e819c7f483c0a3835cdf5982ad5e4576d1d896"
MAX_JAR_BYTES = 4 * 1024 * 1024


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("FreeMarker test dependency must not redirect")


@pytest.fixture(scope="module")
def render(tmp_path_factory):
    java, javac = shutil.which("java"), shutil.which("javac")
    assert java and javac, "A JDK is required for the Keycloak login rendering contract"
    working = tmp_path_factory.mktemp("keycloak-password-theme")
    supplied = os.environ.get("KEYCLOAK_LOGIN_FREEMARKER_JAR") or os.environ.get("KEYCLOAK_EMAIL_FREEMARKER_JAR")
    if supplied:
        with Path(supplied).open("rb") as source:
            data = source.read(MAX_JAR_BYTES + 1)
    else:
        with urllib.request.build_opener(NoRedirect()).open(JAR_URL, timeout=30) as response:
            assert response.status == 200 and response.url == JAR_URL
            data = response.read(MAX_JAR_BYTES + 1)
    assert len(data) <= MAX_JAR_BYTES and hashlib.sha256(data).hexdigest() == JAR_SHA256
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
    css = (THEME / "resources/css/marty.css").read_text(encoding="utf-8")

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
