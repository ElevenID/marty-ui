"""Render the actual shared auth shell and view modules without a live provider."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import unittest
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
AUTH = ROOT / "integrations/supabase-auth-ui"
ORIGIN = "https://auth-layout.example.invalid"

FIXTURE = """
import { renderView } from '/src/view.js';
import { renderRecoveryView } from '/src/recovery-view.js';
const root = document.getElementById('app');
window.fixtureCalls = [];
const action = name => () => window.fixtureCalls.push(name);
const actions = Object.fromEntries(['signIn', 'recover', 'register', 'security',
  'switchAccount', 'requestEmail', 'restart'].map(name => [name, action(name)]));
window.renderFixture = (kind = 'signin', phase = 'signin', extra = {}) => {
  const state = { phase, busy: false, error: null, ...extra };
  if (kind === 'recovery') renderRecoveryView(document, root, state, actions);
  else renderView(document, root, state, actions);
};
window.renderFixture();
"""


class SharedAuthLayoutTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Exercise the actual general source/HTML adapter used by the build.
        result = subprocess.run([
            "node", "--input-type=module", "-e",
            "import {readFileSync} from 'node:fs';"
            "import {renderAuthLayout} from './ui/src/shared/web-layout/html.mjs';"
            "console.log(renderAuthLayout({contentMarkup:readFileSync('./integrations/supabase-auth-ui/public/loading.html','utf8').trim()}));",
        ], cwd=ROOT, capture_output=True, text=True, check=True, timeout=15)
        cls.html = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'">
<title>Sign in · ElevenID LLC</title><link rel="stylesheet" href="/app.css">
<script type="module" src="/fixture.mjs"></script></head><body>""" + result.stdout + "</body></html>"
        theme_css = ROOT / "config/keycloak/themes/11id/login/resources/css/auth-layout.css"
        cls.css = theme_css.read_text(encoding="utf-8") + "\n" + (AUTH / "public/app.css").read_text(encoding="utf-8")
        cls.playwright = sync_playwright().start()
        executable = os.environ.get("CHROME_PATH")
        cls.browser = cls.playwright.chromium.launch(headless=True, **({"executable_path": executable} if executable else {}))

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.playwright.stop()

    def setUp(self):
        self.context = self.browser.new_context(viewport={"width": 390, "height": 1000})
        self.errors = []
        self.unexpected = []
        self.context.route("**/*", self.route)
        self.page = self.context.new_page()
        self.page.on("pageerror", lambda error: self.errors.append(str(error)))
        self.page.goto(ORIGIN + "/", wait_until="load")
        self.page.wait_for_function("typeof window.renderFixture === 'function'")

    def tearDown(self):
        self.context.close()
        self.assertEqual(self.errors, [])
        self.assertEqual(self.unexpected, [])

    def route(self, route):
        request = urlparse(route.request.url)
        if f"{request.scheme}://{request.netloc}" != ORIGIN:
            self.unexpected.append(route.request.url)
            route.abort()
            return
        path = request.path
        if path == "/":
            route.fulfill(status=200, content_type="text/html", body=self.html)
        elif path == "/app.css":
            route.fulfill(status=200, content_type="text/css", body=self.css)
        elif path == "/fixture.mjs":
            route.fulfill(status=200, content_type="text/javascript", body=FIXTURE)
        elif path.startswith("/src/") and path.endswith(".js") and ".." not in path:
            route.fulfill(status=200, content_type="text/javascript", body=(AUTH / path.lstrip("/")).read_text(encoding="utf-8"))
        elif path == "/favicon.ico":
            route.fulfill(status=204, body="")
        else:
            self.unexpected.append(route.request.url)
            route.abort()

    def test_shared_header_and_account_help_are_styled_and_fit_mobile_and_desktop(self):
        for width in [320, 390, 1280]:
            with self.subTest(width=width):
                self.page.set_viewport_size({"width": width, "height": 1000})
                self.assertEqual(self.page.get_by_role("banner").count(), 1)
                self.assertEqual(self.page.locator("#brand-name").inner_text(), "ElevenID LLC")
                self.assertEqual(self.page.get_by_role("banner").evaluate("el => getComputedStyle(el).backgroundColor"), "rgb(25, 118, 210)")
                self.assertGreaterEqual(self.page.locator(".elevenid-toolbar").bounding_box()["height"], 56 if width <= 768 else 64)
                actions = self.page.get_by_role("group", name="Account help").get_by_role("button")
                self.assertEqual(actions.count(), 3)
                previous_bottom = None
                for index in range(actions.count()):
                    button = actions.nth(index)
                    box = button.bounding_box()
                    self.assertGreaterEqual(box["height"], 44)
                    self.assertEqual(button.get_attribute("type"), "button")
                    self.assertEqual(button.evaluate("el => getComputedStyle(el).borderTopWidth"), "1px")
                    self.assertEqual(button.evaluate("el => getComputedStyle(el).borderRadius"), "8px")
                    self.assertIsNone(button.evaluate("el => el.form"))
                    if previous_bottom is not None:
                        self.assertGreaterEqual(box["y"] - previous_bottom, 9)
                    previous_bottom = box["y"] + box["height"]
                self.assertTrue(self.page.evaluate("document.documentElement.scrollWidth <= innerWidth"))

    def test_help_actions_have_separate_handlers_and_busy_state_blocks_repeated_sign_in(self):
        for label in ["Forgot your password?", "Create an account", "Set up an authenticator"]:
            self.page.get_by_role("button", name=label, exact=True).click()
        self.assertEqual(self.page.evaluate("window.fixtureCalls"), ["recover", "register", "security"])
        self.page.get_by_role("button", name="Forgot your password?", exact=True).focus()
        self.page.keyboard.press("Tab")
        self.assertEqual(self.page.evaluate("getComputedStyle(document.activeElement).outlineWidth"), "3px")
        self.page.evaluate("window.renderFixture('signin', 'signin', {busy: true})")
        self.assertEqual(self.page.get_by_role("button", disabled=True).count(), 4)
        self.assertTrue(self.page.get_by_role("button", name="Signing in…").is_disabled())
        self.assertEqual(self.page.locator("#app").get_attribute("aria-busy"), "true")

    def test_recovery_guidance_and_registration_are_identical_for_every_address(self):
        self.page.evaluate("window.renderFixture('recovery', 'request')")
        self.page.get_by_role("button", name="New here? Create an account").click()
        self.assertEqual(self.page.evaluate("window.fixtureCalls"), ["register"])
        rendered = []
        for address in ["known@example.invalid", "new@example.invalid"]:
            self.page.evaluate("email => window.renderFixture('recovery', 'sent', {email})", address)
            rendered.append(self.page.locator("#app").inner_text())
            self.assertIn("If the account can be recovered", rendered[-1])
            self.assertIn("inbox and spam folder", rendered[-1])
            self.assertTrue(self.page.get_by_role("button", name="Return to sign in").is_visible())
            self.assertTrue(self.page.get_by_role("button", name="New here? Create an account").is_visible())
        self.assertEqual(rendered[0], rendered[1])


if __name__ == "__main__":
    unittest.main()
