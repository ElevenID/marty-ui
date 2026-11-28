"""Qualify the real browser POST across separate auth, API and console origins.

Uses the production form helper and policies emitted by the actual Bun build.
Every request is intercepted; credentials, cookies and all origins are synthetic.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from urllib.parse import parse_qs, urlparse

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
AUTH = ROOT / "integrations/supabase-auth-ui"
SOURCE = "https://auth.example.invalid"
API = "https://api.example.invalid"
CONSOLE = "https://console.example.invalid"
UNLISTED = "https://unlisted.example.invalid"
TOKEN = "synthetic_header.synthetic_payload.synthetic_signature"
FIELDS = {"code": "synthetic-code", "state": "synthetic-state", "native_access_token": TOKEN}


class NativeAuthCallbackBrowserTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        bun = os.environ.get("BUN_EXECUTABLE", "bun")
        version = subprocess.run([bun, "--version"], capture_output=True, text=True, check=True, timeout=15).stdout.strip()
        if version != "1.4.4":
            raise RuntimeError(f"The qualified companion toolchain requires Bun 1.4.4; observed {version}")
        cls.configs, cls.policies = {}, {}
        example = json.loads((AUTH / "public/config.split-origin.example.json").read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory(prefix="elevenid-native-callback-") as temporary:
            for version in ["v3", "v4"]:
                config = json.loads(json.dumps(example))
                config["schema"] = f"elevenid.supabase-auth-ui/{version}"
                if version == "v3":
                    del config["postRedirectOrigins"]
                path = Path(temporary) / f"{version}.json"
                path.write_text(json.dumps(config), encoding="utf-8")
                result = subprocess.run([bun, "build.mjs", "--config", str(path)], cwd=AUTH,
                                        capture_output=True, text=True, timeout=45)
                if result.returncode:
                    raise RuntimeError(f"Companion {version} fixture build failed: {result.stderr}")
                headers = {}
                for line in (AUTH / "dist/_headers").read_text(encoding="utf-8").splitlines():
                    if ": " in line:
                        name, value = line.strip().split(": ", 1)
                        headers[name] = value
                cls.configs[version], cls.policies[version] = config, headers
        cls.playwright = sync_playwright().start()
        executable = os.environ.get("CHROME_PATH")
        cls.browser = cls.playwright.chromium.launch(headless=True, **({"executable_path": executable} if executable else {}))

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.playwright.stop()

    def setUp(self):
        self.context = self.browser.new_context()
        self.posts, self.arrivals, self.unexpected, self.errors = [], [], [], []
        self.context.route("**/*", self.route)
        self.page = self.context.new_page()
        self.page.on("pageerror", lambda error: self.errors.append(str(error)))

    def tearDown(self):
        self.context.close()
        self.assertEqual(self.errors, [])
        self.assertEqual(self.unexpected, [])

    def start(self, version, destination=CONSOLE):
        self.version, self.destination = version, destination
        self.page.goto(SOURCE + "/oauth/consent", wait_until="load")
        self.page.wait_for_function("window.callbackFixtureReady === true")
        self.page.get_by_role("button", name="Allow access").click(no_wait_after=True)

    def route(self, route):
        request, url = route.request, urlparse(route.request.url)
        origin = f"{url.scheme}://{url.netloc}"
        if origin == SOURCE and url.path == "/oauth/consent":
            route.fulfill(status=200, content_type="text/html", headers=self.policies[self.version], body="""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="referrer" content="strict-origin">
<title>Synthetic native callback</title><script type="module" src="/fixture.mjs"></script></head>
<body><button type="button">Allow access</button></body></html>""")
        elif origin == SOURCE and url.path == "/fixture.mjs":
            script = """
import { postNativeCallback } from '/src/native-callback.js';
import { nativeCallbackPost, validateConfig, validateRedirect } from '/src/protocol.js';
window.callbackViolations = [];
document.addEventListener('securitypolicyviolation', event => window.callbackViolations.push({
  directive: event.effectiveDirective, blocked: event.blockedURI,
}));
const config = validateConfig(CONFIG);
document.querySelector('button').addEventListener('click', async () => {
  await Promise.resolve();
  const redirect = validateRedirect('https://api.example.invalid/v1/auth/callback?code=synthetic-code&state=synthetic-state', config, 'approve');
  postNativeCallback(document, window, nativeCallbackPost(redirect, config, TOKEN));
});
window.callbackFixtureReady = true;
""".replace("CONFIG", json.dumps(self.configs[self.version])).replace("TOKEN", json.dumps(TOKEN))
            route.fulfill(status=200, content_type="text/javascript", body=script)
        elif origin == SOURCE and url.path in ["/src/native-callback.js", "/src/protocol.js"]:
            route.fulfill(status=200, content_type="text/javascript", body=(AUTH / url.path.lstrip("/")).read_text(encoding="utf-8"))
        elif origin == API and url.path == "/v1/auth/callback":
            self.posts.append({"method": request.method, "fields": parse_qs(request.post_data or ""),
                               "origin": request.headers.get("origin"), "referer": request.headers.get("referer"),
                               "top_level": request.is_navigation_request() and request.frame == self.page.main_frame,
                               "query": url.query})
            route.fulfill(status=303, headers={"Location": self.destination + "/console",
                          "Set-Cookie": "fixture_session=complete; Path=/; HttpOnly; Secure; SameSite=Lax"}, body="")
        elif origin in [CONSOLE, UNLISTED] and url.path == "/console":
            self.arrivals.append({"origin": origin, "method": request.method, "query": url.query,
                                  "top_level": request.is_navigation_request() and request.frame == self.page.main_frame})
            route.fulfill(status=200, content_type="text/html", body='<main id="complete">Application callback completed</main>')
        elif origin in [SOURCE, API, CONSOLE] and url.path == "/favicon.ico":
            route.fulfill(status=204, body="")
        else:
            self.unexpected.append(request.url)
            route.abort()

    def assert_callback_was_accepted(self):
        self.assertEqual(len(self.posts), 1)
        post = self.posts[0]
        self.assertEqual(post["method"], "POST")
        self.assertEqual(post["fields"], {key: [value] for key, value in FIELDS.items()})
        self.assertEqual(post["origin"], SOURCE)
        self.assertEqual(post["referer"], SOURCE + "/")
        self.assertTrue(post["top_level"])
        self.assertEqual(post["query"], "")
        cookies = self.context.cookies(API)
        self.assertTrue(any(cookie["name"] == "fixture_session" and cookie["value"] == "complete" and cookie["httpOnly"] for cookie in cookies))

    def test_v3_policy_reproduces_successful_post_but_blocked_console_redirect(self):
        self.start("v3")
        self.page.wait_for_function("window.callbackViolations.some(item => item.directive === 'form-action')", timeout=5000)
        self.assert_callback_was_accepted()
        self.assertEqual(self.arrivals, [])
        self.assertEqual(self.page.url, SOURCE + "/oauth/consent")
        self.assertTrue(any(item["blocked"].startswith(CONSOLE) for item in self.page.evaluate("window.callbackViolations")))

    def test_v4_policy_delivers_real_form_fields_then_arrives_at_the_console(self):
        self.start("v4")
        self.page.wait_for_url(CONSOLE + "/console", timeout=5000)
        self.assert_callback_was_accepted()
        self.assertEqual(self.arrivals, [{"origin": CONSOLE, "method": "GET", "query": "", "top_level": True}])
        self.assertTrue(self.page.locator("#complete").is_visible())

    def test_v4_still_blocks_an_unlisted_final_origin(self):
        self.start("v4", destination=UNLISTED)
        self.page.wait_for_function("window.callbackViolations.some(item => item.directive === 'form-action')", timeout=5000)
        self.assert_callback_was_accepted()
        self.assertEqual(self.arrivals, [])
        self.assertTrue(any(item["blocked"].startswith(UNLISTED) for item in self.page.evaluate("window.callbackViolations")))


if __name__ == "__main__":
    unittest.main()
