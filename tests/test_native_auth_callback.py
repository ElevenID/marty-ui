"""Qualify a real HTTPS POST and 303 across auth, API and console origins.

Uses the production form helper and policies emitted by the actual Bun build.
Only synthetic hosts resolve, to an ephemeral loopback TLS server. No browser
request interception, system hosts edits, proxy changes or CSP bypass is used.
Set OPENSSL_EXECUTABLE when openssl is not on PATH (for example Git for Windows).
"""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
import unittest
from urllib.parse import parse_qs, urlparse

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
AUTH = ROOT / "integrations/supabase-auth-ui"
SOURCE = "https://auth.example.invalid"
API = "https://api.example.invalid"
CONSOLE = "https://console.example.invalid"
UNLISTED = "https://unlisted.example.invalid"
ORIGINS = (SOURCE, API, CONSOLE, UNLISTED)
TOKEN = "synthetic_header.synthetic_payload.synthetic_signature"
FIELDS = {"code": "synthetic-code", "state": "synthetic-state", "native_access_token": TOKEN}


class CallbackFixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.serve_fixture()

    def do_POST(self):
        self.serve_fixture()

    def serve_fixture(self):
        fixture = self.server.fixture
        if fixture is None:
            self.send_error(503, "No active callback fixture")
            return
        try:
            fixture.serve(self)
        except Exception as error:
            fixture.errors.append(f"HTTPS fixture: {error}")
            self.send_error(500, "Callback fixture failed")

    def respond(self, status, body=b"", content_type=None, headers=None):
        body = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)
        if content_type:
            self.send_header("Content-Type", content_type)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        pass


class CallbackFixtureServer(ThreadingHTTPServer):
    daemon_threads = True
    fixture = None

    def __init__(self, tls):
        self.tls = tls
        super().__init__(("127.0.0.1", 0), CallbackFixtureHandler)

    def process_request_thread(self, request, client_address):
        # A speculative TCP connection must not hold up the accepting thread.
        # Bound both TLS negotiation and request reads on each worker socket.
        request.settimeout(5)
        try:
            connection = self.tls.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError):
            request.close()
            return
        super().process_request_thread(connection, client_address)


class NativeAuthCallbackBrowserTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        bun = os.environ.get("BUN_EXECUTABLE", "bun")
        version = subprocess.run([bun, "--version"], capture_output=True, text=True, check=True, timeout=15).stdout.strip()
        if version != "1.4.4":
            raise RuntimeError(f"The qualified companion toolchain requires Bun 1.4.4; observed {version}")
        temporary = tempfile.TemporaryDirectory(prefix="elevenid-native-callback-")
        cls.addClassCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        cls.configs, cls.policies = {}, {}
        example = json.loads((AUTH / "public/config.split-origin.example.json").read_text(encoding="utf-8"))
        for version in ["v3", "v4"]:
            config = json.loads(json.dumps(example))
            config["schema"] = f"elevenid.supabase-auth-ui/{version}"
            if version == "v3":
                del config["postRedirectOrigins"]
            path = directory / f"{version}.json"
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
            if not headers.get("Content-Security-Policy"):
                raise RuntimeError(f"Companion {version} build omitted its CSP")
            cls.configs[version], cls.policies[version] = config, headers

        # Generate a disposable key, without committing a reusable private key
        # or changing any trust store. Only this browser context accepts its cert.
        certificate, key = directory / "certificate.pem", directory / "key.pem"
        openssl = os.environ.get("OPENSSL_EXECUTABLE", "openssl")
        subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-keyout", str(key), "-out", str(certificate), "-subj", "/CN=auth.example.invalid",
                        "-addext", "subjectAltName=" + ",".join(f"DNS:{urlparse(origin).hostname}" for origin in ORIGINS)],
                       capture_output=True, text=True, check=True, timeout=15)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(certificate, key)
        cls.server = CallbackFixtureServer(tls)
        cls.addClassCleanup(cls.server.server_close)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        cls.addClassCleanup(cls.stop_server)

        cls.playwright = sync_playwright().start()
        cls.addClassCleanup(cls.playwright.stop)
        port = cls.server.server_address[1]
        rules = ", ".join(f"MAP {urlparse(origin).hostname}:443 127.0.0.1:{port}" for origin in ORIGINS)
        rules += ", MAP * ^NOTFOUND"
        executable = os.environ.get("CHROME_PATH")
        # Resolver rules change only connection endpoints; HTTPS origins, Host,
        # cookies and form-action retain the real synthetic host identities.
        cls.browser = cls.playwright.chromium.launch(
            headless=True, args=[f"--host-resolver-rules={rules}", "--no-proxy-server"],
            **({"executable_path": executable} if executable else {}))
        cls.addClassCleanup(cls.browser.close)

    @classmethod
    def stop_server(cls):
        cls.server.shutdown()
        cls.server_thread.join(timeout=5)
        if cls.server_thread.is_alive():
            raise RuntimeError("Callback HTTPS fixture did not stop")

    def setUp(self):
        self.context = self.browser.new_context(ignore_https_errors=True, bypass_csp=False, service_workers="block")
        self.addCleanup(self.context.close)
        self.posts, self.arrivals, self.navigations, self.unexpected, self.errors = [], [], [], [], []
        self.server.fixture = self
        self.page = self.context.new_page()
        self.page.on("pageerror", lambda error: self.errors.append(str(error)))
        self.page.on("request", self.observe_request)

    def tearDown(self):
        self.context.close()
        self.server.fixture = None
        self.assertEqual(self.errors, [])
        self.assertEqual(self.unexpected, [])

    def observe_request(self, request):
        url = urlparse(request.url)
        origin = f"{url.scheme}://{url.netloc}"
        if origin not in ORIGINS:
            self.unexpected.append(request.url)
        if request.is_navigation_request():
            self.navigations.append({"url": request.url, "method": request.method,
                                     "top_level": request.frame == self.page.main_frame})

    def start(self, version, destination=CONSOLE):
        self.version, self.destination = version, destination
        response = self.page.goto(SOURCE + "/oauth/consent", wait_until="load")
        self.assertEqual(response.status, 200)
        self.assertEqual(response.header_value("Content-Security-Policy"), self.policies[version]["Content-Security-Policy"])
        self.page.locator('body[data-callback-ready="true"]').wait_for(state="attached", timeout=5000)
        self.page.get_by_role("button", name="Allow access").click(no_wait_after=True)

    def serve(self, request):
        url = urlparse(request.path)
        origin = "https://" + request.headers.get("Host", "")
        if request.command == "GET" and origin == SOURCE and url.path == "/oauth/consent":
            request.respond(200, content_type="text/html", headers=self.policies[self.version], body="""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="referrer" content="strict-origin">
<title>Synthetic native callback</title><script type="module" src="/fixture.mjs"></script></head>
<body><button type="button" disabled>Allow access</button><div id="violations"></div></body></html>""")
        elif request.command == "GET" and origin == SOURCE and url.path == "/fixture.mjs":
            script = """
import { postNativeCallback } from '/src/native-callback.js';
import { nativeCallbackPost, validateConfig, validateRedirect } from '/src/protocol.js';
document.addEventListener('securitypolicyviolation', event => {
  const item = document.createElement('output');
  item.dataset.directive = event.effectiveDirective;
  item.dataset.blocked = event.blockedURI;
  item.textContent = event.effectiveDirective;
  document.getElementById('violations').append(item);
});
const config = validateConfig(CONFIG);
const button = document.querySelector('button');
button.addEventListener('click', async () => {
  await Promise.resolve();
  const redirect = validateRedirect('https://api.example.invalid/v1/auth/callback?code=synthetic-code&state=synthetic-state', config, 'approve');
  postNativeCallback(document, window, nativeCallbackPost(redirect, config, TOKEN));
});
button.disabled = false;
document.body.dataset.callbackReady = 'true';
""".replace("CONFIG", json.dumps(self.configs[self.version])).replace("TOKEN", json.dumps(TOKEN))
            request.respond(200, content_type="text/javascript", body=script)
        elif request.command == "GET" and origin == SOURCE and url.path in ["/src/native-callback.js", "/src/protocol.js"]:
            request.respond(200, content_type="text/javascript", body=(AUTH / url.path.lstrip("/")).read_bytes())
        elif request.command == "POST" and origin == API and url.path == "/v1/auth/callback":
            length = int(request.headers.get("Content-Length", "0"))
            if not 0 < length <= 4096:
                raise ValueError("Callback form exceeds the fixture body bound")
            fields = parse_qs(request.rfile.read(length).decode("utf-8"))
            self.posts.append({"method": request.command, "fields": fields,
                               "origin": request.headers.get("Origin"), "referer": request.headers.get("Referer"),
                               "content_type": request.headers.get("Content-Type"), "query": url.query})
            request.respond(303, headers={"Location": self.destination + "/console",
                            "Set-Cookie": "fixture_session=complete; Path=/; HttpOnly; Secure; SameSite=Lax"})
        elif request.command == "GET" and origin in [CONSOLE, UNLISTED] and url.path == "/console":
            self.arrivals.append({"origin": origin, "method": request.command, "query": url.query})
            request.respond(200, content_type="text/html", body='<main id="complete">Application callback completed</main>')
        elif request.command == "GET" and origin in ORIGINS and url.path == "/favicon.ico":
            request.respond(204)
        else:
            self.unexpected.append(f"{request.command} {origin}{request.path}")
            request.respond(404)

    def assert_callback_was_accepted(self):
        self.assertEqual(len(self.posts), 1)
        post = self.posts[0]
        self.assertEqual(post["method"], "POST")
        self.assertEqual(post["fields"], {key: [value] for key, value in FIELDS.items()})
        self.assertEqual(post["origin"], SOURCE)
        self.assertEqual(post["referer"], SOURCE + "/")
        self.assertEqual(post["content_type"], "application/x-www-form-urlencoded")
        self.assertEqual(post["query"], "")
        self.assertEqual([item for item in self.navigations if item["url"].startswith(API)],
                         [{"url": API + "/v1/auth/callback", "method": "POST", "top_level": True}])
        cookies = self.context.cookies(API)
        self.assertTrue(any(cookie["name"] == "fixture_session" and cookie["value"] == "complete"
                            and cookie["httpOnly"] and cookie["secure"] and cookie["sameSite"] == "Lax" for cookie in cookies))

    def assert_form_redirect_blocked(self, destination):
        violations = self.page.locator('#violations output[data-directive="form-action"]')
        violations.first.wait_for(state="attached", timeout=5000)
        self.assertTrue(any(violations.nth(index).get_attribute("data-blocked").startswith(destination)
                            for index in range(violations.count())))
        self.assertEqual(self.arrivals, [])
        self.assertEqual(self.page.url, SOURCE + "/oauth/consent")

    def test_v3_policy_reproduces_successful_post_but_blocked_console_redirect(self):
        self.start("v3")
        self.assert_form_redirect_blocked(CONSOLE)
        self.assert_callback_was_accepted()

    def test_v4_policy_delivers_real_form_fields_then_arrives_at_the_console(self):
        self.start("v4")
        self.page.wait_for_url(CONSOLE + "/console", timeout=5000)
        self.page.locator("#complete").wait_for(state="visible", timeout=5000)
        self.assert_callback_was_accepted()
        self.assertEqual(self.arrivals, [{"origin": CONSOLE, "method": "GET", "query": ""}])
        self.assertEqual([item for item in self.navigations if item["url"].startswith(CONSOLE)],
                         [{"url": CONSOLE + "/console", "method": "GET", "top_level": True}])

    def test_v4_still_blocks_an_unlisted_final_origin(self):
        self.start("v4", destination=UNLISTED)
        self.assert_form_redirect_blocked(UNLISTED)
        self.assert_callback_was_accepted()


if __name__ == "__main__":
    unittest.main()
