"""The local test lab must not accept cross-origin control requests."""
from http.client import HTTPConnection
import importlib.util
from pathlib import Path
import threading
import urllib.parse
import pytest

from http.server import ThreadingHTTPServer


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("passkey_test_lab", ROOT / "scripts/run_passkey_test_lab.py")
lab_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lab_module)


def test_control_requests_require_current_host_origin_and_csrf_and_stop_after_closure(tmp_path):
    lab = lab_module.Lab(tmp_path, 1)
    lab.ready = True
    calls = []
    lab.email_action = lambda: calls.append("email")
    server = ThreadingHTTPServer(("127.0.0.1", 0), lab_module.handler(lab))
    lab.origin = "http://localhost:" + str(server.server_port)
    host = urllib.parse.urlparse(lab.origin).netloc
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def request(path, origin, csrf, supplied_host=host):
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=3)
        try:
            connection.request("POST", path, urllib.parse.urlencode({"csrf": csrf}),
                               headers={"Origin": origin, "Host": supplied_host})
            response = connection.getresponse()
            response.read()
            return response.status
        finally:
            connection.close()

    try:
        assert request("/email", "https://foreign.example", lab.csrf) == 403
        assert request("/email", lab.origin, "incorrect") == 403
        assert request("/email", lab.origin, lab.csrf, "foreign.example") == 403
        assert calls == []
        assert request("/email", lab.origin, lab.csrf) == 200
        assert calls == ["email"]
        assert request("/stop", lab.origin, lab.csrf) == 200 and lab.stop.is_set()
        lab.ready = False
        assert request("/email", lab.origin, lab.csrf) == 403
        assert calls == ["email"]
        assert "closed" in lab.page()
    finally:
        server.shutdown()
        server.server_close()


def test_real_browser_form_preserves_origin_and_passes_the_local_control_gate(tmp_path):
    playwright_api = pytest.importorskip("playwright.sync_api")
    lab = lab_module.Lab(tmp_path, 1)
    lab.ready = True
    calls = []
    lab.email_action = lambda: calls.append("email")
    lab.page = lambda: (f'<form method="post" action="/email"><input type="hidden" '
                        f'name="csrf" value="{lab.csrf}"><button>Send</button></form>')
    server = ThreadingHTTPServer(("127.0.0.1", 0), lab_module.handler(lab))
    lab.origin = "http://localhost:" + str(server.server_port)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with playwright_api.sync_playwright() as playwright:
            browser = playwright.chromium.launch(channel="chrome", headless=True)
            try:
                page = browser.new_page()
                page.goto(lab.origin)
                page.get_by_role("button", name="Send", exact=True).click()
                assert "Action completed" in page.locator("body").inner_text()
                assert calls == ["email"]
            finally:
                browser.close()
    finally:
        server.shutdown()
        server.server_close()
