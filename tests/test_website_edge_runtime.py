"""Optional local Nginx integration; no Docker or product process is required."""
from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import urllib.error
import urllib.request

import pytest

from tests.test_deploy_website import candidate, host_candidate, another_release
import deploy_website as deploy

ROOT = Path(__file__).resolve().parents[1]


def test_real_edge_routes_retained_assets_and_starts_while_product_is_unavailable(host_candidate, tmp_path):
    nginx = os.environ.get("MARTY_TEST_NGINX_EXECUTABLE")
    if not nginx:
        pytest.skip("set MARTY_TEST_NGINX_EXECUTABLE for the local Nginx integration")
    host, kwargs, _, _, verifiers = host_candidate
    deploy.apply(host, kwargs["output"], **verifiers)
    assets, _ = another_release(kwargs, "c" * 40)
    state = deploy.apply(host, assets, **verifiers)
    servers = {}
    threads = []
    for owner in ("active", "previous", "application", "gateway", "keycloak"):
        def handler(owner):
            class Handler(BaseHTTPRequestHandler):
                def do_GET(self):
                    raw = json.dumps({"owner": owner, "path": self.path, "host": self.headers.get("Host")}).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                def do_POST(self):
                    body = self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode()
                    raw = json.dumps({"owner": owner, "path": self.path,
                                      "host": self.headers.get("Host"), "body": body}).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                def log_message(self, *_args):
                    pass
            return Handler
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler(owner))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        servers[owner] = server
        threads.append(thread)
    address = {owner: f"127.0.0.1:{server.server_port}" for owner, server in servers.items()}
    routes = deploy.render_routes(state).decode()
    for slot, owner in ((state["active"], "active"), (state["previous"], "previous")):
        routes = routes.replace(f"set $website_upstream {slot}:80;", f"set $website_upstream {address[owner]};")
    include = tmp_path / "website-routes.conf"
    include.write_text(routes)
    with socket.socket() as port_socket:
        port_socket.bind(("127.0.0.1", 0))
        port = port_socket.getsockname()[1]
    template = (ROOT / "docker/nginx-selfhost.prod.conf.template").read_text()
    replacements = {"PUBLIC_DOMAIN": "localhost", "CONSOLE_DISABLED": "0", "GATEWAY_UPSTREAM": address["gateway"],
                    "UI_UPSTREAM": address["application"], "KEYCLOAK_UPSTREAM": address["keycloak"],
                    "FLOW_UPSTREAM": address["gateway"], "CANVAS_REAL_PUBLIC_HOST": "canvas.example.org",
                    "CANVAS_SANDBOX_PUBLIC_HOST": "canvas-test.example.org"}
    for key, value in replacements.items():
        template = template.replace("${" + key + "}", value)
    template = template.replace("listen 80;", f"listen 127.0.0.1:{port};")
    template = template.replace("/etc/nginx/marty-website/*.conf", include.as_posix())
    configuration = tmp_path / "nginx.conf"
    (tmp_path / "logs").mkdir()
    (tmp_path / "temp").mkdir()
    user = "user root;\n" if os.name != "nt" and os.geteuid() == 0 else ""
    configuration.write_text(user + f"daemon off; pid {(tmp_path / 'nginx.pid').as_posix()}; error_log {(tmp_path / 'error.log').as_posix()};\n"
                             "events {}\nhttp { access_log off;\n" + template + "\n}\n")
    command = [nginx, "-p", str(tmp_path), "-c", str(configuration)]
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    process = None
    try:
        checked = subprocess.run([*command, "-t"], capture_output=True, text=True)
        assert checked.returncode == 0, checked.stderr
        # First qualify the default combined route with no website overlay.
        # A slash-ending proxy prefix otherwise redirects /resources into
        # Keycloak, hiding the marketing page before the SPA can receive it.
        include.write_text("")
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        origin = f"http://127.0.0.1:{port}"
        for _ in range(60):
            try:
                with opener.open(origin + "/edge-healthz", timeout=1) as response:
                    assert response.read() == b"ok\n"
                break
            except OSError:
                assert process.poll() is None, process.stderr.read().decode()
                time.sleep(0.05)
        else:
            pytest.fail("combined Nginx did not become ready")
        for path, owner in (("/resources", "application"),
                            ("/resources?next=%2Flogin", "application"),
                            ("/resources/", "keycloak"),
                            ("/resources/auth.css?version=1", "keycloak"),
                            ("/api/organizations?limit=2", "gateway"),
                            ("/auth/login?next=%2Fconsole", "gateway"),
                            ("/console/assets/main.js?version=1", "application")):
            with opener.open(origin + path, timeout=3) as response:
                assert json.load(response) == {"owner": owner, "path": path,
                                              "host": "127.0.0.1"}
        request = urllib.request.Request(origin + "/api/auth/login?next=%2Fconsole",
                                         data=b"synthetic=body", method="POST")
        with opener.open(request, timeout=3) as response:
            assert json.load(response) == {"owner": "gateway",
                "path": "/api/auth/login?next=%2Fconsole", "host": "127.0.0.1",
                "body": "synthetic=body"}
        subprocess.run([*command, "-s", "quit"], capture_output=True, check=True, timeout=5)
        process.communicate(timeout=5)
        process = None
        include.write_text(routes)
        # Remove all product listeners before even starting Nginx. Variable
        # upstreams must not impose startup readiness on these unavailable roles.
        for owner in ("application", "gateway", "keycloak"):
            servers[owner].shutdown()
            servers[owner].server_close()
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        origin = f"http://127.0.0.1:{port}"
        for _ in range(60):
            try:
                with opener.open(origin + "/edge-healthz", timeout=1) as response:
                    assert response.read() == b"ok\n"
                break
            except OSError:
                assert process.poll() is None, process.stderr.read().decode()
                time.sleep(0.05)
        else:
            pytest.fail("local Nginx did not become ready")
        for path, owner in (("/", "active"), ("/product/?next=%2Flogin", "active"), ("/resources", "active"),
                            ("/demos/2026.07.0", "active"), ("/sitemap-blog.xml", "active"),
                            ("/_website/runtime-config.js", "active"),
                            ("/_website/" + state["slots"][state["previous"]]["revision"] + "/assets/chunk.js", "previous"),
                            ("/_website/" + state["slots"][state["active"]]["revision"] + "/assets/chunk.js", "active")):
            with opener.open(origin + path, timeout=3) as response:
                value = json.load(response)
                assert value == {"owner": owner, "path": path, "host": f"127.0.0.1:{port}"}
        for path in ("/resources/auth.css", "/docs", "/login/error", "/console", "/ready", "/health/ready"):
            with pytest.raises(urllib.error.HTTPError) as error:
                opener.open(origin + path, timeout=3)
            assert error.value.code == 502, path
        with pytest.raises(urllib.error.HTTPError) as error:
            opener.open(origin + "/_website/" + "9" * 40 + "/missing.js", timeout=3)
        assert error.value.code == 404
    finally:
        if process is not None:
            if process.poll() is None:
                subprocess.run([*command, "-s", "quit"], capture_output=True, check=True, timeout=5)
            process.communicate(timeout=5)
        for server in servers.values():
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=3)
