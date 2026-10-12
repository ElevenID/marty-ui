"""Executable language-neutral contract for the optional local Canvas bridge."""

from __future__ import annotations

import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import threading
import time

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = json.loads(
    (ROOT / "contracts/canvas-localhost-bridge-behavior.json").read_text(
        encoding="utf-8"
    )
)


@pytest.fixture(scope="session")
def candidate_binary():
    candidate = os.environ.get("CANVAS_LOCALHOST_BRIDGE_CANDIDATE")
    if not candidate:
        pytest.skip("Set CANVAS_LOCALHOST_BRIDGE_CANDIDATE to the built Rust bridge")
    binary = Path(candidate)
    assert binary.is_file(), f"Rust bridge binary missing: {binary}"
    return str(binary)


def unused_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


@pytest.fixture
def upstream():
    requests = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def __getattr__(self, name):
            if name.startswith("do_"):
                return self.handle_any
            raise AttributeError(name)

        def handle_any(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            requests.append((self.command, self.path, body,
                             {key.lower(): value for key, value in self.headers.items()}))
            if self.path == "/redirect-cross-host":
                self.send_response(307)
                self.send_header("Location", self.headers["X-Redirect-To"])
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            payload = b"canvas-upstream-response"
            self.send_response(218)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Connection", "keep-alive")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(payload)

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port, requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


@pytest.fixture
def bridge(upstream, candidate_binary):
    port = unused_port()
    upstream_port, _ = upstream
    env = os.environ.copy()
    env.update(
        CANVAS_LOCALHOST_BRIDGE_LISTEN_HOST="127.0.0.1",
        CANVAS_LOCALHOST_BRIDGE_LISTEN_PORT=str(port),
        CANVAS_LOCALHOST_BRIDGE_UPSTREAM=f"http://127.0.0.1:{upstream_port}/",
        CANVAS_LOCALHOST_BRIDGE_PUBLIC_BASE="http://localhost:8088/",
    )
    process = subprocess.Popen([candidate_binary], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        for _ in range(100):
            if process.poll() is not None:
                raise AssertionError(f"bridge exited: {process.stderr.read().decode()}")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    break
            except OSError:
                time.sleep(0.02)
        else:
            raise AssertionError("bridge did not listen")
        yield port, env
    finally:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
        process.stderr.close()


def request(port, method, path, body=None, headers=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        return response.status, {key.lower(): value for key, value in response.getheaders()}, response.read()
    finally:
        connection.close()


@pytest.mark.parametrize("method", CONTRACT["discovery_methods"])
def test_discovery_is_local_and_does_not_hit_upstream(bridge, upstream, method):
    port, _ = bridge
    _, seen = upstream
    status, headers, body = request(
        port, method, CONTRACT["discovery_path"] + "?query=preserved"
    )
    assert status == 200
    assert headers["content-type"] == "application/json"
    if method == "HEAD":
        assert body == b""
        assert headers["content-length"] == "0"
    else:
        assert json.loads(body) == json.loads(
            json.dumps(CONTRACT["discovery"]).replace(
                "{public_base}", "http://localhost:8088"
            )
        )
        assert int(headers["content-length"]) == len(body)
    assert seen == []


@pytest.mark.parametrize("method", CONTRACT["proxy_methods"])
def test_all_methods_proxy_path_query_body_and_response(bridge, upstream, method):
    port, _ = bridge
    _, seen = upstream
    path = (
        CONTRACT["discovery_path"] + "?post=must-proxy"
        if method == "POST"
        else "/api/lti/test?x=1&y=two"
    )
    body = b"opaque=body\x00payload" if method in ("POST", "PUT", "PATCH", "DELETE") else None
    status, headers, response_body = request(
        port,
        method,
        path,
        body,
        {"Content-Type": "application/x-test", "X-Bridge-Trace": "synthetic"},
    )
    assert status == 218
    assert headers["content-type"] == "application/octet-stream"
    assert "connection" not in headers
    assert len(seen) == 1
    got_method, got_path, got_body, got_headers = seen[0]
    assert (got_method, got_path, got_body) == (method, path, body or b"")
    assert got_headers["content-type"] == "application/x-test"
    assert got_headers["x-bridge-trace"] == "synthetic"
    if method == "HEAD":
        assert response_body == b""
        assert headers["content-length"] == "0"
    else:
        assert response_body == b"canvas-upstream-response"
        assert headers["content-length"] == str(len(response_body))


def test_unavailable_upstream_returns_json_502(candidate_binary):
    port, refused_port = unused_port(), unused_port()
    env = os.environ.copy()
    env.update(
        CANVAS_LOCALHOST_BRIDGE_LISTEN_HOST="127.0.0.1",
        CANVAS_LOCALHOST_BRIDGE_LISTEN_PORT=str(port),
        CANVAS_LOCALHOST_BRIDGE_UPSTREAM=f"http://127.0.0.1:{refused_port}",
    )
    process = subprocess.Popen([candidate_binary], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        for _ in range(100):
            if process.poll() is not None:
                raise AssertionError(f"bridge exited: {process.stderr.read().decode()}")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    break
            except OSError:
                time.sleep(0.02)
        else:
            raise AssertionError("bridge did not listen")
        status, headers, body = request(port, "GET", "/api/lti/failure")
        assert status == CONTRACT["upstream_error_status"]
        assert headers["content-type"] == "application/json"
        assert json.loads(body)["error"].startswith(CONTRACT["upstream_error_json_prefix"])
    finally:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
        process.stderr.close()


def test_cross_host_redirect_is_returned_without_replaying_credentials(bridge, upstream):
    port, _ = bridge
    _, seen = upstream
    replayed = []

    class Sink(BaseHTTPRequestHandler):
        def do_POST(self):
            replayed.append((self.headers.get("Authorization"), self.headers.get("Cookie")))
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *_args):
            pass

    sink = ThreadingHTTPServer(("127.0.0.1", 0), Sink)
    thread = threading.Thread(target=sink.serve_forever, daemon=True)
    thread.start()
    target = f"http://127.0.0.1:{sink.server_port}/steal"
    try:
        status, headers, body = request(
            port,
            "POST",
            "/redirect-cross-host",
            b"sensitive=synthetic",
            {"Authorization": "Bearer synthetic", "Cookie": "session=synthetic",
             "X-Redirect-To": target},
        )
        assert status == 307
        assert headers["location"] == target
        assert body == b""
        assert seen[0][0:3] == ("POST", "/redirect-cross-host", b"sensitive=synthetic")
        assert replayed == []
    finally:
        sink.shutdown()
        sink.server_close()
        thread.join(timeout=3)


@pytest.mark.parametrize("method", CONTRACT["unsupported_methods"])
def test_unsupported_methods_are_not_proxied(bridge, upstream, method):
    port, _ = bridge
    _, seen = upstream
    status, _, _ = request(port, method, "/api/lti/test")
    assert status == CONTRACT["unsupported_method_status"]
    assert seen == []


def test_contract_covers_native_source_and_runtime_wiring():
    source = (ROOT / "docker/canvas-localhost-bridge/src/main.rs").read_text()
    dockerfile = (ROOT / "docker/canvas-localhost-bridge/Dockerfile").read_text()
    compose = (ROOT / "docker-compose.profile.canvas-real.yml").read_text()
    service = yaml.safe_load(compose)["services"]["issuance-canvas-localhost-bridge"]
    catalog = json.loads((ROOT / "deploy-config/catalog/services.json").read_text())
    listed = catalog["services"]["issuance-canvas-localhost-bridge"]
    deploy = (ROOT / "scripts/deploy-local-beta-release.ps1").read_text()
    assert CONTRACT["source"].endswith("be17936d3")
    assert CONTRACT["upstream_timeout_seconds"] == 30
    assert "Duration::from_secs(30)" in source
    assert "redirect::Policy::none()" in source
    assert "FROM rust:1.95-bookworm@sha256:" in dockerfile
    assert "FROM debian:bookworm-slim@sha256:" in dockerfile
    assert "docker/canvas-localhost-bridge/src/main.rs" in deploy
    assert "docker/canvas-localhost-bridge/Cargo.lock" in deploy
    assert deploy.index("$runningCanvasBridge = @(& docker ps") < deploy.index(
        'Write-Step "Enter maintenance window and apply live migration"'
    )
    assert "Stop the optional Canvas localhost bridge before beta release" in deploy
    assert service["build"] == {
        "context": "${MARTY_RUNTIME_CONFIG_ROOT:-.}/docker/canvas-localhost-bridge",
        "dockerfile": "Dockerfile",
    }
    assert service["network_mode"] == "service:issuance"
    assert "command" not in service and "volumes" not in service
    assert listed["image_name"] == "issuance-canvas-localhost-bridge"
    assert listed["dockerfile"] == "docker/canvas-localhost-bridge/Dockerfile"
    assert listed["context"] == "docker/canvas-localhost-bridge"
    assert "python:3.12-alpine" not in compose
    assert "server.py" not in compose
    assert not (ROOT / "docker/canvas-localhost-bridge/server.py").exists()


@pytest.mark.parametrize("running", [False, True])
def test_beta_preflight_rejects_running_optional_bridge_before_mutation(tmp_path, running):
    powershell = shutil.which("pwsh") or shutil.which("powershell")
    if not powershell:
        pytest.skip("PowerShell unavailable")
    deploy = (ROOT / "scripts/deploy-local-beta-release.ps1").read_text()
    start = deploy.index("$runningCanvasBridge = @(& docker ps")
    end = deploy.index("if ($OfficialStackRelease) {", start)
    guard = deploy[start:end]
    marker = "'synthetic-bridge-id'" if running else ""
    harness = tmp_path / "bridge-guard.ps1"
    harness.write_text(
        "$ErrorActionPreference = 'Stop'\n"
        "$script:BetaProject = 'elevenid-beta'\n"
        "function docker {\n"
        "  if ($args[0] -ne 'ps') { throw 'Unexpected Docker invocation' }\n"
        "  $global:LASTEXITCODE = 0\n"
        f"  {marker}\n"
        "}\n"
        + "try {\n"
        + guard
        + "\n} catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }\n",
        encoding="utf-8",
    )
    result = subprocess.run(
        [powershell, "-NoProfile", "-File", str(harness)],
        capture_output=True, text=True, timeout=15,
    )
    assert (result.returncode != 0) is running
    if running:
        assert "Stop the optional Canvas localhost bridge before beta release" in result.stderr
