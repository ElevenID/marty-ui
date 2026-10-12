"""Executable language-neutral contract for the optional local Canvas bridge."""

from __future__ import annotations

import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time

import pytest


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = json.loads(
    (ROOT / "contracts/canvas-localhost-bridge-behavior.json").read_text(
        encoding="utf-8"
    )
)


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
            requests.append((self.command, self.path, body, dict(self.headers)))
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
def bridge(upstream):
    port = unused_port()
    upstream_port, _ = upstream
    env = os.environ.copy()
    env.update(
        CANVAS_LOCALHOST_BRIDGE_LISTEN_HOST="127.0.0.1",
        CANVAS_LOCALHOST_BRIDGE_LISTEN_PORT=str(port),
        CANVAS_LOCALHOST_BRIDGE_UPSTREAM=f"http://127.0.0.1:{upstream_port}/",
        CANVAS_LOCALHOST_BRIDGE_PUBLIC_BASE="http://localhost:8088/",
    )
    candidate = os.environ.get("CANVAS_LOCALHOST_BRIDGE_CANDIDATE")
    command = (
        [candidate]
        if candidate
        else [sys.executable, str(ROOT / "docker/canvas-localhost-bridge/server.py")]
    )
    process = subprocess.Popen(command, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
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
        return response.status, dict(response.getheaders()), response.read()
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
    assert headers["Content-Type"] == "application/json"
    if method == "HEAD":
        assert body == b""
        assert headers["Content-Length"] == "0"
    else:
        assert json.loads(body) == json.loads(
            json.dumps(CONTRACT["discovery"]).replace(
                "{public_base}", "http://localhost:8088"
            )
        )
        assert int(headers["Content-Length"]) == len(body)
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
    assert headers["Content-Type"] == "application/octet-stream"
    assert "Connection" not in headers
    assert len(seen) == 1
    got_method, got_path, got_body, got_headers = seen[0]
    assert (got_method, got_path, got_body) == (method, path, body or b"")
    assert got_headers["Content-Type"] == "application/x-test"
    assert got_headers["X-Bridge-Trace"] == "synthetic"
    if method == "HEAD":
        assert response_body == b""
        assert headers["Content-Length"] == "0"
    else:
        assert response_body == b"canvas-upstream-response"
        assert headers["Content-Length"] == str(len(response_body))


def test_unavailable_upstream_returns_json_502():
    port, refused_port = unused_port(), unused_port()
    env = os.environ.copy()
    env.update(
        CANVAS_LOCALHOST_BRIDGE_LISTEN_HOST="127.0.0.1",
        CANVAS_LOCALHOST_BRIDGE_LISTEN_PORT=str(port),
        CANVAS_LOCALHOST_BRIDGE_UPSTREAM=f"http://127.0.0.1:{refused_port}",
    )
    candidate = os.environ.get("CANVAS_LOCALHOST_BRIDGE_CANDIDATE")
    command = (
        [candidate]
        if candidate
        else [sys.executable, str(ROOT / "docker/canvas-localhost-bridge/server.py")]
    )
    process = subprocess.Popen(command, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
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
        assert headers["Content-Type"] == "application/json"
        assert json.loads(body)["error"].startswith(CONTRACT["upstream_error_json_prefix"])
    finally:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
        process.stderr.close()


def test_contract_covers_source_and_methods():
    source = (ROOT / "docker/canvas-localhost-bridge/server.py").read_text()
    assert CONTRACT["source"].endswith("be17936d3")
    assert CONTRACT["upstream_timeout_seconds"] == 30
    for method in CONTRACT["proxy_methods"]:
        assert f"def do_{method}(" in source
