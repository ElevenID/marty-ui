"""Actual loopback transport for the worker's exact HTTP and custody functions.

Only this extracted transport fixture uses plaintext loopback. The production
worker and its owner both require the pinned https://openbao:8200 endpoint.
"""

import ast
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
import json
import os
import ssl
import sys
import threading
from types import SimpleNamespace
import urllib.error
import urllib.request
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import selfhost_windows_recovery_leaf_caps as caps


@contextmanager
def servers(code, body, *, truncated=False):
    seen = []
    foreign = []

    class Foreign(BaseHTTPRequestHandler):
        def do_POST(self):
            foreign.append(self.headers.get("X-Vault-Token"))
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")

        do_GET = do_POST

        def log_message(self, *args):
            pass

    other = ThreadingHTTPServer(("127.0.0.1", 0), Foreign)

    class Origin(BaseHTTPRequestHandler):
        def do_POST(self):
            size = int(self.headers["Content-Length"])
            self.rfile.read(size)
            seen.append(self.headers.get("X-Vault-Token"))
            self.send_response(code)
            if 300 <= code < 400:
                self.send_header(
                    "Location", f"http://127.0.0.1:{other.server_port}/foreign"
                )
            self.send_header(
                "Content-Length", str(len(body) + (10 if truncated else 0))
            )
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True

        def log_message(self, *args):
            pass

    origin = ThreadingHTTPServer(("127.0.0.1", 0), Origin)
    threads = [
        threading.Thread(target=s.serve_forever, daemon=True) for s in (origin, other)
    ]
    for t in threads:
        t.start()
    try:
        yield SimpleNamespace(
            url=f"http://127.0.0.1:{origin.server_port}",
            proxy=f"http://127.0.0.1:{other.server_port}",
            seen=seen,
            foreign=foreign,
        )
    finally:
        for s in (origin, other):
            s.shutdown()
            s.server_close()
        for t in threads:
            t.join(timeout=5)


def transport(url):
    tree = ast.parse(caps.CAP_WORKER)
    names = {"NoRedirect", "request"}
    nodes = [
        n
        for n in tree.body
        if isinstance(n, (ast.ClassDef, ast.FunctionDef))
        and n.name in names
        or isinstance(n, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "opener" for t in n.targets)
    ]
    assert len(nodes) == 3
    namespace = {
        "urllib": urllib,
        "http": http,
        "json": json,
        "os": os,
        "ctx": ssl.create_default_context(),
        "d": {"bao_addr": url},
        "token": "SYNTHETIC_PRIVATE_AUTHORITY",
    }
    exec(
        compile(
            ast.Module(body=nodes, type_ignores=[]), "exact-cap-http-transport", "exec"
        ),
        namespace,
    )
    return namespace["request"]


@pytest.mark.parametrize("code", [301, 302, 303, 307, 308])
def test_every_redirect_refuses_before_forwarding_authority(tmp_path, code):
    body = b"SYNTHETIC_REDIRECT_RECEIPT"
    with servers(code, body) as server, (tmp_path / "received").open("wb") as custody:
        request = transport(server.url)
        with pytest.raises(AssertionError):
            request("auth/token/create/selfhost-renew-leaf", {}, custody=custody)
        assert server.foreign == [] and server.seen == ["SYNTHETIC_PRIVATE_AUTHORITY"]
    assert (tmp_path / "received").read_bytes() == body


def test_environment_proxies_cannot_receive_authority(monkeypatch):
    with servers(200, b"{}") as server:
        for name in [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
        ]:
            monkeypatch.setenv(name, server.proxy)
        monkeypatch.setenv("NO_PROXY", "")
        monkeypatch.setenv("no_proxy", "")
        assert transport(server.url)("auth/token/lookup", {}) == b"{}"
        assert server.foreign == [] and server.seen == ["SYNTHETIC_PRIVATE_AUTHORITY"]


@pytest.mark.parametrize(
    "fault", ["malformed", "oversized", "truncated", "server-error"]
)
def test_received_mint_bytes_are_preserved_before_validation(tmp_path, fault):
    raw = (
        b'{"auth":'
        if fault == "malformed"
        else b"x" * 131073
        if fault == "oversized"
        else b'{"auth":{}}'
    )
    code = 500 if fault == "server-error" else 200
    with (
        servers(code, raw, truncated=fault == "truncated") as server,
        (tmp_path / "received").open("wb") as custody,
    ):
        request = transport(server.url)
        if fault == "malformed":
            received = request(
                "auth/token/create/selfhost-renew-leaf", {}, custody=custody
            )
            with pytest.raises(ValueError):
                json.loads(received)
        else:
            with pytest.raises(AssertionError):
                request("auth/token/create/selfhost-renew-leaf", {}, custody=custody)
    assert (tmp_path / "received").read_bytes() == raw
