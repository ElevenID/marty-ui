#!/usr/bin/env python3
"""Localhost bridge for real Canvas LTI metadata in local dev.

Why this exists:
- The issuance service allows plain HTTP Canvas base URLs only for localhost.
- The real Canvas container is reachable from issuance via host.docker.internal:8088,
  not issuance-localhost:8088.
- ElevenID's Canvas platform trust layer expects a standards-style
  /.well-known/openid-configuration document, while real Canvas exposes a
  different LTI metadata route.

This bridge listens on 127.0.0.1:8088 inside the issuance network namespace,
serves a local discovery document, and proxies all other requests to the host's
Canvas runtime.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

UPSTREAM_BASE = os.environ.get("CANVAS_LOCALHOST_BRIDGE_UPSTREAM", "http://host.docker.internal:8088").rstrip("/")
PUBLIC_BASE = os.environ.get("CANVAS_LOCALHOST_BRIDGE_PUBLIC_BASE", "http://localhost:8088").rstrip("/")
LISTEN_HOST = os.environ.get("CANVAS_LOCALHOST_BRIDGE_LISTEN_HOST", "127.0.0.1")
LISTEN_PORT = int(os.environ.get("CANVAS_LOCALHOST_BRIDGE_LISTEN_PORT", "8088"))

OIDC_CONFIGURATION = {
    "issuer": PUBLIC_BASE,
    "authorization_endpoint": f"{PUBLIC_BASE}/api/lti/authorize_redirect",
    "token_endpoint": f"{PUBLIC_BASE}/login/oauth2/token",
    "jwks_uri": f"{PUBLIC_BASE}/api/lti/security/jwks",
    "registration_endpoint": f"{PUBLIC_BASE}/api/lti/registrations",
    "scopes_supported": ["openid"],
    "response_types_supported": ["id_token"],
    "subject_types_supported": ["public"],
    "id_token_signing_alg_values_supported": ["RS256"],
    "claims_supported": [
        "iss",
        "sub",
        "aud",
        "exp",
        "iat",
        "nonce",
        "https://purl.imsglobal.org/spec/lti/claim/deployment_id",
        "https://purl.imsglobal.org/spec/lti/claim/context",
        "https://purl.imsglobal.org/spec/lti/claim/roles",
        "https://purl.imsglobal.org/spec/lti/claim/message_type",
        "https://purl.imsglobal.org/spec/lti/claim/version",
        "https://purl.imsglobal.org/spec/lti/claim/target_link_uri",
    ],
}

_HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
}


class BridgeHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802
        self._handle_request(send_body=True)

    def do_HEAD(self) -> None:  # noqa: N802
        self._handle_request(send_body=False)

    def do_POST(self) -> None:  # noqa: N802
        self._proxy(send_body=True)

    def do_PUT(self) -> None:  # noqa: N802
        self._proxy(send_body=True)

    def do_PATCH(self) -> None:  # noqa: N802
        self._proxy(send_body=True)

    def do_DELETE(self) -> None:  # noqa: N802
        self._proxy(send_body=True)

    def _handle_request(self, *, send_body: bool) -> None:
        if self.path.split("?", 1)[0] == "/.well-known/openid-configuration":
            self._send_json(OIDC_CONFIGURATION, send_body=send_body)
            return
        self._proxy(send_body=send_body)

    def _read_request_body(self) -> bytes | None:
        try:
            content_length = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            content_length = 0
        if content_length <= 0:
            return None
        return self.rfile.read(content_length)

    def _proxy(self, *, send_body: bool) -> None:
        body = self._read_request_body()
        target_url = f"{UPSTREAM_BASE}{self.path}"
        headers = {
            key: value
            for key, value in self.headers.items()
            if key.lower() not in _HOP_BY_HOP_HEADERS and key.lower() != "host"
        }
        request = urllib.request.Request(target_url, data=body, headers=headers, method=self.command)

        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                self._relay_response(response.status, response.headers.items(), response.read(), send_body=send_body)
        except urllib.error.HTTPError as exc:
            self._relay_response(exc.code, exc.headers.items(), exc.read(), send_body=send_body)
        except Exception as exc:  # pragma: no cover - defensive local bridge logging
            payload = {"error": f"Canvas localhost bridge upstream failure: {exc}"}
            self._send_json(payload, status=502, send_body=send_body)

    def _relay_response(self, status: int, headers: list[tuple[str, str]], body: bytes, *, send_body: bool) -> None:
        self.send_response(status)
        sent_length = False
        for key, value in headers:
            if key.lower() in _HOP_BY_HOP_HEADERS:
                continue
            if key.lower() == "content-length":
                sent_length = True
                self.send_header(key, str(len(body) if send_body else 0))
                continue
            self.send_header(key, value)
        if not sent_length:
            self.send_header("Content-Length", str(len(body) if send_body else 0))
        self.end_headers()
        if send_body and body:
            self.wfile.write(body)

    def _send_json(self, payload: dict, *, status: int = 200, send_body: bool = True) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body) if send_body else 0))
        self.end_headers()
        if send_body:
            self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        print(f"[canvas-localhost-bridge] {self.address_string()} - {format % args}")


if __name__ == "__main__":
    server = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), BridgeHandler)
    print(
        f"[canvas-localhost-bridge] listening on http://{LISTEN_HOST}:{LISTEN_PORT} "
        f"-> upstream {UPSTREAM_BASE}"
    )
    server.serve_forever()
