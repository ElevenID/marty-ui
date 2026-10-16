"""Small HTTPS OpenBao client shared by disposable self-host provisioners."""

from __future__ import annotations

import json
import ssl
import subprocess
from pathlib import Path
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    ProxyHandler,
    Request,
    build_opener,
)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def public_key_der(pem: str) -> bytes:
    result = subprocess.run(
        ["openssl", "pkey", "-pubin", "-outform", "DER"],
        input=pem.encode("ascii"), capture_output=True, timeout=10, check=False,
    )
    if result.returncode or not result.stdout:
        raise RuntimeError("disposable public key is invalid")
    return result.stdout


class Bao:
    def __init__(self, endpoint: str, ca: Path, token: str) -> None:
        self.endpoint = endpoint
        self.token = token
        self.opener = build_opener(
            ProxyHandler({}), HTTPSHandler(context=ssl.create_default_context(cafile=str(ca))),
            NoRedirect(),
        )

    def request(
        self, method: str, path: str, body: dict | None = None, *, token: str | None = None
    ) -> dict:
        data = None if body is None else json.dumps(body).encode("utf-8")
        request = Request(
            f"{self.endpoint}/v1/{path}", data=data, method=method,
            headers={"X-Vault-Token": token or self.token, "Content-Type": "application/json"},
        )
        with self.opener.open(request, timeout=10) as response:
            content = response.read(1024 * 1024 + 1)
        if len(content) > 1024 * 1024:
            raise RuntimeError("disposable OpenBao response exceeded size bound")
        return json.loads(content) if content else {}
