"""Small HTTPS OpenBao client shared by disposable self-host provisioners."""

from __future__ import annotations

import base64
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


CUSTODY_SIGNER = "selfhost-qualification-custody-v1"
CUSTODY_SIGNER_POLICY = "selfhost-qualification-custody-signer"


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def ed25519_public_pem(raw_base64: str) -> str:
    """Encode OpenBao's raw public Ed25519 bytes as a standard SPKI PEM."""
    if not isinstance(raw_base64, str):
        raise ValueError("OpenBao Ed25519 public key is invalid")
    try:
        raw = base64.b64decode(raw_base64, validate=True)
    except ValueError as error:
        raise ValueError("OpenBao Ed25519 public key is invalid") from error
    if len(raw) != 32 or base64.b64encode(raw).decode("ascii") != raw_base64:
        raise ValueError("OpenBao Ed25519 public key is invalid")
    der = bytes.fromhex("302a300506032b6570032100") + raw
    pem = "-----BEGIN PUBLIC KEY-----\n"
    pem += base64.b64encode(der).decode("ascii") + "\n"
    pem += "-----END PUBLIC KEY-----\n"
    if public_key_der(pem) != der:
        raise ValueError("OpenBao Ed25519 public key is invalid")
    return pem


def custody_signer_public(metadata: dict) -> tuple[int, str]:
    """Read the current non-exportable Transit signer version and public key."""
    if (not isinstance(metadata, dict) or metadata.get("type") != "ed25519"
            or metadata.get("exportable") is not False
            or metadata.get("allow_plaintext_backup") is not False
            or type(metadata.get("latest_version")) is not int
            or metadata["latest_version"] <= 0):
        raise ValueError("OpenBao custody signer is not non-exportable Ed25519")
    version = metadata["latest_version"]
    entry = metadata.get("keys", {}).get(str(version), {})
    if not isinstance(entry, dict):
        raise ValueError("OpenBao custody signer public key is absent")
    return version, ed25519_public_pem(entry.get("public_key"))


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
