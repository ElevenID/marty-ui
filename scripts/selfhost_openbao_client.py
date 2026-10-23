"""Small HTTPS OpenBao client shared by disposable self-host provisioners."""

from __future__ import annotations

import base64
import json
import ssl
from pathlib import Path

if __package__:
    from .selfhost_native_operator import operator_bytes
else:
    from selfhost_native_operator import operator_bytes
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    ProxyHandler,
    Request,
    build_opener,
)


CUSTODY_SIGNER = "selfhost-qualification-custody-v1"
CUSTODY_SIGNER_POLICY = "selfhost-qualification-custody-signer"
CUSTODY_SIGNER_LEAF_ACL = (
    f'path "transit/keys/{CUSTODY_SIGNER}" {{ capabilities = ["read"] }}\n'
    f'path "transit/sign/{CUSTODY_SIGNER}" {{ capabilities = ["update"] }}\n'
    'path "auth/token/lookup-self" { capabilities = ["read"] }\n'
    'path "auth/token/revoke-self" { capabilities = ["update"] }\n'
)
RENEWAL_LEAF_ROLE = "selfhost-renew-leaf"
RENEWAL_OPERATOR_POLICY = "selfhost-kms-renewal"


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
    der = operator_bytes(Path(__file__).resolve().parents[1], "operator",
                         "ed25519-spki", input=raw_base64.encode("ascii"))
    pem = "-----BEGIN PUBLIC KEY-----\n"
    pem += base64.b64encode(der).decode("ascii") + "\n"
    pem += "-----END PUBLIC KEY-----\n"
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
    return operator_bytes(Path(__file__).resolve().parents[1],
                          "operator", "public-spki", input=pem.encode("ascii"))


def certificate_public_key_der(certificate: str) -> bytes:
    """Extract public SPKI; issuer and trust checks remain separate."""
    return operator_bytes(Path(__file__).resolve().parents[1], "operator",
                          "certificate-spki", input=certificate.encode("ascii"))



class Bao:
    def __init__(self, endpoint: str, ca: Path, token: str) -> None:
        self.endpoint = endpoint
        self.ca = ca
        self.token = token
        self.opener = build_opener(
            ProxyHandler({}), HTTPSHandler(context=ssl.create_default_context(cafile=str(ca))),
            NoRedirect(),
        )

    def request(
        self, method: str, path: str, body: dict | None = None, *, token: str | None = None,
        authenticate: bool = True,
    ) -> dict:
        data = None if body is None else json.dumps(body).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if authenticate:
            headers["X-Vault-Token"] = token or self.token
        request = Request(
            f"{self.endpoint}/v1/{path}", data=data, method=method,
            headers=headers,
        )
        with self.opener.open(request, timeout=10) as response:
            content = response.read(1024 * 1024 + 1)
        if len(content) > 1024 * 1024:
            raise RuntimeError("disposable OpenBao response exceeded size bound")
        return json.loads(content) if content else {}


def require_renewal_authority(bao: Bao) -> None:
    data = bao.request("POST", "auth/token/lookup", {"token": bao.token}).get("data", {})
    if (not isinstance(data, dict) or data.get("policies") != [RENEWAL_OPERATOR_POLICY]
            or data.get("path") != "auth/selfhost-renew/login"
            or type(data.get("ttl")) is not int or not 3600 <= data["ttl"] <= 8 * 60 * 60):
        raise ValueError("OpenBao renewal authority is not the scoped AppRole token")


def require_ca_rotation_authority(bao: Bao) -> None:
    data = bao.request("POST", "auth/token/lookup", {"token": bao.token}).get("data", {})
    if (not isinstance(data, dict) or data.get("policies") != ["selfhost-kms-ca-rotation"]
            or data.get("path") != "auth/selfhost-ca-rotation/login"
            or type(data.get("ttl")) is not int
            or not 3600 <= data["ttl"] <= 8 * 60 * 60):
        raise ValueError("OpenBao CA-rotation authority is not the scoped AppRole token")
