"""Small HTTPS OpenBao client shared by disposable self-host provisioners."""

from __future__ import annotations

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
    try:
        return operator_bytes(Path(__file__).resolve().parents[1], "operator",
                              "ed25519-pem", input=raw_base64.encode("ascii")).decode("ascii")
    except (AttributeError, UnicodeError, RuntimeError) as error:
        raise ValueError("OpenBao Ed25519 public key is invalid") from error


def custody_signer_public(metadata: dict, *, version_one: bool = False) -> tuple[int, str]:
    """Read a non-exportable current signer; provisioning requires version one."""
    try:
        result = json.loads(operator_bytes(
            Path(__file__).resolve().parents[1], "operator", "custody-signer",
            input=json.dumps({"metadata": metadata, "version_one": version_one}).encode("utf-8"),
        ))
        return result["version"], result["public_pem"]
    except (TypeError, UnicodeError, RuntimeError, ValueError, KeyError) as error:
        raise ValueError("OpenBao custody signer is not non-exportable Ed25519 or its public key is invalid") from error


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
    if __package__:
        from .selfhost_native_operator import network_operation
    else:
        from selfhost_native_operator import network_operation
    network_operation(bao, "authority-check", rotation=False)


def require_ca_rotation_authority(bao: Bao) -> None:
    if __package__:
        from .selfhost_native_operator import network_operation
    else:
        from selfhost_native_operator import network_operation
    network_operation(bao, "authority-check", rotation=True)
