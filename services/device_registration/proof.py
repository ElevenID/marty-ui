from __future__ import annotations

import base64
import hashlib
import json
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def _b64url_decode(value: str) -> bytes:
    if not value or not re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", value):
        raise ValueError("value must be non-empty base64url without whitespace")
    try:
        return base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, TypeError) as exc:
        raise ValueError("value must be valid base64url") from exc


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def parse_device_public_key(public_key_der: str) -> tuple[rsa.RSAPublicKey, bytes]:
    raw = _b64url_decode(public_key_der)
    try:
        key = serialization.load_der_public_key(raw)
    except ValueError as exc:
        raise ValueError("public_key_der must contain a valid RSA public key") from exc
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError("public_key_der must contain an RSA public key")
    if key.key_size < 2048:
        raise ValueError("device RSA public keys must be at least 2048 bits")
    canonical_pkcs1 = key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.PKCS1,
    )
    if canonical_pkcs1 != raw:
        raise ValueError("public_key_der must use canonical PKCS#1 DER encoding")
    return key, raw


def public_key_thumbprint(key: rsa.RSAPublicKey) -> str:
    numbers = key.public_numbers()
    exponent = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
    modulus = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
    jwk = {
        "e": _b64url_encode(exponent),
        "kty": "RSA",
        "n": _b64url_encode(modulus),
    }
    canonical = json.dumps(jwk, sort_keys=True, separators=(",", ":")).encode()
    return _b64url_encode(hashlib.sha256(canonical).digest())


def public_key_digest(raw_der: bytes) -> str:
    return hashlib.sha256(raw_der).hexdigest()


def verify_challenge_signature(
    key: rsa.RSAPublicKey,
    challenge: bytes,
    signature_b64url: str,
) -> None:
    signature = _b64url_decode(signature_b64url)
    try:
        key.verify(
            signature,
            challenge,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=hashes.SHA256.digest_size,
            ),
            hashes.SHA256(),
        )
    except InvalidSignature as exc:
        raise ValueError("device challenge signature is invalid") from exc
