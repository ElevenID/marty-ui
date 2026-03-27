"""MIP §21.5.1 — Pairwise Subject Identifier Algorithm.

Computes a privacy-preserving, per-relying-party subject identifier so that
different verifiers cannot correlate the same holder across sessions.

Algorithm (normative):
    HMAC-SHA256(
        key   = holder_secret (256-bit),
        message = UTF-8(client_id) || 0x3A || UTF-8(subject_identifier)
    ) → base64url (no padding)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets


def compute_pairwise_id(
    holder_secret: bytes,
    client_id: str,
    subject_identifier: str,
) -> str:
    """Compute a pairwise subject identifier per MIP §21.5.1.

    Args:
        holder_secret: 256-bit (32-byte) secret key for the holder.
        client_id: The relying party / verifier client identifier.
        subject_identifier: The holder's internal subject identifier.

    Returns:
        Base64url-encoded (no padding) HMAC-SHA256 digest.

    Raises:
        ValueError: If holder_secret is not exactly 32 bytes.
    """
    if len(holder_secret) != 32:
        raise ValueError("holder_secret must be exactly 32 bytes (256 bits)")

    message = f"{client_id}\x3A{subject_identifier}".encode("utf-8")
    digest = hmac.new(holder_secret, message, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def generate_holder_secret() -> bytes:
    """Generate a cryptographically random 256-bit holder secret."""
    return secrets.token_bytes(32)
