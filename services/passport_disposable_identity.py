"""Frozen disposable issuer tuple shared by OpenBao bootstrap and ceremony."""

from __future__ import annotations

import uuid


ORGANIZATION_ID = "00000000-0000-0000-0000-000000000001"


def issuer_did(gateway_port: int) -> str:
    if type(gateway_port) is not int or not 1024 <= gateway_port <= 65535:
        raise ValueError("Disposable Gateway port is invalid")
    return f"did:web:localhost%3A{gateway_port}:orgs:marty"


def managed_key_reference(gateway_port: int, purpose: str) -> str:
    if purpose not in ("csca", "x509_doc_signer"):
        raise ValueError("Disposable passport key purpose is invalid")
    tuple_value = "|".join((ORGANIZATION_ID, issuer_did(gateway_port), purpose,
                            "ICAO_EMRTD", "ES256"))
    return "cred-dsc-" + uuid.uuid5(uuid.NAMESPACE_URL, tuple_value).hex[:20] + "-es256"
