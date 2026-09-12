"""Execute the unchanged Python TLS boundary using only synthetic local material.

Usage: python scripts/capture_didcomm_tls_reference.py <credentials-checkout>
The route and its existing controlled test setup are checked by Git blob hash.
No network request, real key or deployment configuration is used or emitted.
"""

from __future__ import annotations

import asyncio
import hashlib
import importlib.util
import json
from pathlib import Path
import ssl
import sys
import tempfile
from unittest.mock import Mock

from test_canvas_lti_https import create_loopback_certificate


def checked_source(path: Path, expected: str) -> None:
    data = path.read_bytes().replace(b"\r\n", b"\n")
    observed = hashlib.sha1(
        b"blob " + str(len(data)).encode() + b"\0" + data
    ).hexdigest()
    assert observed == expected, "reference source changed"


def main() -> None:
    root = Path(sys.argv[1]).resolve(strict=True)
    source = root / "services/issuance/infrastructure/api/routes.py"
    setup = root / "tests/unit/test_didcomm_boundary.py"
    checked_source(source, "6b3a7fa0e169862e815bcb6bca64b0b21a5adf6a")
    checked_source(setup, "f373c4d1762f916b616e4b83a38101112ec78e85")
    for package in ("services", "python", "packages"):
        sys.path.insert(0, str(root / package))

    import pytest
    from fastapi import HTTPException
    from issuance.infrastructure.api import routes

    assert Path(routes.__file__).resolve() == source
    spec = importlib.util.spec_from_file_location("didcomm_tls_reference_setup", setup)
    assert spec is not None and spec.loader is not None
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    real_verifier = routes._didcomm_tls_verifier

    async def failed_delivery(path: Path, name: str) -> dict:
        with pytest.MonkeyPatch.context() as patch:
            tx, repository = helper._configure_delivery_through_transport(
                patch, holder_did="did:example:synthetic-holder"
            )
            patch.setattr(routes, "_didcomm_tls_verifier", real_verifier)
            patch.setenv("DIDCOMM_TLS_CA_FILE", f" {path} ")
            client = Mock(
                side_effect=AssertionError("TLS failure must precede HTTP client")
            )
            patch.setattr(routes.httpx, "AsyncClient", client)
            try:
                await routes._didcomm_sign_and_deliver(
                    tx, "did:example:synthetic-holder", repository
                )
            except HTTPException as error:
                result = {
                    "case": name,
                    "status": error.status_code,
                    "body": {"detail": error.detail},
                    "allocation_calls": routes._allocate_credential_status_list_entries.await_count,
                    "signing_calls": routes.create_sd_jwt_vc_with_remote_signing.await_count,
                    "packing_calls": routes.didcomm_pack_credential.call_count,
                    "encryption_calls": routes.didcomm_encrypt_prepared_delivery.call_count,
                    "http_client_calls": client.call_count,
                    "save_calls": repository.save_transaction.await_count,
                    "status_after": tx.status.value,
                }
            else:
                raise AssertionError("invalid CA unexpectedly succeeded")
            return result

    with tempfile.TemporaryDirectory(
        prefix="marty-didcomm-tls-reference-"
    ) as directory:
        owned = Path(directory)
        ca = owned / "operator-ca.pem"
        cases = [asyncio.run(failed_delivery(ca, "missing_ca"))]
        ca.write_text("synthetic-invalid-ca", encoding="utf-8")
        cases.append(asyncio.run(failed_delivery(ca, "malformed_ca")))
        certs = []
        for name in ("first", "second"):
            child = owned / name
            child.mkdir()
            certificate, _ = create_loopback_certificate(child)
            certs.append(certificate.read_bytes())
        with pytest.MonkeyPatch.context() as patch:
            patch.setenv("DIDCOMM_TLS_CA_FILE", " ")
            assert real_verifier() is True
            patch.setenv("DIDCOMM_TLS_CA_FILE", str(ca))
            ca.write_bytes(certs[0])
            first = real_verifier()
            assert isinstance(first, ssl.SSLContext)
            ca.write_bytes(b"".join(certs))
            second = real_verifier()
            assert isinstance(second, ssl.SSLContext)
            added = second.cert_store_stats()["x509"] - first.cert_store_stats()["x509"]
            assert added == 1
            assert first is not second
            assert first.verify_mode == second.verify_mode == ssl.CERT_REQUIRED
            assert first.check_hostname and second.check_hostname
            cases.append(
                {
                    "case": "same_path_valid_rotation_bundle",
                    "new_context_each_attempt": True,
                    "additional_certificate_count": added,
                    "verification_required": True,
                    "hostname_validation": True,
                    "blank_path_uses_default_web_pki": True,
                }
            )
    fixture = (
        Path(__file__).resolve().parents[1]
        / "contracts/didcomm-tls-python-reference.json"
    )
    assert cases == json.loads(fixture.read_text(encoding="utf-8"))["cases"]
    print(json.dumps(cases, indent=2))


if __name__ == "__main__":
    main()
