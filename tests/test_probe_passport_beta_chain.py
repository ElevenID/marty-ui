"""Governed CSCA/DSC evidence must use real public X.509 chain validation."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import ssl

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import pytest

from scripts import probe_passport_beta_chain as chain_probe
from scripts.probe_passport_beta_chain import ChainProbeError, exercise, openssl_verify


def certificates() -> tuple[str, str, str]:
    now = datetime.now(timezone.utc)
    root_key = ec.generate_private_key(ec.SECP256R1())
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Disposable beta CSCA")])
    root = (x509.CertificateBuilder().subject_name(root_name).issuer_name(root_name)
            .public_key(root_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=2))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                          data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                          crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()), critical=False)
            .sign(root_key, hashes.SHA256()))
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Disposable beta DSC")]))
            .issuer_name(root_name).public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                          data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                          crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()), critical=False)
            .sign(root_key, hashes.SHA256()))
    other_key = ec.generate_private_key(ec.SECP256R1())
    other = (x509.CertificateBuilder().subject_name(root_name).issuer_name(root_name)
             .public_key(other_key.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=2))
             .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
             .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                           data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                           crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
             .add_extension(x509.SubjectKeyIdentifier.from_public_key(other_key.public_key()), critical=False)
             .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(other_key.public_key()), critical=False)
             .sign(other_key, hashes.SHA256()))
    return tuple(cert.public_bytes(serialization.Encoding.PEM).decode() for cert in (root, leaf, other))


def plan() -> dict:
    issuer = "did:web:beta.example:issuers:org-a"
    return {
        "organization_id": "org-a",
        "csca": {"issuer_did": issuer, "certificate_id": "pilot-csca-1", "credential_format": "ICAO_EMRTD",
                 "country": "US", "organization": "Disposable Beta", "common_name": "Beta CSCA", "validity_days": 365},
        "dsc": {"dsc_issuer_did": issuer, "csca_issuer_did": issuer,
                "csca_certificate_id": "pilot-csca-1", "credential_format": "ICAO_EMRTD",
                "country": "US", "organization": "Disposable Beta", "common_name": "Beta DSC",
                "validity_days": 30, "idempotency_key": "beta-dsc-1"},
    }


def test_real_certificate_chain_and_governed_route_sequence() -> None:
    csca, dsc, _ = certificates()
    calls = []

    def request(path: str, body: dict, session: str) -> tuple[int, dict]:
        calls.append((path, body, session))
        if path.endswith("csca-self-signed-certificate"):
            return 200, {"status": "issued", "certificate_id": body["certificate_id"],
                         "issuer_did": body["issuer_did"], "certificate_pem": csca}
        return 200, {"status": "issued", "dsc_issuer_did": body["dsc_issuer_did"],
                     "csca_issuer_did": body["csca_issuer_did"], "certificate_pem": dsc,
                     "chain_pem": csca}

    captured = []
    csca_material = []
    result = exercise(plan(), "sessionId=csca-secret", "sessionId=dsc-secret", request=request,
                      on_dsc_material=lambda *digests: captured.append(digests),
                      on_csca_material=csca_material.append)
    assert result["verified"] is True
    assert result["evidence"]["csca_certificate_sha256"] == hashlib.sha256(ssl.PEM_cert_to_DER_cert(csca)).hexdigest()
    assert result["evidence"]["dsc_certificate_sha256"] == hashlib.sha256(ssl.PEM_cert_to_DER_cert(dsc)).hexdigest()
    assert captured == [(result["evidence"]["dsc_certificate_sha256"], hashlib.sha256(dsc.encode()).hexdigest())]
    assert csca_material == [csca]
    assert len(calls) == 2
    assert calls[0][0].endswith("csca-self-signed-certificate")
    assert calls[1][0].endswith("dsc-certificate")
    assert [call[2] for call in calls] == ["sessionId=csca-secret", "sessionId=dsc-secret"]
    assert all(call[1]["organization_id"] == "org-a" for call in calls)
    assert "secret" not in str(result)
    assert "BEGIN CERTIFICATE" not in str(result)


def test_chain_rejects_unrelated_trust_anchor() -> None:
    csca, dsc, other = certificates()
    with pytest.raises(ChainProbeError, match="did not verify"):
        openssl_verify(other, dsc)
    with pytest.raises(ChainProbeError, match="identical"):
        openssl_verify(csca, csca)
    tampered = bytearray(ssl.PEM_cert_to_DER_cert(csca))
    tampered[-1] ^= 1
    with pytest.raises(ChainProbeError, match="did not verify"):
        openssl_verify(ssl.DER_cert_to_PEM_cert(bytes(tampered)), dsc)


def test_live_request_uses_console_session_and_organization_query(monkeypatch) -> None:
    seen = []
    handlers = []

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def geturl(self):
            return seen[0].full_url

        def read(self, amount):
            return b'{"status":"issued"}'

    class Opener:
        def open(self, request, timeout):
            seen.append(request)
            return Response()

    def opener(*args):
        handlers.extend(args)
        return Opener()

    monkeypatch.setattr(chain_probe, "build_opener", opener)
    status, payload = chain_probe.post_beta(
        "/v1/signing-keys/issuer-identities/dsc-certificate",
        {"organization_id": "org-a", "dsc_issuer_did": "did:web:beta.example:org-a"},
        "sessionId=governed-secret",
    )
    assert (status, payload) == (200, {"status": "issued"})
    assert seen[0].full_url.endswith("/dsc-certificate?organization_id=org-a")
    assert seen[0].get_header("Cookie") == "sessionId=governed-secret"
    assert seen[0].get_header("X-api-key") is None
    assert seen[0].get_header("X-user-id") is None
    assert json.loads(seen[0].data) == {"dsc_issuer_did": "did:web:beta.example:org-a"}
    assert any(isinstance(handler, chain_probe.ProxyHandler)
               and handler.proxies == {} for handler in handlers)


def test_dsc_response_must_publish_selected_csca() -> None:
    csca, dsc, other = certificates()

    def request(path: str, body: dict, session: str) -> tuple[int, dict]:
        if path.endswith("csca-self-signed-certificate"):
            return 200, {"status": "issued", "certificate_id": body["certificate_id"],
                         "issuer_did": body["issuer_did"], "certificate_pem": csca}
        return 200, {"status": "issued", "dsc_issuer_did": body["dsc_issuer_did"],
                     "csca_issuer_did": body["csca_issuer_did"], "certificate_pem": dsc,
                     "chain_pem": other}

    with pytest.raises(ChainProbeError, match="selected CSCA"):
        exercise(plan(), "sessionId=csca", "sessionId=dsc", request=request)


@pytest.mark.parametrize("mutation", [
    lambda value: value["dsc"].update(csca_certificate_id="other"),
    lambda value: value["dsc"].update(credential_format="OTHER"),
    lambda value: value["dsc"].pop("idempotency_key"),
    lambda value: value["dsc"].update(idempotency_key=1),
    lambda value: value["dsc"].update(validity_days="30"),
    lambda value: value["dsc"].update(validity_days=91),
    lambda value: value["dsc"].update(validity_days=True),
    lambda value: value["dsc"].update(country="CA"),
    lambda value: value["dsc"].update(country="us"),
    lambda value: value["dsc"].update(organization="X" * 65),
    lambda value: value["dsc"].update(common_name="bad,name"),
    lambda value: value["dsc"].update(common_name=" trailing "),
    lambda value: (value["dsc"].update(validity_days=90), value["csca"].update(validity_days=90)),
    lambda value: value["dsc"].update(unknown_field="extra"),
    lambda value: value["csca"].update(organization_id="wrong"),
])
def test_invalid_plan_never_starts_csca_ceremony(mutation) -> None:
    value = plan()
    mutation(value)
    with pytest.raises(ChainProbeError):
        exercise(value, "sessionId=csca", "sessionId=dsc",
                 request=lambda *args: pytest.fail("certificate request should not run"))


def test_same_session_or_failed_csca_never_issues_dsc() -> None:
    with pytest.raises(ChainProbeError, match="Separate governed"):
        exercise(plan(), "same", "same", request=lambda *args: pytest.fail("request should not run"))
    calls = []

    def reject(path: str, body: dict, session: str) -> tuple[int, dict]:
        calls.append(path)
        return 403, {}

    with pytest.raises(ChainProbeError, match="CSCA ceremony"):
        exercise(plan(), "sessionId=csca", "sessionId=dsc", request=reject)
    assert len(calls) == 1
