"""Qualify strict root and expiry-only semantics against the previous OpenSSL calls."""
import json
from pathlib import Path
import subprocess

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ObjectIdentifier
import pytest

from scripts.selfhost_native_operator import operator_bytes
from tests.test_selfhost_native_certificates import certificate, key, pem

ROOT = Path(__file__).resolve().parents[1]


def old_ca_profile(content, kind, version, tmp_path):
    def openssl(*args, source=content):
        return subprocess.run(["openssl", *args], input=source, capture_output=True)
    names = openssl("x509", "-noout", "-subject", "-issuer", "-nameopt", "RFC2253")
    name = f"CN=Marty self-host {kind} CA v{version}"
    if names.returncode or names.stdout.decode().splitlines() != [f"subject={name}", f"issuer={name}"]:
        return False
    constraints = openssl("x509", "-noout", "-ext", "basicConstraints")
    if constraints.returncode or [line.strip() for line in constraints.stdout.decode().splitlines()] != [
        "X509v3 Basic Constraints: critical", "CA:TRUE"]:
        return False
    public = openssl("x509", "-pubkey", "-noout")
    details = openssl("pkey", "-pubin", "-text", "-noout", source=public.stdout)
    if details.returncode or b"Public-Key: (256 bit)" not in details.stdout or b"ASN1 OID: prime256v1" not in details.stdout:
        return False
    path = tmp_path / "issuer.pem"
    path.write_bytes(content)
    return openssl("verify", "-x509_strict", "-check_ss_sig", "-no_check_time", "-purpose", "any",
                   "-CAfile", str(path), str(path), source=None).returncode == 0


@pytest.mark.parametrize("case", ["valid", "future", "expired", "wrong-cn", "rsa", "p384", "non-ca",
                                 "noncritical-ca", "pathlen", "no-ku", "bad-ku", "no-ski", "no-bc",
                                 "unknown-critical", "unknown-noncritical", "critical-policy", "tampered", "sha384", "sha512"])
def test_strict_replacement_ca_preserves_openssl_profile(tmp_path, case):
    signer = key("RSA") if case == "rsa" else ec.generate_private_key(ec.SECP384R1()) if case == "p384" else key()
    options = {"ca": case != "non-ca"}
    if case == "future":
        options["before"] = 3600
    elif case == "expired":
        options.update(before=-7200, after=-60)
    elif case == "noncritical-ca":
        options["basic_critical"] = False
    elif case == "pathlen":
        options["path_length"] = 0
    elif case == "no-ku":
        options["ku"] = False
    elif case == "bad-ku":
        options["signing"] = False
    elif case == "no-ski":
        options["ski"] = False
    elif case == "no-bc":
        options["basic_constraints"] = False
    elif case in ("unknown-critical", "unknown-noncritical"):
        options["extensions"] = [(x509.UnrecognizedExtension(ObjectIdentifier("1.2.3.4"), b"\x05\x00"),
                                  case == "unknown-critical")]
    elif case == "critical-policy":
        options["extensions"] = [(x509.CertificatePolicies([
            x509.PolicyInformation(ObjectIdentifier("1.2.3.4"), None)]), True)]
    elif case in ("sha384", "sha512"):
        options["digest"] = hashes.SHA384() if case == "sha384" else hashes.SHA512()
    cert = certificate("wrong" if case == "wrong-cn" else "Marty self-host workload CA v2",
                       signer.public_key(), signer=key() if case == "tampered" else signer, **options)
    content = pem(cert)
    expected = case in ("valid", "future", "expired", "no-ku", "no-ski", "unknown-noncritical", "critical-policy", "sha384", "sha512")
    assert old_ca_profile(content, "workload", 2, tmp_path) is expected
    if expected:
        operator_bytes(ROOT, "operator", "replacement-ca", "workload", "2", input=content)
    else:
        with pytest.raises(RuntimeError):
            operator_bytes(ROOT, "operator", "replacement-ca", "workload", "2", input=content)


@pytest.mark.parametrize("kind,version", [("workload", 2), ("workload", 8), ("keycloak", 2), ("keycloak", 8)])
def test_bounded_ca_kind_and_version_accept_realistic_roots(kind, version):
    signer = key()
    content = pem(certificate(f"Marty self-host {kind} CA v{version}", signer.public_key(), signer=signer, ca=True))
    operator_bytes(ROOT, "operator", "replacement-ca", kind, str(version), input=content)
    for other_kind, other_version in (("foreign", version), (kind, 1), (kind, 9)):
        with pytest.raises(RuntimeError):
            operator_bytes(ROOT, "operator", "replacement-ca", other_kind, str(other_version), input=content)


@pytest.mark.parametrize("transform", [lambda value: value + value, lambda value: b"\n" + value,
                                      lambda value: value + b"\n", lambda value: value.replace(b"\n", b"\r\n")],
                         ids=["two-pems", "leading-blank", "trailing-blank", "crlf"])
def test_ca_pem_envelope_remains_single_and_canonical(transform):
    signer = key()
    content = pem(certificate("Marty self-host workload CA v2", signer.public_key(), signer=signer, ca=True))
    with pytest.raises(RuntimeError):
        operator_bytes(ROOT, "operator", "replacement-ca", "workload", "2", input=transform(content))


@pytest.mark.parametrize("before,after,ttl", [(3600, 7200, 3600), (-7200, -60, 3600),
                                            (-60, 7200, 3600), (-60, 1800, 3600),
                                            (-60, 400 * 86400, 300 * 86400)])
def test_expiry_only_matches_checkend_including_future_notbefore(before, after, ttl):
    signer = key()
    content = pem(certificate("expiry", signer.public_key(), signer=signer, ca=True, before=before, after=after))
    previous = subprocess.run(["openssl", "x509", "-checkend", str(ttl), "-noout"], input=content, capture_output=True)
    native = json.loads(operator_bytes(ROOT, "operator", "certificate-expiry", str(ttl), input=content))
    assert native is (previous.returncode == 0)
