"""Differential renewal validation through the real Rust command, using public fixtures.

Synthetic private keys exist only in memory to generate independent test certificates.
OpenSSL remains the previous verifier's oracle, never a production fallback.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import subprocess
import time
import uuid
from urllib.error import URLError
from urllib.request import ProxyHandler, Request, build_opener

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier
import pytest

from scripts.selfhost_native_operator import operator_bytes

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime.now(timezone.utc).replace(microsecond=0)


def key(kind="EC"):
    if kind == "RSA":
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if kind == "ED25519":
        return ed25519.Ed25519PrivateKey.generate()
    return ec.generate_private_key(ec.SECP256R1())


def certificate(subject, public_key, issuer=None, signer=None, *, ca=False, path_length=None,
                before=-60, after=7200, ku=True, signing=True, eku=None, extensions=(), aki=None,
                basic_constraints=True):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)])
    issuer_name = issuer.subject if issuer else name
    builder = (x509.CertificateBuilder().subject_name(name).issuer_name(issuer_name)
               .public_key(public_key).serial_number(x509.random_serial_number())
               .not_valid_before(NOW + timedelta(seconds=before))
               .not_valid_after(NOW + timedelta(seconds=after))
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), False))
    if basic_constraints:
        builder = builder.add_extension(x509.BasicConstraints(ca=ca, path_length=path_length), True)
    if ku:
        builder = builder.add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=ca and signing,
            crl_sign=ca and signing, encipher_only=None, decipher_only=None), True)
    if eku is not None:
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku), False)
    if issuer is not None:
        builder = builder.add_extension(aki or x509.AuthorityKeyIdentifier.from_issuer_public_key(
            issuer.public_key()), False)
    for extension, critical in extensions:
        builder = builder.add_extension(extension, critical)
    return builder.sign(signer, None if isinstance(signer, ed25519.Ed25519PrivateKey) else hashes.SHA256())


def pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


def native_chain(leaf, issuers):
    operator_bytes(ROOT, "operator", "certificate-chain", input=json.dumps({
        "certificate": leaf.decode("ascii"), "issuer": issuers.decode("ascii"),
    }).encode("ascii"))


def compare(tmp_path, leaf, issuers, accepted):
    (tmp_path / "leaf.pem").write_bytes(leaf)
    (tmp_path / "issuers.pem").write_bytes(issuers)
    previous = subprocess.run(["openssl", "verify", "-no-CApath", "-no-CAstore", "-CAfile",
                               str(tmp_path / "issuers.pem"), str(tmp_path / "leaf.pem")],
                              capture_output=True, check=False)
    assert (previous.returncode == 0) is accepted, previous.stderr.decode()
    if accepted:
        native_chain(leaf, issuers)
    else:
        with pytest.raises(RuntimeError, match="Rust operator validation failed"):
            native_chain(leaf, issuers)


@pytest.mark.parametrize("issuer_kind", ["EC", "RSA", "ED25519"])
@pytest.mark.parametrize("leaf_kind", ["EC", "RSA"])
@pytest.mark.parametrize("eku", [None, [ExtendedKeyUsageOID.SERVER_AUTH],
                                 [ExtendedKeyUsageOID.CLIENT_AUTH],
                                 [ExtendedKeyUsageOID.CODE_SIGNING]])
def test_supported_keys_and_purpose_any(tmp_path, issuer_kind, leaf_kind, eku):
    signer, leaf_key = key(issuer_kind), key(leaf_kind)
    root = certificate("root", signer.public_key(), signer=signer, ca=True, path_length=0)
    leaf = certificate("leaf", leaf_key.public_key(), root, signer, eku=eku)
    compare(tmp_path, pem(leaf), pem(root), True)


@pytest.mark.parametrize("case", ["expired-leaf", "future-leaf", "expired-root", "future-root",
                                 "wrong-issuer", "bad-signature", "non-ca", "issuer-ku",
                                 "unknown-critical-leaf", "unknown-critical-root", "malformed-eku",
                                 "wrong-aki", "wrong-aki-serial", "name-constraint"])
def test_chain_rejects_security_failures_like_openssl(tmp_path, case):
    signer, leaf_key = key(), key()
    root_options, leaf_options = {}, {}
    if case == "expired-leaf":
        leaf_options = {"before": -7200, "after": -60}
    elif case == "future-leaf":
        leaf_options = {"before": 3600}
    elif case == "expired-root":
        root_options = {"before": -7200, "after": -60}
    elif case == "future-root":
        root_options = {"before": 3600}
    elif case == "issuer-ku":
        root_options = {"signing": False}
    elif case in ("unknown-critical-root", "unknown-critical-leaf"):
        target = root_options if case.endswith("root") else leaf_options
        target["extensions"] = [(x509.UnrecognizedExtension(ObjectIdentifier("1.2.3.4"), b"\x05\x00"), True)]
    elif case == "malformed-eku":
        # First valid OID followed by NULL: a purpose-any implementation must not
        # return early and miss the malformed second item.
        leaf_options["extensions"] = [(x509.UnrecognizedExtension(
            ObjectIdentifier("2.5.29.37"), bytes.fromhex("300c06082b060105050703010500")), False)]
    elif case == "wrong-aki":
        leaf_options["aki"] = x509.AuthorityKeyIdentifier(b"mismatch", None, None)
    elif case == "wrong-aki-serial":
        leaf_options["aki"] = x509.AuthorityKeyIdentifier(None, [x509.DirectoryName(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "root")]))], 42)
    elif case == "name-constraint":
        root_options["extensions"] = [(x509.NameConstraints(
            permitted_subtrees=[x509.DNSName("allowed.test")], excluded_subtrees=None), True)]
        leaf_options["extensions"] = [(x509.SubjectAlternativeName([x509.DNSName("other.test")]), False)]
    root = certificate("root", signer.public_key(), signer=signer, ca=case != "non-ca", **root_options)
    leaf = certificate("leaf", leaf_key.public_key(), root,
                       key() if case == "bad-signature" else signer, **leaf_options)
    trusted = certificate("other-root", key().public_key(), signer=signer, ca=True) if case == "wrong-issuer" else root
    compare(tmp_path, pem(leaf), pem(trusted), False)


@pytest.mark.parametrize("case", ["no-issuer-ku", "unknown-noncritical", "invalid-root-signature",
                                 "multiple-anchors", "multiple-leaf-pems", "valid-name-constraint",
                                 "issuer-eku-any-purpose"])
def test_compatibility_acceptance(tmp_path, case):
    signer, leaf_key = key(), key()
    root_options, leaf_options = {}, {}
    if case == "no-issuer-ku":
        root_options["ku"] = False
    elif case == "unknown-noncritical":
        leaf_options["extensions"] = [(x509.UnrecognizedExtension(ObjectIdentifier("1.2.3.4"), b"\x05\x00"), False)]
    elif case == "valid-name-constraint":
        root_options["extensions"] = [(x509.NameConstraints(
            permitted_subtrees=[x509.DNSName("allowed.test")], excluded_subtrees=None), True)]
        leaf_options["extensions"] = [(x509.SubjectAlternativeName([x509.DNSName("service.allowed.test")]), False)]
    elif case == "issuer-eku-any-purpose":
        root_options["eku"] = [ExtendedKeyUsageOID.CODE_SIGNING]
    root = certificate("root", signer.public_key(), signer=key() if case == "invalid-root-signature" else signer,
                       ca=True, **root_options)
    leaf = certificate("leaf", leaf_key.public_key(), root, signer, **leaf_options)
    trust, target = pem(root), pem(leaf)
    if case == "multiple-anchors":
        other_key = key()
        other = certificate("other-root", other_key.public_key(), signer=other_key, ca=True)
        trust = pem(other) + trust
    if case == "multiple-leaf-pems":
        target += trust
    compare(tmp_path, target, trust, True)


@pytest.mark.parametrize("case", ["valid", "missing-root", "root-pathlen", "intermediate-ku",
                                 "expired-intermediate", "leaf-extra-does-not-supply-intermediate"])
def test_issuer_bundle_path_building(tmp_path, case):
    signer, intermediate_key, leaf_key = key(), key(), key()
    root = certificate("root", signer.public_key(), signer=signer, ca=True,
                       path_length=0 if case == "root-pathlen" else 1)
    options = {"before": -7200, "after": -60} if case == "expired-intermediate" else {}
    intermediate = certificate("intermediate", intermediate_key.public_key(), root, signer,
                               ca=True, signing=case != "intermediate-ku", **options)
    leaf = certificate("leaf", leaf_key.public_key(), intermediate, intermediate_key)
    target, trust = pem(leaf), pem(intermediate) + pem(root)
    if case == "missing-root":
        trust = pem(intermediate)
    elif case == "leaf-extra-does-not-supply-intermediate":
        target += pem(intermediate)
        trust = pem(root)
    compare(tmp_path, target, trust, case == "valid")


@pytest.mark.parametrize("before,after,ttl,valid", [(-60, 7200, 3600, True), (-60, 1800, 3600, False),
                                                 (3600, 7200, 0, False), (-7200, -60, 0, False)])
def test_native_lifetime_overlap(before, after, ttl, valid):
    signer = key()
    cert = certificate("root", signer.public_key(), signer=signer, ca=True, before=before, after=after)
    result = operator_bytes(ROOT, "operator", "certificate-lifetime", str(ttl), input=pem(cert))
    assert json.loads(result) is valid


@pytest.mark.parametrize("operation,args,input", [
    ("certificate-lifetime", ["3600"], b"invalid"),
    ("certificate-lifetime", ["-1"], b"invalid"),
    ("certificate-lifetime", ["3600"], b"x" * (64 * 1024 + 1)),
    ("certificate-chain", [], b"{}"),
    ("certificate-chain", [], b"x" * (256 * 1024 + 1)),
], ids=["bad-pem", "negative-ttl", "oversized-pem", "missing-chain", "oversized-chain"])
def test_bounded_invalid_inputs_are_sanitized(operation, args, input):
    with pytest.raises(RuntimeError, match="^Rust operator validation failed$"):
        operator_bytes(ROOT, "operator", operation, *args, input=input)


@pytest.mark.parametrize("issuer", ["", "\n", " \r\n", "not a certificate"])
def test_malformed_issuer_bundle_is_refused(issuer):
    signer = key()
    root = certificate("root", signer.public_key(), signer=signer, ca=True)
    leaf = certificate("leaf", key().public_key(), root, signer)
    with pytest.raises(RuntimeError, match="^Rust operator validation failed$"):
        native_chain(pem(leaf), issuer.encode())


@pytest.mark.parametrize("case", ["ca-target", "legacy-issuer-without-basic-constraints"])
def test_supported_profile_refuses_legacy_ca_forms(tmp_path, case):
    # OpenSSL's generic compatibility mode accepts these; neither is emitted by
    # our OpenBao end-entity producers. Explicitly qualify the narrower boundary.
    signer = key()
    root = certificate("root", signer.public_key(), signer=signer, ca=True,
                       basic_constraints=case != "legacy-issuer-without-basic-constraints")
    leaf = certificate("leaf", key().public_key(), root, signer, ca=case == "ca-target")
    (tmp_path / "leaf.pem").write_bytes(pem(leaf))
    (tmp_path / "root.pem").write_bytes(pem(root))
    previous = subprocess.run(["openssl", "verify", "-CAfile", str(tmp_path / "root.pem"),
                               str(tmp_path / "leaf.pem")], capture_output=True)
    assert previous.returncode == 0, previous.stderr.decode()
    with pytest.raises(RuntimeError, match="^Rust operator validation failed$"):
        native_chain(pem(leaf), pem(root))


@pytest.mark.skipif(os.environ.get("MARTY_TEST_OPENBAO_CERTIFICATES") != "1",
                    reason="disposable OpenBao producer qualification is enabled in amd64 CI")
def test_actual_openbao_transit_csr_producers(tmp_path):
    image = json.loads((ROOT / "deploy-config/passport-supported-disposable-infra-images.json")
                       .read_text())["images"]["openbao"]["reference"]
    name = "codex-certificate-test-" + uuid.uuid4().hex
    subprocess.run(["docker", "run", "--detach", "--name", name, "--platform", "linux/amd64",
                    "-p", "127.0.0.1::8200", "-e", "BAO_DEV_ROOT_TOKEN_ID=synthetic-test-root",
                    image, "server", "-dev", "-dev-listen-address=0.0.0.0:8200"],
                   check=True, capture_output=True, timeout=180)
    try:
        port = json.loads(subprocess.check_output(["docker", "inspect", name]))[0][
            "NetworkSettings"]["Ports"]["8200/tcp"][0]["HostPort"]
        endpoint = f"http://127.0.0.1:{port}/v1/"
        opener = build_opener(ProxyHandler({}))

        def request(method, path, body=None):
            data = json.dumps(body).encode() if body is not None else None
            req = Request(endpoint + path, data=data, method=method,
                          headers={"X-Vault-Token": "synthetic-test-root", "Content-Type": "application/json"})
            with opener.open(req, timeout=10) as response:
                content = response.read()
            return json.loads(content) if content else {}

        for attempt in range(60):
            try:
                request("GET", "sys/health")
                break
            except (URLError, ConnectionError):
                if attempt == 59:
                    raise
                time.sleep(0.5)
        request("POST", "sys/mounts/transit", {"type": "transit"})
        request("POST", "sys/mounts/pki", {"type": "pki", "config": {"max_lease_ttl": "8760h"}})
        issuer = request("POST", "pki/root/generate/internal", {
            "common_name": "synthetic OpenBao root", "key_type": "ec", "key_bits": 256,
            "ttl": "8760h"})["data"]["certificate"].encode()
        for role, kind, bits, server, client in [
            ("workload-server", "ec", 256, True, False),
            ("workload-client", "ec", 256, False, True),
            ("keycloak", "rsa", 2048, True, True),
        ]:
            request("POST", f"transit/keys/{role}", {
                "type": "ecdsa-p256" if kind == "ec" else "rsa-2048",
                "exportable": False, "allow_plaintext_backup": False})
            csr = request("POST", f"transit/keys/{role}/csr", {"version": 1})["data"]["csr"]
            request("POST", f"pki/roles/{role}", {
                "allow_any_name": True, "key_type": kind, "key_bits": bits,
                "max_ttl": "8h", "server_flag": server, "client_flag": client})
            issued = request("POST", f"pki/sign/{role}", {
                "csr": csr, "common_name": role + ".internal", "ttl": "8h"})["data"]
            assert "private_key" not in issued
            leaf = issued["certificate"].encode()
            compare(tmp_path, leaf, issuer, True)
            assert json.loads(operator_bytes(ROOT, "operator", "certificate-lifetime", "3600", input=leaf))
            metadata = request("GET", f"transit/keys/{role}")["data"]
            assert metadata["exportable"] is False and metadata["allow_plaintext_backup"] is False
            public = metadata["keys"]["1"]["public_key"].encode()
            assert operator_bytes(ROOT, "operator", "certificate-spki", input=leaf) == operator_bytes(
                ROOT, "operator", "public-spki", input=public)
    finally:
        # This UUID-named container belongs solely to this test. Remove it even
        # if the server no longer responds to a graceful stop.
        subprocess.run(["docker", "rm", "--force", "--volumes", name],
                       check=True, capture_output=True, timeout=30)
