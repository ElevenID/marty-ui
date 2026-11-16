#!/usr/bin/env python3
"""Reproduce public unit-test fixtures with deliberately disposable test keys.

Development-only requirements: PyLD 3.3.0 and cryptography 50.0.0. Neither is a
runtime dependency. Context resolution is pinned and strictly offline. No
service, issuer registry, KMS, or production key material is used.
"""
import argparse
import base64
import copy
import hashlib
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils
from pyld import jsonld

HERE = Path(__file__).resolve().parent
HISTORICAL = {
    "governed_ob3.json": "3b65cb9fb09ee9bf324def612388d687c96019b9076dd98bb7125f2b8d848af9",
    "foreign_ob3_jwt.json": "9d88b796b081aee3507654ca719c058b633c689ace6b6a54cb1597ce4822a0c0",
}
CONTEXTS = {
    "https://www.w3.org/ns/credentials/v2": (
        "credentials-v2.jsonld",
        "e2fdd92278c972bec624dfffd9a89558d92556a9b8fd246a6a8daed1c98de46e",
    ),
    "https://purl.imsglobal.org/spec/ob/v3p0/context.json": (
        "openbadges-v3.jsonld",
        "b2c5a415b2d5e7e5c111732a4e8173d70297a1a76f877f8d0582e9e10493e846",
    ),
    "https://w3id.org/security/suites/jws-2020/v1": (
        "security-jws-2020.jsonld",
        "d648e05ddc6577827ca2bfd5e931f53e9ebc6e52a57a8da81df4ec8c46ffcd1e",
    ),
    "https://w3id.org/security/v1": (
        "security-v1.jsonld",
        "abaf97e107d1925503c433dcaf3ffd2831697cacc1ed2a293e1bc8030d5bcb47",
    ),
    "https://w3id.org/security/v2": (
        "security-v2.jsonld",
        "611bd81151d5efe53ec9aed78f5a813e577287bc9451ee26d6879b1b8b46bc3b",
    ),
}
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def unb64(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def encoded_json(value):
    return b64(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def frozen_inputs(core_root):
    fixtures = {}
    for name, expected in HISTORICAL.items():
        raw = (HERE / name).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == expected, name
        fixtures[name] = json.loads(raw)
    contexts = {}
    context_root = core_root / "marty-verification/src/open_badges/contexts"
    for url, (name, expected) in CONTEXTS.items():
        raw = (context_root / name).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == expected, name
        contexts[url] = json.loads(raw)

    def loader(url, _options=None):
        if url not in contexts:
            raise ValueError("Unexpected context: network resolution is forbidden")
        return {"contextUrl": None, "documentUrl": url,
                "document": copy.deepcopy(contexts[url])}

    return fixtures, loader


def jws2020_input(credential, header, loader):
    unsigned = copy.deepcopy(credential)
    proof = unsigned.pop("proof")
    proof.pop("jws", None)
    # JWS2020 proof configuration includes the credential context plus its own
    # proof context. The historical signature verifies this independently.
    proof["@context"] = unsigned["@context"] + [proof["@context"]]

    def digest(value):
        canonical = jsonld.normalize(value, {"algorithm": "URDNA2015",
            "format": "application/n-quads", "documentLoader": loader}).encode()
        return hashlib.sha256(canonical).digest()

    proof_hash, document_hash = digest(proof), digest(unsigned)
    return (header.encode() + b"." + proof_hash + document_hash,
            {"proof_nquads_sha256": proof_hash.hex(),
             "document_nquads_sha256": document_hash.hex()})


def verify_jws2020(fixture, loader):
    header, empty, signature = fixture["credential"]["proof"]["jws"].split(".")
    assert empty == ""
    assert json.loads(unb64(header)) == {"alg": "EdDSA", "b64": False, "crit": ["b64"]}
    signing_input, digests = jws2020_input(fixture["credential"], header, loader)
    public = ed25519.Ed25519PublicKey.from_public_bytes(
        unb64(fixture["governed_method"]["public_jwk"]["x"]))
    public.verify(unb64(signature), signing_input)
    return digests


def verify_es256(fixture):
    header, payload, signature = fixture["token"].split(".")
    assert json.loads(unb64(header))["alg"] == "ES256"
    key = fixture["public_jwk"]
    public = ec.EllipticCurvePublicNumbers(
        int.from_bytes(unb64(key["x"]), "big"),
        int.from_bytes(unb64(key["y"]), "big"), ec.SECP256R1()).public_key()
    raw = unb64(signature)
    assert len(raw) == 64
    der = utils.encode_dss_signature(int.from_bytes(raw[:32], "big"),
                                     int.from_bytes(raw[32:], "big"))
    public.verify(der, (header + "." + payload).encode(), ec.ECDSA(hashes.SHA256()))


def governed_positive(historical, loader):
    fixture = copy.deepcopy(historical)
    credential = fixture["credential"]
    assert "criteria" not in credential["credentialSubject"]["achievement"]
    issuer = credential["issuer"]
    credential["issuer"] = {"id": issuer, "type": ["Profile"],
                            "name": "Synthetic Governed Issuer"}
    credential["validFrom"] = "2026-01-01T00:00:00Z"
    credential["credentialSubject"]["achievement"]["criteria"] = {
        "narrative": "Complete the synthetic governed-issuer verification exercise."}
    proof = credential["proof"]
    proof["created"] = "2026-01-01T00:00:01Z"
    proof.pop("jws")
    # Known, disposable unit-test material, analogous to existing Rust fixtures.
    signer = ed25519.Ed25519PrivateKey.from_private_bytes(bytes([71]) * 32)
    public = {"kty": "OKP", "crv": "Ed25519",
              "x": b64(signer.public_key().public_bytes_raw())}
    method = fixture["governed_method"]["id"]
    fixture["governed_method"]["public_jwk"] = public
    fixture["document_store"][method]["publicKeyJwk"] = public
    header = encoded_json({"alg": "EdDSA", "b64": False, "crit": ["b64"]})
    signing_input, _digests = jws2020_input(credential, header, loader)
    proof["jws"] = header + ".." + b64(signer.sign(signing_input))
    verify_jws2020(fixture, loader)
    return fixture


def foreign_positive(historical):
    fixture = copy.deepcopy(historical)
    old_header, old_payload, _signature = fixture["token"].split(".")
    header, payload = json.loads(unb64(old_header)), json.loads(unb64(old_payload))
    achievement = payload["vc"]["credentialSubject"]["achievement"]
    assert "criteria" not in achievement
    achievement["criteria"] = {
        "narrative": "Complete the synthetic foreign-issuer verification exercise."}
    # This scalar is public test material and never a production signing key.
    signer = ec.derive_private_key(int.from_bytes(bytes([72]) * 32, "big"), ec.SECP256R1())
    public = signer.public_key().public_numbers()
    fixture["public_jwk"] = {"kty": "EC", "crv": "P-256",
        "x": b64(public.x.to_bytes(32, "big")), "y": b64(public.y.to_bytes(32, "big")),
        "kid": header["kid"]}
    signing_input = encoded_json(header) + "." + encoded_json(payload)
    der = signer.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    r, s = utils.decode_dss_signature(der)
    s = min(s, P256_ORDER - s)
    fixture["token"] = signing_input + "." + b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
    verify_es256(fixture)
    return fixture


def assert_criteria_tampering_rejected(governed, foreign, loader):
    changed = copy.deepcopy(governed)
    changed["credential"]["credentialSubject"]["achievement"]["criteria"]["narrative"] = "Different criterion"
    try:
        verify_jws2020(changed, loader)
    except InvalidSignature:
        pass
    else:
        raise AssertionError("JWS2020 criteria are not signature-bound")
    changed = copy.deepcopy(foreign)
    header, payload, signature = changed["token"].split(".")
    claims = json.loads(unb64(payload))
    claims["vc"]["credentialSubject"]["achievement"]["criteria"]["narrative"] = "Different criterion"
    changed["token"] = header + "." + encoded_json(claims) + "." + signature
    try:
        verify_es256(changed)
    except InvalidSignature:
        pass
    else:
        raise AssertionError("ES256 criteria are not signature-bound")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core-root", type=Path, required=True,
                        help="Core checkout containing the pinned public JSON-LD contexts")
    parser.add_argument("--write", action="store_true",
                        help="write only the two derived positive public fixture files")
    args = parser.parse_args()
    historical, loader = frozen_inputs(args.core_root)
    old_governed = historical["governed_ob3.json"]
    old_foreign = historical["foreign_ob3_jwt.json"]
    old_digests = verify_jws2020(old_governed, loader)
    verify_es256(old_foreign)
    new_governed = governed_positive(old_governed, loader)
    new_foreign = foreign_positive(old_foreign)
    assert_criteria_tampering_rejected(new_governed, new_foreign, loader)
    outputs = {
        "governed_ob3_with_criteria.json": new_governed,
        "foreign_ob3_with_criteria_jwt.json": new_foreign,
    }
    hashes_out = {}
    for name, value in outputs.items():
        raw = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
        if args.write:
            (HERE / name).write_bytes(raw)
        else:
            assert (HERE / name).read_bytes() == raw, name
        hashes_out[name] = hashlib.sha256(raw).hexdigest()
    print(json.dumps({"historical_signatures_verified": True,
        "criteria_tampering_rejected": True,
        "historical_jws2020": old_digests,
        "positive_jws2020": verify_jws2020(new_governed, loader),
        "positive_sha256": hashes_out, "network_context_resolution": False}, indent=2))


if __name__ == "__main__":
    main()
