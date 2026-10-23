"""Cross-check native public conversion against the previous OpenSSL implementation."""
from pathlib import Path
import subprocess
import hashlib
import os

import pytest

from scripts.selfhost_native_operator import operator_bytes

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("kind", ["RSA", "EC", "ED25519"])
def test_native_spki_matches_openssl_for_supported_operator_keys(tmp_path: Path, kind: str) -> None:
    private = tmp_path / "synthetic.pem"
    args = ["openssl", "genpkey", "-algorithm", kind, "-out", str(private)]
    if kind == "RSA":
        args += ["-pkeyopt", "rsa_keygen_bits:2048"]
    elif kind == "EC":
        args += ["-pkeyopt", "ec_paramgen_curve:P-256"]
    subprocess.run(args, capture_output=True, check=True)
    public = subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout"],
                            capture_output=True, check=True).stdout
    expected = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "DER"],
                              input=public, capture_output=True, check=True).stdout
    assert operator_bytes(ROOT, "operator", "public-spki", input=public) == expected


def test_native_certificate_spki_matches_openssl() -> None:
    certificate = (ROOT / "tests/fixtures/selfhost_ca_issuer_public.pem").read_bytes()
    public = subprocess.run(["openssl", "x509", "-pubkey", "-noout"],
                            input=certificate, capture_output=True, check=True).stdout
    expected = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "DER"],
                              input=public, capture_output=True, check=True).stdout
    assert operator_bytes(ROOT, "operator", "certificate-spki", input=certificate) == expected


def test_installed_bundle_uses_verified_native_operator_without_source(tmp_path: Path, monkeypatch) -> None:
    # Build identity comes from the same candidate source, never a fake executable.
    source = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    env = {**os.environ, "CARGO_TARGET_DIR": str(tmp_path / "native-target"),
           "MARTY_DEPLOY_SOURCE_SHA": source,
           "MARTY_DEPLOY_RELEASE_TAG": "v0.0.0"}
    subprocess.run(["cargo", "+1.95.0", "build", "--locked", "--manifest-path",
                    str(ROOT / "rust/Cargo.toml"), "-p", "marty-deployment-catalog"],
                   env=env, check=True, capture_output=True, timeout=300)
    target = Path(env.get("CARGO_TARGET_DIR", ROOT / "rust/target"))
    binary = (target / "debug" / ("marty-deploy.exe" if os.name == "nt" else "marty-deploy")).resolve()
    for name, value in {"MARTY_DEPLOY_SOURCE_SHA": source,
                        "MARTY_DEPLOY_RELEASE_TAG": "v0.0.0",
                        "MARTY_DEPLOY_BIN": str(binary),
                        "MARTY_DEPLOY_BIN_SHA256": hashlib.sha256(binary.read_bytes()).hexdigest()}.items():
        monkeypatch.setenv(name, value)
    certificate = (ROOT / "tests/fixtures/selfhost_ca_issuer_public.pem").read_bytes()
    assert operator_bytes(tmp_path, "operator", "certificate-spki", input=certificate).startswith(b"\x30")
    monkeypatch.setenv("MARTY_DEPLOY_BIN_SHA256", "0" * 64)
    with pytest.raises(RuntimeError, match="digest mismatch"):
        operator_bytes(tmp_path, "operator", "certificate-spki", input=certificate)
