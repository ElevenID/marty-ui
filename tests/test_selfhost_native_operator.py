"""Cross-check native public conversion against the previous OpenSSL implementation."""
from pathlib import Path
import subprocess
import hashlib
import os
import base64

import pytest

from scripts.selfhost_native_operator import operator_bytes

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("operation,timeout", [("approle-bootstrap", None), ("approle-mint", None),
                                            ("approle-login", 300), ("approle-policy", 300),
                                            ("approle-rotate", None), ("approle-retire", None),
                                            ("leaf-refresh", None), ("keycloak-token", None)])
def test_native_transactions_cannot_be_killed_during_cleanup(monkeypatch, operation, timeout):
    from types import SimpleNamespace
    from scripts import selfhost_native_operator as native

    monkeypatch.setattr(native, "operator_command", lambda *_: ["native-operator"])

    def run(command, **kwargs):
        assert command == ["native-operator"]
        assert kwargs["timeout"] == timeout
        assert kwargs["capture_output"] is True
        return SimpleNamespace(returncode=0, stdout=b"{}")

    monkeypatch.setattr(native.subprocess, "run", run)
    assert native.operator_bytes(ROOT, "operator", operation, input=b"{}") == b"{}"


@pytest.mark.parametrize("code", [-15, 101, 3221225477])
def test_keycloak_abnormal_exit_is_sanitized_recovery(monkeypatch, code):
    from types import SimpleNamespace
    from scripts import selfhost_native_operator as native
    monkeypatch.setattr(native, "operator_command", lambda *_: ["native-operator"])
    monkeypatch.setattr(native.subprocess, "run", lambda *_, **kwargs: SimpleNamespace(
        returncode=code, stdout=b"", stderr=b"sensitive-crash-detail"))
    with pytest.raises(native.OperatorCleanupError, match="^Keycloak provisioning requires operator recovery$"):
        native.operator_bytes(ROOT, "operator", "keycloak-token", input=b"{}")


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
    if kind == "ED25519":
        from scripts.selfhost_openbao_client import ed25519_public_pem
        encoded = base64.b64encode(expected[-32:]).decode("ascii")
        assert operator_bytes(ROOT, "operator", "ed25519-spki", input=encoded.encode()) == expected
        assert ed25519_public_pem(encoded).encode() == public.replace(b"\r\n", b"\n")


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
