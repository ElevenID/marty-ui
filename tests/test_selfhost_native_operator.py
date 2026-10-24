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
                                            ("leaf-refresh", None), ("keycloak-token", None),
                                            ("keycloak-provision", None), ("ca-issuer", None),
                                            ("renewal-inventory", 600)])
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
@pytest.mark.parametrize("operation", ["keycloak-token", "keycloak-provision"])
def test_keycloak_abnormal_exit_is_sanitized_recovery(monkeypatch, code, operation):
    from types import SimpleNamespace
    from scripts import selfhost_native_operator as native
    monkeypatch.setattr(native, "operator_command", lambda *_: ["native-operator"])
    monkeypatch.setattr(native.subprocess, "run", lambda *_, **kwargs: SimpleNamespace(
        returncode=code, stdout=b"", stderr=b"sensitive-crash-detail"))
    with pytest.raises(native.OperatorCleanupError, match="^Keycloak provisioning requires operator recovery$"):
        native.operator_bytes(ROOT, "operator", operation, input=b"{}")


@pytest.mark.parametrize("code", [-15, 101, 3221225477])
def test_ca_issuer_abnormal_exit_is_sanitized_recovery(monkeypatch, code):
    from types import SimpleNamespace
    from scripts import selfhost_native_operator as native
    monkeypatch.setattr(native, "operator_command", lambda *_: ["native-operator"])
    monkeypatch.setattr(native.subprocess, "run", lambda *_, **kwargs: SimpleNamespace(
        returncode=code, stdout=b"", stderr=b"sensitive-crash-detail"))
    with pytest.raises(native.OperatorCleanupError, match="^CA issuer staging requires operator recovery$"):
        native.operator_bytes(ROOT, "operator", "ca-issuer", input=b"{}")


@pytest.mark.parametrize("payload", [b'{"value":', b'null', b'{"value":null}', b'{"value":"wrong-pki-v9"}'])
def test_ca_issuer_malformed_delivery_requires_recovery(monkeypatch, payload, tmp_path):
    from importlib import import_module
    from types import SimpleNamespace
    monkeypatch.syspath_prepend(str(ROOT / "scripts"))
    import provision_selfhost_ca_rotation_identity as rotation
    # Exercise the adapter module actually imported by the sibling CLI. Mixing
    # package and sibling imports would create two distinct exception classes.
    native = import_module(rotation.network_operation.__module__)
    monkeypatch.setattr(native, "operator_bytes", lambda *args, **kwargs: payload)
    bao = SimpleNamespace(endpoint="https://unused", ca=tmp_path, token="")
    with pytest.raises(rotation.OperatorCleanupError, match="^CA issuer staging requires operator recovery$"):
        rotation.stage_issuer(bao, tmp_path, tmp_path, "workload", 2)


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


@pytest.mark.parametrize("version,pinned,valid", [(1, False, True), (2, False, True), (1, True, True),
                                                 (2, True, False), (True, False, False),
                                                 (1.0, False, False), (0, False, False), (-1, False, False)])
def test_native_custody_signer_preserves_latest_and_provisioning_modes(version, pinned, valid):
    from scripts.selfhost_openbao_client import custody_signer_public
    raw = "V4R5DrcNEOahL046jfk/QYO+hD44DCZ/LMzSHqcMIrM="
    metadata = {"type": "ed25519", "exportable": False, "allow_plaintext_backup": False,
                "latest_version": version, "keys": {str(version): {"public_key": raw}}}
    if not valid:
        with pytest.raises(ValueError):
            custody_signer_public(metadata, version_one=pinned)
        return
    result_version, pem = custody_signer_public(metadata, version_one=pinned)
    assert result_version == version
    assert operator_bytes(ROOT, "operator", "public-spki", input=pem.encode()) == operator_bytes(
        ROOT, "operator", "ed25519-spki", input=raw.encode())


@pytest.mark.parametrize("fault", ["exportable", "backup", "type", "missing-current", "noncanonical", "oversized"])
def test_native_custody_signer_refuses_custody_and_current_key_drift(fault):
    import json
    from scripts.selfhost_openbao_client import custody_signer_public
    raw = "V4R5DrcNEOahL046jfk/QYO+hD44DCZ/LMzSHqcMIrM="
    metadata = {"type": "ed25519", "exportable": False, "allow_plaintext_backup": False,
                "latest_version": 2, "keys": {"1": {"public_key": raw}, "2": {"public_key": raw}}}
    if fault == "exportable":
        metadata["exportable"] = True
    elif fault == "backup":
        metadata["allow_plaintext_backup"] = True
    elif fault == "type":
        metadata["type"] = "rsa-2048"
    elif fault == "missing-current":
        del metadata["keys"]["2"]
    elif fault == "noncanonical":
        metadata["keys"]["2"]["public_key"] += "\n"
    else:
        metadata["extra"] = "x" * 65536
    with pytest.raises(ValueError):
        custody_signer_public(metadata)
    with pytest.raises(RuntimeError, match="^Rust operator validation failed$"):
        operator_bytes(ROOT, "operator", "custody-signer", input=json.dumps(
            {"metadata": metadata, "version_one": False}).encode())
