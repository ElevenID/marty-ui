"""Disposable Keycloak inputs stay scoped, source-backed, and fail closed."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from provision_selfhost_keycloak_kms import (  # noqa: E402
    OUTPUTS, require_cert_lifetime, require_mounts, selected_pki_mount, write_outputs,
)
from with_disposable_event_stream_kms import PLUGIN_IMAGE  # noqa: E402


EXPECTED = {
    "keycloak_signing_kms_token", "keycloak_master_rs256_cert",
    "keycloak_11id_rs256_cert", "keycloak_master_cookie_token",
    "keycloak_master_ciba_token", "keycloak_11id_cookie_token",
    "keycloak_11id_ciba_token",
}


def test_keycloak_outputs_match_independent_catalog_and_ci_owner() -> None:
    catalog = json.loads((ROOT / "deploy-config/catalog/secrets.json").read_text(
        encoding="utf-8"))["secrets"]
    assert EXPECTED == set(OUTPUTS)
    assert EXPECTED <= set(catalog)
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "--image marty-openbao-didcomm:ci --profile selfhost-keycloak" in workflow
    assert "-- python3 scripts/provision_selfhost_keycloak_kms.py" in workflow
    bundle = json.loads((ROOT / "deploy-config/bundles/selfhost.json").read_text(
        encoding="utf-8"))
    assert {"scripts/provision_selfhost_keycloak_kms.py",
            "scripts/selfhost_openbao_client.py"} <= set(bundle["assets"])


@pytest.mark.skipif(os.name != "posix", reason="POSIX private-root contract")
def test_keycloak_output_refuses_overwrite_missing_or_private_material(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    values = {name: f"scope-{name}" for name in EXPECTED}
    values["keycloak_master_rs256_cert"] = "-----BEGIN CERTIFICATE-----\npublic\n"
    values["keycloak_11id_rs256_cert"] = "-----BEGIN CERTIFICATE-----\npublic\n"
    with pytest.raises(RuntimeError, match="omit a secret"):
        write_outputs(tmp_path, {"keycloak_signing_kms_token": "scoped"})
    assert list(tmp_path.iterdir()) == []
    values["keycloak_signing_kms_token"] = "-----BEGIN PRIVATE KEY-----\nsecret\n"
    with pytest.raises(RuntimeError, match="private or empty"):
        write_outputs(tmp_path, values)
    assert list(tmp_path.iterdir()) == []
    values["keycloak_signing_kms_token"] = "scoped-signing-token"
    write_outputs(tmp_path, values)
    assert {path.name for path in tmp_path.iterdir()} == EXPECTED
    assert {path.stat().st_mode & 0o777 for path in tmp_path.iterdir()} == {0o444}
    with pytest.raises(RuntimeError, match="overwrite an existing secret"):
        write_outputs(tmp_path, values)


@pytest.mark.skipif(os.name != "posix", reason="POSIX private-root contract")
def test_keycloak_output_preserves_unrelated_existing_file(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    marker = tmp_path / "operator-note"
    marker.write_text("keep me", encoding="ascii")
    values = {name: f"scope-{name}" for name in EXPECTED}
    write_outputs(tmp_path, values)
    assert {path.name for path in tmp_path.iterdir()} == EXPECTED | {marker.name}
    assert marker.read_text(encoding="ascii") == "keep me"


@pytest.mark.skipif(os.name != "posix", reason="POSIX private-root contract")
def test_renewal_stages_owner_only_files(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    values = {name: f"scope-{name}" for name in EXPECTED}
    write_outputs(tmp_path, values, staged=True)
    assert {path.stat().st_mode & 0o777 for path in tmp_path.iterdir()} == {0o600}


@pytest.mark.skipif(os.name != "posix", reason="POSIX private-root contract")
def test_keycloak_output_rejects_existing_target_without_mutating_it(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    target = tmp_path / "keycloak_signing_kms_token"
    target.write_text("existing", encoding="ascii")
    values = {name: f"scope-{name}" for name in EXPECTED}
    with pytest.raises(RuntimeError, match="overwrite an existing secret"):
        write_outputs(tmp_path, values)
    assert list(tmp_path.iterdir()) == [target]
    assert target.read_text(encoding="ascii") == "existing"


@pytest.mark.skipif(os.name != "posix", reason="POSIX private-root contract")
def test_keycloak_output_rolls_back_only_files_created_on_write_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    tmp_path.chmod(0o700)
    values = {name: f"scope-{name}" for name in EXPECTED}
    original = os.open
    calls = 0

    def fail_after_three(path: Path, flags: int, mode: int = 0o777) -> int:
        nonlocal calls
        calls += 1
        if calls == 4:
            raise OSError("synthetic disk failure")
        return original(path, flags, mode)

    with monkeypatch.context() as patch:
        patch.setattr("provision_selfhost_keycloak_kms.os.open", fail_after_three)
        with pytest.raises(OSError, match="synthetic disk failure"):
            write_outputs(tmp_path, values)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.skipif(os.name != "posix", reason="POSIX file mode transition")
def test_keycloak_output_rolls_back_on_mode_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    tmp_path.chmod(0o700)
    values = {name: f"scope-{name}" for name in EXPECTED}
    with monkeypatch.context() as patch:
        patch.setattr("provision_selfhost_keycloak_kms.os.fchmod",
                      lambda _fd, _mode: (_ for _ in ()).throw(OSError("mode failure")))
        with pytest.raises(OSError, match="mode failure"):
            write_outputs(tmp_path, values)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.skipif(os.name == "nt", reason="Unix ownership and mode contract")
def test_keycloak_output_requires_owner_private_directory(tmp_path: Path) -> None:
    tmp_path.chmod(0o755)
    values = {name: f"scope-{name}" for name in EXPECTED}
    with pytest.raises(RuntimeError, match="owner-private"):
        write_outputs(tmp_path, values)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.skipif(os.name == "posix", reason="native non-POSIX rejection")
def test_keycloak_output_rejects_native_windows(tmp_path: Path) -> None:
    values = {name: f"scope-{name}" for name in EXPECTED}
    with pytest.raises(RuntimeError, match="requires a POSIX filesystem"):
        write_outputs(tmp_path, values)
    assert list(tmp_path.iterdir()) == []


class Mounts:
    def __init__(self, didcomm: str, *, keycloak: bool = False) -> None:
        self.didcomm = didcomm
        self.keycloak = keycloak

    def request(self, method: str, path: str) -> dict:
        assert (method, path) == ("GET", "sys/mounts")
        mounts = {"transit/": {"type": "transit"}, "didcomm/": {"type": self.didcomm}}
        if self.keycloak:
            mounts["keycloak-pki/"] = {"type": "pki"}
        return {"data": mounts}


def test_keycloak_provisioning_requires_current_didcomm_plugin() -> None:
    require_mounts(Mounts("openbao-didcomm-authcrypt"))
    with pytest.raises(RuntimeError, match="reviewed Keycloak mounts"):
        require_mounts(Mounts("kv"))
    require_mounts(Mounts("openbao-didcomm-authcrypt", keycloak=True), renew=True)
    with pytest.raises(RuntimeError, match="reviewed Keycloak mounts"):
        require_mounts(Mounts("openbao-didcomm-authcrypt"), renew=True)
    assert PLUGIN_IMAGE.fullmatch("marty-openbao-didcomm:ci")
    assert PLUGIN_IMAGE.fullmatch("marty-openbao-didcomm:local")
    assert not PLUGIN_IMAGE.fullmatch("ghcr.io/elevenid/marty-ui-oss/openbao-didcomm:latest")


def test_replacement_keycloak_issuer_is_explicit_and_bounded() -> None:
    assert selected_pki_mount(renew=True, requested=None) == "keycloak-pki"
    assert selected_pki_mount(renew=True, requested="keycloak-pki-v2") == "keycloak-pki-v2"
    assert selected_pki_mount(renew=True, requested="keycloak-pki-v8") == "keycloak-pki-v8"
    for value in ("", "keycloak-pki-v1", "keycloak-pki-v02", "keycloak-pki-v9",
                  "keycloak-pki-v2/sign/rs256"):
        with pytest.raises(ValueError, match="mount is invalid"):
            selected_pki_mount(renew=True, requested=value)
    with pytest.raises(ValueError, match="renewal-only"):
        selected_pki_mount(renew=False, requested="keycloak-pki-v2")

    class ReplacementMounts(Mounts):
        def request(self, method: str, path: str) -> dict:
            response = super().request(method, path)
            response["data"]["keycloak-pki-v2/"] = {"type": "pki"}
            return response

    require_mounts(ReplacementMounts("openbao-didcomm-authcrypt", keycloak=True),
                   renew=True, pki_mount="keycloak-pki-v2")
    with pytest.raises(RuntimeError, match="reviewed Keycloak mounts"):
        require_mounts(Mounts("openbao-didcomm-authcrypt", keycloak=True),
                       renew=True, pki_mount="keycloak-pki-v2")


def test_keycloak_certificate_requires_a_real_session_length() -> None:
    from tests.test_selfhost_native_certificates import certificate, key, pem
    signer = key()
    short = certificate("short", signer.public_key(), signer=signer, after=1800)
    with pytest.raises(RuntimeError, match="certificate expires before tester session"):
        require_cert_lifetime(pem(short).decode())


@pytest.mark.parametrize("minted", [False, True])
def test_provision_reports_recovery_only_after_leaf_creation(monkeypatch, minted):
    import provision_selfhost_keycloak_kms as keycloak
    from selfhost_native_operator import OperatorCleanupError

    def fail(bao, created, **context):
        if minted:
            created.append("sensitive-leaf-token-not-for-diagnostics")
        raise RuntimeError("synthetic preflight failure")

    monkeypatch.setattr(keycloak, "_provision", fail)
    error = OperatorCleanupError if minted else RuntimeError
    message = "Keycloak provisioning requires operator recovery" if minted else "synthetic preflight failure"
    with pytest.raises(error, match="^" + message + "$"):
        keycloak.provision(object())


def test_cli_staging_failure_after_qualified_mint_is_exit_three(tmp_path, monkeypatch, capsys):
    import provision_selfhost_keycloak_kms as keycloak
    ca, token = tmp_path / "ca.crt", tmp_path / "token"
    ca.write_text("public CA")
    token.write_text("synthetic-operator-token-long-enough")
    for name, value in {"BAO_ADDR": "https://synthetic.invalid", "BAO_CACERT": str(ca),
                        "SELFHOST_KEYCLOAK_MODE": "initial", "BAO_ROOT_TOKEN_FILE": str(token),
                        "SELFHOST_KEYCLOAK_OUTPUT_DIR": str(tmp_path)}.items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("SELFHOST_KEYCLOAK_PKI_MOUNT", raising=False)
    monkeypatch.setattr(keycloak, "require_available_private_root", lambda *_: None)
    monkeypatch.setattr(keycloak, "KeycloakBao", lambda *_: object())
    monkeypatch.setattr(keycloak, "provision", lambda *_, **kwargs: {"minted": "sensitive-token"})

    def failed_write(*args, **kwargs):
        raise OSError("sensitive-local-path")
    monkeypatch.setattr(keycloak, "write_outputs", failed_write)
    assert keycloak.main() == 3
    assert capsys.readouterr().err.strip() == "Keycloak provisioning requires operator recovery"
