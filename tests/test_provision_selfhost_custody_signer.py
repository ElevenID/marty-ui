"""The disposable signer helper keeps operator secret material out of source."""

import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import provision_selfhost_custody_signer as signer
import provision_selfhost_disposable_tls as tls


def test_refresh_requires_evidence_identity_before_root_token_use(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_root = tmp_path / "private"
    state_root = private_root / "openbao-state"
    output_root = private_root / "secrets"
    (state_root / "tls").mkdir(parents=True)
    output_root.mkdir()
    (state_root / "tls" / "ca.crt").write_text("ca", encoding="ascii")
    (output_root / "selfhost_custody_signer_token").write_text("old", encoding="ascii")
    (output_root / "selfhost_custody_signer.pub").write_text("pem", encoding="ascii")
    monkeypatch.setattr(signer, "private_directory", lambda path: path)
    monkeypatch.setattr(signer, "verified_openbao_owner", lambda *_args: "locked-image")
    monkeypatch.setattr(signer, "read_protected_root_token",
                        lambda _path: pytest.fail("root token was read"))
    monkeypatch.setattr(signer, "Bao", lambda *_args: pytest.fail("Bao was used"))
    monkeypatch.setattr(signer, "os", SimpleNamespace(name="posix", geteuid=lambda: 0))
    with pytest.raises(ValueError, match="evidence identity is required"):
        signer.provision("https://127.0.0.1:18200", state_root, output_root,
                         "marty-selfhost-openbao-qualification",
                         refresh_token=True)
    assert (output_root / "selfhost_custody_signer_token").read_text(encoding="ascii") == "old"


def test_rootless_identity_cannot_share_runtime_secret_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    private = tmp_path / "private"
    state = private / "openbao-state"
    secrets = private / "secrets"
    (state / "tls").mkdir(parents=True)
    secrets.mkdir()
    (state / "tls" / "ca.crt").write_text("ca", encoding="ascii")
    (secrets / "selfhost_custody_signer_token").write_text("old", encoding="ascii")
    (secrets / "selfhost_custody_signer.pub").write_text("public", encoding="ascii")
    monkeypatch.setattr(signer, "os", SimpleNamespace(name="posix", geteuid=lambda: 0))
    monkeypatch.setattr(signer, "private_directory", lambda path: path)
    monkeypatch.setattr(signer, "verified_openbao_owner", lambda *_args: "owned")
    monkeypatch.setattr(signer, "Bao", lambda *_args: pytest.fail("identity was read"))
    with pytest.raises(ValueError, match="separate from stack secrets"):
        signer.provision("https://127.0.0.1:18200", state, secrets,
                         "marty-selfhost-openbao-qualification",
                         refresh_token=True, identity_root=secrets)


def test_pending_refresh_rejected_before_new_token_created(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_root = tmp_path / "private"
    state_root = private_root / "openbao-state"
    output_root = private_root / "secrets"
    (state_root / "tls").mkdir(parents=True)
    output_root.mkdir()
    (state_root / "root.token").write_text("root", encoding="ascii")
    (state_root / "tls" / "ca.crt").write_text("ca", encoding="ascii")
    (output_root / "selfhost_custody_signer_token").write_text("old", encoding="ascii")
    (output_root / "selfhost_custody_signer.pub").write_text("public", encoding="ascii")
    (output_root / "selfhost_custody_signer_token.new").write_text("pending", encoding="ascii")
    monkeypatch.setattr(signer, "os", SimpleNamespace(name="posix", geteuid=lambda: 0))
    monkeypatch.setattr(signer, "private_directory", lambda path: path)
    monkeypatch.setattr(signer, "verified_openbao_owner", lambda *_args: "locked-image")
    monkeypatch.setattr(signer, "Bao", lambda *_args: pytest.fail("new token was created"))

    with pytest.raises(ValueError, match="pending custody token refresh"):
        signer.provision("https://127.0.0.1:18200", state_root, output_root,
                         "marty-selfhost-openbao-qualification",
                         refresh_token=True, identity_root=private_root / "evidence-identity")


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode bits are required")
def test_operator_root_must_be_private_and_outside_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    candidate = source / "operator-secrets"
    candidate.mkdir(mode=0o700)
    monkeypatch.setattr(signer, "SOURCE_ROOT", source)
    with pytest.raises(ValueError, match="outside the source checkout"):
        signer.private_directory(candidate)
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    assert signer.private_directory(outside) == outside.resolve()
    outside.chmod(0o755)
    with pytest.raises(ValueError, match="private directory"):
        signer.private_directory(outside)


def test_rejects_foreign_https_port_before_root_token_use(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    private = tmp_path / "private"
    state = private / "openbao-state"
    output = private / "secrets"
    state.mkdir(parents=True)
    output.mkdir()
    monkeypatch.setattr(signer, "private_directory", lambda path: path)
    def reject_unowned_port(_project: str, _state: Path, _install: Path,
                            port: int) -> None:
        assert port == 18201
        raise RuntimeError("OpenBao container does not own the loopback HTTPS port")

    monkeypatch.setattr(signer, "verified_openbao_owner", reject_unowned_port)
    monkeypatch.setattr(signer, "Bao", lambda *_args: pytest.fail("root token leaked"))
    monkeypatch.setattr(signer, "os", SimpleNamespace(name="posix", geteuid=lambda: 0))
    with pytest.raises(RuntimeError, match="does not own"):
        signer.provision("https://127.0.0.1:18201", state, output,
                         "marty-selfhost-openbao-qualification")


def test_rejects_unowned_docker_binding_before_root_token_use(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    private = tmp_path / "private"
    state = private / "openbao-state"
    output = private / "secrets"
    install = private / "install" / "selfhost-prepared"
    state.mkdir(parents=True)
    output.mkdir()
    install.mkdir(parents=True)
    (private / "openbao.json").write_text(json.dumps({
        "schema": "marty.selfhost-disposable-openbao/v1",
        "qualification": "unqualified",
        "project": "marty-preview-1234567890abcdef", "host_port": 18200,
        "image": "locked-image",
    }), encoding="utf-8")
    monkeypatch.setattr(signer, "private_directory", lambda path: path)
    monkeypatch.setattr(tls, "exact_images", lambda _install: ("services", "locked-image"))

    def reject_foreign_port(_project: str, _state: Path, _image: str,
                            *, expected_host_port: int) -> None:
        assert expected_host_port == 18200
        raise RuntimeError("OpenBao container does not own the loopback HTTPS port")

    monkeypatch.setattr(tls, "openbao_network", reject_foreign_port)
    monkeypatch.setattr(signer, "Bao", lambda *_args: pytest.fail("root token leaked"))
    monkeypatch.setattr(signer, "os", SimpleNamespace(name="posix", geteuid=lambda: 0))
    with pytest.raises(RuntimeError, match="does not own"):
        signer.provision("https://127.0.0.1:18200", state, output,
                         "marty-selfhost-openbao-qualification")


def test_rejects_readable_root_token_before_openbao_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    private = tmp_path / "private"
    state = private / "openbao-state"
    output = private / "secrets"
    (state / "tls").mkdir(parents=True)
    output.mkdir()
    token = state / "root.token"
    token.write_text("r" * 16, encoding="ascii")
    token.chmod(0o444)
    (state / "tls" / "ca.crt").write_text("ca", encoding="ascii")
    monkeypatch.setattr(signer, "private_directory", lambda path: path)
    monkeypatch.setattr(signer, "verified_openbao_owner", lambda *_args: "locked-image")
    monkeypatch.setattr(signer, "Bao", lambda *_args: pytest.fail("root token leaked"))
    monkeypatch.setattr(signer, "os", SimpleNamespace(name="posix", geteuid=lambda: 0))
    with pytest.raises(ValueError, match="unsafe ownership or mode"):
        signer.provision("https://127.0.0.1:18200", state, output,
                         "marty-selfhost-openbao-qualification")


def test_provisioning_rejects_rotated_signer_before_policy_or_token_creation(tmp_path, monkeypatch):
    private = tmp_path / "private"
    state, output = private / "openbao-state", private / "secrets"
    (state / "tls").mkdir(parents=True)
    output.mkdir()
    (state / "root.token").write_text("synthetic-root")
    (state / "tls" / "ca.crt").write_text("public-ca")
    monkeypatch.setattr(signer, "os", SimpleNamespace(name="posix", geteuid=lambda: 0))
    monkeypatch.setattr(signer, "private_directory", lambda path: path)
    monkeypatch.setattr(signer, "verified_openbao_owner", lambda *_: None)
    monkeypatch.setattr(signer, "read_protected_root_token", lambda _: "synthetic-root")
    calls = []

    class Bao:
        def __init__(self, *_):
            pass

        def request(self, method, path):
            calls.append((method, path))
            assert method == "GET" and path == "transit/keys/" + signer.CUSTODY_SIGNER
            return {"data": {"type": "ed25519", "exportable": False, "allow_plaintext_backup": False,
                             "latest_version": 2, "keys": {"2": {"public_key":
                             "V4R5DrcNEOahL046jfk/QYO+hD44DCZ/LMzSHqcMIrM="}}}}

    monkeypatch.setattr(signer, "Bao", Bao)
    with pytest.raises(ValueError):
        signer.provision("https://127.0.0.1:18200", state, output, "synthetic-stack")
    assert len(calls) == 2
    assert not list(output.iterdir())
