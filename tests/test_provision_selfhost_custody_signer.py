"""The disposable signer helper keeps operator secret material out of source."""

import os
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from urllib.error import HTTPError

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import provision_selfhost_custody_signer as signer
import provision_selfhost_disposable_tls as tls


@pytest.mark.parametrize("cleanup_fails,write_fails,valid_policy,orphan", [
    (False, False, False, True), (True, False, False, True),
    (False, True, True, True), (False, False, True, False),
])
def test_scoped_validation_failure_revokes_or_preserves_new_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    cleanup_fails: bool, write_fails: bool, valid_policy: bool, orphan: bool,
) -> None:
    private_root = tmp_path / "private"
    state_root = private_root / "openbao-state"
    output_root = private_root / "secrets"
    (state_root / "tls").mkdir(parents=True)
    output_root.mkdir()
    root_token = state_root / "root.token"
    root_token.write_text("r" * 16, encoding="ascii")
    root_token.chmod(0o400)
    (state_root / "tls" / "ca.crt").write_text("ca", encoding="ascii")
    (output_root / "selfhost_custody_signer_token").write_text("old", encoding="ascii")
    (output_root / "selfhost_custody_signer.pub").write_text("pem", encoding="ascii")
    calls = []

    class FakeBao:
        def __init__(self, endpoint: str, ca: Path, token: str) -> None:
            self.token = token

        def request(self, method: str, path: str, body: dict | None = None) -> dict:
            calls.append((self.token, method, path))
            if path == f"transit/keys/{signer.CUSTODY_SIGNER}":
                return {"data": {"type": "ed25519", "exportable": False,
                                 "allow_plaintext_backup": False,
                                 "latest_version": 1,
                                 "keys": {"1": {"public_key": "raw"}}}}
            if path == "auth/token/create":
                assert body is not None
                assert body["no_parent"] is True
                assert "orphan" not in body
                return {"auth": {"client_token": "new"}}
            if path == "auth/token/lookup-self":
                return {"data": {"policies": ([signer.CUSTODY_SIGNER_POLICY]
                                               if valid_policy else []),
                                 "orphan": orphan, "ttl": 3600}}
            if path == f"transit/export/signing-key/{signer.CUSTODY_SIGNER}":
                raise HTTPError("https://127.0.0.1", 403, "denied", {}, None)
            if path == "auth/token/revoke" and cleanup_fails:
                raise HTTPError("https://127.0.0.1", 503, "unavailable", {}, None)
            return {}

    monkeypatch.setattr(signer, "private_directory", lambda path: path)
    monkeypatch.setattr(signer, "verified_openbao_owner", lambda *_args: "locked-image")
    monkeypatch.setattr(signer, "read_protected_root_token", lambda _path: "r" * 16)
    monkeypatch.setattr(signer, "Bao", FakeBao)
    monkeypatch.setattr(signer, "ed25519_public_pem", lambda _raw: "pem")

    def secure_open(path: Path, flags: int, mode: int) -> int:
        if write_fails and str(path).endswith(".new"):
            raise PermissionError("injected pending-token write failure")
        return os.open(path, flags, mode)

    monkeypatch.setattr(signer, "os", SimpleNamespace(
        name="posix", geteuid=lambda: 0, open=secure_open, fdopen=os.fdopen,
        fchown=lambda *_args: None, fchmod=lambda *_args: None,
        O_WRONLY=os.O_WRONLY, O_CREAT=os.O_CREAT, O_EXCL=os.O_EXCL,
        O_NOFOLLOW=getattr(os, "O_NOFOLLOW", 0),
    ))
    expected = PermissionError if write_fails else ValueError
    with pytest.raises(expected):
        signer.provision("https://127.0.0.1:18200", state_root, output_root,
                         "marty-selfhost-openbao-qualification",
                         refresh_token=True)
    assert ("r" * 16, "POST", "auth/token/revoke") in calls
    assert (output_root / "selfhost_custody_signer_token").read_text(encoding="ascii") == "old"
    pending = output_root / "selfhost_custody_signer_token.new"
    assert pending.exists() is cleanup_fails
    if cleanup_fails:
        assert pending.read_text(encoding="ascii") == "new"


def test_refresh_revokes_old_token_before_replacement(tmp_path: Path) -> None:
    token_file = tmp_path / "selfhost_custody_signer_token"
    token_file.write_text("old", encoding="ascii")

    class BaoSuccess:
        def request(self, method: str, path: str, body: dict) -> None:
            assert (method, path, body["token"]) == (
                "POST", "auth/token/revoke", "old")
            assert token_file.read_text(encoding="ascii") == "old"

    signer.refresh_scoped_token(
        BaoSuccess(), token_file, "new",
        lambda path, value, mode: path.write_text(value, encoding="ascii"),
    )
    assert token_file.read_text(encoding="ascii") == "new"
    assert not token_file.with_name(token_file.name + ".new").exists()


def test_refresh_keeps_old_token_if_revocation_fails(tmp_path: Path) -> None:
    token_file = tmp_path / "selfhost_custody_signer_token"
    token_file.write_text("old", encoding="ascii")
    calls = []

    class BaoFailure:
        def request(self, method: str, path: str, body: dict) -> None:
            calls.append((method, path, body["token"]))
            if body["token"] == "old":
                raise HTTPError("https://127.0.0.1", 503, "unavailable", {}, None)

    def write(path: Path, value: str, mode: int) -> None:
        assert mode == 0o400
        path.write_text(value, encoding="ascii")

    with pytest.raises(RuntimeError, match="operator recovery"):
        signer.refresh_scoped_token(BaoFailure(), token_file, "new", write)
    assert token_file.read_text(encoding="ascii") == "old"
    assert token_file.with_name(token_file.name + ".new").read_text(encoding="ascii") == "new"
    assert calls == [("POST", "auth/token/revoke", "old")]


def test_refresh_preserves_new_token_if_revoke_response_is_lost(tmp_path: Path) -> None:
    token_file = tmp_path / "selfhost_custody_signer_token"
    token_file.write_text("old", encoding="ascii")

    class BaoFailure:
        def request(self, method: str, path: str, body: dict) -> None:
            assert body["token"] == "old"
            active_tokens.discard("old")  # Server acted, but its reply was lost.
            raise HTTPError("https://127.0.0.1", 503, "unavailable", {}, None)

    active_tokens = {"old", "new"}
    with pytest.raises(RuntimeError, match="operator recovery"):
        signer.refresh_scoped_token(
            BaoFailure(), token_file, "new",
            lambda path, value, mode: path.write_text(value, encoding="ascii"),
        )
    assert token_file.read_text(encoding="ascii") == "old"
    assert token_file.with_name(token_file.name + ".new").read_text(encoding="ascii") == "new"
    assert active_tokens == {"new"}


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
                         refresh_token=True)


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
