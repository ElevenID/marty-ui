"""The disposable signer helper keeps operator secret material out of source."""

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from urllib.error import HTTPError

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


@pytest.mark.parametrize("lost_response", [False, True])
def test_refresh_preserves_new_token_if_revocation_is_ambiguous(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, lost_response: bool,
) -> None:
    token_file = tmp_path / "selfhost_custody_signer_token"
    token_file.write_text("old", encoding="ascii")
    active_tokens = {"old", "new"}

    class Operator:
        endpoint = "https://127.0.0.1:18200"
        ca = tmp_path / "ca.crt"

    class Leaf:
        def __init__(self, _endpoint, _ca, token):
            assert token == "old"

        def request(self, method, path):
            assert (method, path) == ("POST", "auth/token/revoke-self")
            assert token_file.read_text(encoding="ascii") == "old"
            if lost_response:
                active_tokens.discard("old")
            raise HTTPError("https://127.0.0.1", 503, "unavailable", {}, None)

    monkeypatch.setattr(signer, "Bao", Leaf)
    with pytest.raises(RuntimeError, match="operator recovery"):
        signer.refresh_scoped_token(
            Operator(), token_file, "new",
            lambda path, value, mode: path.write_text(value, encoding="ascii"),
        )
    assert token_file.read_text(encoding="ascii") == "old"
    assert token_file.with_name(token_file.name + ".new").read_text(encoding="ascii") == "new"
    assert active_tokens == ({"new"} if lost_response else {"old", "new"})


def test_rootless_refresh_uses_old_leaf_self_revocation(tmp_path: Path,
                                                        monkeypatch: pytest.MonkeyPatch) -> None:
    token_file = tmp_path / "selfhost_custody_signer_token"
    token_file.write_text("old", encoding="ascii")
    calls = []

    class Operator:
        endpoint = "https://127.0.0.1:18200"
        ca = tmp_path / "ca.crt"

    class Leaf:
        def __init__(self, endpoint, ca, token):
            assert (endpoint, ca, token) == (Operator.endpoint, Operator.ca, "old")

        def request(self, method, path):
            assert token_file.read_text(encoding="ascii") == "old"
            calls.append((method, path))

    monkeypatch.setattr(signer, "Bao", Leaf)
    signer.refresh_scoped_token(
        Operator(), token_file, "new",
        lambda path, value, mode: path.write_text(value, encoding="ascii"),
    )
    assert calls == [("POST", "auth/token/revoke-self")]
    assert token_file.read_text(encoding="ascii") == "new"


@pytest.mark.parametrize("new_lookup_valid", [False, True])
def test_expired_leaf_403_requires_live_operator_lookup_of_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, new_lookup_valid: bool,
) -> None:
    token_file = tmp_path / "selfhost_custody_signer_token"
    token_file.write_text("expired", encoding="ascii")

    class Operator:
        endpoint = "https://127.0.0.1:18200"
        ca = tmp_path / "ca.crt"

        def request(self, method, path, body):
            assert (method, path) == ("POST", "auth/token/lookup")
            if body["token"] == "expired":
                raise HTTPError(self.endpoint, 403, "denied", {}, None)
            assert body["token"] == "replacement"
            return {"data": {"ttl": 3599 if new_lookup_valid else 0}}

    class Leaf:
        def __init__(self, endpoint, ca, token):
            assert (endpoint, ca, token) == (Operator.endpoint, Operator.ca,
                                             "expired")

        def request(self, method, path):
            assert (method, path) == ("POST", "auth/token/revoke-self")
            raise HTTPError(Operator.endpoint, 403, "expired", {}, None)

    monkeypatch.setattr(signer, "Bao", Leaf)
    if new_lookup_valid:
        signer.refresh_scoped_token(
            Operator(), token_file, "replacement",
            lambda path, value, _mode: path.write_text(value, encoding="ascii"),
        )
        assert token_file.read_text(encoding="ascii") == "replacement"
        assert not token_file.with_name(token_file.name + ".new").exists()
    else:
        with pytest.raises(RuntimeError, match="operator recovery"):
            signer.refresh_scoped_token(
                Operator(), token_file, "replacement",
                lambda path, value, _mode: path.write_text(value, encoding="ascii"),
            )
        assert token_file.read_text(encoding="ascii") == "expired"
        assert token_file.with_name(token_file.name + ".new").read_text() == (
            "replacement"
        )


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
