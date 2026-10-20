"""The audit operator mints only an exact read-only orphan leaf."""

from pathlib import Path
import sys
from urllib.error import HTTPError

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import provision_selfhost_audit_identity as audit_identity  # noqa: E402


def test_audit_operator_acl_excludes_signing_and_snapshot_authority() -> None:
    acl = audit_identity.OPERATOR_ACL
    assert f'path "auth/token/create/{audit_identity.LEAF_ROLE}"' in acl
    assert 'path "auth/token/create"' not in acl
    assert 'path "transit/sign/' not in acl
    assert 'path "transit/export/' not in acl
    assert 'path "sys/storage/raft/snapshot"' not in acl
    assert 'path "sys/policies/acl/*"' not in acl


def test_mint_rejects_nonorphan_leaf_and_revokes_it(monkeypatch) -> None:
    policy = 'path "transit/keys/test" { capabilities = ["read"] }\n'
    paths = ("transit/keys/test",)
    monkeypatch.setattr(audit_identity, "checked_login", lambda *_: "operator-token")

    class FakeBao:
        def __init__(self, orphan: bool):
            self.orphan = orphan
            self.calls = []

        def request(self, method, path, body=None, *, token=None):
            self.calls.append((method, path, token))
            if path == f"auth/token/create/{audit_identity.LEAF_ROLE}":
                assert body["policies"] == [audit_identity.POLICY]
                return {"auth": {"client_token": "leaf-token-01234567890123456789"}}
            if path == "auth/token/lookup":
                return {"data": {"policies": [audit_identity.POLICY],
                                 "orphan": self.orphan,
                                 "path": f"auth/token/create/{audit_identity.LEAF_ROLE}",
                                 "ttl": 3599}}
            if path == "sys/capabilities-self":
                return {"transit/keys/test": ["read"],
                        **{item: ["deny"] for item in body["paths"] if item not in paths}}
            if path == "auth/token/revoke-self":
                return {}
            raise AssertionError(path)

    good = FakeBao(True)
    assert audit_identity.mint(good, Path("/unused"), policy, paths) == (
        "leaf-token-01234567890123456789"
    )
    wrong = FakeBao(False)
    with pytest.raises(ValueError, match="scope, lineage"):
        audit_identity.mint(wrong, Path("/unused"), policy, paths)
    assert ("POST", "auth/token/revoke-self", "leaf-token-01234567890123456789") \
        in wrong.calls


def test_failed_rotation_preserves_old_secret_and_destroys_replacement(
    tmp_path: Path, monkeypatch,
) -> None:
    old = tmp_path / "audit-identity"
    new = tmp_path / "audit-identity-rotated"
    old.mkdir()
    new.mkdir()
    (old / audit_identity.ROLE_ID_FILE).write_text("role-id-01234567890123456789")
    (old / audit_identity.SECRET_ID_FILE).write_text("old-secret-01234567890123456789")
    monkeypatch.setattr(audit_identity, "private_empty_or_source", lambda path, **_: path)
    monkeypatch.setattr(audit_identity, "private_file", lambda path: path.read_text())
    monkeypatch.setattr(audit_identity, "checked_login",
                        lambda _bao, path, _policy: "old-operator-token" if path == old else
                        (_ for _ in ()).throw(ValueError("replacement login rejected")))

    class RotationBao:
        def __init__(self):
            self.destroyed = []

        def request(self, method, path, body=None, *, token=None):
            if path.endswith("/secret-id"):
                assert token == "old-operator-token"
                return {"data": {"secret_id": "new-secret-01234567890123456789"}}
            if path.endswith("/secret-id/destroy"):
                self.destroyed.append((body["secret_id"], token))
                return {}
            raise AssertionError(path)

    bao = RotationBao()
    with pytest.raises(ValueError, match="replacement login rejected"):
        audit_identity.rotate(bao, old, new, "policy")
    assert bao.destroyed == [("new-secret-01234567890123456789",
                              "old-operator-token")]
    assert list(new.iterdir()) == []
    assert (old / audit_identity.SECRET_ID_FILE).read_text() == (
        "old-secret-01234567890123456789"
    )


def test_revoked_secret_id_must_fail_login() -> None:
    class ActiveBao:
        def request(self, *_args, **_kwargs):
            return {"auth": {"client_token": "still-live"}}

    with pytest.raises(ValueError, match="remains usable"):
        audit_identity.require_revoked(ActiveBao(), "role", "secret")

    class RevokedBao:
        def request(self, *_args, **_kwargs):
            raise HTTPError("https://127.0.0.1", 403, "denied", {}, None)

    audit_identity.require_revoked(RevokedBao(), "role", "secret")
