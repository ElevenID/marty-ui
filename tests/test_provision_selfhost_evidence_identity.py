"""The evidence operator may only mint an orphan for one non-exportable signer."""

from pathlib import Path
import sys
from urllib.error import HTTPError

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import provision_selfhost_evidence_identity as evidence  # noqa: E402


def test_evidence_operator_acl_excludes_signing_and_backup_authority() -> None:
    acl = evidence.OPERATOR_ACL
    assert f'path "auth/token/create/{evidence.LEAF_ROLE}"' in acl
    assert 'path "auth/token/create"' not in acl
    assert 'path "transit/sign/' not in acl
    assert 'path "transit/export/' not in acl
    assert 'path "sys/storage/raft/snapshot"' not in acl
    assert 'path "sys/policies/acl/*"' not in acl
    assert 'path "auth/selfhost-renew/' not in acl


class FakeBao:
    def __init__(self, *, orphan: bool = True) -> None:
        self.orphan = orphan
        self.calls = []

    def request(self, method, path, body=None, *, token=None):
        self.calls.append((method, path, token))
        if path == f"auth/token/create/{evidence.LEAF_ROLE}":
            assert body == {
                "policies": [evidence.CUSTODY_SIGNER_POLICY],
                "no_default_policy": True, "renewable": False,
                "ttl": "1h", "explicit_max_ttl": "1h",
            }
            return {"auth": {"client_token": "leaf-token-01234567890123456789"}}
        if path == "auth/token/lookup":
            return {"data": {"policies": [evidence.CUSTODY_SIGNER_POLICY],
                             "orphan": self.orphan,
                             "path": f"auth/token/create/{evidence.LEAF_ROLE}",
                             "ttl": 3599}}
        if path == f"transit/sign/{evidence.CUSTODY_SIGNER}":
            assert body["key_version"] == 1
            return {"data": {"signature": "vault:v1:synthetic"}}
        if path == f"transit/export/signing-key/{evidence.CUSTODY_SIGNER}":
            raise HTTPError(path, 403, "denied", {}, None)
        if path == "auth/token/revoke-self":
            return {}
        raise AssertionError(path)


def test_mint_rejects_nonorphan_leaf_and_revokes_it(monkeypatch) -> None:
    monkeypatch.setattr(evidence, "checked_login", lambda *_: "operator-token")
    valid = FakeBao()
    assert evidence.mint(valid, Path("/unused")) == "leaf-token-01234567890123456789"
    assert ("POST", "auth/token/revoke-self", "leaf-token-01234567890123456789") \
        not in valid.calls
    wrong = FakeBao(orphan=False)
    with pytest.raises(ValueError, match="scope, lineage"):
        evidence.mint(wrong, Path("/unused"))
    assert ("POST", "auth/token/revoke-self", "leaf-token-01234567890123456789") \
        in wrong.calls


def test_failed_rotation_destroys_replacement_without_retiring_old(
    tmp_path: Path, monkeypatch,
) -> None:
    old = tmp_path / "evidence-identity"
    new = tmp_path / "evidence-identity-rotated"
    old.mkdir()
    new.mkdir()
    (old / evidence.ROLE_ID_FILE).write_text("role-id-01234567890123456789")
    (old / evidence.SECRET_ID_FILE).write_text("old-secret-01234567890123456789")
    monkeypatch.setattr(evidence, "private_empty_or_source", lambda path, **_: path)
    monkeypatch.setattr(evidence, "private_file", lambda path: path.read_text())
    monkeypatch.setattr(evidence, "checked_login",
                        lambda _bao, path: "old-operator-token" if path == old else
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
        evidence.rotate(bao, old, new)
    assert bao.destroyed == [("new-secret-01234567890123456789",
                              "old-operator-token")]
    assert list(new.iterdir()) == []
    assert (old / evidence.SECRET_ID_FILE).read_text() == (
        "old-secret-01234567890123456789"
    )
