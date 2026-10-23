"""The evidence operator may only mint an orphan for one non-exportable signer."""

from pathlib import Path
import sys

import pytest
from tests.test_selfhost_native_approle import approle_server as approle_server

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




def test_mint_rejects_nonorphan_leaf_and_revokes_it(approle_server) -> None:
    from tests.test_selfhost_native_approle import LEAF
    state = approle_server
    bao, identity = state.prepare("evidence")
    assert evidence.mint(bao, identity) == LEAF
    state.overrides["POST", "auth/token/lookup"] = 200, {"data": {
        "policies": [evidence.CUSTODY_SIGNER_POLICY], "orphan": False,
        "path": f"auth/token/create/{evidence.LEAF_ROLE}", "ttl": 3599}}
    with pytest.raises(RuntimeError):
        evidence.mint(bao, identity)
    assert ("POST", "auth/token/revoke-self", None, LEAF) in state.seen


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
