"""Snapshot SecretID rotation cannot confer snapshot read to its rotator."""

from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import provision_selfhost_snapshot_rotator as rotator  # noqa: E402


def test_rotator_acl_excludes_snapshot_read_and_other_custody() -> None:
    acl = rotator.ACL
    assert f'path "{rotator.READER_ROTATION.secret_id_path}"' in acl
    assert f'path "{rotator.ROTATOR_ROTATION.secret_id_path}"' in acl
    assert 'path "sys/storage/raft/snapshot"' not in acl
    assert 'path "transit/' not in acl
    assert 'path "auth/token/create"' not in acl
    assert 'path "sys/policies/acl/*"' not in acl


def test_failed_reader_rotation_destroys_new_secret_and_preserves_old(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    old = tmp_path / "snapshot-identity"
    new = tmp_path / "snapshot-identity-next"
    manager = tmp_path / "snapshot-rotator-identity"
    for path in (old, new, manager):
        path.mkdir()
    (old / rotator.READER_ROLE_ID_FILE).write_text("reader-role-01234567890123456789")
    (old / rotator.READER_SECRET_ID_FILE).write_text("reader-old-01234567890123456789")
    monkeypatch.setattr(rotator, "private_empty_or_source", lambda path, **_: path)
    monkeypatch.setattr(rotator, "private_file", lambda path: path.read_text())
    monkeypatch.setattr(rotator, "reader_login",
                        lambda _bao, path: "reader-token" if path == old else
                        (_ for _ in ()).throw(ValueError("replacement login rejected")))
    monkeypatch.setattr(rotator, "checked_login", lambda _bao, path: (
        "rotator-token" if path == manager else pytest.fail("wrong manager")
    ))

    class FakeBao:
        def __init__(self):
            self.destroyed = []

        def request(self, method, path, body=None, *, token=None):
            if path == rotator.READER_ROTATION.secret_id_path:
                assert token == "rotator-token"
                return {"data": {"secret_id": "reader-new-01234567890123456789"}}
            if path == rotator.READER_ROTATION.secret_id_path + "/destroy":
                self.destroyed.append((body["secret_id"], token))
                return {}
            raise AssertionError(path)

    bao = FakeBao()
    with pytest.raises(ValueError, match="replacement login rejected"):
        rotator.rotate_reader(bao, old, new, manager)
    assert bao.destroyed == [("reader-new-01234567890123456789",
                              "rotator-token")]
    assert list(new.iterdir()) == []
    assert (old / rotator.READER_SECRET_ID_FILE).read_text() == (
        "reader-old-01234567890123456789"
    )
