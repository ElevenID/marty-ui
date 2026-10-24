"""Snapshot SecretID rotation cannot confer snapshot read to its rotator."""

from pathlib import Path
import sys


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
