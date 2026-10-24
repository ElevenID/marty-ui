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
