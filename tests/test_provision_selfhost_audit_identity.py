"""The audit operator mints only an exact read-only orphan leaf."""

from pathlib import Path
import sys
from urllib.error import HTTPError

import pytest
from tests.test_selfhost_native_approle import approle_server as approle_server

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


def test_mint_rejects_nonorphan_leaf_and_revokes_it(approle_server) -> None:
    from tests.test_selfhost_native_approle import CONTEXT, LEAF
    state = approle_server
    bao, identity = state.prepare("audit")
    assert audit_identity.mint(bao, identity, CONTEXT["policy"], tuple(CONTEXT["paths"])) == LEAF
    state.overrides["POST", "auth/token/lookup"] = 200, {"data": {
        "policies": [audit_identity.POLICY], "orphan": False,
        "path": f"auth/token/create/{audit_identity.LEAF_ROLE}", "ttl": 3599}}
    with pytest.raises(RuntimeError):
        audit_identity.mint(bao, identity, CONTEXT["policy"], tuple(CONTEXT["paths"]))
    assert ("POST", "auth/token/revoke-self", None, LEAF) in state.seen


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
