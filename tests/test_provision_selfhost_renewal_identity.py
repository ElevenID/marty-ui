"""A renewal login must stay inside the reviewed OpenBao authority boundary."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
from urllib.error import HTTPError

import pytest
from tests.test_selfhost_native_approle import approle_server as approle_server


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import provision_selfhost_renewal_identity as identity  # noqa: E402
from selfhost_openbao_client import require_renewal_authority  # noqa: E402

operator_acl = identity.operator_acl
verify_denials = identity.verify_denials


def test_operator_acl_has_exact_signers_and_only_named_leaf_issuance() -> None:
    policies = [f"selfhost-test-policy-{index}" for index in range(21)]
    acl = operator_acl(policies)
    assert 'path "auth/token/create/selfhost-renew-leaf"' in acl
    assert 'path "auth/token/roles/selfhost-renew-leaf"' in acl
    assert 'path "sys/capabilities" { capabilities = ["update"] }' in acl
    assert 'path "sys/policies/acl/selfhost-kms-renewal" { capabilities = ["read"] }' in acl
    assert 'path "sys/capabilities-self"' not in acl
    assert 'path "auth/selfhost-renew/role/kms-renewer/secret-id"' in acl
    assert 'path "auth/selfhost-renew/role/kms-renewer/secret-id/destroy"' in acl
    assert 'path "auth/token/create"' not in acl
    assert 'path "sys/policies/acl/*"' not in acl
    assert 'path "transit/export/' not in acl
    assert 'path "sys/mounts/*"' not in acl
    assert acl.count('path "sys/policies/acl/selfhost-test-policy-') == 21
    bundle = json.loads((Path(__file__).resolve().parents[1] /
                         "deploy-config/bundles/selfhost.json").read_text(encoding="utf-8"))
    assert "scripts/provision_selfhost_renewal_identity.py" in bundle["assets"]


def test_renewal_operator_policy_must_match_reviewed_acl() -> None:
    names = [f"selfhost-test-policy-{index}" for index in range(21)]

    class PolicyBao:
        def __init__(self, policy: str) -> None:
            self.policy = policy

        def request(self, method, path, body=None, *, token=None):
            assert (method, path, token) == (
                "GET", "sys/policies/acl/selfhost-kms-renewal", "scoped-token")
            return {"data": {"policy": self.policy}}

    acl = operator_acl(names)
    identity.verified_operator_policy(PolicyBao(acl), "scoped-token", names)
    with pytest.raises(ValueError, match="drifted"):
        identity.verified_operator_policy(PolicyBao(acl + "\npath \"sys/*\" {}"),
                                          "scoped-token", names)


class FakeBao:
    def __init__(self, *, policy: str = "selfhost-kms-renewal", denied: int = 403) -> None:
        self.token = "operator-token"
        self.policy = policy
        self.denied = denied
        self.calls = []

    def request(self, method, path, body=None, *, token=None):
        self.calls.append((method, path, token))
        if path == "auth/token/lookup":
            return {"data": {"policies": [self.policy], "ttl": 7200,
                             "path": "auth/selfhost-renew/login"}}
        raise HTTPError(path, self.denied, "denied", None, None)


def test_renewal_authority_rejects_root_and_denials_must_be_real() -> None:
    require_renewal_authority(FakeBao())
    with pytest.raises(ValueError, match="scoped AppRole"):
        require_renewal_authority(FakeBao(policy="root"))
    scoped = FakeBao()
    verify_denials(scoped, scoped.token)
    assert len(scoped.calls) == 4
    with pytest.raises(ValueError, match="exceeded"):
        verify_denials(FakeBao(denied=400), "operator-token")


@pytest.mark.skipif(os.name != "posix", reason="POSIX private bootstrap contract")
def test_failed_bootstrap_removes_partial_remote_authority(approle_server, monkeypatch) -> None:
    from tests.test_selfhost_native_approle import NAMES
    state = approle_server
    bao, output = state.prepare("renewal", bootstrap=True)
    current = output.parent / "current"
    current.mkdir(mode=0o700)
    monkeypatch.setattr(identity, "existing_policy_names", lambda *_: NAMES)
    state.overrides["POST", "auth/token/roles/selfhost-renew-leaf"] = 500, {}
    with pytest.raises(RuntimeError):
        identity.bootstrap(bao, current, output)
    assert "auth/token/roles/selfhost-renew-leaf" in state.deleted
    assert "sys/auth/selfhost-renew" in state.deleted
    assert not list(output.iterdir())
