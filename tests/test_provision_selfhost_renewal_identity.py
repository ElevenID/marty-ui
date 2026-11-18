"""A renewal login must stay inside the reviewed OpenBao authority boundary."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys

import pytest
from tests.test_selfhost_native_approle import approle_server as approle_server


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import provision_selfhost_renewal_identity as identity  # noqa: E402

operator_acl = identity.operator_acl


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


@pytest.mark.parametrize("drift", [False, True])
def test_native_renewal_login_keeps_exact_policy_and_real_denials(approle_server, drift):
    state = approle_server
    bao, private = state.prepare("renewal")
    if drift:
        state.policies["selfhost-kms-renewal"] += '\npath "sys/*" {}'
        with pytest.raises(RuntimeError):
            identity.checked_login(bao, private)
        return
    assert identity.checked_login(bao, private)[-1]
    probes = {path for _, path, _, _ in state.seen}
    assert {"transit/keys/foreign-keycloak-selfhost", "auth/token/create",
            "sys/policies/acl/selfhost-renewal-forbidden-probe",
            "sys/mounts/selfhost-renewal-forbidden-probe"} <= probes


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
