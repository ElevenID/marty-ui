"""A renewal login must stay inside the reviewed OpenBao authority boundary."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
from urllib.error import HTTPError

import pytest


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
def test_failed_bootstrap_removes_partial_remote_authority(tmp_path: Path,
                                                            monkeypatch: pytest.MonkeyPatch) -> None:
    current, output = tmp_path / "current", tmp_path / "identity"
    current.mkdir(mode=0o700)
    output.mkdir(mode=0o700)
    monkeypatch.setattr(identity, "existing_policy_names",
                        lambda *_: [f"selfhost-test-policy-{index}" for index in range(21)])

    class InterruptedBao:
        def __init__(self) -> None:
            self.deleted = []

        def request(self, method, path, body=None):
            if method == "GET" and path == "sys/auth":
                return {"data": {}}
            if method == "GET":
                raise HTTPError(path, 404, "absent", None, None)
            if method == "DELETE":
                self.deleted.append(path)
                return {}
            if path == "auth/token/roles/selfhost-renew-leaf":
                raise RuntimeError("controlled role creation failure")
            return {}

    bao = InterruptedBao()
    with pytest.raises(RuntimeError, match="controlled role creation failure"):
        identity.bootstrap(bao, current, output)
    assert "auth/token/roles/selfhost-renew-leaf" in bao.deleted
    assert "sys/auth/selfhost-renew" in bao.deleted
    assert list(output.iterdir()) == []


@pytest.mark.skipif(os.name != "posix", reason="POSIX private identity contract")
def test_rotation_persists_valid_replacement_before_revoking_old(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    old, new = tmp_path / "old", tmp_path / "new"
    old.mkdir(mode=0o700)
    new.mkdir(mode=0o700)
    names = sorted(f"selfhost-test-policy-{index}" for index in range(21))
    monkeypatch.setattr(identity, "checked_login",
                        lambda *_: ("role-id", "old-secret-id", names, "old-token"))
    monkeypatch.setattr(identity, "verify_denials", lambda *_: None)

    class RotationBao:
        def __init__(self) -> None:
            self.revoked = []

        def request(self, method, path, body=None, *, token=None, authenticate=True):
            if path.endswith("/secret-id"):
                assert token == "old-token"
                return {"data": {"secret_id": "replacement-secret-id-0123456789"}}
            if path.endswith("/login"):
                assert authenticate is False
                if body["secret_id"] == "old-secret-id":
                    assert self.revoked
                    raise HTTPError(path, 400, "invalid credential", None, None)
                assert body == {"role_id": "role-id",
                                "secret_id": "replacement-secret-id-0123456789"}
                return {"auth": {"client_token": "new-token-0123456789012345",
                                 "policies": [identity.OPERATOR_POLICY],
                                 "lease_duration": 7200}}
            if path.endswith("/secret-id/destroy"):
                assert all((new / name).is_file() for name in (
                    identity.ROLE_ID_FILE, identity.SECRET_ID_FILE,
                    identity.POLICY_NAMES_FILE,
                ))
                self.revoked.append((body["secret_id"], token))
                return {}
            raise AssertionError(path)

    bao = RotationBao()
    identity.rotate(bao, old, new)
    assert bao.revoked == [("old-secret-id", "new-token-0123456789012345")]
    assert (new / identity.SECRET_ID_FILE).read_text().strip() == (
        "replacement-secret-id-0123456789"
    )
    assert all((new / name).stat().st_mode & 0o777 == 0o600 for name in (
        identity.ROLE_ID_FILE, identity.SECRET_ID_FILE, identity.POLICY_NAMES_FILE,
    ))


@pytest.mark.skipif(os.name != "posix", reason="POSIX private identity contract")
def test_rotation_rejects_bad_replacement_and_destroys_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    old, new = tmp_path / "old", tmp_path / "new"
    old.mkdir(mode=0o700)
    new.mkdir(mode=0o700)
    monkeypatch.setattr(identity, "checked_login",
                        lambda *_: ("role-id", "old-secret-id", [], "old-token"))

    class BadBao:
        def __init__(self) -> None:
            self.revoked = []

        def request(self, method, path, body=None, *, token=None, authenticate=True):
            if path.endswith("/secret-id"):
                return {"data": {"secret_id": "replacement-secret-id-0123456789"}}
            if path.endswith("/login"):
                return {"auth": {"client_token": "new-token-0123456789012345",
                                 "policies": ["root"], "lease_duration": 7200}}
            if path.endswith("/secret-id/destroy"):
                self.revoked.append((body["secret_id"], token))
                return {}
            raise AssertionError(path)

    bao = BadBao()
    with pytest.raises(ValueError, match="replacement AppRole login"):
        identity.rotate(bao, old, new)
    assert bao.revoked == [("replacement-secret-id-0123456789", "old-token")]
    assert list(new.iterdir()) == []


@pytest.mark.skipif(os.name != "posix", reason="POSIX private identity contract")
def test_retirement_finishes_an_interrupted_rotation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    old, new = tmp_path / "old", tmp_path / "new"
    old.mkdir(mode=0o700)
    new.mkdir(mode=0o700)
    identity.write_private(old / identity.ROLE_ID_FILE, "role-id")
    identity.write_private(old / identity.SECRET_ID_FILE, "old-secret-id")
    monkeypatch.setattr(identity, "checked_login",
                        lambda *_: ("role-id", "new-secret-id", [], "new-token"))

    class RetirementBao:
        def __init__(self) -> None:
            self.destroyed = False

        def request(self, method, path, body=None, *, token=None, authenticate=True):
            if path.endswith("/destroy"):
                assert body == {"secret_id": "old-secret-id"}
                assert token == "new-token"
                self.destroyed = True
                return {}
            if path.endswith("/login"):
                assert self.destroyed and authenticate is False
                raise HTTPError(path, 400, "invalid credential", None, None)
            raise AssertionError(path)

    bao = RetirementBao()
    identity.retire(bao, new, old)
    assert bao.destroyed
