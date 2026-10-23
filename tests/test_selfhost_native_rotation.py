"""Qualify rotation and refresh recovery through the real native HTTPS boundary."""
from __future__ import annotations

import json
import importlib
import os
from pathlib import Path
import sys

import pytest

from tests.test_selfhost_native_approle import (
    CREDENTIAL, CONTEXT, NAMES, ROLES, TOKEN,
    approle_server as approle_server,
)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from selfhost_native_operator import OperatorCleanupError, approle_operation, approle_policy  # noqa: E402
from provision_selfhost_custody_signer import refresh_scoped_token  # noqa: E402

NEW_SECRET = "replacement-secret-id-012345678901"
NEW_TOKEN = "replacement-operator-token-0123456789"
MANAGER = "snapshot-manager-token-012345678901"
PREFIX = {"audit": "audit-identity", "evidence": "evidence-identity",
          "renewal": "renewal-identity", "snapshot": "snapshot-identity",
          "snapshot-rotator": "snapshot-rotator-identity"}


@pytest.fixture
def rotation(approle_server):
    state = approle_server

    def prepare(role, failure=None):
        bao, old = state.prepare(role)
        old = old.rename(old.with_name(PREFIX[role]))
        output = old.with_name(PREFIX[role] + "-next")
        output.mkdir(mode=0o700)
        manager = old.with_name("snapshot-rotator-identity-manager")
        manager.mkdir(mode=0o700)
        for suffix in ("role-id", "secret-id"):
            p = manager / f"snapshot-rotator-{suffix}"
            p.write_text(CREDENTIAL)
            p.chmod(0o600)
        state.output, state.old, state.retired = output, old, False
        state.destroyed = []
        state.token_aliases = {NEW_TOKEN: TOKEN}
        mount, name, policy, *_ = ROLES[role]
        path = f"auth/{mount}/role/{name}/secret-id"

        def hook(method, route, body, token):
            if route == path:
                assert method == "POST"
                assert token == (MANAGER if role == "snapshot" else TOKEN)
                assert not list(output.iterdir())
                if failure in ("create-response", "create-lost-response"):
                    return (503 if failure == "create-response" else 0), {}
                if failure in ("role-write", "secret-write", "receipt-write"):
                    field = {"role-write": f"{role}-role-id", "secret-write": f"{role}-secret-id",
                             "receipt-write": "renewal-leaf-policies.json"}[failure]
                    (output / field).mkdir()
                return 200, {"data": {"secret_id": NEW_SECRET}}
            if route == path + "/destroy":
                assert method == "POST"
                state.destroyed.append((body["secret_id"], token))
                if body["secret_id"] == CREDENTIAL:
                    assert token == (MANAGER if role == "snapshot" else NEW_TOKEN)
                    assert (output / f"{role}-secret-id").read_text().strip() == NEW_SECRET
                    if role == "renewal":
                        assert json.loads((output / "renewal-leaf-policies.json").read_text()) == NAMES
                    if failure == "old-destroy":
                        return 503, {}
                    state.retired = True
                else:
                    assert body["secret_id"] == NEW_SECRET
                    assert token == (MANAGER if role == "snapshot" else TOKEN)
                    if failure == "rollback":
                        return 503, {}
                return 204, {}
            if route == f"auth/{mount}/login" and body["secret_id"] == CREDENTIAL:
                if state.retired:
                    return (200 if failure == "old-still-usable" else 400), {}
                return 200, {"auth": {"client_token": TOKEN, "policies": [policy], "lease_duration": 3600}}
            if route == f"auth/{mount}/login" and body["secret_id"] == NEW_SECRET:
                if role == "renewal" and failure not in ("role-write", "secret-write", "receipt-write"):
                    assert not list(output.iterdir())
                return 200, {"auth": {"client_token": NEW_TOKEN,
                    "policies": ["root"] if failure in ("scope", "rollback") else [policy],
                    "lease_duration": {"ttl-low": 0, "ttl-high": 28801, "ttl-type": 3600.0}.get(failure, 3600)}}
            if token == NEW_TOKEN and failure == "denial" and route in (
                "auth/token/create", "transit/keys/foreign-snapshot-probe"):
                return 400, {}
            if role == "snapshot":
                if route == "auth/selfhost-snapshot/login" and body["role_id"] == CREDENTIAL:
                    return 200, {"auth": {"client_token": MANAGER,
                        "policies": [ROLES["snapshot-rotator"][2]], "lease_duration": 3600}}
                if token == MANAGER:
                    if route == "auth/selfhost-snapshot/role/raft-exporter-rotator":
                        return 200, {"data": {"token_policies": [ROLES["snapshot-rotator"][2]],
                                             "token_no_default_policy": True}}
                    if route.startswith("sys/policies/acl/"):
                        which = "snapshot-rotator" if route.endswith(ROLES["snapshot-rotator"][2]) else "snapshot"
                        return 200, {"data": {"policy": approle_policy(which)}}
                    return 403, {}
            return None

        # Distinguish the reader and manager RoleIDs on their shared auth mount.
        if role == "snapshot":
            p = manager / "snapshot-rotator-role-id"
            p.write_text("manager-role-id-0123456789012345")
            original_hook = hook

            def hook(method, route, body, token):
                if route == "auth/selfhost-snapshot/login" and body["role_id"].startswith("manager-"):
                    return 200, {"auth": {"client_token": MANAGER,
                        "policies": [ROLES["snapshot-rotator"][2]], "lease_duration": 3600}}
                return original_hook(method, route, body, token)

        state.hook = hook
        context = {**CONTEXT, "output": str(output)}
        if role == "snapshot":
            context["manager_identity"] = str(manager)
        return bao, old, output, context

    state.rotation = prepare
    return state


@pytest.mark.parametrize("role", PREFIX)
def test_rotation_commits_then_proves_old_secret_revoked(rotation, role):
    bao, old, output, context = rotation.rotation(role)
    module = importlib.import_module("provision_selfhost_" + (
        "snapshot_rotator" if role.startswith("snapshot") else f"{role}_identity"))
    if role == "audit":
        module.rotate(bao, old, output, CONTEXT["policy"])
    elif role == "snapshot":
        module.rotate_reader(bao, old, output, Path(context["manager_identity"]))
    elif role == "snapshot-rotator":
        module.rotate_rotator(bao, old, output)
    else:
        module.rotate(bao, old, output)
    assert rotation.destroyed == [(CREDENTIAL, MANAGER if role == "snapshot" else NEW_TOKEN)]
    assert (old / f"{role}-secret-id").read_text() == CREDENTIAL
    assert (output / f"{role}-secret-id").read_text().strip() == NEW_SECRET
    assert all(p.stat().st_mode & 0o777 == 0o600 for p in output.iterdir())
    assert not rotation.errors


@pytest.mark.parametrize("role", PREFIX)
@pytest.mark.parametrize("failure", ["scope", "ttl-low", "ttl-high", "ttl-type", "denial", "rollback",
                                    "old-destroy", "old-still-usable", "role-write", "secret-write"])
def test_rotation_failure_preserves_authority(rotation, role, failure):
    bao, old, output, context = rotation.rotation(role, failure)
    error = OperatorCleanupError if failure in (
        "rollback", "old-destroy", "old-still-usable", "role-write", "secret-write") else RuntimeError
    with pytest.raises(error):
        approle_operation(bao, "rotate", role, old, **context)
    assert (old / f"{role}-secret-id").read_text() == CREDENTIAL
    if failure in ("old-destroy", "old-still-usable"):
        assert rotation.destroyed == [(CREDENTIAL, MANAGER if role == "snapshot" else NEW_TOKEN)]
        assert (output / f"{role}-secret-id").read_text().strip() == NEW_SECRET
    else:
        assert rotation.destroyed == [(NEW_SECRET, MANAGER if role == "snapshot" else TOKEN)]
        assert not any(p.is_file() for p in output.iterdir())
    assert not rotation.errors


def test_renewal_receipt_write_failure_still_revokes_replacement(rotation):
    bao, old, output, context = rotation.rotation("renewal", "receipt-write")
    with pytest.raises(OperatorCleanupError):
        approle_operation(bao, "rotate", "renewal", old, **context)
    assert rotation.destroyed == [(NEW_SECRET, TOKEN)]
    assert not any(p.is_file() for p in output.iterdir())


@pytest.mark.parametrize("role", PREFIX)
@pytest.mark.parametrize("failure", ["create-response", "create-lost-response"])
def test_uncertain_creation_reports_recovery_without_retiring_old(rotation, role, failure):
    bao, old, output, context = rotation.rotation(role, failure)
    with pytest.raises(OperatorCleanupError, match="operator recovery"):
        approle_operation(bao, "rotate", role, old, **context)
    assert rotation.destroyed == [] and not list(output.iterdir())
    assert (old / f"{role}-secret-id").read_text() == CREDENTIAL


def test_native_rotation_recovery_failure_reaches_public_cli(rotation, monkeypatch, capsys):
    from provision_selfhost_evidence_identity import main
    bao, old, output, _ = rotation.rotation("evidence", "old-destroy")
    monkeypatch.setattr(sys, "argv", ["evidence", "--mode", "rotate", "--bao-addr", bao.endpoint,
                                     "--bao-ca", str(bao.ca), "--identity", str(old),
                                     "--output", str(output)])
    assert main() == 3
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "AppRole rotation requires operator recovery\n"
    assert (output / "evidence-secret-id").read_text().strip() == NEW_SECRET


@pytest.mark.parametrize("role", PREFIX)
def test_retirement_finishes_interrupted_rotation(rotation, role):
    bao, old, output, context = rotation.rotation(role, "old-destroy")
    with pytest.raises(OperatorCleanupError):
        approle_operation(bao, "rotate", role, old, **context)
    # The recovery operation logs in using the replacement and then retires old.
    previous = rotation.hook

    def hook(method, path, body, token):
        if path.endswith("/login") and body["secret_id"] == NEW_SECRET:
            return 200, {"auth": {"client_token": NEW_TOKEN, "policies": [ROLES[role][2]], "lease_duration": 3600}}
        if path.endswith("/destroy"):
            assert body == {"secret_id": CREDENTIAL}
            assert token == (MANAGER if role == "snapshot" else NEW_TOKEN)
            rotation.retired = True
            return 204, {}
        return previous(method, path, body, token)

    rotation.hook = hook
    context.pop("output")
    approle_operation(bao, "retire", role, output, retired=str(old), **context)
    assert rotation.retired
    assert (output / f"{role}-secret-id").read_text().strip() == NEW_SECRET
    assert not rotation.errors


@pytest.mark.parametrize("revoke,old_lookup,new_ttl,success", [
    (204, 200, 3599, True), (400, 400, 3599, True), (403, 404, 3599, True),
    (403, 403, 3599, True), (403, 403, 0, False), (403, 403, 1.0, False),
    (403, 403, True, False), (403, 200, 3599, False), (503, 404, 3599, False),
    (400, 503, 3599, False), (0, 404, 3599, False),
])
def test_refresh_retains_pending_token_until_revocation_proven(
    approle_server, revoke, old_lookup, new_ttl, success,
):
    state = approle_server
    state.bao.token = TOKEN
    token_file = state.identity / "custody.token"
    token_file.write_text("expired")
    token_file.chmod(0o400)
    pending = token_file.with_name(token_file.name + ".new")

    def hook(method, path, body, token):
        assert pending.read_text() == NEW_TOKEN
        assert token_file.read_text() == "expired"
        if path == "auth/token/revoke-self":
            assert token == "expired"
            return revoke, {}
        assert path == "auth/token/lookup" and token == TOKEN
        if body == {"token": "expired"}:
            return old_lookup, {}
        assert body == {"token": NEW_TOKEN}
        return 200, {"data": {"ttl": new_ttl}}

    state.hook = hook

    def write(path, value, mode):
        with path.open("x") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        path.chmod(mode)

    if success:
        refresh_scoped_token(state.bao, token_file, NEW_TOKEN, write)
        assert token_file.read_text() == NEW_TOKEN and not pending.exists()
    else:
        with pytest.raises(OperatorCleanupError, match="operator recovery"):
            refresh_scoped_token(state.bao, token_file, NEW_TOKEN, write)
        assert token_file.read_text() == "expired" and pending.read_text() == NEW_TOKEN
    assert not state.errors
