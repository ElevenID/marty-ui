"""Exercise scoped native transactions over real, private loopback HTTPS."""
from __future__ import annotations

import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import threading
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from selfhost_native_operator import approle_operation, approle_policy  # noqa: E402
from selfhost_openbao_client import CUSTODY_SIGNER_LEAF_ACL  # noqa: E402

ROLES = {
    "audit": ("selfhost-audit", "custody-auditor", "selfhost-audit-operator", "selfhost-audit-leaf", "selfhost-qualification-audit"),
    "evidence": ("selfhost-evidence", "custody-renewer", "selfhost-evidence-operator", "selfhost-evidence-leaf", "selfhost-qualification-custody-signer"),
    "renewal": ("selfhost-renew", "kms-renewer", "selfhost-kms-renewal", "selfhost-renew-leaf", None),
    "ca-rotation": ("selfhost-ca-rotation", "kms-ca-rotator", "selfhost-kms-ca-rotation", None, None),
    "snapshot": ("selfhost-snapshot", "raft-exporter", "selfhost-raft-snapshot-read", None, None),
    "snapshot-rotator": ("selfhost-snapshot", "raft-exporter-rotator", "selfhost-raft-snapshot-rotation", None, None),
}
NAMES = sorted(f"selfhost-test-policy-{i}" for i in range(21))
TOKEN = "synthetic-operator-token-0123456789"
LEAF = "synthetic-leaf-token-0123456789012"
CREDENTIAL = "synthetic-credential-012345678901"
AUDIT_ACL = 'path "transit/keys/test" { capabilities = ["read"] }\n'
CONTEXT = {"policy": AUDIT_ACL, "names": NAMES, "paths": ["transit/keys/test"]}


@pytest.fixture
def approle_server(tmp_path):
    if os.name != "posix":
        pytest.skip("native AppRole requires POSIX private identities")
    key, ca = tmp_path / "listener.key", tmp_path / "ca.crt"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", str(key), "-out", str(ca), "-days", "1", "-subj", "/CN=localhost",
                    "-addext", "subjectAltName=IP:127.0.0.1", "-addext", "basicConstraints=critical,CA:FALSE"],
                   check=True, capture_output=True)
    state = SimpleNamespace(role="audit", seen=[], overrides={}, deleted=[], boot=False,
                            policies={}, leaf_roles={}, role_records={}, mount_exists=False,
                            denial=403, cleanup=204, fail_path=None, minted=False)

    def dispatch(method, path, body, token):
        mount, role, policy, leaf_role, leaf_policy = ROLES[state.role]
        state.seen.append((method, path, body, token))
        if getattr(state, "hook", None):
            result = state.hook(method, path, body, token)
            if result is not None:
                return result
        token = getattr(state, "token_aliases", {}).get(token, token)
        if (method, path, token) in state.overrides:
            return state.overrides[method, path, token]
        if (method, path) in state.overrides:
            return state.overrides[method, path]
        if method == "DELETE":
            assert token == state.bao.token
            state.deleted.append(path)
            return state.cleanup, {}
        if path == state.fail_path:
            return 500, {}
        if path == "sys/auth":
            return 200, {"data": {f"{mount}/": {}} if state.mount_exists else {}}
        if path == f"sys/auth/{mount}":
            assert body == {"type": "approle"}
            state.mount_exists = True
            return 204, {}
        if path == f"auth/{mount}/login":
            assert token is None
            assert body == {"role_id": CREDENTIAL, "secret_id": CREDENTIAL}
            return 200, {"auth": {"client_token": TOKEN, "policies": [policy], "lease_duration": 3600}}
        if path.startswith("sys/policies/acl/"):
            name = path.rsplit("/", 1)[1]
            if method == "PUT":
                if token != state.bao.token:
                    return state.denial, {}
                state.policies[name] = body["policy"]
                return 204, {}
            if state.role == "snapshot" and token == TOKEN:
                return state.denial, {}
            if token == state.bao.token and name == policy and name not in state.policies:
                return 404, {}
            if name in state.policies:
                return 200, {"data": {"policy": state.policies[name]}}
            if name == leaf_policy:
                return 200, {"data": {"policy": AUDIT_ACL if state.role == "audit" else CUSTODY_SIGNER_LEAF_ACL}}
            if name == "selfhost-raft-snapshot-read" and state.role == "snapshot-rotator":
                return 200, {"data": {"policy": 'path "sys/storage/raft/snapshot" { capabilities = ["read"] }'}}
        if leaf_role and path == f"auth/token/roles/{leaf_role}":
            if method == "POST":
                state.leaf_roles[path] = body
                return 204, {}
            if state.boot and token == state.bao.token and path not in state.leaf_roles:
                return 404, {}
            return 200, {"data": {"allowed_policies": NAMES if state.role == "renewal" else [leaf_policy],
                                  "disallowed_policies": ["default", "root"], "orphan": True,
                                  "token_no_default_policy": True,
                                  "token_explicit_max_ttl": 28800 if state.role == "renewal" else 3600}}
        if path == f"auth/{mount}/role/{role}":
            if method == "POST":
                state.role_records[path] = body
                return 204, {}
            if state.boot and token == state.bao.token and path not in state.role_records:
                return 404, {}
            return 200, {"data": {"token_policies": [policy], "token_no_default_policy": True}}
        if path.endswith("/role-id") and token == state.bao.token:
            return 200, {"data": {"role_id": CREDENTIAL}}
        if path.endswith("/secret-id") and token == state.bao.token:
            return 200, {"data": {"secret_id": CREDENTIAL}}
        if path == "transit/keys/selfhost-qualification-custody-v1" and token == state.bao.token:
            return 200, {"data": {"type": "ed25519", "exportable": False, "allow_plaintext_backup": False,
                                  "latest_version": 1, "keys": {"1": {"public_key": base64.b64encode(bytes(range(32))).decode()}}}}
        if path == f"auth/token/create/{leaf_role}":
            assert token == TOKEN
            assert body == {"policies": [leaf_policy], "no_default_policy": True, "renewable": False,
                            "ttl": "1h", "explicit_max_ttl": "1h"}
            state.minted = True
            return 200, {"auth": {"client_token": LEAF}}
        if path == "auth/token/lookup":
            assert token == TOKEN and body == {"token": LEAF}
            return 200, {"data": {"policies": [leaf_policy], "orphan": True,
                                  "path": f"auth/token/create/{leaf_role}", "ttl": 3599}}
        if path == "sys/capabilities-self":
            assert token == LEAF
            return 200, {p: ["read"] if p == "transit/keys/test" else ["deny"] for p in body["paths"]}
        if path == "transit/sign/selfhost-qualification-custody-v1" and token == LEAF:
            assert body == {"key_version": 1, "input": base64.b64encode(b"evidence-custody-canary").decode()}
            return 200, {"data": {"signature": "vault:v1:synthetic"}}
        if path == "auth/token/revoke-self":
            assert token == LEAF
            return 204, {}
        assert token in (TOKEN, LEAF), (method, path, token)
        return state.denial, {}

    class Handler(BaseHTTPRequestHandler):
        def handle_request(self):
            length = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(length)) if length else None
            try:
                code, response = dispatch(self.command, self.path.removeprefix("/v1/"), body,
                                          self.headers.get("X-Vault-Token"))
                if code == 0:
                    self.close_connection = True
                    return
                data = json.dumps(response).encode() if code != 204 else b""
            except Exception as error:
                state.errors.append(error)
                code, data = 500, b"{}"
            self.send_response(code)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        do_GET = do_POST = do_PUT = do_DELETE = handle_request

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(ca, key)
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    state.bao = SimpleNamespace(endpoint=f"https://127.0.0.1:{server.server_port}", ca=ca,
                                token="synthetic-bootstrap-root-0123456789")
    state.errors = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    state.identity = tmp_path / "identity"
    state.identity.mkdir(mode=0o700)

    def prepare(role, *, bootstrap=False):
        state.role, state.boot = role, bootstrap
        state.mount_exists = role == "snapshot-rotator"
        state.policies = {} if bootstrap else {ROLES[role][2]: approle_policy(role, **CONTEXT)}
        if not bootstrap:
            for suffix in ("role-id", "secret-id"):
                path = state.identity / f"{role}-{suffix}"
                path.write_text(CREDENTIAL)
                path.chmod(0o600)
            if role in ("renewal", "ca-rotation"):
                path = state.identity / f"{role}-leaf-policies.json"
                path.write_text(json.dumps(NAMES))
                path.chmod(0o600)
        return state.bao, state.identity

    state.prepare = prepare
    try:
        yield state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not state.errors


@pytest.mark.parametrize("role", ROLES)
def test_all_scoped_logins(approle_server, role):
    bao, identity = approle_server.prepare(role)
    assert approle_operation(bao, "login", role, identity, **CONTEXT)["token"] == TOKEN
    assert all(token is None if path.endswith("/login") else token == TOKEN
               for _, path, _, token in approle_server.seen)


@pytest.mark.parametrize("role", ROLES)
@pytest.mark.parametrize("status", [200, 400, 401, 404, 500])
def test_every_role_requires_actual_403(approle_server, role, status):
    bao, identity = approle_server.prepare(role)
    approle_server.denial = status
    with pytest.raises(RuntimeError):
        approle_operation(bao, "login", role, identity, **CONTEXT)


@pytest.mark.parametrize("role", ROLES)
def test_all_bootstraps_persist_private_credentials(approle_server, role):
    bao, identity = approle_server.prepare(role, bootstrap=True)
    approle_operation(bao, "bootstrap", role, identity, **CONTEXT)
    assert not approle_server.deleted
    assert (identity / f"{role}-role-id").read_text().strip() == CREDENTIAL
    assert all(p.stat().st_mode & 0o777 == 0o600 for p in identity.iterdir())
    record = next(iter(approle_server.role_records.values()))
    assert record["token_no_default_policy"] is True
    assert record["token_policies"] == [ROLES[role][2]]
    assert record["token_max_ttl"] == ("1h" if role.startswith("snapshot") else "24h")


@pytest.mark.parametrize("role", ROLES)
@pytest.mark.parametrize("cleanup", [204, 404, 500])
def test_bootstrap_failure_exhausts_only_owned_cleanup(approle_server, role, cleanup):
    bao, identity = approle_server.prepare(role, bootstrap=True)
    mount, name, policy, leaf, _ = ROLES[role]
    approle_server.fail_path = f"auth/{mount}/role/{name}/secret-id"
    approle_server.cleanup = cleanup
    with pytest.raises(RuntimeError, match="cleanup is incomplete" if cleanup == 500 else "validation failed"):
        approle_operation(bao, "bootstrap", role, identity, **CONTEXT)
    expected = [f"auth/{mount}/role/{name}"]
    if role == "renewal":
        expected.append(f"auth/token/roles/{leaf}")
    expected.append(f"sys/policies/acl/{policy}")
    if role in ("audit", "evidence"):
        expected.append(f"auth/token/roles/{leaf}")
    if role != "snapshot-rotator":
        expected.append(f"sys/auth/{mount}")
    assert approle_server.deleted == expected
    assert not list(identity.iterdir())


@pytest.mark.parametrize("role", ["audit", "evidence"])
@pytest.mark.parametrize("defect", [None, "orphan", "policies", "path", "ttl", "revoke-failure"])
def test_leaf_scope_lineage_and_revocation(approle_server, role, defect):
    bao, identity = approle_server.prepare(role)
    if defect:
        data = {"policies": [ROLES[role][4]], "orphan": True,
                "path": f"auth/token/create/{ROLES[role][3]}", "ttl": 3599}
        field = "orphan" if defect == "revoke-failure" else defect
        data[field] = {"orphan": False, "policies": ["root"], "path": "auth/token/create", "ttl": 3600.0}[field]
        approle_server.overrides["POST", "auth/token/lookup"] = 200, {"data": data}
        if defect == "revoke-failure":
            approle_server.overrides["POST", "auth/token/revoke-self"] = 500, {}
        with pytest.raises(RuntimeError, match="cleanup is unconfirmed" if defect == "revoke-failure" else "validation failed"):
            approle_operation(bao, "mint", role, identity, **CONTEXT)
    else:
        assert approle_operation(bao, "mint", role, identity, **CONTEXT) == LEAF
    assert approle_server.minted
    revoked = [r for r in approle_server.seen if r[1] == "auth/token/revoke-self"]
    assert bool(revoked) == bool(defect)


@pytest.mark.parametrize("role", ROLES)
@pytest.mark.parametrize("field,value", [("policies", ["root"]), ("lease_duration", True),
                                        ("lease_duration", 3600.0), ("lease_duration", 0),
                                        ("lease_duration", 28801), ("client_token", "short")])
def test_all_roles_reject_login_scope_and_ttl_drift(approle_server, role, field, value):
    bao, identity = approle_server.prepare(role)
    auth = {"client_token": TOKEN, "policies": [ROLES[role][2]], "lease_duration": 3600}
    auth[field] = value
    approle_server.overrides["POST", f"auth/{ROLES[role][0]}/login"] = 200, {"auth": auth}
    with pytest.raises(RuntimeError):
        approle_operation(bao, "login", role, identity, **CONTEXT)
    assert len(approle_server.seen) == 1


@pytest.mark.parametrize("role", ROLES)
@pytest.mark.parametrize("stage", ["policy", "role", "post-login"])
def test_bootstrap_failure_at_each_stage_preserves_no_local_identity(approle_server, role, stage):
    if role == "renewal" and stage == "post-login":
        pytest.skip("renewal deliberately defers first login to its existing owner")
    bao, identity = approle_server.prepare(role, bootstrap=True)
    mount, name, policy, _, _ = ROLES[role]
    method, path = {"policy": ("PUT", f"sys/policies/acl/{policy}"),
                    "role": ("POST", f"auth/{mount}/role/{name}"),
                    "post-login": ("POST", f"auth/{mount}/login")}[stage]
    approle_server.overrides[method, path] = 500, {}
    with pytest.raises(RuntimeError):
        approle_operation(bao, "bootstrap", role, identity, **CONTEXT)
    assert approle_server.deleted
    assert not list(identity.iterdir())
    assert (f"sys/auth/{mount}" in approle_server.deleted) == (role != "snapshot-rotator")


@pytest.mark.parametrize("role", ROLES)
def test_bootstrap_does_not_erase_preexisting_authority(approle_server, role):
    bao, identity = approle_server.prepare(role, bootstrap=True)
    approle_server.policies[ROLES[role][2]] = "preexisting authority"
    with pytest.raises(RuntimeError):
        approle_operation(bao, "bootstrap", role, identity, **CONTEXT)
    assert not approle_server.deleted
    assert all(method == "GET" for method, _, _, _ in approle_server.seen)


@pytest.mark.parametrize("role", ["audit", "evidence"])
def test_leaf_canary_failure_revokes_created_leaf(approle_server, role):
    bao, identity = approle_server.prepare(role)
    if role == "audit":
        approle_server.overrides["POST", "sys/capabilities-self"] = 200, {"transit/keys/test": ["update"]}
    else:
        approle_server.overrides["POST", "transit/sign/selfhost-qualification-custody-v1", LEAF] = 200, {"data": {"signature": "vault:v2:wrong"}}
    with pytest.raises(RuntimeError):
        approle_operation(bao, "mint", role, identity, **CONTEXT)
    assert ("POST", "auth/token/revoke-self", None, LEAF) in approle_server.seen


def test_evidence_export_denial_must_be_403_after_mint(approle_server):
    bao, identity = approle_server.prepare("evidence")
    approle_server.overrides["GET", "transit/export/signing-key/selfhost-qualification-custody-v1"] = 404, {}
    with pytest.raises(RuntimeError):
        approle_operation(bao, "mint", "evidence", identity, **CONTEXT)
    assert ("POST", "auth/token/revoke-self", None, LEAF) in approle_server.seen


@pytest.mark.parametrize("role", ROLES)
def test_partial_credential_write_is_rolled_back(approle_server, role):
    bao, identity = approle_server.prepare(role, bootstrap=True)
    mount, name, *_ = ROLES[role]
    approle_server.overrides["POST", f"auth/{mount}/role/{name}/secret-id"] = 200, {
        "data": {"secret_id": CREDENTIAL + "\ninvalid"}}
    with pytest.raises(RuntimeError):
        approle_operation(bao, "bootstrap", role, identity, **CONTEXT)
    assert approle_server.deleted
    assert not list(identity.iterdir())


@pytest.mark.parametrize("role", ROLES)
@pytest.mark.parametrize("defect", ["public-mode", "symlink", "oversized"])
def test_private_credential_refusal_precedes_network(approle_server, role, defect):
    bao, identity = approle_server.prepare(role)
    path = identity / f"{role}-secret-id"
    if defect == "public-mode":
        path.chmod(0o644)
    elif defect == "symlink":
        target = identity / "target"
        path.rename(target)
        path.symlink_to(target)
    else:
        path.write_text("x" * (64 * 1024 + 1))
    with pytest.raises(RuntimeError):
        approle_operation(bao, "login", role, identity, **CONTEXT)
    assert not approle_server.seen
