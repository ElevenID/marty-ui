"""Closed Keycloak policies and token qualification over actual loopback HTTPS."""
from types import SimpleNamespace
import json
from pathlib import Path
import subprocess

import pytest

from scripts.selfhost_native_operator import keycloak_policy, keycloak_token, OperatorCleanupError
from tests.native_operator_https import https_json_server

OPERATOR = "synthetic-keycloak-operator-0123456789"
LEAF = "synthetic-keycloak-leaf-01234567890123"
SCOPES = [{"scope": "signing"}, *({"scope": "jwe", "realm": realm, "purpose": purpose,
                                  "version": "v1-synthetic"}
                                 for realm in ("master", "11id") for purpose in ("cookie", "ciba"))]


def expected(context):
    if context["scope"] == "signing":
        policy = "".join(
            f'path "transit/keys/keycloak-{realm}-rs256" {{ capabilities = ["read"] }}\n'
            f'path "transit/sign/keycloak-{realm}-rs256" {{ capabilities = ["update"] }}\n'
            f'path "transit/keys/keycloak-{realm}-hs512" {{ capabilities = ["read"] }}\n'
            f'path "transit/hmac/keycloak-{realm}-hs512/sha2-512" {{ capabilities = ["update"] }}\n'
            f'path "transit/verify/keycloak-{realm}-hs512/sha2-512" {{ capabilities = ["update"] }}\n'
            for realm in ("master", "11id"))
        return policy, "selfhost-keycloak-sign-", None
    realm, purpose, version = (context[n] for n in ("realm", "purpose", "version"))
    path = f"didcomm/keycloak/keys/{realm}/{purpose}"
    return (f'path "{path}" {{ capabilities = ["read"] }}\n'
            f'path "didcomm/keycloak/jwe/encode/{realm}/{purpose}/{version}" {{ capabilities = ["update"] }}\n'
            f'path "didcomm/keycloak/jwe/decode/{realm}/{purpose}/{version}" {{ capabilities = ["update"] }}\n',
            f"selfhost-keycloak-{realm}-{purpose}-", path)


@pytest.fixture
def keycloak_server(tmp_path):
    state = SimpleNamespace(context=SCOPES[0], failure=None, renew=True, seen=[], errors=[])

    def dispatch(method, path, body, token):
        state.seen.append((method, path, body, token))
        if getattr(state, "producer", None):
            response = state.producer(method, path, body, token)
            if response is not None:
                return response
        leaf_value = (LEAF + str(SCOPES.index(state.context))
                      if getattr(state, "batch", False) and not getattr(state, "duplicate_tokens", False) else LEAF)
        policy, prefix, key_path = expected(state.context)
        name = prefix + ("old" if state.renew else "012345abcdef")
        if path == "sys/policies/acl":
            assert method == "LIST" and token == OPERATOR
            names = [name, "unrelated", prefix + "bad/name"]
            if state.failure == "missing-policy":
                names = ["unrelated"]
            elif state.failure == "duplicate-policy":
                names += [prefix + "second"]
            elif state.failure == "invalid-inventory":
                names += [False]
            return 200, {"data": {"keys": names}}
        if path.startswith("sys/policies/acl/"):
            assert token == OPERATOR
            if method == "PUT":
                assert not state.renew and body == {"policy": policy}
                return 204, {}
            assert state.renew and method == "GET"
            return 200, {"data": {"policy": policy + ("changed" if state.failure == "changed-policy" else "")}}
        if path in ("auth/token/create", "auth/token/create/selfhost-renew-leaf"):
            assert method == "POST" and token == OPERATOR
            assert path.endswith("/selfhost-renew-leaf") is state.renew
            assert body == {"policies": [name], "no_default_policy": True, "ttl": "8h"}
            if state.failure in ("create-lost", "create-503"):
                return (0 if state.failure == "create-lost" else 503), {}
            leaf = {"short-token": "short", "same-token": OPERATOR}.get(state.failure, leaf_value)
            ttl = {"auth-short": 25199, "auth-float": 28800.0, "auth-bool": True}.get(state.failure, 28800)
            return 200, {"auth": {"client_token": leaf, "lease_duration": ttl}}
        if path == "auth/token/lookup":
            assert method == "POST" and token == OPERATOR and body == {"token": leaf_value}
            return 200, {"data": {
                "policies": ["widened"] if state.failure == "lookup-policy" else [name],
                "ttl": {"lookup-short": 25199, "lookup-long": 28801, "lookup-float": 28800.0,
                        "lookup-bool": True}.get(state.failure, 28800),
                "orphan": state.failure != "lookup-orphan",
                "path": "auth/token/create" if state.failure == "lookup-path" else "auth/token/create/selfhost-renew-leaf"}}
        if path.startswith("transit/sign/keycloak-"):
            assert state.context["scope"] == "signing" and token == leaf_value
            assert body == {"input": "c2VsZmhvc3Qta2V5Y2xvYWstcHJvYmU=",
                            "hash_algorithm": "sha2-256", "signature_algorithm": "pkcs1v15"}
            if state.failure == "sign-failed" and "11id" in path:
                return 200, {"data": {"signature": ""}}
            return 200, {"data": {"signature": "vault:v1:synthetic"}}
        if path == key_path:
            assert token == leaf_value and method == "GET"
            return 200, {"data": {"version": "changed" if state.failure == "jwe-version" else state.context["version"]}}
        if path == "transit/keys/foreign-keycloak-selfhost":
            assert method == "GET" and token == leaf_value
            status = int(state.failure.removeprefix("denial-")) if (state.failure or "").startswith("denial-") else 403
            return status, {}
        raise AssertionError((method, path))

    with https_json_server(tmp_path, dispatch, state.errors) as transport:
        state.bao = SimpleNamespace(endpoint=transport.endpoint, ca=transport.ca, token=OPERATOR)
        yield state


@pytest.mark.parametrize("context", SCOPES, ids=["signing", "master-cookie", "master-ciba", "11id-cookie", "11id-ciba"])
@pytest.mark.parametrize("renew", [False, True])
def test_native_closed_scope_and_initial_renewal_parity(keycloak_server, context, renew):
    state = keycloak_server
    state.context, state.renew = context, renew
    assert keycloak_policy(**context) == expected(context)[0]
    assert keycloak_token(state.bao, **context, renew=renew, nonce="012345abcdef", policy="injected") == LEAF
    assert any(path == "transit/keys/foreign-keycloak-selfhost" for _, path, *_ in state.seen)
    assert any(method == "PUT" for method, *_ in state.seen) is (not renew)
    assert any(path == "auth/token/lookup" for _, path, *_ in state.seen) is renew


@pytest.mark.parametrize("failure", ["missing-policy", "duplicate-policy", "invalid-inventory", "changed-policy"])
def test_renewal_refuses_before_mint_when_policy_is_not_unique_exact(keycloak_server, failure):
    state = keycloak_server
    state.failure = failure
    with pytest.raises(RuntimeError, match="^Rust operator validation failed$"):
        keycloak_token(state.bao, "signing", renew=True)
    assert not any(path.startswith("auth/token/create") or method == "PUT" for method, path, *_ in state.seen)


@pytest.mark.parametrize("failure", ["create-lost", "create-503", "short-token", "same-token", "auth-short",
                                    "auth-float", "auth-bool", "lookup-policy", "lookup-short", "lookup-long",
                                    "lookup-float", "lookup-bool", "lookup-orphan", "lookup-path", "sign-failed",
                                    "denial-200", "denial-400", "denial-401", "denial-404", "denial-500"])
def test_post_mint_faults_require_sanitized_operator_recovery(keycloak_server, failure):
    state = keycloak_server
    state.failure = failure
    with pytest.raises(OperatorCleanupError, match="^Keycloak provisioning requires operator recovery$"):
        keycloak_token(state.bao, "signing", renew=True)


@pytest.mark.parametrize("context", SCOPES[1:])
@pytest.mark.parametrize("failure", ["jwe-version", "denial-200", "denial-404"])
def test_each_jwe_scope_requires_live_version_and_actual_foreign_denial(keycloak_server, context, failure):
    state = keycloak_server
    state.context, state.failure = context, failure
    with pytest.raises(OperatorCleanupError):
        keycloak_token(state.bao, **context, renew=True)


@pytest.mark.parametrize("context", [
    {"scope": "foreign"}, {"scope": "jwe", "realm": "other", "purpose": "cookie", "version": "v1"},
    {"scope": "jwe", "realm": "master", "purpose": "other", "version": "v1"},
    {"scope": "jwe", "realm": "master", "purpose": "cookie", "version": "../escape"},
])
def test_scope_references_are_closed(context):
    with pytest.raises(RuntimeError):
        keycloak_policy(**context)


def test_successful_mint_with_closed_stdout_is_recovery(keycloak_server):
    from scripts.selfhost_native_operator import operator_command
    bao = keycloak_server.bao
    command = operator_command(Path(__file__).resolve().parents[1], "operator", "keycloak-token",
                               bao.endpoint, str(bao.ca))
    assert OPERATOR not in " ".join(command)
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    process.stdout.close()
    process.stdin.write(json.dumps({"scope": "signing", "renew": True, "token": OPERATOR}).encode())
    process.stdin.close()
    assert process.wait(timeout=30) == 3
    assert process.stderr.read().decode().strip() == "Keycloak provisioning requires operator recovery"
    assert any(path == "transit/keys/foreign-keycloak-selfhost" for _, path, *_ in keycloak_server.seen)


@pytest.mark.parametrize("response", [b'"truncated', b"null", b"true", b'"short"'])
def test_truncated_or_invalid_successful_token_response_is_recovery(monkeypatch, response):
    from scripts import selfhost_native_operator as native
    monkeypatch.setattr(native, "operator_bytes", lambda *_, **kwargs: response)
    bao = SimpleNamespace(endpoint="https://synthetic.invalid", ca=Path("ca.pem"), token=OPERATOR)
    with pytest.raises(OperatorCleanupError, match="^Keycloak provisioning requires operator recovery$"):
        native.keycloak_token(bao, "signing", renew=True)


@pytest.mark.parametrize("mode", ["initial", "renew", "ca-renew"])
@pytest.mark.parametrize("duplicate", [False, True])
def test_complete_producer_keeps_seven_outputs_and_all_remote_proofs(keycloak_server, monkeypatch, mode, duplicate):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    import provision_selfhost_keycloak_kms as producer
    from scripts.selfhost_openbao_client import Bao
    from tests.test_selfhost_native_certificates import certificate, key, pem
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    state = keycloak_server
    state.batch, state.renew = True, mode != "initial"
    state.duplicate_tokens = duplicate
    mount = "keycloak-pki-v2" if mode == "ca-renew" else "keycloak-pki"
    signer = key()
    issuer = certificate("root", signer.public_key(), signer=signer, ca=True, after=8760 * 3600)
    keys = {realm: key("RSA") for realm in ("master", "11id")}
    leaves = {realm: pem(certificate(realm + ".keycloak.internal", keys[realm].public_key(),
                                    issuer, signer, after=8 * 3600)).decode() for realm in keys}
    monkeypatch.setattr(producer.secrets, "token_hex", lambda _: "012345abcdef")

    def owned_producer(method, path, body, token):
        if token != OPERATOR:
            return None
        if path == "auth/token/lookup" and body == {"token": OPERATOR}:
            ca_rotation = mode == "ca-renew"
            return 200, {"data": {
                "policies": ["selfhost-kms-ca-rotation" if ca_rotation else "selfhost-kms-renewal"],
                "path": "auth/selfhost-ca-rotation/login" if ca_rotation else "auth/selfhost-renew/login",
                "ttl": 7200}}
        if path == "sys/mounts":
            mounts = {"transit/": {"type": "transit"}, "didcomm/": {"type": "openbao-didcomm-authcrypt"}}
            if state.renew:
                mounts.update({"keycloak-pki/": {"type": "pki"}, mount + "/": {"type": "pki"}})
            return 200, {"data": mounts}
        if path == "sys/mounts/keycloak-pki":
            assert mode == "initial" and method == "POST"
            return 204, {}
        if path == "keycloak-pki/root/generate/internal" or path == mount + "/cert/ca":
            return 200, {"data": {"certificate": pem(issuer).decode()}}
        if path == mount + "/roles/rs256":
            if method == "POST":
                assert mode != "renew" and body == producer.ROLE_CONFIG
                return 204, {}
            return 200, {"data": {**producer.ROLE_CONFIG, "max_ttl": 28800}}
        if path.startswith("transit/keys/"):
            if method == "POST" and not path.endswith("/csr"):
                assert mode == "initial" and body["exportable"] is False and body["allow_plaintext_backup"] is False
                return 204, {}
            realm = "master" if "master" in path else "11id"
            if path.endswith("/csr"):
                assert body == {"version": 1}
                csr = (x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
                    x509.NameAttribute(NameOID.COMMON_NAME, realm)]))
                       .sign(keys[realm], hashes.SHA256()))
                return 200, {"data": {"csr": csr.public_bytes(serialization.Encoding.PEM).decode()}}
            data = {"type": "rsa-2048" if path.endswith("-rs256") else "hmac", "exportable": False,
                    "allow_plaintext_backup": False, "latest_version": 1}
            data["keys"] = {"1": {"public_key": keys[realm].public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()}}
            return 200, {"data": data}
        if path == mount + "/sign/rs256":
            assert body["ttl"] == "8h" and "BEGIN CERTIFICATE REQUEST" in body["csr"]
            realm = "master" if body["common_name"].startswith("master.") else "11id"
            return 200, {"data": {"certificate": leaves[realm]}}
        if path.startswith("didcomm/keycloak/keys/"):
            if method == "POST":
                assert mode == "initial"
                return 204, {}
            realm, purpose = path.split("/")[-2:]
            state.context = {"scope": "jwe", "realm": realm, "purpose": purpose, "version": "v1-synthetic"}
            return 200, {"data": {"version": "v1-synthetic"}}
        return None

    state.producer = owned_producer
    bao = Bao(state.bao.endpoint, state.bao.ca, OPERATOR)
    if duplicate:
        with pytest.raises(producer.OperatorCleanupError, match="^Keycloak provisioning requires operator recovery$"):
            producer.provision(bao, renew=state.renew, pki_mount=mount)
        return
    outputs = producer.provision(bao, renew=state.renew, pki_mount=mount)
    assert set(outputs) == producer.OUTPUTS and len(outputs) == 7
    assert len({value for name, value in outputs.items() if name.endswith("_token")}) == 5
    assert sum(path == "transit/keys/foreign-keycloak-selfhost" and token != OPERATOR
               for _, path, _, token in state.seen) == 5
    assert sum(path.startswith("transit/sign/keycloak-") for _, path, *_ in state.seen) == 2
    assert any(method == "PUT" for method, *_ in state.seen) is (mode == "initial")
