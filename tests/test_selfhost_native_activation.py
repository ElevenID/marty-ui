"""Live preflight uses real HTTPS and certificates; expected scopes stay independent."""

from pathlib import Path
from types import SimpleNamespace
import sys

import pytest
from cryptography.hazmat.primitives import serialization

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from scripts.selfhost_openbao_client import (
    require_ca_rotation_authority,
    require_renewal_authority,
)
from scripts import activate_selfhost_renewed_secrets as activation
from tests.native_operator_https import https_json_server
from tests.test_selfhost_native_certificates import key, certificate, pem
from passport_remote_tls import SELFHOST_TOKEN_FILES, SELFHOST_CERT_FILES
from provision_selfhost_disposable_tls import KEY_NAMES, ENV_PREFIX_ROLE

TLS_CERT_BY_ROLE = {
    "signing-keys-server": "signing_keys_workload_server_cert",
    "gateway-client": "gateway_workload_client_cert",
    "auth-client": "auth_workload_client_cert",
    "auth-server": "auth_workload_server_cert",
    "compliance-profile-client": "compliance_profile_workload_client_cert",
    "deployment-profile-client": "deployment_profile_workload_client_cert",
    "organization-server": "org_workload_server_cert",
    "event-stream-server": "es_workload_server_cert",
    "notification-server": "notification_workload_server_cert",
    "revocation-profile-server": "rp_workload_server_cert",
    "credential-template-server": "ct_workload_server_cert",
    "issuance-server": "issuance_workload_server_cert",
    "flow-client": "flow_workload_client_cert",
    "flow-server": "flow_workload_server_cert",
    "pp-server": "pp_workload_server_cert",
    "verification-client": "verification_workload_client_cert",
}


OPERATOR = "synthetic-renewal-operator-0123456789"


def expected_scope(name):
    if name.endswith("_tls_kms_token"):
        remote = KEY_NAMES[ENV_PREFIX_ROLE[name.removesuffix("_tls_kms_token").upper()]]
        return (
            f'path "transit/keys/{remote}" {{ capabilities = ["read"] }}\n'
            f'path "transit/sign/{remote}" {{ capabilities = ["update"] }}'
        )
    if name == "keycloak_signing_kms_token":
        return "".join(
            f'path "transit/keys/keycloak-{r}-rs256" {{ capabilities = ["read"] }}\n'
            f'path "transit/sign/keycloak-{r}-rs256" {{ capabilities = ["update"] }}\n'
            f'path "transit/keys/keycloak-{r}-hs512" {{ capabilities = ["read"] }}\n'
            f'path "transit/hmac/keycloak-{r}-hs512/sha2-512" {{ capabilities = ["update"] }}\n'
            f'path "transit/verify/keycloak-{r}-hs512/sha2-512" {{ capabilities = ["update"] }}\n'
            for r in ("master", "11id")
        )
    _, realm, purpose, _ = name.split("_")
    return (
        f'path "didcomm/keycloak/keys/{realm}/{purpose}" {{ capabilities = ["read"] }}\n'
        f'path "didcomm/keycloak/jwe/encode/{realm}/{purpose}/v1" {{ capabilities = ["update"] }}\n'
        f'path "didcomm/keycloak/jwe/decode/{realm}/{purpose}/v1" {{ capabilities = ["update"] }}\n'
    )


@pytest.fixture
def preflight_server(tmp_path):
    state = SimpleNamespace(fault=None, errors=[], seen=[], rotation=False)
    names = sorted(
        SELFHOST_TOKEN_FILES
        | {
            "keycloak_signing_kms_token",
            *(
                f"keycloak_{realm}_{purpose}_token"
                for realm in ("master", "11id")
                for purpose in ("cookie", "ciba")
            ),
        }
    )
    roots = {}
    for generation in ("old", "new"):
        root = tmp_path / generation
        root.mkdir()
        roots[generation] = root
        for name in names:
            (root / name).write_text(f"synthetic-{generation}-{name}")

    def dispatch(method, path, body, token):
        state.seen.append((method, path, body, token))
        if path == "auth/token/lookup":
            if body["token"] == OPERATOR:
                return 200, {
                    "data": {
                        "policies": [
                            "root"
                            if state.fault == "authority-policy"
                            else "selfhost-kms-ca-rotation"
                            if state.rotation
                            else "selfhost-kms-renewal"
                        ],
                        "path": "wrong"
                        if state.fault == "authority-path"
                        else "auth/selfhost-ca-rotation/login"
                        if state.rotation
                        else "auth/selfhost-renew/login",
                        "ttl": {
                            "authority-float": 7200.0,
                            "authority-short": 3599,
                            "authority-long": 28801,
                        }.get(state.fault, 7200),
                    }
                }
            leaf = body["token"]
            generation = "old" if leaf.startswith("synthetic-old-") else "new"
            name = leaf.removeprefix(f"synthetic-{generation}-")
            data = {
                "policies": ["scope-" + name.replace("_", "-")],
                "ttl": 7200,
                "orphan": state.fault != generation + "-root-child",
                "path": "auth/token/create/selfhost-renew-leaf",
            }
            if state.fault == "policy-reference":
                data["policies"] = ["bad/path"]
            if state.fault == "scope-default":
                data["policies"] = ["default"]
            if state.fault == "scope-many":
                data["policies"].append("root")
            if state.fault == "ttl-float":
                data["ttl"] = 7200.0
            if state.fault == "ttl-short":
                data["ttl"] = 3599
            if state.fault == "ttl-long":
                data["ttl"] = 28801
            if state.fault == "leaf-path":
                data["path"] = "auth/token/create"
            return 200, {"data": data}
        if path.startswith("sys/policies/acl/"):
            name = next(
                name
                for name in names
                if "scope-" + name.replace("_", "-") == path.rsplit("/", 1)[1]
            )
            return 200, {
                "data": {
                    "policy": expected_scope(name)
                    + (" " if state.fault == "policy-drift" else "")
                }
            }
        if path.startswith("transit/sign/"):
            assert token != OPERATOR
            assert (
                body["input"] == "YWN0aXZhdGlvbi1zY29wZQ==" and body["key_version"] == 1
            )
            if "keycloak-" in path:
                assert (
                    body["hash_algorithm"] == "sha2-256"
                    and body["signature_algorithm"] == "pkcs1v15"
                )
            return 200, {
                "data": {
                    "signature": "vault:v2:wrong"
                    if state.fault == "sign-version"
                    else "vault:v1:proof"
                }
            }
        if path.startswith("didcomm/keycloak/keys/"):
            return 200, {
                "data": {
                    "version": "wrong/version"
                    if state.fault == "jwe-invalid"
                    else "v2"
                    if token != OPERATOR and state.fault == "jwe-drift"
                    else "v1"
                }
            }
        if path.endswith("/cert/ca"):
            mount = path.removesuffix("/cert/ca")
            value = state.issuers[mount]
            if state.fault == "same-keycloak" and mount == "keycloak-pki-v5":
                value = state.issuers["keycloak-pki"]
            return 200, {"data": {"certificate": value}}
        if path.startswith("transit/keys/"):
            remote = path.removeprefix("transit/keys/")
            data = dict(state.metadata[remote])
            if state.fault == "key-export":
                data["exportable"] = True
            if state.fault == "key-backup":
                data["allow_plaintext_backup"] = True
            if state.fault == "key-version":
                data["latest_version"] = 2
            if state.fault == "key-version-bool":
                data["latest_version"] = True
            if state.fault == "key-kind":
                data["type"] = "ed25519"
            return 200, {"data": data}
        raise AssertionError((method, path))

    with https_json_server(tmp_path, dispatch, state.errors) as transport:
        state.bao = SimpleNamespace(
            endpoint=transport.endpoint, ca=transport.ca, token=OPERATOR
        )
        state.old, state.new = roots["old"], roots["new"]
        yield state


@pytest.mark.parametrize("rotation", [False, True])
@pytest.mark.parametrize(
    "fault",
    [
        None,
        "authority-policy",
        "authority-path",
        "authority-short",
        "authority-long",
        "authority-float",
    ],
)
def test_native_authority_binds_role_path_and_integer_ttl(
    preflight_server, rotation, fault
):
    state = preflight_server
    state.rotation, state.fault = rotation, fault
    check = require_ca_rotation_authority if rotation else require_renewal_authority
    if fault:
        with pytest.raises(ValueError, match="scoped AppRole"):
            check(state.bao)
    else:
        check(state.bao)


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "old-root-child",
        "new-root-child",
        "policy-reference",
        "scope-default",
        "scope-many",
        "ttl-float",
        "ttl-short",
        "ttl-long",
        "leaf-path",
        "policy-drift",
        "sign-version",
        "jwe-invalid",
        "jwe-drift",
    ],
)
def test_native_tokens_prove_both_generations_without_widening(preflight_server, fault):
    state = preflight_server
    state.fault = fault
    if fault:
        with pytest.raises(ValueError):
            activation.checked_tokens(
                state.bao,
                state.old,
                state.new,
                3600,
                require_orphan_new=True,
                require_orphan_old=True,
            )
    else:
        activation.checked_tokens(
            state.bao,
            state.old,
            state.new,
            3600,
            require_orphan_new=True,
            require_orphan_old=True,
        )
        lookups = [
            body for _, path, body, _ in state.seen if path == "auth/token/lookup"
        ]
        assert len(lookups) == 42
        # Observe compiled native traversal against the deployed Python inventory.
        expected_names = SELFHOST_TOKEN_FILES | {
            "keycloak_signing_kms_token",
            *(
                f"keycloak_{r}_{p}_token"
                for r in ("master", "11id")
                for p in ("cookie", "ciba")
            ),
        }
        assert {item["token"] for item in lookups} == {
            f"synthetic-{generation}-{name}"
            for generation in ("old", "new")
            for name in expected_names
        }
        assert sum(path.startswith("transit/sign/") for _, path, *_ in state.seen) == 36


@pytest.mark.parametrize("mode", ["ordinary", "overlap", "retire"])
@pytest.mark.parametrize(
    "fault",
    [
        None,
        "key-export",
        "key-backup",
        "key-version",
        "key-version-bool",
        "key-kind",
        "key-spki",
        "wrong-chain",
        "short-leaf",
        "trust-order",
        "same-keycloak",
    ],
)
def test_native_certificates_bind_issuers_remote_keys_and_trust_modes(
    preflight_server, mode, fault
):
    state = preflight_server
    assert set(TLS_CERT_BY_ROLE) == set(KEY_NAMES)
    assert set(TLS_CERT_BY_ROLE.values()) == SELFHOST_CERT_FILES - {
        "workload_identity_ca_cert"
    }
    state.fault = fault
    roots = {}
    for kind in ("workload", "keycloak"):
        for replacement in (False, True):
            signer = key()
            name = kind + ("-pki-v5" if replacement else "-pki")
            issuer = certificate(
                name,
                signer.public_key(),
                signer=signer,
                ca=True,
                before=-7200,
                after=-3600 if mode == "retire" and not replacement else 365 * 86400,
            )
            roots[name] = signer, issuer
    state.issuers = {name: pem(cert).decode() for name, (_, cert) in roots.items()}
    state.metadata = {}
    roles = [
        (remote, TLS_CERT_BY_ROLE[role], "workload")
        for role, remote in KEY_NAMES.items()
    ]
    roles += [
        (f"keycloak-{realm}-rs256", f"keycloak_{realm}_rs256_cert", "keycloak")
        for realm in ("master", "11id")
    ]
    for remote, filename, kind in roles:
        signer = key("RSA") if kind == "keycloak" else key()
        public = (
            (key() if fault == "key-spki" else signer)
            .public_key()
            .public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode()
        )
        state.metadata[remote] = {
            "type": "rsa-2048" if kind == "keycloak" else "ecdsa-p256",
            "latest_version": 1,
            "exportable": False,
            "allow_plaintext_backup": False,
            "keys": {"1": {"public_key": public}},
        }
        for directory in (state.old, state.new):
            replacement = mode == "retire" or (
                mode == "overlap" and directory == state.new
            )
            ca_name = kind + ("-pki-v5" if replacement else "-pki")
            issuer_signer, issuer = roots[ca_name]
            if fault == "wrong-chain":
                issuer_signer = key()
            leaf = certificate(
                remote,
                signer.public_key(),
                issuer,
                issuer_signer,
                after=1800 if fault == "short-leaf" else 8 * 3600,
            )
            (directory / filename).write_bytes(pem(leaf))
    before, after = state.issuers["workload-pki"], state.issuers["workload-pki-v5"]
    (state.old / "workload_identity_ca_cert").write_text(
        before + after if mode == "retire" else before
    )
    (state.new / "workload_identity_ca_cert").write_text(
        before + after if mode == "overlap" else after if mode == "retire" else before
    )
    if fault == "trust-order":
        (state.new / "workload_identity_ca_cert").write_text(after + before)
    replacement = (
        None
        if mode == "ordinary"
        else (state.bao, "workload-pki-v5", "keycloak-pki-v5")
    )
    applicable = fault is not None and (fault != "same-keycloak" or mode != "ordinary")
    if applicable:
        with pytest.raises(ValueError):
            activation.checked_certificates(
                state.bao,
                state.old,
                state.new,
                3600,
                replacement=replacement,
                retiring=mode == "retire",
            )
    else:
        activation.checked_certificates(
            state.bao,
            state.old,
            state.new,
            3600,
            replacement=replacement,
            retiring=mode == "retire",
        )
        assert sum(path.startswith("transit/keys/") for _, path, *_ in state.seen) == 36
        expected_keys = set(KEY_NAMES.values()) | {
            f"keycloak-{r}-rs256" for r in ("master", "11id")
        }
        assert {
            path.removeprefix("transit/keys/")
            for _, path, *_ in state.seen
            if path.startswith("transit/keys/")
        } == expected_keys
