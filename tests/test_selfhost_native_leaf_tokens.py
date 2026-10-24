"""Native scope checks keep fixture and provisioning contracts distinct."""
import json
from types import SimpleNamespace

import pytest

from scripts.selfhost_native_operator import network_operation, operator_bytes
from tests.native_operator_https import https_json_server

SIGNER = "selfhost-qualification-custody-v1"
POLICY = "selfhost-qualification-custody-signer"
AUDIT = "selfhost-qualification-audit"


@pytest.mark.parametrize("kind", ["audit", "custody"])
@pytest.mark.parametrize("fault", [None, "duplicates", "default", "orphan", "float", "bool", "zero", "long",
                                  "lookup-denied", "missing-read", "excess-access", "export-allowed", "export-500"])
def test_native_leaf_scope_refuses_drift_without_mutating_authority(tmp_path, kind, fault):
    seen, errors = [], []
    allowed = ["transit/keys/cred-issuer-literal", "transit/keys/oid4vp-verifier-literal", f"transit/keys/{SIGNER}"]
    policy = AUDIT if kind == "audit" else POLICY

    def dispatch(method, path, body, token):
        seen.append((method, path, body, token))
        assert token == "synthetic-leaf-token"
        if path == "auth/token/lookup-self":
            if fault == "lookup-denied":
                return 403, {}
            return 200, {"data": {"policies": [policy, policy] if fault == "duplicates" else
                                  [policy, "default"] if fault == "default" else [policy],
                                  "orphan": fault != "orphan",
                                  "ttl": {"float": 3600.0, "bool": True, "zero": 0, "long": 3601}.get(fault, 3600)}}
        if path == "sys/capabilities-self":
            access = {p: ["read"] if p in allowed else ["deny"] for p in body["paths"]}
            if fault == "missing-read":
                access[allowed[0]] = []
            if fault == "excess-access":
                access[f"transit/sign/{SIGNER}"] = ["update"]
            return 200, access
        if path == f"transit/keys/{SIGNER}":
            return (500, {}) if fault == "missing-read" else (200, {"data": {}})
        if path == f"transit/export/signing-key/{SIGNER}":
            return (200 if fault == "export-allowed" else 500 if fault == "export-500" else 403), {}
        raise AssertionError(path)

    applicable = fault is not None and not (kind == "audit" and fault in ("export-allowed", "export-500")) and not (
        kind == "custody" and fault == "excess-access")
    with https_json_server(tmp_path, dispatch, errors) as transport:
        bao = SimpleNamespace(endpoint=transport.endpoint, ca=transport.ca, token="synthetic-leaf-token")
        if applicable:
            with pytest.raises(ValueError):
                network_operation(bao, "leaf-check", kind=kind, paths=allowed)
        else:
            network_operation(bao, "leaf-check", kind=kind, paths=allowed)
    assert not errors
    assert all(path in ("auth/token/lookup-self", "sys/capabilities-self", f"transit/keys/{SIGNER}",
                        f"transit/export/signing-key/{SIGNER}") for _, path, *_ in seen)


@pytest.mark.parametrize("policies,valid", [([POLICY], True), ([POLICY, POLICY], True),
                                           ([POLICY, "default"], False), ([], False), (["root"], False)])
def test_fixture_custody_scope_keeps_its_historical_set_semantics(policies, valid):
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    data = json.dumps({"metadata": {"policies": policies, "orphan": True, "ttl": 3600}}).encode()
    if valid:
        operator_bytes(root, "operator", "leaf-metadata", input=data)
    else:
        with pytest.raises(RuntimeError):
            operator_bytes(root, "operator", "leaf-metadata", input=data)


@pytest.mark.parametrize("org,namespace", [("00000000-0000-0000-0000-000000000001", "52224a0cec8a56149d0967de03fadd5c"),
                                           ("Acme", "fc98e4867bf95735b25748954893b06b"),
                                           ("acme", "7efecc64b5ed5dbfb37990a0ffcfe6df")])
def test_managed_reference_bridge_matches_independent_literal_vectors(org, namespace):
    from scripts.selfhost_managed_reference import managed_reference
    assert managed_reference(org, "vc_jwt_issuer") == f"cred-issuer-{namespace}-marty-es256"
    assert managed_reference(org, "oid4vp_request_signing") == f"oid4vp-verifier-{namespace}-marty-es256"
    with pytest.raises(ValueError):
        managed_reference(org, "holder_binding")
