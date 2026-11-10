"""Refusal tests for existing Secret custody and untrusted bootstrap outputs."""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
from types import SimpleNamespace
import zipfile

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import bootstrap_kubernetes_openbao as bootstrap


pytestmark = pytest.mark.skipif(os.name != "posix", reason="Linux bootstrap file contract")


def expected_publication_contract():
    return {
        "schema": "marty.kubernetes-secret-publication/v1",
        "catalog": json.loads(
            (bootstrap.ROOT / "deploy-config/catalog/kubernetes-secrets.json").read_bytes()),
    }


def expected_application_contract():
    return json.loads((bootstrap.ROOT / "deploy-config/catalog/kubernetes-application-tokens.json").read_bytes())


def application_identity_archive(binding, *, extra=None, missing=None, mode=0o600):
    members = {
        "application-role-id": b"PUBLIC_APPLICATION_ROLE_ID_CANARY",
        "application-secret-id": b"PRIVATE_APPLICATION_SECRET_ID_CANARY",
        "application-binding.json": bootstrap.encoded(binding),
    }
    if extra:
        members.update(extra)
    if missing:
        members.pop(missing)
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as archive:
        for name, value in members.items():
            entry = tarfile.TarInfo("./" + name)
            entry.mode = mode
            entry.size = len(value)
            archive.addfile(entry, io.BytesIO(value))
    return raw.getvalue()


class ExistingNamespace:
    namespace = "marty-test"

    def __init__(self, state: Path, secrets: set[str]):
        self.state = state
        self.secrets = secrets
        self.inspected_secrets: set[str] = set()
        self.mutations = []

    def kubectl(self, operation, *args, **kwargs):
        if operation == "namespace workload inspection":
            return b'{"items":[]}'
        if operation == "namespace Secret inspection":
            assert args[:2] == ("get", "secret")
            assert args[-3:] == ("--ignore-not-found", "-o", "name")
            self.inspected_secrets.update(args[2:-3])
            return "\n".join("secret/" + name for name in sorted(
                self.secrets & self.inspected_secrets)).encode()
        if operation in {"namespace inspection", "namespace identity"}:
            return b'{"metadata":{"name":"marty-test","uid":"namespace-fixture"}}'
        raise AssertionError("unexpected operation")

    def create(self, resource):
        self.mutations.append(resource)


@pytest.mark.parametrize("name", [
    "org-workload-tls", "issuance-server-kms", "notification-workload-tls",
    "notification-tls-kms", "marty-operator", "marty-openbao-seal",
])
def test_existing_destination_secret_refused_before_mutation(tmp_path, name):
    transport = ExistingNamespace(tmp_path, {name})
    with pytest.raises(bootstrap.BootstrapError, match="already contains Marty credentials"):
        bootstrap.prepare_namespace(transport, "fixture-bootstrap", expected_publication_contract())
    assert name in transport.inspected_secrets
    assert transport.mutations == []
    assert list(tmp_path.iterdir()) == []


def test_existing_ingress_and_registry_secrets_are_preserved(tmp_path):
    transport = ExistingNamespace(tmp_path, {"marty-ingress-tls", "registry-pull"})
    identity = bootstrap.prepare_namespace(transport, "fixture-bootstrap", expected_publication_contract())
    assert transport.mutations == []
    assert transport.secrets == {"marty-ingress-tls", "registry-pull"}
    assert identity == {"name": "marty-test", "uid": "namespace-fixture"}
    assert json.loads((tmp_path / "namespace.json").read_bytes())["uid"] == "namespace-fixture"


def test_namespace_destinations_come_from_retained_validated_publication_contract(tmp_path, monkeypatch):
    publication = expected_publication_contract()
    transport = ExistingNamespace(tmp_path, set())
    # Once validated, inspection must use this exact publisher inventory rather
    # than reopening a checkout that can change during later cluster work.
    monkeypatch.setattr(bootstrap, "ROOT", tmp_path / "no-checkout")
    bootstrap.prepare_namespace(transport, "fixture-bootstrap", publication)
    assert transport.inspected_secrets == {
        entry["name"] for entry in publication["catalog"]["secrets"]
    } | {"marty-operator", "marty-openbao-seal"}


def archive_bytes(entries, contents=b"synthetic public certificate or scoped credential"):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as archive:
        for name, kind in entries:
            entry = tarfile.TarInfo(name)
            if kind == "symlink":
                entry.type = tarfile.SYMTYPE
                entry.linkname = "/private/operator/root.token"
                archive.addfile(entry)
            else:
                entry.size = len(contents)
                archive.addfile(entry, io.BytesIO(contents))
    return raw.getvalue()


def valid_entries():
    return [("./" + name, "file") for name in sorted(
        set(bootstrap.SELFHOST_TLS_FILES) | {"selfhost-tls-kms-roles.json"})]


@pytest.mark.parametrize("invalid", ["unexpected", "duplicate", "symlink", "incomplete", "traversal"])
def test_tls_archive_invalid_inventory_is_rejected(tmp_path, invalid):
    entries = valid_entries()
    if invalid == "unexpected":
        entries.append(("./root.token", "file"))
    elif invalid == "duplicate":
        entries.append(entries[0])
    elif invalid == "symlink":
        entries[0] = (entries[0][0], "symlink")
    elif invalid == "incomplete":
        entries.pop()
    else:
        entries[0] = ("../escaped.token", "file")
    output = tmp_path / "staging"
    output.mkdir()
    with pytest.raises(bootstrap.BootstrapError, match="inventory differs|incomplete"):
        bootstrap.take_tls_outputs(archive_bytes(entries), output)
    assert not (tmp_path / "escaped.token").exists()
    assert not (tmp_path / "credentials").exists()


def test_complete_tls_archive_is_accepted_only_into_staging(tmp_path):
    bootstrap.take_tls_outputs(archive_bytes(valid_entries()), tmp_path)
    assert {path.name for path in tmp_path.iterdir()} == {
        name.removeprefix("./") for name, _ in valid_entries()}
    assert all(path.is_file() and not path.is_symlink() for path in tmp_path.iterdir())


def write_private(path, contents):
    path.write_bytes(contents)
    path.chmod(0o600)


@pytest.fixture
def authenticated_inputs(tmp_path):
    operator = b"synthetic signed operator; never executed by this test"
    script = b"#!/bin/sh\nexit 0\n"
    bundle = io.BytesIO()
    with zipfile.ZipFile(bundle, "w") as archive:
        archive.writestr("selfhost-prepared/docker/openbao-init.sh", script)
    bundle = bundle.getvalue()
    inventory = {"artifacts": [
        {"name": "marty-deploy-linux-amd64", "sha256": hashlib.sha256(operator).hexdigest()},
        {"name": "prepared-selfhost-bundle.zip", "sha256": hashlib.sha256(bundle).hexdigest()},
    ]}
    raw = json.dumps(inventory).encode()
    write_private(tmp_path / "installer-inventory.json", raw)
    write_private(tmp_path / "marty-deploy-linux-amd64", operator)
    write_private(tmp_path / "prepared-selfhost-bundle.zip", bundle)
    identity = {"inventorySha256": hashlib.sha256(raw).hexdigest(),
                "operatorSha256": hashlib.sha256(operator).hexdigest()}
    return tmp_path, identity, operator, script


@pytest.mark.parametrize("changed", ["inventory", "operator", "bundle"])
def test_staged_artifact_changes_cannot_replace_authenticated_bytes(authenticated_inputs, changed):
    assets, identity, _, _ = authenticated_inputs
    if changed == "inventory":
        # A replacement payload and matching replacement inventory are still
        # outside the original in-process authentication result.
        replacement = b"replacement operator"
        write_private(assets / "marty-deploy-linux-amd64", replacement)
        inventory = json.loads((assets / "installer-inventory.json").read_bytes())
        inventory["artifacts"][0]["sha256"] = hashlib.sha256(replacement).hexdigest()
        write_private(assets / "installer-inventory.json", json.dumps(inventory).encode())
    else:
        name = "marty-deploy-linux-amd64" if changed == "operator" else "prepared-selfhost-bundle.zip"
        write_private(assets / name, b"changed after authentication")
    with pytest.raises(bootstrap.BootstrapError, match="authenticated installer .* changed"):
        bootstrap.authenticated_bootstrap_inputs(assets, identity)


def test_consumed_init_script_is_retained_from_authenticated_bundle(authenticated_inputs):
    assets, identity, operator, script = authenticated_inputs
    captured_operator, captured_script = bootstrap.authenticated_bootstrap_inputs(assets, identity)
    write_private(assets / "prepared-selfhost-bundle.zip", b"changed during later cluster operations")
    assert captured_operator == operator
    assert captured_script == script


# This independent expected inventory catches both command/receipt disagreement
# and a widened policy or lifetime that changed in both places.
EXPECTED_ORDINARY_POLICIES = {
    "OPENBAO_SERVICE_TOKEN": ["credential-service"],
    "OPENBAO_BOOTSTRAP_TOKEN": ["kms-bootstrap"],
    "SIGNING_KEYS_OPENBAO_TOKEN": ["credential-service", "signing-keys-managed"],
    "DIDCOMM_ISSUANCE_OPENBAO_TOKEN": ["didcomm-issuance"],
    "NOTIFICATION_OPENBAO_TOKEN": ["notification-webhook-service"],
    "GATEWAY_SIGN_GRANT_MINT_TOKEN": ["sign-grant-mint-gateway-service"],
    "GATEWAY_ISSUER_CSR_GRANT_MINT_TOKEN": ["sign-grant-mint-gateway-issuer-did"],
    "FLOW_SIGN_GRANT_MINT_TOKEN": ["sign-grant-mint-flow-wallet"],
    "ISSUANCE_CREDENTIAL_SIGN_GRANT_MINT_TOKEN": ["sign-grant-mint-issuance-credential"],
    "ISSUANCE_CANVAS_SIGN_GRANT_MINT_TOKEN": ["sign-grant-mint-issuance-canvas"],
    "ISSUANCE_READINESS_SIGN_GRANT_MINT_TOKEN": ["sign-grant-mint-issuance-readiness"],
    "ISSUANCE_PASSPORT_SIGN_GRANT_MINT_TOKEN": ["sign-grant-mint-issuance-passport"],
    "SIGNING_KEYS_GRANT_VERIFY_TOKEN": ["sign-grant-verify"],
}
NAMESPACE_UID = "c647e5d2-85d7-409b-8729-94b8f8cf29ab"
CLUSTER_ID = "9347f7a0-aae1-4ecf-9e77-165626c051c2"
PRODUCER_NONCE = "0123456789ab"
ROOT_TOKEN = "PRIVATE_ROOT_TOKEN_CANARY_NEVER_EXPORTED"


@pytest.fixture
def bootstrap_flow(tmp_path, monkeypatch):
    """Run real adapter control flow; fake only process/cluster/crypto boundaries."""
    args = SimpleNamespace(
        namespace="marty-test", context="selected-fixture",
        kubeconfig=tmp_path / "input-kubeconfig", state_dir=tmp_path / "state",
        assets=tmp_path / "assets", runtime_source_sha="1" * 40,
        chart_source_sha="2" * 40, release_tag="v1.2.3-nightly.20261107.123",
        build_run_id=123, build_run_attempt=1, image_pull_secret=["registry-pull"],
        gh=tmp_path / "gh", cosign=tmp_path / "cosign",
        helm=tmp_path / "helm", chart_package=tmp_path / "openbao.tgz",
    )
    write_private(args.kubeconfig, b"PRIVATE_INPUT_KUBECONFIG_CANARY")
    write_private(args.chart_package, b"synthetic chart; never installed")
    upstream = tmp_path / "upstream.json"
    write_private(upstream, bootstrap.encoded({
        "version": "fixture-chart",
        "sha256": hashlib.sha256(args.chart_package.read_bytes()).hexdigest(),
    }))
    values = {
        "release": {"inventorySha256": "3" * 64, "operatorSha256": "4" * 64},
        "images": {
            "services": "ghcr.io/elevenid/marty-ui-oss/services@sha256:" + "5" * 64,
            "openbao_didcomm": "ghcr.io/elevenid/marty-ui-oss/openbao-didcomm@sha256:" + "6" * 64,
        },
    }
    ready = {
        "initialized": True, "sealed": False, "type": "static",
        "storage_type": "raft", "cluster_id": CLUSTER_ID,
    }
    flow = SimpleNamespace(
        args=args, values=values, fail_at=None, init_calls=0, cleanup_calls=0,
        namespace_reads=0, status_reads=0, publication_calls=0,
        publication_contract=expected_publication_contract(), contract_bytes=None,
        contract_returncode=0, contract_exception=None,
        application_contract=expected_application_contract(), application_contract_bytes=None,
        application_contract_returncode=0, application_contract_exception=None,
        authority_calls=0, authority_context=None, authority_requested_at_call=None,
        authority_exports=0, authority_archive_override=None,
        authority_response=b'{"ready":true}',
        processes=[], cluster_operations=[], supplemental_publications=[], events=[],
        publication_before_cluster=None, native_publication=None,
        namespace_documents=[
            {"metadata": {"name": args.namespace, "uid": NAMESPACE_UID}},
            {"metadata": {"name": args.namespace, "uid": NAMESPACE_UID}},
            {"metadata": {"name": args.namespace, "uid": NAMESPACE_UID}},
        ],
        status_documents=[dict(ready), dict(ready), dict(ready)],
        token_commands={}, uploads={}, resources=[], workload_command=None,
        keycloak_context=None, requested_at_init=None,
    )
    operator_bytes = b"synthetic authenticated operator; never executed"

    def prepared(**kwargs):
        flow.events.append("prepare")
        assert kwargs["assets"] == args.assets
        for key in ("output", "openbao_output"):
            bootstrap.write_new(kwargs[key], b"{}")
        return values, {}

    def authenticated(assets, identity):
        flow.events.append("authenticated")
        assert assets == args.assets and identity == values["release"]
        return operator_bytes, b"synthetic authenticated initializer; never executed"

    def process(command, **kwargs):
        flow.processes.append(command)
        if command == [str(args.state_dir / "marty-deploy"), "--build-identity"]:
            flow.events.append("build-identity")
            stdout = (args.runtime_source_sha + ":" + args.release_tag).encode()
        elif command == [str(args.state_dir / "marty-deploy"), "kubernetes-secrets-contract"]:
            flow.events.append("publication-contract")
            assert kwargs["env"] == {}
            assert kwargs["stdin"] == bootstrap.subprocess.DEVNULL
            assert kwargs["capture_output"] is True and kwargs["check"] is False
            assert kwargs["timeout"] == 10
            if flow.contract_exception:
                raise flow.contract_exception
            return SimpleNamespace(
                returncode=flow.contract_returncode,
                stdout=(bootstrap.encoded(flow.publication_contract)
                        if flow.contract_bytes is None else flow.contract_bytes),
                stderr=b"PRIVATE_CONTRACT_DIAGNOSTIC_CANARY",
            )
        elif command == [str(args.state_dir / "marty-deploy"), "kubernetes-application-token-contract"]:
            flow.events.append("application-contract")
            assert kwargs["env"] == {} and kwargs["stdin"] == bootstrap.subprocess.DEVNULL
            if flow.application_contract_exception:
                raise flow.application_contract_exception
            return SimpleNamespace(returncode=flow.application_contract_returncode,
                stdout=(bootstrap.encoded(flow.application_contract)
                        if flow.application_contract_bytes is None else flow.application_contract_bytes),
                stderr=b"PRIVATE_APPLICATION_CONTRACT_DIAGNOSTIC_CANARY")
        elif command[:1] == ["/synthetic/kubectl"] and "config" in command:
            flow.events.append("kubeconfig")
            flow.publication_before_cluster = json.loads(
                (args.state_dir / "kubernetes-secret-publication.json").read_bytes())
            stdout = bootstrap.encoded({
                "current-context": args.context, "contexts": [{"name": args.context}],
                "users": [{"user": {"token": "PRIVATE_KUBECONFIG_CANARY"}}],
            })
        else:
            raise AssertionError("unexpected local process")
        return SimpleNamespace(returncode=0, stdout=stdout, stderr=b"")

    class FlowTransport:
        def __init__(self, state, kubeconfig, namespace, kubectl):
            self.state, self.namespace = state, namespace
            flow.transport = self

        def run(self, operation, command, **kwargs):
            flow.cluster_operations.append(operation)
            if operation == "official OpenBao Helm installation":
                return b""
            assert operation == "native Kubernetes credential publication"
            flow.publication_calls += 1
            flow.native_publication = (command, kwargs["env"])
            assert kwargs["env"]["KUBECONFIG"] == str(self.state / "kubeconfig")
            if flow.fail_at == "publication":
                raise bootstrap.BootstrapError("synthetic publication failure")
            return b""

        def create(self, document):
            flow.cluster_operations.append("create")
            flow.resources.append(document)

        def upload(self, pod, destination, contents, **kwargs):
            flow.cluster_operations.append("upload")
            flow.uploads[(pod, destination)] = contents

        def kubectl(self, operation, *command, **kwargs):
            flow.cluster_operations.append(operation)
            if operation == "namespace inspection":
                return b""
            if operation == "namespace identity":
                assert command[:3] == ("get", "namespace", self.namespace)
                document = flow.namespace_documents[flow.namespace_reads]
                flow.namespace_reads += 1
                return bootstrap.encoded(document)
            if operation in {
                "OpenBao container startup", "unsealed OpenBao readiness",
                "native producer readiness",
            }:
                return b""
            if operation == "native producer cleanup":
                flow.cleanup_calls += 1
                if flow.fail_at == "producer-cleanup":
                    raise bootstrap.BootstrapError("synthetic producer cleanup failure")
                return b""
            if operation == "application credential publication":
                flow.supplemental_publications.append(command)
                if flow.fail_at == "operator-publication":
                    raise bootstrap.BootstrapError("synthetic operator publication failure")
                return b""
            raise AssertionError("unexpected Kubernetes operation: " + operation)

        def execute(self, pod, command, *, data=None, **kwargs):
            flow.cluster_operations.append("execute")
            if command[:3] == ["bao", "operator", "init"]:
                flow.init_calls += 1
                # Reading here proves persistence precedes the mutating call.
                flow.requested_at_init = json.loads(
                    (self.state / "initialize-requested.json").read_bytes())
                return bootstrap.encoded({
                    "root_token": ROOT_TOKEN, "recovery_keys_b64": ["PRIVATE_RECOVERY_CANARY"],
                })
            if command == ["bao", "status", "-format=json"]:
                document = flow.status_documents[flow.status_reads]
                flow.status_reads += 1
                return bootstrap.encoded(document)
            if command == ["cat", "/bao/data/tls/ca.crt"]:
                return b"-----BEGIN CERTIFICATE-----\nPUBLIC_FIXTURE_CA\n-----END CERTIFICATE-----"
            if command[:2] == ["/bin/sh", "-ec"]:
                if len(command) == 3 and command[2].startswith("for attempt in"):
                    return b'{"initialized":false,"type":"static"}'
                if command[2] == 'umask 077; mkdir "$1" "$2"; chmod 700 "$1" "$2"':
                    assert command[4:] == ["/tmp/application-current", "/tmp/application-identity"]
                    return b""
                if command[2] == bootstrap.REMOTE_ARCHIVE_COMMAND:
                    assert command[4] == "/tmp/application-identity"
                    flow.authority_exports += 1
                    if flow.fail_at == "authority-export":
                        raise bootstrap.BootstrapError("synthetic private archive failure")
                    if flow.authority_archive_override is not None:
                        return flow.authority_archive_override
                    return application_identity_archive(flow.authority_context["binding"])
                assert command[3] == "--" and data == (ROOT_TOKEN + "\n").encode()
                native = command[4:]
                if native[:3] == ["bao", "token", "create"]:
                    token = f"PRIVATE_ORDINARY_TOKEN_{len(flow.token_commands):02d}_CANARY".encode()
                    flow.token_commands[token] = native
                    return token + b"\n"
                assert native[:2] == ["env", "DIDCOMM_KMS_PLUGIN_REQUIRED=true"]
                return b""
            if command == ["sha256sum", "/tmp/marty-deploy"]:
                return hashlib.sha256(flow.uploads[(pod, "/tmp/marty-deploy")]).hexdigest().encode()
            if command[-1:] == ["/usr/local/bin/marty-passport-tls-bootstrap"]:
                flow.workload_command = command
                if flow.fail_at == "producer":
                    raise bootstrap.BootstrapError("synthetic producer failure")
                return b""
            if command == ["tar", "-cf", "-", "-C", "/tmp/workload-tls", "."]:
                return archive_bytes(valid_entries(), b"PRIVATE_WORKLOAD_TOKEN_CANARY")
            if command[:3] == ["/tmp/marty-deploy", "operator", "keycloak-provision"]:
                flow.keycloak_context = json.loads(data)
                return bootstrap.encoded({
                    name: ("PRIVATE_KEYCLOAK_TOKEN_CANARY_" + name if name.endswith("_token")
                           else "-----BEGIN CERTIFICATE-----\nPUBLIC_FIXTURE_CERT")
                    for name in bootstrap.KEYCLOAK_FILES
                })
            if command[:4] == ["/tmp/marty-deploy", "operator", "approle-bootstrap", "application"]:
                flow.authority_calls += 1
                flow.authority_context = json.loads(data)
                flow.authority_requested_at_call = json.loads(
                    (self.state / "application-authority-requested.json").read_bytes())
                assert flow.namespace_reads == flow.status_reads == 2
                if flow.fail_at == "authority":
                    raise bootstrap.BootstrapError("PRIVATE_AUTHORITY_RESPONSE_CANARY")
                if flow.fail_at == "authority-timeout":
                    raise bootstrap.subprocess.TimeoutExpired(command, 600,
                        output=b"PRIVATE_UNCERTAIN_RESPONSE_CANARY")
                return flow.authority_response
            raise AssertionError("unexpected remote process")

    def accept_tls(output, destination, root_token, *, expected_files, certificate_files):
        assert root_token == ROOT_TOKEN
        # Native crypto is outside this control-flow test; retain actual output
        # staging, inventory checks, exclusive writes and publication calls.
        for name in expected_files:
            bootstrap.write_new(destination / name, (output / name).read_bytes())

    monkeypatch.setattr(bootstrap, "UPSTREAM", upstream)
    monkeypatch.setattr(bootstrap, "prepare", prepared)
    monkeypatch.setattr(bootstrap, "authenticated_bootstrap_inputs", authenticated)
    monkeypatch.setattr(bootstrap.subprocess, "run", process)
    monkeypatch.setattr(bootstrap.shutil, "which", lambda name: "/synthetic/kubectl" if name == "kubectl" else None)
    monkeypatch.setattr(bootstrap.secrets, "token_hex",
                        lambda count: PRODUCER_NONCE if count == 6 else "PRIVATE_SCALAR_CANARY")
    monkeypatch.setattr(bootstrap, "Transport", FlowTransport)
    monkeypatch.setattr(bootstrap, "verified_key_metadata", lambda output: {})
    monkeypatch.setattr(bootstrap, "accept_remote_tls", accept_tls)
    return flow


@pytest.mark.parametrize("invalid", [
    "unsupported", "timeout", "unavailable", "empty", "malformed", "non-utf8",
    "oversized", "array", "schema", "missing-secret", "extra-secret",
    "duplicate-secret", "wrong-input", "wrong-key", "missing-required",
    "boolean-version", "duplicate-json-member", "extra-member",
])
def test_incompatible_compiled_publisher_refused_before_cluster_access(bootstrap_flow, invalid, capsys):
    flow = bootstrap_flow
    contract = flow.publication_contract
    catalog = contract["catalog"]
    notification = next(entry for entry in catalog["secrets"] if entry["name"] == "notification-tls-kms")
    if invalid == "unsupported":
        flow.contract_returncode = 2
        flow.contract_bytes = b"PRIVATE_UNSUPPORTED_OPERATOR_OUTPUT"
    elif invalid == "timeout":
        flow.contract_exception = bootstrap.subprocess.TimeoutExpired(
            ["PRIVATE_CONTRACT_COMMAND"], 10,
            output=b"PRIVATE_CONTRACT_OUTPUT", stderr=b"PRIVATE_CONTRACT_ERROR",
        )
    elif invalid == "unavailable":
        flow.contract_exception = OSError("PRIVATE_CONTRACT_PROCESS_ERROR")
    elif invalid == "empty":
        flow.contract_bytes = b""
    elif invalid == "malformed":
        flow.contract_bytes = b'{"PRIVATE_INVALID_JSON"'
    elif invalid == "non-utf8":
        flow.contract_bytes = b"\xff\xfePRIVATE_INVALID_ENCODING"
    elif invalid == "oversized":
        flow.contract_bytes = b" " * (128 * 1024) + bootstrap.encoded(contract)
    elif invalid == "array":
        flow.contract_bytes = b"[]"
    elif invalid == "schema":
        contract["schema"] = "marty.kubernetes-secret-publication/v0"
    elif invalid == "missing-secret":
        catalog["secrets"].remove(notification)
    elif invalid == "extra-secret":
        catalog["secrets"].append({
            "name": "unexpected-destination", "fields": {"token": {"env": "OPENBAO_SERVICE_TOKEN"}},
        })
    elif invalid == "duplicate-secret":
        catalog["secrets"].append(notification)
    elif invalid == "wrong-input":
        notification["fields"]["token"]["env"] = "OPENBAO_SERVICE_TOKEN"
    elif invalid == "wrong-key":
        notification["fields"]["password"] = notification["fields"].pop("token")
    elif invalid == "missing-required":
        catalog["required"].remove("NOTIFICATION_TLS_KMS_TOKEN")
    elif invalid == "boolean-version":
        catalog["schema_version"] = True  # bool and int compare equal in Python.
    elif invalid == "duplicate-json-member":
        # The last schema is correct: a permissive decoder would hide the first.
        flow.contract_bytes = b'{"schema":"PRIVATE_DUPLICATE_SCHEMA",' + bootstrap.encoded(contract)[1:]
    else:
        contract["private"] = "PRIVATE_EXTRA_CONTRACT_MEMBER"

    with pytest.raises(bootstrap.BootstrapError) as failure:
        bootstrap.bootstrap(flow.args)
    assert flow.events == ["prepare", "authenticated", "build-identity", "publication-contract"]
    assert not any(command[0] == "/synthetic/kubectl" for command in flow.processes)
    assert flow.cluster_operations == []
    assert flow.resources == [] and flow.token_commands == {}
    assert flow.init_calls == flow.publication_calls == 0
    for name in ("kubeconfig", "namespace.json", "initialize-requested.json",
                 "bootstrap-complete.json", "kubernetes-secret-publication.json"):
        assert not (flow.args.state_dir / name).exists()
    captured = capsys.readouterr()
    assert "PRIVATE_" not in str(failure.value) + captured.out + captured.err


def test_compiled_publication_preflight_retained_before_cluster_and_owns_notification(bootstrap_flow):
    flow = bootstrap_flow
    assert flow.args.runtime_source_sha != flow.args.chart_source_sha
    bootstrap.bootstrap(flow.args)
    contract = expected_publication_contract()
    assert flow.events[:6] == [
        "prepare", "authenticated", "build-identity", "publication-contract", "application-contract", "kubeconfig",
    ]
    assert flow.events.count("publication-contract") == 1
    assert flow.publication_before_cluster == contract
    state = flow.args.state_dir
    retained = state / "kubernetes-secret-publication.json"
    assert json.loads(retained.read_bytes()) == contract
    assert stat.S_IMODE(retained.stat().st_mode) == 0o600
    complete = json.loads((state / "bootstrap-complete.json").read_bytes())
    assert complete["credentialPublication"] == contract
    command, environment = flow.native_publication
    assert command == [
        str(state / "marty-deploy"), "--repo-root", str(bootstrap.ROOT),
        "kubernetes-secrets", "kubernetes-production", flow.args.namespace,
    ]
    assert environment["NOTIFICATION_WORKLOAD_SERVER_CERT_FILE"] == str(
        state / "credentials/notification_workload_server_cert")
    assert environment["NOTIFICATION_TLS_KMS_TOKEN_FILE"] == str(
        state / "credentials/notification_tls_kms_token")
    assert flow.supplemental_publications == [(
        "create", "secret", "generic", "marty-operator",
        "--from-file=password=" + str(state / "credentials/marty_org_admin_password"),
    )]


def test_lifecycle_receipt_binds_actual_producers_and_ordinary_token_requests(bootstrap_flow, capsys):
    flow = bootstrap_flow
    bootstrap.bootstrap(flow.args)
    state = flow.args.state_dir
    requested = json.loads((state / "initialize-requested.json").read_bytes())
    complete = json.loads((state / "bootstrap-complete.json").read_bytes())
    lifecycle = complete["credentialLifecycle"]

    assert flow.init_calls == flow.cleanup_calls == flow.publication_calls == 1
    assert flow.namespace_reads == flow.status_reads == 3
    assert requested == flow.requested_at_init
    assert requested["bootstrapId"] == complete["bootstrapId"]
    project = "marty-selfhost-disposable-k8s-" + PRODUCER_NONCE
    for record in (requested, lifecycle):
        assert record["namespaceUid"] == NAMESPACE_UID
        assert record["producerNonce"] == PRODUCER_NONCE
        assert record["workloadProject"] == project
    producer_env = dict(item.split("=", 1) for item in flow.workload_command[1:-1])
    assert producer_env["MARTY_SELFHOST_PROJECT"] == project
    assert flow.keycloak_context["nonce"] == PRODUCER_NONCE
    assert complete["openbaoClusterId"] == CLUSTER_ID
    assert complete["runtimeSourceSha"] == flow.args.runtime_source_sha
    assert complete["chartSourceSha"] == flow.args.chart_source_sha
    assert complete["status"] == "openbao-and-application-credentials-ready"
    assert lifecycle["schema"] == "marty.kubernetes-credential-lifecycle/v1"
    assert set(lifecycle) == {
        "schema", "namespaceUid", "producerNonce", "workloadProject", "ordinaryTokens",
    }
    requests = lifecycle["ordinaryTokens"]
    assert len(requests) == 13
    assert {entry["input"] for entry in requests} == set(EXPECTED_ORDINARY_POLICIES)
    for entry in requests:
        name = entry["input"]
        ttl = "2h" if name == "OPENBAO_BOOTSTRAP_TOKEN" else "8h"
        policies = EXPECTED_ORDINARY_POLICIES[name]
        assert entry == {
            "input": name, "requestedPolicies": policies, "requestedTtl": ttl,
            "requestedRenewable": False, "requestedOrphan": True,
            "requestedNoDefaultPolicy": True,
        }
        token = (state / "credentials" / name.lower()).read_bytes()
        assert flow.token_commands[token] == [
            "bao", "token", "create", "-no-default-policy", "-orphan",
            "-ttl=" + ttl, "-renewable=false", "-field=token",
            *["-policy=" + policy for policy in policies],
        ]

    # Sensitive sentinels really travelled through the private flow, but only
    # selected metadata is serialized to these safe receipt surfaces.
    assert ROOT_TOKEN.encode() in (state / "openbao-initialization.json").read_bytes()
    assert b"PRIVATE_SCALAR_CANARY" in (state / "credentials/keycloak_admin_password").read_bytes()
    assert b"PRIVATE_WORKLOAD_TOKEN_CANARY" in (state / "credentials/gateway_tls_kms_token").read_bytes()
    for name in ("namespace.json", "initialize-requested.json", "bootstrap-complete.json",
                 "kubernetes-secret-publication.json", "kubernetes-application-tokens.json",
                 "application-authority-requested.json"):
        path = state / name
        assert b"PRIVATE_" not in path.read_bytes()
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    captured = capsys.readouterr()
    assert "PRIVATE_" not in captured.out + captured.err


@pytest.mark.parametrize("uid", [None, "", False, "x" * 257, "../foreign", "line\nbreak"])
def test_initial_namespace_uid_refusal_prevents_initialization(bootstrap_flow, uid):
    flow = bootstrap_flow
    flow.namespace_documents[0]["metadata"]["uid"] = uid
    with pytest.raises(bootstrap.BootstrapError):
        bootstrap.bootstrap(flow.args)
    assert flow.init_calls == 0
    assert not (flow.args.state_dir / "initialize-requested.json").exists()
    assert not (flow.args.state_dir / "bootstrap-complete.json").exists()


def test_wrong_initial_namespace_name_prevents_initialization(bootstrap_flow):
    flow = bootstrap_flow
    flow.namespace_documents[0]["metadata"]["name"] = "foreign-namespace"
    with pytest.raises(bootstrap.BootstrapError):
        bootstrap.bootstrap(flow.args)
    assert flow.init_calls == 0
    assert not (flow.args.state_dir / "bootstrap-complete.json").exists()


@pytest.mark.parametrize("identity,field,value", [
    ("namespace", "uid", "65b79c11-558b-44eb-9ad1-1588882cd6b6"),
    ("namespace", "name", "foreign-namespace"),
    ("namespace", "uid", None),
    ("cluster", "cluster_id", "120bc8ac-bbc4-4316-b057-55126c4e4717"),
    ("cluster", "cluster_id", None),
    ("cluster", "cluster_id", ""),
    ("cluster", "initialized", False),
    ("cluster", "sealed", True),
    ("cluster", "type", "shamir"),
    ("cluster", "storage_type", "inmem"),
])
def test_final_identity_drift_withholds_success_receipt(bootstrap_flow, identity, field, value):
    flow = bootstrap_flow
    document = (flow.namespace_documents[2]["metadata"] if identity == "namespace"
                else flow.status_documents[2])
    document[field] = value
    with pytest.raises(bootstrap.BootstrapError):
        bootstrap.bootstrap(flow.args)
    assert flow.init_calls == flow.cleanup_calls == flow.publication_calls == 1
    assert flow.requested_at_init["workloadProject"] == "marty-selfhost-disposable-k8s-" + PRODUCER_NONCE
    assert (flow.args.state_dir / "initialize-requested.json").is_file()
    assert not (flow.args.state_dir / "bootstrap-complete.json").exists()


@pytest.mark.parametrize("cluster_id", [None, "", False, "x" * 257, "invalid\nid"])
def test_initial_cluster_identity_refusal_prevents_credential_provisioning(bootstrap_flow, cluster_id):
    flow = bootstrap_flow
    flow.status_documents[0]["cluster_id"] = cluster_id
    with pytest.raises(bootstrap.BootstrapError):
        bootstrap.bootstrap(flow.args)
    assert flow.init_calls == 1
    assert flow.token_commands == {}
    assert flow.workload_command is None
    assert flow.publication_calls == 0
    assert (flow.args.state_dir / "initialize-requested.json").is_file()
    assert not (flow.args.state_dir / "bootstrap-complete.json").exists()


@pytest.mark.parametrize("failure", [
    "producer", "producer-cleanup", "publication", "operator-publication",
])
def test_producer_or_publication_failure_preserves_request_without_success(bootstrap_flow, failure):
    flow = bootstrap_flow
    flow.fail_at = failure
    with pytest.raises(bootstrap.BootstrapError, match="synthetic"):
        bootstrap.bootstrap(flow.args)
    assert flow.init_calls == 1
    assert flow.cleanup_calls == 1
    assert flow.requested_at_init == json.loads(
        (flow.args.state_dir / "initialize-requested.json").read_bytes())
    assert not (flow.args.state_dir / "bootstrap-complete.json").exists()
    assert flow.publication_calls == (0 if failure in {"producer", "producer-cleanup"} else 1)
    retained_publication = flow.args.state_dir / "kubernetes-secret-publication.json"
    assert json.loads(retained_publication.read_bytes()) == expected_publication_contract()
    if failure != "operator-publication":
        assert flow.supplemental_publications == []


@pytest.mark.parametrize("nonce,project", [
    ("bad", "marty-selfhost-disposable-k8s-bad"),
    (PRODUCER_NONCE, "marty-selfhost-disposable-k8s-ffffffffffff"),
    (PRODUCER_NONCE, "marty-selfhost-" + PRODUCER_NONCE),
])
def test_unbound_producer_identity_is_rejected_before_mutation(tmp_path, nonce, project):
    class NoMutationTransport:
        state = tmp_path

        def create(self, resource):
            pytest.fail("invalid producer identity reached a cluster mutation")

    with pytest.raises(bootstrap.BootstrapError):
        bootstrap.provision_workload_identity(
            NoMutationTransport(), image="synthetic-image", operator=tmp_path / "unused-operator",
            root_token=ROOT_TOKEN, ca=b"synthetic-ca", nonce=nonce,
            workload_project=project, files={}, pull_secrets=[],
            binding={"workloadProject": project},
        )


@pytest.mark.parametrize("existing", ["file", "symlink"])
def test_new_lifecycle_record_does_not_overwrite_existing_destination(tmp_path, existing):
    destination = tmp_path / "bootstrap-complete.json"
    original = b"earlier evidence must survive"
    target = tmp_path / "unrelated-evidence.json"
    write_private(target, original)
    if existing == "symlink":
        destination.symlink_to(target)
    else:
        write_private(destination, original)
    with pytest.raises(FileExistsError):
        bootstrap.write_new(destination, bootstrap.encoded({"credentialLifecycle": {}}))
    assert destination.read_bytes() == target.read_bytes() == original
    assert destination.is_symlink() == (existing == "symlink")


@pytest.mark.parametrize("invalid", [
    "unsupported", "timeout", "malformed", "duplicate-json", "policy", "ttl-type", "replacement", "extra",
])
def test_application_contract_refuses_before_kubectl_including_config(bootstrap_flow, invalid, capsys):
    flow = bootstrap_flow
    contract = flow.application_contract
    if invalid == "unsupported":
        flow.application_contract_returncode = 2
        flow.application_contract_bytes = b"PRIVATE_UNSUPPORTED_APPLICATION_CONTRACT"
    elif invalid == "timeout":
        flow.application_contract_exception = bootstrap.subprocess.TimeoutExpired(
            ["PRIVATE_CONTRACT_CANARY"], 10, output=b"PRIVATE_RESPONSE_CANARY")
    elif invalid == "malformed":
        flow.application_contract_bytes = b'{"PRIVATE_INVALID_JSON"'
    elif invalid == "duplicate-json":
        flow.application_contract_bytes = b'{"schema":"PRIVATE_DUPLICATE",' + bootstrap.encoded(contract)[1:]
    elif invalid == "policy":
        contract["tokens"][0]["policies"] = ["root"]
    elif invalid == "ttl-type":
        contract["tokens"][0]["ttlSeconds"] = 28800.0
    elif invalid == "replacement":
        contract["tokens"][0]["replacementRole"] = "foreign-role"
    else:
        contract["private"] = "PRIVATE_EXTRA_MEMBER"
    with pytest.raises(bootstrap.BootstrapError) as error:
        bootstrap.bootstrap(flow.args)
    assert flow.events == ["prepare", "authenticated", "build-identity", "publication-contract", "application-contract"]
    assert flow.cluster_operations == [] and flow.resources == []
    assert not any(command[0] == "/synthetic/kubectl" for command in flow.processes)
    assert flow.init_calls == flow.authority_calls == flow.publication_calls == 0
    assert not (flow.args.state_dir / "bootstrap-complete.json").exists()
    assert "PRIVATE_" not in str(error.value) + "".join(capsys.readouterr())


def test_application_authority_enrollment_has_persisted_binding_and_exact_private_inputs(bootstrap_flow):
    flow = bootstrap_flow
    bootstrap.bootstrap(flow.args)
    state = flow.args.state_dir
    binding = {"namespace": flow.args.namespace, "namespaceUid": NAMESPACE_UID,
        "openbaoClusterId": CLUSTER_ID, "workloadProject": "marty-selfhost-disposable-k8s-" + PRODUCER_NONCE}
    assert flow.authority_calls == flow.authority_exports == flow.cleanup_calls == 1
    assert flow.authority_context == {"root_token": ROOT_TOKEN, "binding": binding,
                                     "current": "/tmp/application-current"}
    request = flow.authority_requested_at_call
    assert request["binding"] == binding and request["ordinaryInputs"] == list(bootstrap.TOKEN_POLICIES)
    pod = "marty-kms-bootstrap-" + PRODUCER_NONCE
    assert request["transportPod"] == pod and request["transportDeadlineSeconds"] == 1200
    current = {path.removeprefix("/tmp/application-current/"): value
               for (name, path), value in flow.uploads.items() if path.startswith("/tmp/application-current/")}
    assert set(current) == set(bootstrap.TOKEN_FILES.values()) and len(current) == 13
    assert all(value == (state / "credentials" / name).read_bytes() for name, value in current.items())
    identity = state / "application-identity"
    assert {path.name for path in identity.iterdir()} == bootstrap.APPLICATION_IDENTITY_FILES
    assert stat.S_IMODE(identity.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in identity.iterdir())
    assert json.loads((identity / "application-binding.json").read_bytes()) == binding
    complete = json.loads((state / "bootstrap-complete.json").read_bytes())
    assert complete["applicationAuthority"]["binding"] == binding
    assert complete["imagePullSecrets"] == ["registry-pull"]
    assert complete["applicationTokenContract"] == expected_application_contract()
    assert b"PRIVATE_" not in (state / "transport-pod.json").read_bytes()


@pytest.mark.parametrize("response", [
    b'{"ready":1}', b'{"ready":false}', b'{"ready":true,"extra":"PRIVATE_CANARY"}',
    b'{"ready":false,"ready":true}', b'[]',
])
def test_application_authority_success_response_is_exact_and_typed(bootstrap_flow, response, capsys):
    flow = bootstrap_flow
    flow.authority_response = response
    with pytest.raises(bootstrap.BootstrapError) as error:
        bootstrap.bootstrap(flow.args)
    assert flow.authority_calls == flow.authority_exports == flow.cleanup_calls == 1
    assert flow.publication_calls == 0
    assert (flow.args.state_dir / "application-authority-recovery.tar").exists()
    assert not (flow.args.state_dir / "bootstrap-complete.json").exists()
    assert "PRIVATE_" not in str(error.value) + "".join(capsys.readouterr())


@pytest.mark.parametrize("identity", ["namespace", "cluster"])
def test_enrollment_binding_is_fresh_before_authority_mutation(bootstrap_flow, identity):
    flow = bootstrap_flow
    if identity == "namespace":
        flow.namespace_documents[1]["metadata"]["uid"] = "20c184dc-712f-41c4-968d-d87027eb4981"
    else:
        flow.status_documents[1]["cluster_id"] = "20c184dc-712f-41c4-968d-d87027eb4981"
    with pytest.raises(bootstrap.BootstrapError):
        bootstrap.bootstrap(flow.args)
    assert flow.authority_calls == flow.publication_calls == 0 and flow.cleanup_calls == 1
    assert (flow.args.state_dir / "application-authority-requested.json").exists()
    assert not (flow.args.state_dir / "bootstrap-complete.json").exists()


@pytest.mark.parametrize("failure", ["authority", "authority-timeout", "authority-export"])
def test_uncertain_enrollment_or_failed_export_retains_bounded_pod_without_completion(bootstrap_flow, failure, capsys):
    flow = bootstrap_flow
    flow.fail_at = failure
    with pytest.raises(bootstrap.RetainProducerError) as error:
        bootstrap.bootstrap(flow.args)
    assert flow.authority_calls == 1 and flow.cleanup_calls == flow.publication_calls == 0
    assert not (flow.args.state_dir / "bootstrap-complete.json").exists()
    assert (flow.args.state_dir / "application-authority-recovery.tar").exists() == (failure != "authority-export")
    pointer = json.loads((flow.args.state_dir / "transport-pod.json").read_bytes())
    assert pointer["pod"] == "marty-kms-bootstrap-" + PRODUCER_NONCE
    assert pointer["activeDeadlineSeconds"] == 1200 and pointer["durableRecovery"] is False
    assert "1200-second total lifetime" in str(error.value) and "do not replay" in str(error.value)
    assert "PRIVATE_" not in str(error.value) + "".join(capsys.readouterr())


@pytest.mark.parametrize("invalid", ["extra", "missing", "mode", "binding", "root", "oversized-binding", "truncated"])
def test_application_identity_export_refuses_invalid_custody_without_false_completion(bootstrap_flow, invalid):
    flow = bootstrap_flow
    binding = {"namespace": flow.args.namespace, "namespaceUid": NAMESPACE_UID,
        "openbaoClusterId": CLUSTER_ID, "workloadProject": "marty-selfhost-disposable-k8s-" + PRODUCER_NONCE}
    kwargs = {}
    if invalid == "extra":
        kwargs["extra"] = {"unexpected": b"PRIVATE_UNEXPECTED_CANARY"}
    elif invalid == "missing":
        kwargs["missing"] = "application-secret-id"
    elif invalid == "mode":
        kwargs["mode"] = 0o644
    elif invalid == "binding":
        binding["namespaceUid"] = "20c184dc-712f-41c4-968d-d87027eb4981"
    elif invalid == "root":
        kwargs["extra"] = {"application-secret-id": ROOT_TOKEN.encode()}
    elif invalid == "oversized-binding":
        kwargs["extra"] = {"application-binding.json": b" " * 4098 + bootstrap.encoded(binding)}
    payload = application_identity_archive(binding, **kwargs)
    if invalid == "truncated":
        payload = payload[:3072]  # All three file records, but no tar terminator.
    flow.authority_archive_override = payload
    with pytest.raises(bootstrap.BootstrapError):
        bootstrap.bootstrap(flow.args)
    assert flow.authority_calls == 1 and flow.publication_calls == 0
    retained = invalid in {"extra", "mode", "oversized-binding", "truncated"}
    assert flow.cleanup_calls == (0 if retained else 1)
    assert not (flow.args.state_dir / "bootstrap-complete.json").exists()


@pytest.mark.parametrize("source_state", ["valid", "missing", "not-directory", "oversized"])
def test_real_posix_archive_command_observes_tar_failure_and_bounds_output(tmp_path, source_state):
    source, temporary = tmp_path / "source", tmp_path / "private-export.tar"
    if source_state == "not-directory":
        write_private(source, b"PRIVATE_SOURCE_CANARY")
    elif source_state != "missing":
        source.mkdir(mode=0o700)
        write_private(source / "attempt.json", b"PRIVATE_SOURCE_CANARY" * (1000 if source_state == "oversized" else 1))
    results = []

    class LocalTransport:
        def execute(self, pod, command):
            assert pod == "fixture" and command[4] == "/tmp/application-operation"
            assert command[6].startswith("/tmp/marty-native-export-")
            command = [*command[:4], str(source), command[5], str(temporary)]
            result = bootstrap.subprocess.run(command, capture_output=True, timeout=10,
                                              env={"PATH": os.defpath}, check=False)
            results.append(result)
            if result.returncode:
                raise bootstrap.BootstrapError("private archive producer failed")
            return result.stdout

    if source_state == "valid":
        payload = bootstrap.remote_archive(LocalTransport(), "fixture", "/tmp/application-operation", 10240)
        assert bootstrap.flat_archive(payload, {"attempt.json"}, maximum=10240,
            modes={0o600})["attempt.json"][0] == b"PRIVATE_SOURCE_CANARY"
        assert results[0].returncode == 0
    else:
        with pytest.raises(bootstrap.BootstrapError, match="producer failed"):
            bootstrap.remote_archive(LocalTransport(), "fixture", "/tmp/application-operation", 10240)
        assert results[0].returncode != 0 and results[0].stdout == b""
    assert not temporary.exists()
