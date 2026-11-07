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
        bootstrap.prepare_namespace(transport, "fixture-bootstrap")
    assert name in transport.inspected_secrets
    assert transport.mutations == []
    assert list(tmp_path.iterdir()) == []


def test_existing_ingress_and_registry_secrets_are_preserved(tmp_path):
    transport = ExistingNamespace(tmp_path, {"marty-ingress-tls", "registry-pull"})
    identity = bootstrap.prepare_namespace(transport, "fixture-bootstrap")
    assert transport.mutations == []
    assert transport.secrets == {"marty-ingress-tls", "registry-pull"}
    assert identity == {"name": "marty-test", "uid": "namespace-fixture"}
    assert json.loads((tmp_path / "namespace.json").read_bytes())["uid"] == "namespace-fixture"


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
        namespace_documents=[
            {"metadata": {"name": args.namespace, "uid": NAMESPACE_UID}},
            {"metadata": {"name": args.namespace, "uid": NAMESPACE_UID}},
        ],
        status_documents=[dict(ready), dict(ready)],
        token_commands={}, uploads={}, resources=[], workload_command=None,
        keycloak_context=None, requested_at_init=None,
    )
    operator_bytes = b"synthetic authenticated operator; never executed"

    def prepared(**kwargs):
        assert kwargs["assets"] == args.assets
        for key in ("output", "openbao_output"):
            bootstrap.write_new(kwargs[key], b"{}")
        return values, {}

    def authenticated(assets, identity):
        assert assets == args.assets and identity == values["release"]
        return operator_bytes, b"synthetic authenticated initializer; never executed"

    def process(command, **kwargs):
        if command == [str(args.state_dir / "marty-deploy"), "--build-identity"]:
            stdout = (args.runtime_source_sha + ":" + args.release_tag).encode()
        elif command[:1] == ["/synthetic/kubectl"] and "config" in command:
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
            if operation == "official OpenBao Helm installation":
                return b""
            assert operation == "native Kubernetes credential publication"
            flow.publication_calls += 1
            assert kwargs["env"]["KUBECONFIG"] == str(self.state / "kubeconfig")
            if flow.fail_at == "publication":
                raise bootstrap.BootstrapError("synthetic publication failure")
            return b""

        def create(self, document):
            flow.resources.append(document)

        def upload(self, pod, destination, contents, **kwargs):
            flow.uploads[(pod, destination)] = contents

        def kubectl(self, operation, *command, **kwargs):
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
                if flow.fail_at == "notification-publication" and command[3] == "notification-tls-kms":
                    raise bootstrap.BootstrapError("synthetic Notification publication failure")
                return b""
            raise AssertionError("unexpected Kubernetes operation: " + operation)

        def execute(self, pod, command, *, data=None, **kwargs):
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


def test_lifecycle_receipt_binds_actual_producers_and_ordinary_token_requests(bootstrap_flow, capsys):
    flow = bootstrap_flow
    bootstrap.bootstrap(flow.args)
    state = flow.args.state_dir
    requested = json.loads((state / "initialize-requested.json").read_bytes())
    complete = json.loads((state / "bootstrap-complete.json").read_bytes())
    lifecycle = complete["credentialLifecycle"]

    assert flow.init_calls == flow.cleanup_calls == flow.publication_calls == 1
    assert flow.namespace_reads == flow.status_reads == 2
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
    for name in ("namespace.json", "initialize-requested.json", "bootstrap-complete.json"):
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
    document = (flow.namespace_documents[1]["metadata"] if identity == "namespace"
                else flow.status_documents[1])
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
    "producer", "producer-cleanup", "publication", "notification-publication",
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
