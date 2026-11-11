"""Refusal tests for existing Secret custody and untrusted bootstrap outputs."""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import shlex
import stat
import subprocess
import sys
import tarfile
from types import SimpleNamespace
import zipfile

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import bootstrap_kubernetes_openbao as bootstrap


pytestmark = pytest.mark.skipif(os.name != "posix", reason="Linux bootstrap file contract")
REAL_RUN = subprocess.run


def capture_private_directory_commands(monkeypatch, transport_class):
    """Keep the commands emitted by a real adapter before its cluster double."""
    commands = []
    execute = transport_class.execute

    def captured(self, pod, command, **kwargs):
        if command[:2] == ["/bin/sh", "-ec"] and "mkdir " in command[2]:
            assert kwargs.get("data") is None
            commands.append(command)
        return execute(self, pod, command, **kwargs)

    monkeypatch.setattr(transport_class, "execute", captured)
    return commands


def assert_private_directory_command(command, tmp_path):
    """Run the actual mkdir/chmod command on the fsGroup-style filesystem."""
    volume = tmp_path / "setgid volume"
    volume.mkdir(mode=0o700)
    volume.chmod(0o2770)
    inherited = volume / "inheritance-probe"
    inherited.mkdir(mode=0o700)
    assert stat.S_IMODE(inherited.stat().st_mode) == 0o2700
    inherited.rmdir()

    assert command[:2] == ["/bin/sh", "-ec"]
    script = command[2]
    if len(command) == 3:
        # The pod's bounded sleep is unrelated to directory creation.
        assert script.endswith("; exec sleep 1200")
        script = script.removesuffix("; exec sleep 1200")
        destinations = ["/tmp/workload-tls"]
        script = script.replace(destinations[0], shlex.quote(str(volume / "workload-tls")))
        arguments = []
    else:
        assert command[3] == "--"
        destinations = command[4:]
        arguments = ["--", *(str(volume / Path(path).relative_to("/tmp")) for path in destinations)]
    result = REAL_RUN(["/bin/sh", "-ec", script, *arguments], capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr.decode()
    for path in destinations:
        directory = volume / Path(path).relative_to("/tmp")
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700, str(path)
        assert directory.stat().st_uid == os.geteuid()
        child = directory / "native-child"
        child.mkdir(mode=0o700)
        assert stat.S_IMODE(child.stat().st_mode) == 0o700
        child.rmdir()
        archive = REAL_RUN(["tar", "-cf", "-", "-C", str(directory), "."],
                           capture_output=True, check=True, timeout=10).stdout
        names = {"."} | {str(item.relative_to(directory)) for item in directory.rglob("*")}
        assert bootstrap.private_archive(archive, {}, maximum=64 * 1024, modes={0o600},
            directories=names, complete=True, allow_empty=True) == {}
    assert stat.S_IMODE(volume.stat().st_mode) == 0o2770


def test_real_directory_archive_still_rejects_setgid_custody(tmp_path):
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    directory.chmod(0o2700)
    archive = REAL_RUN(["tar", "-cf", "-", "-C", str(directory), "."],
                       capture_output=True, check=True, timeout=10).stdout
    with pytest.raises(bootstrap.BootstrapError, match="directory custody differs"):
        bootstrap.private_archive(archive, {}, maximum=64 * 1024, modes={0o600},
            directories={"."}, complete=True, allow_empty=True)


def expected_publication_contract():
    return {
        "schema": "marty.kubernetes-secret-publication/v1",
        "catalog": json.loads(
            (bootstrap.ROOT / "deploy-config/catalog/kubernetes-secrets.json").read_bytes()),
    }


def expected_application_contract():
    return json.loads((bootstrap.ROOT / "deploy-config/catalog/kubernetes-application-tokens.json").read_bytes())


def expected_renewal_contract():
    return {
        "schema": "marty.kubernetes-renewal/v1",
        "enrollmentOperation": "kubernetes-renewal-enroll",
        "stagingOperation": "kubernetes-renewal-stage",
        "bindingSchema": "marty.kubernetes-renewal-binding/v1",
        "identityFiles": ["renewal-leaf-policies.json", "renewal-role-id", "renewal-secret-id"],
        "minimumTtlSeconds": 3600, "operationBudgetSeconds": 900,
        "renewableFiles": sorted(set(bootstrap.SELFHOST_TLS_FILES) | bootstrap.KEYCLOAK_FILES),
        "unchangedFiles": ["workload_identity_ca_cert"], "changedFiles": 39,
        "scopedLeafTokens": 21, "tlsMetadataFile": "selfhost-tls-kms-roles.json",
    }


def renewal_archive(members, *, mode=0o600):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as archive:
        for name, value in members.items():
            entry = tarfile.TarInfo("./" + name)
            entry.mode, entry.size = mode, len(value)
            archive.addfile(entry, io.BytesIO(value))
    return raw.getvalue()


def renewal_identity_members():
    return {
        "renewal-role-id": b"PUBLIC_RENEWAL_ROLE_ID_CANARY",
        "renewal-secret-id": b"PRIVATE_RENEWAL_SECRET_ID_CANARY",
        "renewal-leaf-policies.json": bootstrap.encoded([f"policy-{index:02d}" for index in range(21)]),
    }


def renewal_evidence_members(binding):
    nonce = binding["workloadProject"].removeprefix("marty-selfhost-disposable-k8s-")
    return {
        "pending.json": bootstrap.encoded({"binding": binding}),
        "binding.json": bootstrap.encoded({"schema": "marty.kubernetes-renewal-binding/v1",
            "binding": binding, "producerNonce": nonce}),
        "completed.json": bootstrap.encoded({"schema": "marty.kubernetes-renewal-enrollment/v1",
            "binding": binding, "producerNonce": nonce,
            "identityFiles": sorted(bootstrap.RENEWAL_IDENTITY_FILES),
            "scopedLeafTokens": 21, "enrolled": True, "activated": False}),
    }


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
    write_private(args.helm, b"synthetic executable; never launched")
    args.helm.chmod(0o700)
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
        helm_version=b"v3.22.1+gfixture\n", helm_returncode=0, helm_exception=None,
        namespace_exists=True,
        pull_secret_summaries={"registry-pull": b"registry-pull\tkubernetes.io/dockerconfigjson"},
        namespace_reads=0, status_reads=0, publication_calls=0,
        publication_contract=expected_publication_contract(), contract_bytes=None,
        contract_returncode=0, contract_exception=None,
        application_contract=expected_application_contract(), application_contract_bytes=None,
        application_contract_returncode=0, application_contract_exception=None,
        renewal_contract=expected_renewal_contract(), renewal_contract_bytes=None,
        renewal_contract_returncode=0, renewal_contract_exception=None,
        renewal_calls=0, renewal_context=None, renewal_requested_at_call=None,
        renewal_current_archive=None, renewal_identity_override=None, renewal_evidence_override=None,
        renewal_response=bootstrap.encoded({"ready": True, "identity": "/tmp/renewal-identity",
            "binding": "/tmp/renewal-enrollment/binding.json", "count": 3}),
        authority_calls=0, authority_context=None, authority_requested_at_call=None,
        authority_exports=0, authority_archive_override=None,
        authority_response=b'{"ready":true}',
        processes=[], cluster_operations=[], supplemental_publications=[], events=[],
        publication_before_cluster=None, native_publication=None,
        namespace_documents=[
            {"metadata": {"name": args.namespace, "uid": NAMESPACE_UID}},
            {"metadata": {"name": args.namespace, "uid": NAMESPACE_UID}},
            {"metadata": {"name": args.namespace, "uid": NAMESPACE_UID}},
            {"metadata": {"name": args.namespace, "uid": NAMESPACE_UID}},
        ],
        status_documents=[dict(ready), dict(ready), dict(ready), dict(ready)],
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
        if command == [str(args.helm.resolve()), "version", "--short"]:
            assert kwargs["stdin"] == subprocess.DEVNULL and kwargs["timeout"] == 10
            if flow.helm_exception:
                raise flow.helm_exception
            return SimpleNamespace(returncode=flow.helm_returncode, stdout=flow.helm_version,
                                   stderr=b"PRIVATE_HELM_DIAGNOSTIC_CANARY")
        elif command == [str(args.state_dir / "marty-deploy"), "--build-identity"]:
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
        elif command == [str(args.state_dir / "marty-deploy"), "kubernetes-renewal-contract"]:
            flow.events.append("renewal-contract")
            assert kwargs["env"] == {} and kwargs["stdin"] == bootstrap.subprocess.DEVNULL
            if flow.renewal_contract_exception:
                raise flow.renewal_contract_exception
            return SimpleNamespace(returncode=flow.renewal_contract_returncode,
                stdout=(bootstrap.encoded(flow.renewal_contract)
                        if flow.renewal_contract_bytes is None else flow.renewal_contract_bytes),
                stderr=b"PRIVATE_RENEWAL_CONTRACT_DIAGNOSTIC_CANARY")
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
                assert command[0] == str(args.helm.resolve())
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
            if operation == "image pull Secret preflight":
                assert command[:2] == ("get", "secret")
                assert command[3:] == ("--ignore-not-found", "--request-timeout=10s",
                                      '-o=jsonpath={.metadata.name}{"\\t"}{.type}')
                assert kwargs["timeout"] == 15
                if flow.fail_at == "pull-secret-read":
                    raise bootstrap.BootstrapError("image pull Secret preflight failed; private diagnostics retained")
                return flow.pull_secret_summaries.get(command[2], b"")
            if operation == "namespace inspection":
                return (bootstrap.encoded(flow.namespace_documents[0]) if flow.namespace_exists else b"")
            if operation == "namespace workload inspection":
                return b'{"items":[]}'
            if operation == "namespace Secret inspection":
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
                if command[2] == 'umask 077; mkdir "$1" "$2"; chmod u=rwx,go=,a-s,a-t "$1" "$2"':
                    assert command[4:] == ["/tmp/application-current", "/tmp/application-identity"]
                    return b""
                if command[2] == 'umask 077; mkdir "$1" "$2" "$3"; chmod u=rwx,go=,a-s,a-t "$1" "$2" "$3"':
                    assert command[4:] == ["/tmp/renewal-current", "/tmp/renewal-identity",
                                           "/tmp/renewal-enrollment"]
                    return b""
                if command[2] == bootstrap.REMOTE_ARCHIVE_COMMAND:
                    if command[4] == "/tmp/renewal-identity":
                        if flow.fail_at == "renewal-identity-export":
                            raise bootstrap.BootstrapError("synthetic private renewal export failure")
                        return (flow.renewal_identity_override if flow.renewal_identity_override is not None
                                else renewal_archive(renewal_identity_members()))
                    if command[4] == "/tmp/renewal-enrollment":
                        if flow.fail_at == "renewal-evidence-export":
                            raise bootstrap.BootstrapError("synthetic private renewal evidence failure")
                        return (flow.renewal_evidence_override if flow.renewal_evidence_override is not None
                                else renewal_archive(renewal_evidence_members(flow.renewal_context["binding"])))
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
            if command == ["tar", "-xf", "-", "-C", "/tmp/renewal-current"]:
                flow.renewal_current_archive = data
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
            if command[:3] == ["/tmp/marty-deploy", "operator", "kubernetes-renewal-enroll"]:
                assert command[3:] == ["https://openbao:8200", "/tmp/ca.crt", "/tmp/renewal-identity"]
                assert kwargs["timeout"] == 930
                flow.renewal_calls += 1
                flow.renewal_context = json.loads(data)
                flow.renewal_requested_at_call = json.loads(
                    (self.state / "renewal-authority-requested.json").read_bytes())
                assert flow.namespace_reads == flow.status_reads == 3
                if flow.fail_at == "renewal-native":
                    raise bootstrap.BootstrapError("PRIVATE_RENEWAL_RESPONSE_CANARY")
                if flow.fail_at == "renewal-timeout":
                    raise bootstrap.subprocess.TimeoutExpired(command, 930,
                        output=b"PRIVATE_RENEWAL_UNCERTAIN_CANARY")
                return flow.renewal_response
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


@pytest.mark.parametrize("invalid", ["missing", "directory", "not-executable", "fails", "timeout", "os-error", "wrong-major", "malformed", "oversized"])
def test_helm_preflight_refuses_before_state_and_cluster(bootstrap_flow, invalid, capsys):
    flow = bootstrap_flow
    if invalid == "missing":
        flow.args.helm.unlink()
    elif invalid == "directory":
        flow.args.helm.unlink()
        flow.args.helm.mkdir()
    elif invalid == "not-executable":
        flow.args.helm.chmod(0o600)
    elif invalid == "fails":
        flow.helm_returncode = 1
    elif invalid == "timeout":
        flow.helm_exception = subprocess.TimeoutExpired(
            ["PRIVATE_HELM_COMMAND_CANARY"], 10, output=b"PRIVATE_HELM_OUTPUT_CANARY")
    elif invalid == "os-error":
        flow.helm_exception = OSError("PRIVATE_HELM_FAILURE_CANARY")
    elif invalid == "wrong-major":
        flow.helm_version = b"v4.0.0\n"
    elif invalid == "malformed":
        flow.helm_version = b"PRIVATE_HELM_OUTPUT_CANARY"
    else:
        flow.helm_version = b"v3.22.1+" + b"x" * 256
    with pytest.raises(bootstrap.BootstrapError, match="Helm") as failure:
        bootstrap.bootstrap(flow.args)
    assert not flow.args.state_dir.exists()
    assert flow.events == flow.cluster_operations == flow.resources == []
    assert flow.init_calls == 0
    captured = capsys.readouterr()
    assert "PRIVATE_" not in str(failure.value) + captured.out + captured.err


@pytest.mark.parametrize("names", [
    [""], ["-registry"], ["registry-"], ["Registry"], ["registry..pull"],
    ["registry/pull"], ["a" * 254], ["registry-pull", "registry-pull"],
    ["registry-" + str(index) for index in range(17)],
])
def test_image_pull_secret_names_refused_before_state_and_processes(bootstrap_flow, names):
    flow = bootstrap_flow
    flow.args.image_pull_secret = names
    with pytest.raises(bootstrap.BootstrapError, match="Secret"):
        bootstrap.bootstrap(flow.args)
    assert not flow.args.state_dir.exists()
    assert flow.events == flow.processes == flow.cluster_operations == flow.resources == []


@pytest.mark.parametrize("summary", [
    b"", b"registry-pull\tOpaque", b"registry-pull\tkubernetes.io/tls",
    b"wrong-name\tkubernetes.io/dockerconfigjson", b"PRIVATE_SECRET_RESPONSE_CANARY",
])
def test_image_pull_secret_preflight_refuses_before_namespace_or_seal_write(bootstrap_flow, summary, capsys):
    flow = bootstrap_flow
    flow.pull_secret_summaries["registry-pull"] = summary
    with pytest.raises(bootstrap.BootstrapError, match="image pull Secret") as failure:
        bootstrap.bootstrap(flow.args)
    assert flow.cluster_operations == ["image pull Secret preflight"]
    assert flow.resources == [] and flow.init_calls == flow.publication_calls == 0
    for name in ("namespace.json", "static.key", "initialize-requested.json", "bootstrap-complete.json"):
        assert not (flow.args.state_dir / name).exists()
    assert (flow.args.state_dir / "kubernetes-secret-publication.json").exists()
    captured = capsys.readouterr()
    assert "PRIVATE_" not in str(failure.value) + captured.out + captured.err


def test_image_pull_secret_read_failure_never_reaches_initialization(bootstrap_flow):
    flow = bootstrap_flow
    flow.fail_at = "pull-secret-read"
    with pytest.raises(bootstrap.BootstrapError, match="image pull Secret preflight failed"):
        bootstrap.bootstrap(flow.args)
    assert flow.cluster_operations == ["image pull Secret preflight"]
    assert flow.resources == [] and flow.init_calls == 0


@pytest.mark.parametrize("kind", ["kubernetes.io/dockerconfigjson", "kubernetes.io/dockercfg"])
def test_image_pull_secret_preflight_accepts_supported_registry_types(bootstrap_flow, kind):
    flow = bootstrap_flow
    flow.pull_secret_summaries["registry-pull"] = ("registry-pull\t" + kind).encode()
    bootstrap.bootstrap(flow.args)
    assert flow.cluster_operations[0] == "image pull Secret preflight"
    assert flow.cluster_operations.index("image pull Secret preflight") < flow.cluster_operations.index("create")
    assert flow.init_calls == 1
    assert (flow.args.state_dir / "bootstrap-complete.json").is_file()


def test_public_registry_bootstrap_does_not_require_pull_secrets(bootstrap_flow):
    flow = bootstrap_flow
    flow.args.image_pull_secret = []
    flow.namespace_exists = False
    bootstrap.bootstrap(flow.args)
    assert "image pull Secret preflight" not in flow.cluster_operations
    assert any(resource["kind"] == "Namespace" for resource in flow.resources)
    assert flow.init_calls == 1


@pytest.mark.parametrize("names", [[], ["registry-pull"], ["second-registry", "first-registry"]])
def test_registry_selection_is_shared_with_application_and_openbao_values(bootstrap_flow, names):
    flow = bootstrap_flow
    flow.args.image_pull_secret = names
    flow.pull_secret_summaries = {
        name: (name + "\tkubernetes.io/dockerconfigjson").encode() for name in names
    }
    bootstrap.bootstrap(flow.args)
    state = flow.args.state_dir
    expected = [{"name": name} for name in names]
    for filename, document in (
        ("marty-pull-secrets.json", {"imagePullSecrets": expected}),
        ("openbao-pull-secrets.json", {"global": {"imagePullSecrets": expected}}),
    ):
        path = state / filename
        assert json.loads(path.read_bytes()) == document
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert b"PRIVATE_" not in path.read_bytes()
    assert (state / "marty-images.json").read_bytes() == b"{}"
    assert (state / "openbao-images.json").read_bytes() == b"{}"
    producer = next(resource for resource in flow.resources if resource["kind"] == "Pod")
    assert producer["spec"]["imagePullSecrets"] == expected
    assert json.loads((state / "bootstrap-complete.json").read_bytes())["imagePullSecrets"] == names


def test_selected_helm_relative_path_is_not_resolved_through_path(tmp_path, monkeypatch):
    binary = tmp_path / "helm"
    write_private(binary, b"synthetic executable; never launched")
    binary.chmod(0o700)
    monkeypatch.chdir(tmp_path)
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout=b"v3.22.1\n", stderr=b"")

    monkeypatch.setattr(bootstrap.subprocess, "run", run)
    assert bootstrap.helm_executable(Path("helm")) == binary
    assert calls == [[str(binary), "version", "--short"]]


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


@pytest.mark.parametrize("site", ["workload", "application", "renewal"])
def test_bootstrap_private_directories_clear_inherited_setgid(bootstrap_flow, tmp_path, monkeypatch, site):
    commands = capture_private_directory_commands(monkeypatch, bootstrap.Transport)
    bootstrap.bootstrap(bootstrap_flow.args)
    pod = next(resource for resource in bootstrap_flow.resources if resource["kind"] == "Pod")
    assert len(commands) == 2
    selected = {"workload": pod["spec"]["containers"][0]["command"],
                "application": commands[0], "renewal": commands[1]}
    assert_private_directory_command(selected[site], tmp_path)


def test_compiled_publication_preflight_retained_before_cluster_and_owns_notification(bootstrap_flow):
    flow = bootstrap_flow
    assert flow.args.runtime_source_sha != flow.args.chart_source_sha
    bootstrap.bootstrap(flow.args)
    contract = expected_publication_contract()
    assert flow.events[:7] == [
        "prepare", "authenticated", "build-identity", "publication-contract", "application-contract",
        "renewal-contract", "kubeconfig",
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
    assert flow.namespace_reads == flow.status_reads == 4
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
    document = (flow.namespace_documents[3]["metadata"] if identity == "namespace"
                else flow.status_documents[3])
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


@pytest.mark.parametrize("invalid", [
    "unsupported", "timeout", "malformed", "duplicate", "ttl-type", "changed-count",
    "extra-input", "missing-input", "authority-count", "budget", "extra-field",
])
def test_renewal_capability_refuses_before_kubernetes_context_selection(bootstrap_flow, invalid, capsys):
    flow = bootstrap_flow
    contract = flow.renewal_contract
    if invalid == "unsupported":
        flow.renewal_contract_returncode = 2
    elif invalid == "timeout":
        flow.renewal_contract_exception = bootstrap.subprocess.TimeoutExpired(
            ["PRIVATE_RENEWAL_CONTRACT"], 10, output=b"PRIVATE_RENEWAL_OUTPUT")
    elif invalid == "malformed":
        flow.renewal_contract_bytes = b'{"PRIVATE_BAD_JSON"'
    elif invalid == "duplicate":
        flow.renewal_contract_bytes = b'{"schema":"PRIVATE_DUPLICATE",' + bootstrap.encoded(contract)[1:]
    elif invalid == "ttl-type":
        contract["minimumTtlSeconds"] = "3600"
    elif invalid == "changed-count":
        contract["changedFiles"] = 40
    elif invalid == "extra-input":
        contract["renewableFiles"].append("unreviewed-token")
    elif invalid == "missing-input":
        contract["renewableFiles"].pop()
    elif invalid == "authority-count":
        contract["scopedLeafTokens"] = 22
    elif invalid == "budget":
        contract["operationBudgetSeconds"] = 1200
    else:
        contract["private"] = "PRIVATE_EXTRA_FIELD"
    with pytest.raises(bootstrap.BootstrapError) as failure:
        bootstrap.bootstrap(flow.args)
    assert flow.events == ["prepare", "authenticated", "build-identity", "publication-contract",
                           "application-contract", "renewal-contract"]
    assert flow.cluster_operations == [] and flow.init_calls == flow.renewal_calls == 0
    assert not (flow.args.state_dir / "kubeconfig").exists()
    captured = capsys.readouterr()
    assert "PRIVATE_" not in str(failure.value) + captured.out + captured.err


def test_fresh_bootstrap_enrolls_renewal_from_complete_generation_with_original_binding(bootstrap_flow):
    flow = bootstrap_flow
    bootstrap.bootstrap(flow.args)
    state = flow.args.state_dir
    complete = json.loads((state / "bootstrap-complete.json").read_bytes())
    authority = complete["renewalAuthority"]
    binding = complete["applicationAuthority"]["binding"]
    assert authority == {"schema": "marty.kubernetes-renewal-authority/v1", "binding": binding,
        "identityDirectory": "renewal-identity", "files": sorted(bootstrap.RENEWAL_IDENTITY_FILES),
        "bindingFile": "renewal-binding.json"}
    assert complete["renewalContract"] == expected_renewal_contract()
    assert len(complete["renewalContract"]["renewableFiles"]) == 40
    assert flow.renewal_calls == 1
    assert flow.renewal_context == {"root_token": ROOT_TOKEN, "binding": binding,
        "current": "/tmp/renewal-current", "output": "/tmp/renewal-enrollment"}
    request = flow.renewal_requested_at_call
    assert request == json.loads((state / "renewal-authority-requested.json").read_bytes())
    assert request["binding"] == binding and request["transportDeadlineSeconds"] == 1200
    source = state / "credentials"
    members = bootstrap.flat_archive(flow.renewal_current_archive,
        {entry.name for entry in source.iterdir()}, maximum=9 * 1024 * 1024, modes={0o600})
    assert request["currentFiles"] == len(members) > 40
    for name, (value, mode) in members.items():
        assert value == (source / name).read_bytes() and mode == 0o600
    identity = state / "renewal-identity"
    assert {path.name for path in identity.iterdir()} == bootstrap.RENEWAL_IDENTITY_FILES
    assert stat.S_IMODE(identity.stat().st_mode) == 0o700
    for name, value in renewal_identity_members().items():
        assert (identity / name).read_bytes() == value
        assert stat.S_IMODE((identity / name).stat().st_mode) == 0o600
    receipt = json.loads((state / "renewal-binding.json").read_bytes())
    assert receipt["binding"] == binding and receipt["producerNonce"] == PRODUCER_NONCE
    for name in ("renewal-authority-requested.json", "renewal-binding.json", "kubernetes-renewal.json",
                 "bootstrap-complete.json"):
        assert b"PRIVATE_" not in (state / name).read_bytes()
    assert (state / "renewal-enrollment-evidence.tar").is_file()


@pytest.mark.parametrize("identity", ["namespace", "cluster"])
def test_renewal_enrollment_checks_binding_again_before_root_mutation(bootstrap_flow, identity):
    flow = bootstrap_flow
    if identity == "namespace":
        flow.namespace_documents[2]["metadata"]["uid"] = "20c184dc-712f-41c4-968d-d87027eb4981"
    else:
        flow.status_documents[2]["cluster_id"] = "20c184dc-712f-41c4-968d-d87027eb4981"
    with pytest.raises(bootstrap.BootstrapError):
        bootstrap.bootstrap(flow.args)
    assert flow.authority_calls == 1 and flow.renewal_calls == flow.publication_calls == 0
    assert flow.cleanup_calls == 1
    assert (flow.args.state_dir / "renewal-authority-requested.json").exists()
    assert not (flow.args.state_dir / "bootstrap-complete.json").exists()


@pytest.mark.parametrize("failure", [
    "renewal-native", "renewal-timeout", "renewal-identity-export", "renewal-evidence-export",
])
def test_renewal_uncertainty_preserves_original_bounded_pod_and_never_completes(bootstrap_flow, failure, capsys):
    flow = bootstrap_flow
    flow.fail_at = failure
    with pytest.raises(bootstrap.RetainProducerError, match="do not replay") as error:
        bootstrap.bootstrap(flow.args)
    assert flow.renewal_calls == 1 and flow.cleanup_calls == flow.publication_calls == 0
    state = flow.args.state_dir
    assert not (state / "bootstrap-complete.json").exists()
    assert (state / "renewal-authority-requested.json").exists()
    pointer = json.loads((state / "transport-pod.json").read_bytes())
    assert pointer["activeDeadlineSeconds"] == 1200 and pointer["durableRecovery"] is False
    assert len([item for item in flow.resources if item["kind"] == "Pod"]) == 1
    if failure in {"renewal-native", "renewal-timeout"}:
        assert (state / "renewal-authority-recovery.tar").exists()
        assert (state / "renewal-enrollment-recovery.tar").exists()
    captured = capsys.readouterr()
    assert "PRIVATE_" not in str(error.value) + captured.out + captured.err


@pytest.mark.parametrize("value", [False, 1, "true", None])
def test_renewal_success_requires_typed_native_readiness_and_retainable_evidence(bootstrap_flow, value):
    flow = bootstrap_flow
    response = json.loads(flow.renewal_response)
    response["ready"] = value
    flow.renewal_response = bootstrap.encoded(response)
    with pytest.raises(bootstrap.BootstrapError, match="do not replay"):
        bootstrap.bootstrap(flow.args)
    assert flow.renewal_calls == flow.cleanup_calls == 1 and flow.publication_calls == 0
    assert (flow.args.state_dir / "renewal-authority-recovery.tar").exists()
    assert (flow.args.state_dir / "renewal-enrollment-recovery.tar").exists()
    assert not (flow.args.state_dir / "bootstrap-complete.json").exists()


@pytest.mark.parametrize("invalid", ["missing", "root", "shared", "extra", "duplicate-policy", "ingress", "mode"])
def test_renewal_identity_export_refuses_broadened_or_malformed_private_inventory(bootstrap_flow, invalid):
    flow = bootstrap_flow
    members = renewal_identity_members()
    if invalid == "missing":
        members.pop("renewal-secret-id")
    elif invalid == "root":
        members["renewal-secret-id"] = ROOT_TOKEN.encode()
    elif invalid == "shared":
        members["renewal-secret-id"] = members["renewal-role-id"]
    elif invalid == "extra":
        members["root.token"] = ROOT_TOKEN.encode()
    elif invalid in {"duplicate-policy", "ingress"}:
        policies = json.loads(members["renewal-leaf-policies.json"])
        policies[-1] = policies[0] if invalid == "duplicate-policy" else "installer-ingress-" + "a" * 32
        members["renewal-leaf-policies.json"] = bootstrap.encoded(sorted(policies))
    flow.renewal_identity_override = renewal_archive(members, mode=0o644 if invalid == "mode" else 0o600)
    with pytest.raises(bootstrap.BootstrapError):
        bootstrap.bootstrap(flow.args)
    assert flow.renewal_calls == 1 and flow.publication_calls == 0
    assert not (flow.args.state_dir / "bootstrap-complete.json").exists()


@pytest.mark.parametrize("invalid", ["nonce", "cluster", "enrolled-type", "activated", "root"])
def test_renewal_enrollment_evidence_must_bind_original_producers(bootstrap_flow, invalid):
    flow = bootstrap_flow
    binding = {"namespace": flow.args.namespace, "namespaceUid": NAMESPACE_UID,
        "openbaoClusterId": CLUSTER_ID, "workloadProject": "marty-selfhost-disposable-k8s-" + PRODUCER_NONCE}
    members = renewal_evidence_members(binding)
    if invalid in {"nonce", "cluster"}:
        receipt = json.loads(members["binding.json"])
        if invalid == "nonce":
            receipt["producerNonce"] = "ffffffffffff"
        else:
            receipt["binding"]["openbaoClusterId"] = "20c184dc-712f-41c4-968d-d87027eb4981"
        members["binding.json"] = bootstrap.encoded(receipt)
    elif invalid == "root":
        members["pending.json"] = bootstrap.encoded({"secret": ROOT_TOKEN})
    else:
        receipt = json.loads(members["completed.json"])
        receipt["enrolled" if invalid == "enrolled-type" else "activated"] = 1 if invalid == "enrolled-type" else True
        members["completed.json"] = bootstrap.encoded(receipt)
    flow.renewal_evidence_override = renewal_archive(members)
    with pytest.raises(bootstrap.BootstrapError):
        bootstrap.bootstrap(flow.args)
    assert flow.renewal_calls == 1 and flow.publication_calls == 0
    assert not (flow.args.state_dir / "bootstrap-complete.json").exists()


def test_renewal_binding_persistence_failure_never_publishes_or_completes(bootstrap_flow, monkeypatch):
    flow = bootstrap_flow
    original = bootstrap.write_new

    def fail_binding(path, data, mode=0o600):
        if path.name == "renewal-binding.json":
            raise OSError("synthetic fsync failure")
        return original(path, data, mode)

    monkeypatch.setattr(bootstrap, "write_new", fail_binding)
    with pytest.raises(bootstrap.BootstrapError, match="do not replay"):
        bootstrap.bootstrap(flow.args)
    assert flow.renewal_calls == flow.cleanup_calls == 1 and flow.publication_calls == 0
    assert (flow.args.state_dir / "renewal-authority-recovery.tar").exists()
    assert not (flow.args.state_dir / "bootstrap-complete.json").exists()


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
