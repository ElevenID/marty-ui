"""Exercise the real inspection adapter with closed artifact/process/cluster doubles."""
from __future__ import annotations

from copy import deepcopy
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import bootstrap_kubernetes_openbao as bootstrap
import inspect_kubernetes_legacy_credentials as inspection
from test_bootstrap_kubernetes_openbao import assert_private_directory_command, capture_private_directory_commands


pytestmark = pytest.mark.skipif(os.name != "posix", reason="Linux private transport")


def test_inspection_private_directories_clear_inherited_setgid(flow, tmp_path, monkeypatch):
    commands = capture_private_directory_commands(monkeypatch, bootstrap.Transport)
    inspection.inspect(flow.args)
    assert len(commands) == 1
    assert_private_directory_command(commands[0], tmp_path)


NAMESPACE_UID = "bd2fd39c-2947-474d-b508-66dc5d7e9088"
CLUSTER = "9e38e97b-56dc-4ea0-be5f-688de619c891"
POD_UID = "ccfd7b48-909a-4a75-bee8-f2490cf76dd6"
BAO_UID = "5921d6fe-ab65-451b-8db2-5d6054812cb0"
OTHER_UID = "d025f4af-0676-4eab-9a79-5f67fffbddf5"
BOOTSTRAP_ID = "8a8c5b50-46c2-4347-ab36-377c662c61eb"
ROOT_TOKEN = b"PRIVATE_RETAINED_ORIGINAL_ROOT_TOKEN_CANARY"
RECOVERY_KEY = "PRIVATE_RECOVERY_SHARE_CANARY_NEVER_UPLOAD"
KUBECONFIG_KEY = "PRIVATE_KUBERNETES_ADMIN_KEY_CANARY_NEVER_UPLOAD"


def write(path, value, mode=0o600):
    path.write_bytes(value)
    path.chmod(mode)


def archive(members):
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode="w") as output:
        for name, (value, mode) in members.items():
            entry = tarfile.TarInfo(name)
            entry.mode, entry.size = mode, len(value)
            output.addfile(entry, io.BytesIO(value))
    return result.getvalue()


def unpack(payload):
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as source:
        return {entry.name: (source.extractfile(entry).read(), entry.mode)
                for entry in source if entry.isfile()}


@pytest.fixture
def flow(tmp_path, monkeypatch):
    state = tmp_path / "retained"
    state.mkdir(mode=0o700)
    current = state / "credentials"
    current.mkdir(mode=0o700)
    args = SimpleNamespace(state_dir=state, operation_dir=tmp_path / "inspection",
        original_assets=tmp_path / "original-assets", recovery_assets=tmp_path / "recovery-assets",
        gh=tmp_path / "gh", cosign=tmp_path / "cosign", chart_source_sha="2" * 40,
        original_release_tag="v1.1.274", original_build_run_id=123, original_build_run_attempt=1,
        recovery_source_sha="3" * 40, recovery_release_tag="v1.1.275", recovery_build_run_id=124,
        recovery_build_run_attempt=1)
    original_operator = b"synthetic authenticated original operator; never executed"
    operator = b"synthetic authenticated recovery operator; never executed"
    initializer = (bootstrap.ROOT / "docker/openbao-init.sh").read_bytes()
    original = {"release": {"runtimeSourceSha": inspection.LEGACY_RUNTIME,
        "chartSourceSha": args.chart_source_sha, "tag": args.original_release_tag,
        "buildRunId": 123, "buildRunAttempt": 1, "inventorySha256": "4" * 64,
        "imageLockSha256": "5" * 64, "operatorSha256": hashlib.sha256(original_operator).hexdigest()},
        "images": {"services": "ghcr.io/elevenid/marty-ui-oss/services@sha256:" + "6" * 64,
                   "openbao_didcomm": "ghcr.io/elevenid/marty-ui-oss/openbao-didcomm@sha256:" + "7" * 64}}
    recovery = deepcopy(original)
    recovery["release"].update(runtimeSourceSha=args.recovery_source_sha, tag=args.recovery_release_tag,
                               buildRunId=124, operatorSha256=hashlib.sha256(operator).hexdigest())
    recovery["images"]["services"] = "ghcr.io/elevenid/marty-ui-oss/services@sha256:" + "8" * 64
    openbao_values = {"server": {"image": {"repository": "elevenid/marty-ui-oss/openbao-didcomm",
        "registry": "ghcr.io", "tag": "2.5.5@sha256:" + "7" * 64, "pullPolicy": "IfNotPresent"}}}
    binding = {"namespace": "marty-test", "namespaceUid": NAMESPACE_UID,
               "openbaoClusterId": CLUSTER, "workloadProject": "marty-selfhost-disposable-k8s-012345abcdef"}
    complete = {"status": "openbao-and-application-credentials-ready", "bootstrapId": BOOTSTRAP_ID,
        "namespace": binding["namespace"], "openbaoClusterId": CLUSTER,
        "runtimeSourceSha": inspection.LEGACY_RUNTIME, "chartSourceSha": args.chart_source_sha,
        "openbaoChart": "0.30.6", "openbaoImage": original["images"]["openbao_didcomm"],
        "credentialLifetimeHours": 8, "migrationBootstrapLifetimeHours": 2,
        "credentialLifecycle": {"schema": "marty.kubernetes-credential-lifecycle/v1",
            "namespaceUid": NAMESPACE_UID, "producerNonce": "012345abcdef",
            "workloadProject": binding["workloadProject"], "ordinaryTokens": bootstrap.ordinary_token_requests()}}
    initialize = {"bootstrapId": BOOTSTRAP_ID, "namespace": binding["namespace"], "namespaceUid": NAMESPACE_UID,
        "producerNonce": "012345abcdef", "workloadProject": binding["workloadProject"],
        "operation": "bao operator init", "recoveryShares": 1, "recoveryThreshold": 1}
    for name, value in {
        "bootstrap-complete.json": complete, "initialize-requested.json": initialize,
        "namespace.json": {"name": binding["namespace"], "uid": NAMESPACE_UID, "bootstrapId": BOOTSTRAP_ID},
        "tls-key-metadata.json": {"schema": "marty.selfhost-disposable-tls-keys/v1", "roles": []},
        "marty-images.json": original, "openbao-images.json": openbao_values,
        "openbao-pull-secrets.json": {"global": {"imagePullSecrets": []}},
    }.items():
        write(state / name, bootstrap.encoded(value))
    write(state / "marty-deploy", original_operator, 0o700)
    write(state / "openbao-initialization.json", bootstrap.encoded({"root_token": ROOT_TOKEN.decode(),
        "recovery_keys_b64": [RECOVERY_KEY], "recovery_keys_hex": ["PRIVATE_RECOVERY_HEX_CANARY"]}), 0o400)
    write(state / "kubeconfig", bootstrap.encoded({"current-context": "retained-context",
        "contexts": [{"name": "retained-context", "context": {"cluster": "retained-cluster", "user": "retained-user"}}],
        "clusters": [{"name": "retained-cluster", "cluster": {"server": "https://127.0.0.1:6443", "certificate-authority-data": "public-ca"}}],
        "users": [{"name": "retained-user", "user": {"client-certificate-data": "public-client", "client-key-data": KUBECONFIG_KEY}}]}))
    names = set(bootstrap.SELFHOST_TLS_FILES) | bootstrap.KEYCLOAK_FILES | set(bootstrap.TOKEN_FILES.values())
    snapshot = {name: (("PRIVATE_CURRENT_CREDENTIAL_" + name).encode(), 0o600) for name in names}
    snapshot["openbao_tls_ca_cert"] = b"PUBLIC_RETAINED_OPENBAO_CA", 0o644
    snapshot["optional-empty"] = b"", 0o640
    for name, (value, mode) in snapshot.items():
        write(current / name, value, mode)
    item = SimpleNamespace(args=args, original=original, recovery=recovery, openbao_values=openbao_values,
        operator=operator, snapshot=snapshot, binding=binding, complete=complete, initialize=initialize,
        events=[], uploads=[], imports={}, processes=[], requests=[], reads=[], creates=[], deletions=[],
        pod=None, report=None, target_calls=0, native_calls=0, failure=None, pod_tamper=None,
        drift=None, target_override=None, report_override=None, auth_calls=0, bad_contract=False)

    def prepare(**kwargs):
        item.auth_calls += 1
        item.events.append("authenticate-" + str(item.auth_calls))
        if item.failure == "authenticate-" + str(item.auth_calls):
            raise ValueError("synthetic rejected artifact authentication")
        selected = original if kwargs["assets"] == args.original_assets else recovery
        assert kwargs["runtime_source_sha"] == selected["release"]["runtimeSourceSha"]
        assert kwargs["build_run_id"] == selected["release"]["buildRunId"]
        assert kwargs["chart_source_sha"] == args.chart_source_sha
        bootstrap.write_new(kwargs["output"], bootstrap.encoded(selected))
        bootstrap.write_new(kwargs["openbao_output"], bootstrap.encoded(openbao_values))
        return selected, openbao_values

    def authenticated(assets, identity):
        selected = original if assets == args.original_assets else recovery
        assert identity == selected["release"]
        return (original_operator if assets == args.original_assets else operator), initializer

    def process(command, **kwargs):
        item.processes.append(command)
        assert kwargs["env"] == {} and kwargs["stdin"] == subprocess.DEVNULL
        if command[-1] == "--build-identity":
            raw = (args.recovery_source_sha + ":" + args.recovery_release_tag).encode()
            if item.failure == "build-identity":
                raw = b"wrong-source:wrong-release"
        else:
            assert command[-2:] == ["operator", "kubernetes-legacy-recovery-contract"]
            value = deepcopy(inspection.CONTRACT)
            if item.bad_contract:
                value["mutationAvailable"] = True
            raw = bootstrap.encoded(value)
        return SimpleNamespace(returncode=0, stdout=raw, stderr=b"")

    def pod_observation():
        observed = deepcopy(item.pod)
        observed["status"] = {"phase": "Running", "containerStatuses": [{"name": "native-producers",
            "ready": True, "restartCount": 0, "state": {"running": {"startedAt": "2026-11-09T00:00:00Z"}}}]}
        if item.pod_tamper:
            item.pod_tamper(observed)
        if item.drift == "uid-after-target" and item.target_calls:
            observed["metadata"]["uid"] = OTHER_UID
        if item.drift == "uid-after-current" and item.imports:
            observed["metadata"]["uid"] = OTHER_UID
        return observed

    class Transport:
        def __init__(self, operation, kubeconfig, namespace, kubectl):
            assert item.auth_calls == 2
            assert kubeconfig == operation / "kubeconfig" and namespace == binding["namespace"]
            self.state, self.namespace = operation, namespace

        def kubectl(self, operation, *command, data=None, **kwargs):
            item.events.append(operation)
            if operation == "legacy namespace identity":
                uid = OTHER_UID if item.drift == "namespace-after-target" and item.target_calls else NAMESPACE_UID
                return bootstrap.encoded({"metadata": {"name": self.namespace, "uid": uid}})
            if operation == "legacy OpenBao image identity":
                image = original["images"]["openbao_didcomm"].replace("@sha256:", ":2.5.5@sha256:")
                if item.failure == "openbao-image":
                    image = image[:-64] + "9" * 64
                return bootstrap.encoded({"metadata": {"name": "openbao-0", "namespace": self.namespace, "uid": BAO_UID},
                    "spec": {"containers": [{"name": "openbao", "image": image}]}})
            if operation == "legacy producer creation":
                value = json.loads(data)
                item.creates.append(value)
                item.pod = deepcopy(value)
                item.pod["metadata"]["uid"] = POD_UID
                item.pod["metadata"]["resourceVersion"] = "20"
                item.pod["spec"].update(serviceAccount="default", schedulerName="default-scheduler", priority=0,
                                         preemptionPolicy="PreemptLowerPriority", nodeName="synthetic-node")
                item.pod["spec"]["containers"][0].update(terminationMessagePath="/dev/termination-log", terminationMessagePolicy="File")
                for field in ("hostNetwork", "hostPID", "hostIPC", "imagePullSecrets"):
                    item.pod["spec"].pop(field)
                return bootstrap.encoded(item.pod)
            if operation == "legacy producer readiness":
                return b"ready"
            if operation == "legacy producer identity":
                return bootstrap.encoded(pod_observation())
            if operation == "legacy producer cleanup":
                options = json.loads(data)
                assert command[:2] == ("delete", "--raw")
                assert options["preconditions"] == {"uid": POD_UID}
                item.deletions.append(options)
                return bootstrap.encoded({"kind": "Status", "status": "Success"})
            if operation == "legacy producer cleanup wait":
                return b"deleted"
            raise AssertionError("unexpected Kubernetes operation " + operation)

        def upload(self, pod, destination, contents, **kwargs):
            assert pod == item.pod["metadata"]["name"]
            if destination == inspection.REMOTE_ROOT:
                assert item.target_calls == 1 and contents == ROOT_TOKEN
            item.uploads.append((destination, contents))

        def execute(self, pod, command, *, data=None, **kwargs):
            item.requests.append((command, data))
            if command[:2] == ["/bin/sh", "-ec"]:
                if command[2].startswith("umask 077; for path"):
                    return b""
                assert command[2] == bootstrap.REMOTE_ARCHIVE_COMMAND
                assert command[4] == inspection.REMOTE_OPERATION
                if item.failure == "evidence":
                    raise bootstrap.BootstrapError("synthetic private evidence failure")
                report = item.report_override if item.report_override is not None else item.report
                return archive({"inspection.json": (bootstrap.encoded(report), 0o600)} if report else {})
            if command == ["sha256sum", inspection.REMOTE_OPERATOR]:
                return hashlib.sha256(operator).hexdigest().encode() + b"  /tmp/marty-deploy\n"
            if command[:3] == [inspection.REMOTE_OPERATOR, "operator", "kubernetes-legacy-recovery-target"]:
                assert [name for name, _ in item.uploads] == [inspection.REMOTE_OPERATOR, inspection.REMOTE_CA]
                item.target_calls += 1
                return bootstrap.encoded(item.target_override or {
                    "schema": inspection.TARGET_SCHEMA, "ready": True, "clusterId": CLUSTER, "authenticated": False})
            if command[:3] == ["tar", "-xpf", "-"]:
                assert item.target_calls == 1
                item.imports[command[-1]] = unpack(data)
                return b""
            if command[:3] == [inspection.REMOTE_OPERATOR, "operator", "kubernetes-legacy-recovery-inspect"]:
                item.native_calls += 1
                context = json.loads(data)
                assert context["retainedRootSha256"] == hashlib.sha256(ROOT_TOKEN).hexdigest()
                assert context["rootTokenFile"] == inspection.REMOTE_ROOT
                assert context["namespaceObservation"] == {"name": binding["namespace"], "uid": NAMESPACE_UID}
                assert dict(item.uploads)[inspection.REMOTE_ROOT] == ROOT_TOKEN
                item.report = {"schema": inspection.SCHEMA, "status": "inspected-not-staged", "mutationAvailable": False,
                    "binding": {"bootstrapId": BOOTSTRAP_ID, **binding, "producerNonce": "012345abcdef",
                        "runtimeSourceSha": inspection.LEGACY_RUNTIME, "chartSourceSha": args.chart_source_sha},
                    "inputBindings": {name: {"sha256": hashlib.sha256(value).hexdigest(), "mode": mode}
                                      for name, (value, mode) in snapshot.items()}, "observed": {}}
                if item.failure == "native":
                    raise bootstrap.BootstrapError("synthetic native outcome unavailable")
                if item.drift == "retained-current":
                    write(current / "optional-empty", b"concurrent-change", 0o640)
                return bootstrap.encoded({"schema": inspection.SCHEMA, "status": "inspected-not-staged", "mutationAvailable": False,
                    "namespace": binding["namespace"], "workloadIdentities": 16, "keycloakSigningCertificates": 2,
                    "keycloakTokens": 5, "ordinaryRuntimeTokens": 12, "privateReportWritten": True})
            raise AssertionError("unexpected native request")

    original_private_bytes = inspection.private.private_bytes
    def tracked_private_bytes(path, *rest, **kwargs):
        item.reads.append(path.name)
        return original_private_bytes(path, *rest, **kwargs)

    monkeypatch.setattr(bootstrap, "prepare", prepare)
    monkeypatch.setattr(bootstrap, "authenticated_bootstrap_inputs", authenticated)
    def authenticated_sources(assets, identity):
        assert item.auth_calls == 2 and assets == args.recovery_assets and identity == recovery["release"]
        item.events.append("authenticated-source-match")
        if item.failure == "source-mismatch":
            raise bootstrap.BootstrapError("synthetic authenticated source mismatch")
        return {"synthetic-reviewed-source": "a" * 64}

    def source_recheck(expected):
        assert expected == {"synthetic-reviewed-source": "a" * 64}
        if item.drift == "source-after-target" and item.target_calls:
            raise bootstrap.BootstrapError("synthetic source drift after target admission")

    monkeypatch.setattr(inspection.sources, "authenticate", authenticated_sources)
    monkeypatch.setattr(inspection.sources, "recheck", source_recheck)
    monkeypatch.setattr(inspection.subprocess, "run", process)
    monkeypatch.setattr(inspection.shutil, "which", lambda name: "/synthetic/kubectl")
    monkeypatch.setattr(bootstrap.secrets, "token_hex", lambda length: "abcdef012345")
    monkeypatch.setattr(bootstrap, "Transport", Transport)
    monkeypatch.setattr(inspection.private, "private_bytes", tracked_private_bytes)
    return item


def test_inspection_authenticates_both_closures_probes_before_root_and_preserves_private_evidence(flow, capsys):
    before = {path.relative_to(flow.args.state_dir): (path.read_bytes(), stat.S_IMODE(path.stat().st_mode))
              for path in flow.args.state_dir.rglob("*") if path.is_file()}
    inspection.inspect(flow.args)
    assert flow.auth_calls == 2 and flow.target_calls == 1 and flow.native_calls == 1
    assert len(flow.creates) == len(flow.deletions) == 1
    assert flow.imports[inspection.REMOTE_CURRENT] == flow.snapshot
    uploaded = b"\n".join(value for _, value in flow.uploads)
    sent = b"\n".join(data for _, data in flow.requests if data is not None)
    for forbidden in (RECOVERY_KEY.encode(), KUBECONFIG_KEY.encode(), b"PRIVATE_RECOVERY_HEX_CANARY"):
        assert forbidden not in uploaded + sent
    assert dict(flow.uploads)[inspection.REMOTE_ROOT] == ROOT_TOKEN
    assert before == {path.relative_to(flow.args.state_dir): (path.read_bytes(), stat.S_IMODE(path.stat().st_mode))
                      for path in flow.args.state_dir.rglob("*") if path.is_file()}
    for name in ("inspection.json", "native-inspection-evidence.tar", "native-inspection-request.json", "inspection-complete.json"):
        assert stat.S_IMODE((flow.args.operation_dir / name).stat().st_mode) == 0o600
    assert json.loads((flow.args.operation_dir / "inspection-complete.json").read_bytes())["activation"] is False
    public = capsys.readouterr().out
    assert "were not changed" in public
    assert ROOT_TOKEN.decode() not in public and hashlib.sha256(ROOT_TOKEN).hexdigest() not in public


@pytest.mark.parametrize("failure", ["authenticate-1", "authenticate-2", "build-identity", "source-mismatch"])
def test_artifact_authentication_or_build_identity_failure_precedes_cluster_or_root_access(flow, failure):
    flow.failure = failure
    with pytest.raises((ValueError, bootstrap.BootstrapError)):
        inspection.inspect(flow.args)
    assert not flow.creates and not flow.uploads
    assert "openbao-initialization.json" not in flow.reads
    assert not any(event.startswith("legacy ") for event in flow.events)


def test_mutation_capable_contract_is_not_accepted_as_read_only_inspector(flow):
    flow.bad_contract = True
    with pytest.raises(bootstrap.BootstrapError, match="inspection contract differs"):
        inspection.inspect(flow.args)
    assert not flow.creates and "openbao-initialization.json" not in flow.reads


@pytest.mark.parametrize("field,value", [("runtimeSourceSha", "a" * 40), ("openbaoChart", "0.31.0"), ("applicationAuthority", {})])
def test_unsupported_retained_generation_fails_before_authentication(flow, field, value):
    complete = dict(flow.complete)
    complete[field] = value
    write(flow.args.state_dir / "bootstrap-complete.json", bootstrap.encoded(complete))
    with pytest.raises(bootstrap.BootstrapError, match="supported legacy"):
        inspection.inspect(flow.args)
    assert flow.auth_calls == 0 and not flow.creates


@pytest.mark.parametrize("tamper", [
    lambda pod: pod["spec"]["containers"].append(deepcopy(pod["spec"]["containers"][0])),
    lambda pod: pod["spec"].update(initContainers=[{"name": "injected"}]),
    lambda pod: pod["spec"].update(ephemeralContainers=[{"name": "injected"}]),
    lambda pod: pod["spec"].update(automountServiceAccountToken=True),
    lambda pod: pod["spec"].update(volumes=[{"name": "private", "hostPath": {"path": "/var/lib"}}]),
    lambda pod: pod["spec"]["containers"][0].update(env=[{"name": "BAO_TOKEN", "value": "injected"}]),
    lambda pod: pod["spec"]["containers"][0].update(image="unverified:latest"),
    lambda pod: pod["spec"]["containers"][0]["securityContext"].update(privileged=True),
])
def test_effective_producer_spec_injection_blocks_every_credential_upload(flow, tamper):
    flow.pod_tamper = tamper
    with pytest.raises(bootstrap.BootstrapError):
        inspection.inspect(flow.args)
    assert not flow.uploads and not flow.imports and flow.native_calls == 0
    assert flow.deletions[0]["preconditions"] == {"uid": POD_UID}


@pytest.mark.parametrize("drift", ["uid-after-target", "namespace-after-target", "uid-after-current"])
def test_phase_identity_drift_never_uploads_root_to_changed_target(flow, drift):
    flow.drift = drift
    with pytest.raises(bootstrap.BootstrapError):
        inspection.inspect(flow.args)
    assert inspection.REMOTE_ROOT not in dict(flow.uploads)
    assert flow.native_calls == 0
    assert not (flow.args.operation_dir / "inspection-complete.json").exists()


def test_wrong_cluster_confirmation_blocks_private_upload(flow):
    flow.target_override = {"schema": inspection.TARGET_SCHEMA, "ready": True, "clusterId": OTHER_UID, "authenticated": False}
    with pytest.raises(bootstrap.BootstrapError, match="retained cluster"):
        inspection.inspect(flow.args)
    assert not flow.imports and inspection.REMOTE_ROOT not in dict(flow.uploads)
    assert flow.native_calls == 0 and len(flow.deletions) == 1


def test_source_drift_after_target_admission_blocks_authority_upload(flow):
    flow.drift = "source-after-target"
    with pytest.raises(bootstrap.BootstrapError):
        inspection.inspect(flow.args)
    assert flow.target_calls == 1 and flow.native_calls == 0
    assert not flow.imports and inspection.REMOTE_ROOT not in dict(flow.uploads)
    assert not (flow.args.operation_dir / "inspection-complete.json").exists()


def test_live_openbao_digest_must_match_authenticated_original(flow):
    flow.failure = "openbao-image"
    with pytest.raises(bootstrap.BootstrapError, match="authenticated original runtime"):
        inspection.inspect(flow.args)
    assert not flow.creates and not flow.uploads


@pytest.mark.parametrize("failure", ["evidence", "native"])
def test_failed_or_uncertain_native_evidence_is_never_cleaned_or_marked_complete(flow, failure):
    flow.failure = failure
    with pytest.raises(bootstrap.BootstrapError, match="remaining original 1200-second"):
        inspection.inspect(flow.args)
    assert flow.native_calls == 1 and not flow.deletions
    assert not (flow.args.operation_dir / "inspection-complete.json").exists()


def test_mismatched_exported_input_binding_withholds_completion_and_retains_pod(flow):
    flow.report_override = {"schema": inspection.SCHEMA, "status": "inspected-not-staged", "mutationAvailable": False,
                            "inputBindings": {}}
    with pytest.raises(bootstrap.BootstrapError, match="evidence could not be retained"):
        inspection.inspect(flow.args)
    assert not flow.deletions and not (flow.args.operation_dir / "inspection-complete.json").exists()
    assert (flow.args.operation_dir / "native-inspection-evidence.tar").exists()


def test_original_input_change_after_native_inspection_withholds_completion(flow):
    flow.drift = "retained-current"
    with pytest.raises(bootstrap.BootstrapError, match="credentials changed"):
        inspection.inspect(flow.args)
    assert len(flow.deletions) == 1 and not (flow.args.operation_dir / "inspection-complete.json").exists()


def test_recovery_lock_is_on_original_directory_without_creating_retained_files(flow):
    names = set(flow.args.state_dir.iterdir())
    descriptor = os.open(flow.args.state_dir, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(bootstrap.BootstrapError, match="holds the retained-state lock"):
            inspection.inspect(flow.args)
    finally:
        os.close(descriptor)
    assert set(flow.args.state_dir.iterdir()) == names and not flow.args.operation_dir.exists()


def test_root_input_is_extracted_from_private_retained_initialization_not_an_override(flow):
    path = flow.args.state_dir / "openbao-initialization.json"
    path.chmod(0o644)
    with pytest.raises(bootstrap.BootstrapError, match="custody differs"):
        inspection.inspect(flow.args)
    assert not flow.creates and not flow.uploads


def test_duplicate_retained_json_members_fail_before_cluster(flow):
    write(flow.args.state_dir / "initialize-requested.json", b'{"namespace":"marty-test","namespace":"forged"}')
    with pytest.raises(ValueError, match="duplicate metadata"):
        inspection.inspect(flow.args)
    assert not flow.creates and not flow.uploads


def test_effective_spec_accepts_only_harmless_kubernetes_defaults(flow):
    document = inspection.producer_document("marty-test", flow.recovery["images"]["services"], "abcdef012345", [])
    observed = deepcopy(document)
    observed["metadata"]["uid"] = POD_UID
    for field in ("hostNetwork", "hostPID", "hostIPC", "imagePullSecrets"):
        observed["spec"].pop(field)
    observed["spec"].update(nodeName="selected-node", serviceAccount="default", schedulerName="default-scheduler")
    assert inspection.pod_identity(observed, document) == POD_UID
    observed["spec"]["containers"][0]["terminationMessagePath"] = "/tmp/application-identity/root-token"
    with pytest.raises(bootstrap.BootstrapError, match="termination output is redirected"):
        inspection.pod_identity(observed, document)
