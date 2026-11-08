"""Exercise real private transport control flow with closed process/cluster doubles."""
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

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import bootstrap_kubernetes_openbao as bootstrap
import stage_kubernetes_application_credentials as staging


pytestmark = pytest.mark.skipif(os.name != "posix", reason="Linux private transport contract")
UID = "c647e5d2-85d7-409b-8729-94b8f8cf29ab"
CLUSTER = "9347f7a0-aae1-4ecf-9e77-165626c051c2"
PROJECT = "marty-selfhost-disposable-k8s-0123456789ab"


def write(path, value, mode=0o600):
    path.write_bytes(value)
    path.chmod(mode)


def archive(members):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as output:
        for name, (value, mode) in members.items():
            entry = tarfile.TarInfo(name)
            entry.size, entry.mode = len(value), mode
            output.addfile(entry, io.BytesIO(value))
    return stream.getvalue()


def unpack(payload):
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as source:
        return {member.name: (source.extractfile(member).read(), member.mode)
                for member in source if member.isfile()}


@pytest.fixture
def flow(tmp_path, monkeypatch):
    state = tmp_path / "original"
    state.mkdir(mode=0o700)
    current = state / "credentials"
    current.mkdir(mode=0o700)
    identity_path = state / "application-identity"
    identity_path.mkdir(mode=0o700)
    binding = {"namespace": "marty-test", "namespaceUid": UID,
               "openbaoClusterId": CLUSTER, "workloadProject": PROJECT}
    args = SimpleNamespace(state_dir=state, operation_dir=tmp_path / "attempt",
        assets=tmp_path / "assets", gh=tmp_path / "gh", cosign=tmp_path / "cosign",
        runtime_source_sha="1" * 40, chart_source_sha="2" * 40,
        release_tag="v1.2.3-nightly.20261108.123", build_run_id=123, build_run_attempt=1)
    publication = {"schema": bootstrap.PUBLICATION_SCHEMA, "catalog": json.loads(
        (bootstrap.ROOT / "deploy-config/catalog/kubernetes-secrets.json").read_bytes())}
    application = json.loads(bootstrap.encoded(bootstrap.APPLICATION_TOKEN_SPEC))
    operator = b"synthetic authenticated operator; never executed"
    values = {"release": {
        "runtimeSourceSha": args.runtime_source_sha, "chartSourceSha": args.chart_source_sha,
        "tag": args.release_tag, "buildRunId": 123, "buildRunAttempt": 1,
        "inventorySha256": "3" * 64, "imageLockSha256": "4" * 64,
        "operatorSha256": hashlib.sha256(operator).hexdigest(),
    }, "images": {"services": "ghcr.io/elevenid/marty-ui-oss/services@sha256:" + "5" * 64}}
    complete = {"status": "openbao-and-application-credentials-ready",
        "namespace": binding["namespace"], "openbaoClusterId": CLUSTER,
        "runtimeSourceSha": args.runtime_source_sha, "chartSourceSha": args.chart_source_sha,
        "credentialLifecycle": {"namespaceUid": UID, "workloadProject": PROJECT},
        "credentialPublication": publication, "applicationTokenContract": application,
        "applicationAuthority": {"schema": "marty.kubernetes-application-authority/v1",
            "binding": binding, "identityDirectory": "application-identity",
            "files": sorted(bootstrap.APPLICATION_IDENTITY_FILES)},
        "imagePullSecrets": ["registry-pull"]}
    write(state / "bootstrap-complete.json", bootstrap.encoded(complete))
    write(state / "marty-images.json", bootstrap.encoded(values))
    write(state / "marty-deploy", operator, 0o700)
    write(state / "kubeconfig", bootstrap.encoded({"current-context": "retained-fixture",
        "contexts": [{"name": "retained-fixture"}], "users": [{"token": "PRIVATE_KUBECONFIG_CANARY"}]}))
    # A root initialization file exists but staging must never open it.
    write(state / "openbao-initialization.json", b"PRIVATE_ROOT_CANARY_NEVER_READ", 0o400)
    inputs = set(bootstrap.SELFHOST_TLS_FILES) | bootstrap.KEYCLOAK_FILES | set(bootstrap.TOKEN_FILES.values())
    snapshot = {name: (("PRIVATE_CURRENT_CANARY_" + name).encode(), 0o600) for name in inputs}
    snapshot["workload_identity_ca_cert"] = b"PUBLIC_WORKLOAD_CERTIFICATE_CANARY", 0o444
    snapshot["openbao_tls_ca_cert"] = b"PUBLIC_OPENBAO_CA_CANARY", 0o644
    snapshot["optional-empty"] = b"", 0o640
    snapshot["optional-scalar"] = b"PRIVATE_UNCHANGED_SCALAR_CANARY", 0o640
    for name, (value, mode) in snapshot.items():
        write(current / name, value, mode)
    identity = {
        "application-role-id": (b"PUBLIC_APPLICATION_ROLE_ID_CANARY", 0o600),
        "application-secret-id": (b"PRIVATE_APPLICATION_SECRET_ID_CANARY", 0o600),
        "application-binding.json": (bootstrap.encoded(binding), 0o600),
    }
    for name, (value, mode) in identity.items():
        write(identity_path / name, value, mode)
    runtime = {entry["file"] for entry in application["tokens"] if entry["replacementRole"]}
    minted = {name: (("PRIVATE_NEW_SCOPED_TOKEN_CANARY_" + name).encode(), 0o600) for name in runtime}
    candidate = {**snapshot, **minted}
    item = SimpleNamespace(args=args, binding=binding, values=values, operator=operator,
        publication=publication, application=application, snapshot=snapshot,
        identity=identity, runtime=runtime, minted=minted, candidate=candidate,
        processes=[], events=[], creates=[], uploads=[], imported={}, generation_calls=[],
        namespace_reads=0, cluster_reads=0, stage_calls=0, cleanup_calls=0,
        fail_at=None, bad_contract=None, batch_override=None, generation_override=None,
        export_override={}, namespace_ids=[UID] * 4, cluster_ids=[CLUSTER] * 4)

    def prepared(**kwargs):
        item.events.append("authenticate")
        assert kwargs["runtime_source_sha"] == args.runtime_source_sha
        for key in ("output", "openbao_output"):
            bootstrap.write_new(kwargs[key], bootstrap.encoded(values if key == "output" else {}))
        return values, {}

    def process(command, **kwargs):
        item.processes.append(command)
        assert kwargs["env"] == {} and kwargs["stdin"] == bootstrap.subprocess.DEVNULL
        if command[-1] == "--build-identity":
            return SimpleNamespace(returncode=0,
                stdout=(args.runtime_source_sha + ":" + args.release_tag).encode(), stderr=b"")
        key = command[-1]
        assert key in {"kubernetes-secrets-contract", "kubernetes-application-token-contract"}
        item.events.append(key)
        if item.bad_contract == key:
            return SimpleNamespace(returncode=2, stdout=b"PRIVATE_UNSUPPORTED_CANARY", stderr=b"PRIVATE_STDERR_CANARY")
        output = publication if key == "kubernetes-secrets-contract" else application
        return SimpleNamespace(returncode=0, stdout=bootstrap.encoded(output), stderr=b"")

    def generation(context, location):
        item.generation_calls.append((location, context))
        operation = context["operation"]
        phase = location + "-" + operation
        if item.fail_at == phase:
            return b'{"error":"PRIVATE_NATIVE_REFUSAL_CANARY"}'
        if item.generation_override is not None:
            return bootstrap.encoded({"value": item.generation_override})
        if location == "local" and operation == "application-verify":
            result = staging.current_snapshot(Path(context["candidate"]))
            if result != item.candidate:
                return b'{"error":"PRIVATE_NATIVE_GENERATION_PROOF_CANARY"}'
        value = [len(snapshot), len(runtime)] if operation == "application-verify" else len(snapshot)
        return bootstrap.encoded({"value": value})

    class Transport:
        def __init__(self, operation, kubeconfig, namespace, kubectl):
            self.state, self.namespace = operation, namespace
            assert kubeconfig == operation / "kubeconfig" and namespace == binding["namespace"]

        def run(self, operation, command, **kwargs):
            assert operation == "native application generation validation"
            assert command == [str(args.operation_dir / "marty-deploy"), "operator", "generation"]
            assert kwargs["env"] == {}
            return generation(json.loads(kwargs["data"]), "local")

        def create(self, resource):
            assert resource["kind"] == "Pod"
            assert item.namespace_reads == item.cluster_reads == 1
            item.creates.append(resource)

        def kubectl(self, operation, *command, **kwargs):
            item.events.append(operation)
            if operation == "namespace identity":
                uid = item.namespace_ids[item.namespace_reads]
                item.namespace_reads += 1
                return bootstrap.encoded({"metadata": {"name": self.namespace, "uid": uid}})
            if operation == "native producer readiness":
                if item.fail_at == "readiness":
                    raise bootstrap.BootstrapError("native readiness failed")
                return b""
            if operation == "native producer cleanup":
                item.cleanup_calls += 1
                if item.fail_at == "cleanup":
                    raise bootstrap.BootstrapError("native cleanup failed")
                return b""
            raise AssertionError("unexpected Kubernetes mutation")

        def upload(self, pod, destination, contents, **kwargs):
            assert item.namespace_reads == item.cluster_reads == 2
            item.uploads.append((destination, contents))

        def execute(self, pod, command, *, data=None, **kwargs):
            if command == ["bao", "status", "-format=json"]:
                cluster = item.cluster_ids[item.cluster_reads]
                item.cluster_reads += 1
                return bootstrap.encoded({"initialized": True, "sealed": False, "type": "static",
                    "storage_type": "raft", "cluster_id": cluster})
            if command[:2] == ["/bin/sh", "-ec"]:
                if command[2].startswith("umask 077; for path"):
                    return b""
                assert command[2] == bootstrap.REMOTE_ARCHIVE_COMMAND
                source = command[4]
                if item.fail_at == "evidence" and source == staging.REMOTE_OPERATION:
                    raise bootstrap.BootstrapError("private evidence unavailable")
                if source in item.export_override:
                    return item.export_override[source]
                if source == staging.REMOTE_INPUTS:
                    return archive(item.minted)
                if source == staging.REMOTE_CANDIDATE:
                    return archive(item.candidate)
                assert source == staging.REMOTE_OPERATION
                evidence = {"attempt.json": (bootstrap.encoded({"binding": binding}), 0o600),
                    "login-response.json": (b"PRIVATE_NATIVE_RESPONSE_CAPTURE_CANARY", 0o600)}
                if item.fail_at not in {"remote-application-check", "native-stage", "native-timeout"}:
                    evidence["complete.json"] = bootstrap.encoded({"ready": True}), 0o600
                    evidence.update({f"mint-response-{index:02d}.json": (b"PRIVATE_MINT_RESPONSE_CANARY", 0o600)
                                     for index in range(len(runtime))})
                    evidence.update({"inputs/" + name: value for name, value in item.minted.items()})
                return archive(evidence)
            if command == ["sha256sum", staging.REMOTE_OPERATOR]:
                return hashlib.sha256(operator).hexdigest().encode()
            if command[:3] == ["tar", "-xpf", "-"]:
                assert item.namespace_reads == item.cluster_reads == 2
                item.imported[command[-1]] = unpack(data)
                return b""
            if command == [staging.REMOTE_OPERATOR, "operator", "generation"]:
                return generation(json.loads(data), "remote")
            if command[:3] == [staging.REMOTE_OPERATOR, "operator", "application-token-stage"]:
                item.stage_calls += 1
                assert item.namespace_reads == item.cluster_reads == 3
                assert (args.operation_dir / "application-stage-requested.json").exists()
                assert json.loads(data) == {"current": staging.REMOTE_CURRENT,
                    "output": staging.REMOTE_OPERATION, "binding": binding}
                if item.fail_at == "native-stage":
                    raise bootstrap.BootstrapError("native authority stage failed; private evidence retained")
                if item.fail_at == "native-timeout":
                    raise bootstrap.subprocess.TimeoutExpired(command, 600,
                        output=b"PRIVATE_UNCERTAIN_RESPONSE_CANARY")
                response = item.batch_override if item.batch_override is not None else {
                    "ready": True, "inputs": staging.REMOTE_INPUTS, "count": len(runtime)}
                return bootstrap.encoded(response)
            raise AssertionError("unexpected native operation")

    original_private_bytes = staging.private_bytes
    def guarded_private_bytes(path, *args, **kwargs):
        assert path.name not in {"openbao-initialization.json", "static.key"}, "staging opened root authority"
        return original_private_bytes(path, *args, **kwargs)

    monkeypatch.setattr(bootstrap, "prepare", prepared)
    monkeypatch.setattr(bootstrap, "authenticated_bootstrap_inputs", lambda assets, identity: (operator, b"unused init"))
    monkeypatch.setattr(staging.subprocess, "run", process)
    monkeypatch.setattr(staging.shutil, "which", lambda name: "/synthetic/kubectl" if name == "kubectl" else None)
    monkeypatch.setattr(bootstrap.secrets, "token_hex", lambda count: "abcdef123456")
    monkeypatch.setattr(bootstrap, "Transport", Transport)
    monkeypatch.setattr(staging, "private_bytes", guarded_private_bytes)
    return item


def test_stages_candidate_only_with_native_proofs_private_captures_and_preserved_modes(flow, capsys):
    before = dict(flow.snapshot)
    mask = os.umask(0o077)
    try:
        staging.stage(flow.args)
    finally:
        os.umask(mask)
    assert staging.current_snapshot(flow.args.state_dir / "credentials") == before
    assert staging.current_snapshot(flow.args.operation_dir / "candidate") == flow.candidate
    assert (flow.args.operation_dir / "candidate/workload_identity_ca_cert").stat().st_mode & 0o777 == 0o444
    assert (flow.args.operation_dir / "candidate/optional-empty").stat().st_mode & 0o777 == 0o640
    assert flow.imported[staging.REMOTE_CURRENT] == flow.snapshot
    assert flow.imported[staging.REMOTE_IDENTITY] == flow.identity
    assert flow.stage_calls == flow.cleanup_calls == 1
    assert flow.namespace_reads == flow.cluster_reads == 4
    assert flow.events[:3] == ["authenticate", "kubernetes-secrets-contract", "kubernetes-application-token-contract"]
    assert len(flow.creates) == 1 and flow.creates[0]["spec"]["automountServiceAccountToken"] is False
    assert flow.creates[0]["spec"]["activeDeadlineSeconds"] == 1200
    assert flow.creates[0]["spec"]["volumes"][0]["emptyDir"]["medium"] == "Memory"
    receipt = json.loads((flow.args.operation_dir / "application-stage-complete.json").read_bytes())
    assert receipt["activation"] is False and receipt["status"] == "candidate-staged-not-activated"
    assert len(receipt["replacedInputs"]) == 11
    evidence = flow.args.operation_dir / "native-operation-evidence.tar"
    assert b"PRIVATE_NATIVE_RESPONSE_CAPTURE_CANARY" in evidence.read_bytes()
    assert stat.S_IMODE(evidence.stat().st_mode) == 0o600
    captured = capsys.readouterr()
    assert "PRIVATE_" not in captured.out + captured.err
    assert "PRIVATE_" not in json.dumps(flow.creates) + json.dumps(receipt)
    for name in ("marty-images.json", "application-stage-requested.json", "application-stage-complete.json"):
        assert b"PRIVATE_" not in (flow.args.operation_dir / name).read_bytes()


@pytest.mark.parametrize("command", ["kubernetes-secrets-contract", "kubernetes-application-token-contract"])
def test_unsupported_signed_contract_stops_before_any_cluster_access(flow, command):
    flow.bad_contract = command
    with pytest.raises(bootstrap.BootstrapError) as error:
        staging.stage(flow.args)
    assert "PRIVATE_" not in str(error.value)
    assert flow.namespace_reads == flow.cluster_reads == flow.stage_calls == 0
    assert flow.creates == flow.uploads == []


@pytest.mark.parametrize("phase", [
    "local-application-check", "readiness", "remote-application-check", "native-stage",
    "native-timeout", "remote-application-stage", "remote-application-verify",
    "local-application-verify", "evidence", "cleanup",
])
def test_failure_retains_attempt_without_completion_or_activation(flow, phase, capsys):
    flow.fail_at = phase
    with pytest.raises(bootstrap.BootstrapError) as error:
        staging.stage(flow.args)
    assert "PRIVATE_" not in str(error.value)
    assert not (flow.args.operation_dir / "application-stage-complete.json").exists()
    assert staging.current_snapshot(flow.args.state_dir / "credentials") == flow.snapshot
    if phase == "local-application-check":
        assert flow.creates == [] and flow.cleanup_calls == 0
    else:
        assert flow.cleanup_calls == (0 if phase in {"native-stage", "native-timeout", "evidence"} else 1)
        assert (flow.args.operation_dir / "application-stage-requested.json").exists()
        pointer = json.loads((flow.args.operation_dir / "transport-pod.json").read_bytes())
        assert pointer["activeDeadlineSeconds"] == 1200 and pointer["durableRecovery"] is False
        assert pointer["pod"] == flow.creates[0]["metadata"]["name"]
    if phase not in {"local-application-check", "readiness", "evidence"}:
        assert (flow.args.operation_dir / "native-operation-evidence.tar").exists()
    assert "PRIVATE_" not in "".join(capsys.readouterr())


@pytest.mark.parametrize("observation", [0, 1, 2, 3])
@pytest.mark.parametrize("identity", ["namespace", "cluster"])
def test_binding_drift_refuses_before_private_upload_or_authority_at_each_boundary(flow, observation, identity):
    values = flow.namespace_ids if identity == "namespace" else flow.cluster_ids
    values[observation] = "20c184dc-712f-41c4-968d-d87027eb4981"
    with pytest.raises(bootstrap.BootstrapError):
        staging.stage(flow.args)
    assert not (flow.args.operation_dir / "application-stage-complete.json").exists()
    assert flow.stage_calls == (1 if observation == 3 else 0)
    if observation <= 1:
        assert flow.uploads == [] and flow.imported == {}
    assert flow.cleanup_calls == (0 if observation == 0 else 1)


@pytest.mark.parametrize("response", [
    {"ready": 1, "inputs": staging.REMOTE_INPUTS, "count": 11},
    {"ready": True, "inputs": "/tmp/foreign", "count": 11},
    {"ready": True, "inputs": staging.REMOTE_INPUTS, "count": 11.0},
    {"ready": True, "inputs": staging.REMOTE_INPUTS, "count": 10},
    {"ready": True, "inputs": staging.REMOTE_INPUTS, "count": 11, "private": "PRIVATE_CANARY"},
])
def test_native_batch_response_is_exact_and_typed(flow, response):
    flow.batch_override = response
    with pytest.raises(bootstrap.BootstrapError) as error:
        staging.stage(flow.args)
    assert "PRIVATE_" not in str(error.value)
    assert flow.stage_calls == flow.cleanup_calls == 1
    assert not (flow.args.operation_dir / "application-stage-complete.json").exists()
    assert not (flow.args.operation_dir / "candidate").exists()


@pytest.mark.parametrize("invalid", ["extra", "missing", "mode", "duplicate", "symlink"])
def test_native_input_export_inventory_is_closed(flow, invalid):
    members = dict(flow.minted)
    first = next(iter(members))
    if invalid == "extra":
        members["root.token"] = b"PRIVATE_FORBIDDEN_ROOT_CANARY", 0o600
    elif invalid == "missing":
        members.pop(first)
    elif invalid == "mode":
        members[first] = members[first][0], 0o644
    payload = archive(members)
    if invalid in {"duplicate", "symlink"}:
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w") as target:
            for name, (value, mode) in members.items():
                entry = tarfile.TarInfo(name)
                entry.mode, entry.size = mode, len(value)
                target.addfile(entry, io.BytesIO(value))
            entry = tarfile.TarInfo(first)
            entry.mode = 0o600
            if invalid == "symlink":
                entry.type, entry.linkname = tarfile.SYMTYPE, "/private/root.token"
            target.addfile(entry)
        payload = stream.getvalue()
    flow.export_override[staging.REMOTE_INPUTS] = payload
    with pytest.raises(bootstrap.BootstrapError):
        staging.stage(flow.args)
    assert flow.stage_calls == flow.cleanup_calls == 1
    assert not (flow.args.operation_dir / "candidate").exists()
    assert (flow.args.operation_dir / "native-operation-evidence.tar").exists()


def test_same_attempt_is_never_replayed(flow):
    flow.fail_at = "native-stage"
    with pytest.raises(bootstrap.BootstrapError):
        staging.stage(flow.args)
    flow.fail_at = None
    with pytest.raises(bootstrap.BootstrapError, match="already exists"):
        staging.stage(flow.args)
    assert flow.stage_calls == 1 and flow.cleanup_calls == 0


@pytest.mark.parametrize("tampered", ["operator", "images", "identity", "binding", "no-authority"])
def test_retained_bootstrap_tampering_stops_before_cluster_access(flow, tampered):
    state = flow.args.state_dir
    if tampered == "operator":
        write(state / "marty-deploy", b"different unsigned operator", 0o700)
    elif tampered == "images":
        data = json.loads((state / "marty-images.json").read_bytes())
        data["images"]["services"] = "foreign"
        write(state / "marty-images.json", bootstrap.encoded(data))
    elif tampered == "identity":
        write(state / "application-identity/root.token", b"PRIVATE_ROOT_CANARY")
    else:
        data = json.loads((state / "bootstrap-complete.json").read_bytes())
        if tampered == "binding":
            data["applicationAuthority"]["binding"]["namespaceUid"] = "20c184dc-712f-41c4-968d-d87027eb4981"
        else:
            data.pop("applicationAuthority")
        write(state / "bootstrap-complete.json", bootstrap.encoded(data))
    with pytest.raises(bootstrap.BootstrapError):
        staging.stage(flow.args)
    assert flow.namespace_reads == flow.cluster_reads == flow.stage_calls == 0
    assert flow.creates == flow.uploads == []


@pytest.mark.parametrize("invalid", ["truncated", "missing-completion", "unexpected", "mode", "local-write"])
def test_unverified_native_evidence_keeps_pod_and_withholds_completion(flow, invalid, monkeypatch, capsys):
    if invalid == "local-write":
        original = bootstrap.write_new
        def fail_evidence(path, value, *args, **kwargs):
            if path.name == "native-operation-evidence.tar":
                raise OSError("PRIVATE_DISK_FAILURE_CANARY")
            return original(path, value, *args, **kwargs)
        monkeypatch.setattr(bootstrap, "write_new", fail_evidence)
    else:
        evidence = {"attempt.json": (b"PRIVATE_ATTEMPT_CANARY", 0o600)}
        if invalid == "unexpected":
            evidence["root.token"] = b"PRIVATE_UNEXPECTED_AUTHORITY_CANARY", 0o600
        elif invalid == "mode":
            evidence["attempt.json"] = b"PRIVATE_ATTEMPT_CANARY", 0o644
        payload = archive(evidence)
        if invalid == "truncated":
            payload = payload[:1024]
        flow.export_override[staging.REMOTE_OPERATION] = payload
    with pytest.raises(bootstrap.BootstrapError) as error:
        staging.stage(flow.args)
    assert flow.stage_calls == 1 and flow.cleanup_calls == 0
    assert not (flow.args.operation_dir / "application-stage-complete.json").exists()
    assert (flow.args.operation_dir / "transport-pod.json").exists()
    assert "1200-second total lifetime" in str(error.value)
    assert "PRIVATE_" not in str(error.value) + "".join(capsys.readouterr())


def test_readonly_retained_approle_identity_is_supported_without_mode_changes(flow):
    for name, (value, _) in flow.identity.items():
        flow.identity[name] = value, 0o400
        (flow.args.state_dir / "application-identity" / name).chmod(0o400)
    staging.stage(flow.args)
    assert flow.imported[staging.REMOTE_IDENTITY] == flow.identity
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o400
               for path in (flow.args.operation_dir / "application-identity").iterdir())


@pytest.mark.parametrize("value", [True, 56.0, "56", {}, [56, 11]])
def test_generation_inventory_response_requires_an_integer_before_cluster_access(flow, value):
    flow.generation_override = value
    with pytest.raises(bootstrap.BootstrapError):
        staging.stage(flow.args)
    assert flow.creates == [] and flow.namespace_reads == flow.cluster_reads == flow.stage_calls == 0


@pytest.mark.parametrize("trailer", [b"", b"\0" * 512, b"\0" * 1023, b"\0" * 1023 + b"X"])
def test_flat_export_requires_a_complete_tar_terminator(trailer):
    payload = archive({"input": (b"PRIVATE_TRANSPORT_CANARY", 0o600)})[:1024] + trailer
    with pytest.raises(bootstrap.BootstrapError, match="terminator"):
        bootstrap.flat_archive(payload, {"input"}, maximum=65536, modes={0o600})


def retained_activation(flow, *, complete=True):
    """A private completed adapter proof for the next-staging continuity tests."""
    state = staging.application_state
    operation = flow.args.state_dir.parent / "prior-activation"
    operation.mkdir(mode=0o700)
    candidate = operation / "candidate"
    candidate.mkdir(mode=0o700)
    for name, (value, mode) in flow.candidate.items():
        staging.write_preserved(candidate / name, value, mode)
    with state.locked(flow.args.state_dir) as held:
        current = held.current(flow.binding)
        held.begin(flow.binding, operation, candidate, "a" * 32, expected=current)
        if complete:
            proof = {"schema": state.VERIFIED_SCHEMA, "binding": flow.binding,
                "activationId": "a" * 32, "operationDirectory": str(operation),
                "candidateDirectory": str(candidate), "previousDirectory": str(current.directory),
                "runtime": flow.values["release"],
                "secret": {"name": "marty-secrets", "uid": "secret-uid", "resourceVersion": "201"},
                "deployments": [{"name": name, "uid": name + "-uid", "generation": 3,
                    "revision": 2, "podUids": [name + "-pod-uid"]}
                    for name in ["flow", "gateway", "issuance-native", "notification", "signing-keys"]],
                "status": "secret-and-rollouts-verified", "credentialDeliveryVerified": True,
                "credentialConsumptionVerified": False}
            write(operation / state.VERIFIED, bootstrap.encoded(proof))
            held.publish(flow.binding, operation, expected=current)
            held.complete(flow.binding, operation)
            held.finish(flow.binding, operation)
    return candidate


def test_next_stage_uses_verified_selected_generation_and_preserves_bootstrap_credentials(flow):
    original = dict(flow.snapshot)
    selected = retained_activation(flow)
    selected_snapshot = staging.current_snapshot(selected)
    flow.minted = {name: (("PRIVATE_SECOND_SCOPED_TOKEN_CANARY_" + name).encode(), 0o600)
                   for name in flow.runtime}
    flow.candidate = {**selected_snapshot, **flow.minted}
    selector_path = flow.args.state_dir / staging.application_state.SELECTOR
    selector = selector_path.read_bytes()
    staging.stage(flow.args)
    assert flow.imported[staging.REMOTE_CURRENT] == selected_snapshot
    assert flow.generation_calls[0][1]["current"] == str(selected)
    assert staging.current_snapshot(flow.args.operation_dir / "candidate") == flow.candidate
    assert staging.current_snapshot(selected) == selected_snapshot
    assert staging.current_snapshot(flow.args.state_dir / "credentials") == original
    assert selector_path.read_bytes() == selector
    assert flow.stage_calls == 1


def test_pending_activation_refuses_staging_before_artifact_or_cluster_activity(flow):
    retained_activation(flow, complete=False)
    with pytest.raises(bootstrap.BootstrapError, match="activation is pending"):
        staging.stage(flow.args)
    assert flow.events == [] and flow.processes == []
    assert flow.namespace_reads == flow.cluster_reads == flow.stage_calls == 0
    assert not flow.args.operation_dir.exists()


@pytest.mark.parametrize("target", ["selected", "original", "renewal-identity"])
def test_new_stage_directory_cannot_be_created_inside_retained_generations(flow, target):
    selected = retained_activation(flow)
    if target == "renewal-identity":
        protected = flow.args.state_dir / target
        protected.mkdir(mode=0o700)
        write(protected / "renewal-role-id", b"PUBLIC_RENEWAL_ROLE_CANARY")
        write(protected / "renewal-secret-id", b"PRIVATE_RENEWAL_SECRET_CANARY")
        write(protected / "renewal-leaf-policies.json", b"[]")
    else:
        protected = selected if target == "selected" else flow.args.state_dir / "credentials"
    before = staging.current_snapshot(protected)
    flow.args.operation_dir = protected / "unsafe-operation"
    with pytest.raises(bootstrap.BootstrapError, match="overlaps retained credential inputs"):
        staging.stage(flow.args)
    assert not flow.args.operation_dir.exists()
    assert staging.current_snapshot(protected) == before
    assert flow.events == [] and flow.creates == []


def test_observed_selection_inode_drift_refuses_before_issuing_replacements(flow, monkeypatch):
    retained_activation(flow)
    original_check = bootstrap.check_application_binding

    def change_selection_at_issue_boundary(transport, binding):
        original_check(transport, binding)
        if flow.namespace_reads == 3:
            selector = flow.args.state_dir / staging.application_state.SELECTOR
            replacement = selector.with_suffix(".replacement")
            write(replacement, selector.read_bytes())
            os.replace(replacement, selector)

    monkeypatch.setattr(bootstrap, "check_application_binding", change_selection_at_issue_boundary)
    with pytest.raises(bootstrap.BootstrapError, match="selected application generation changed"):
        staging.stage(flow.args)
    assert flow.stage_calls == 0
    assert not (flow.args.operation_dir / "application-stage-complete.json").exists()
