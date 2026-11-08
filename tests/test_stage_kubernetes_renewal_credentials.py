"""Exercise Renewal transport boundaries with closed native and Kubernetes doubles."""
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
import stage_kubernetes_renewal_credentials as staging


pytestmark = pytest.mark.skipif(os.name != "posix", reason="Linux private transport contract")
UID = "c647e5d2-85d7-409b-8729-94b8f8cf29ab"
CLUSTER = "9347f7a0-aae1-4ecf-9e77-165626c051c2"
NONCE = "0123456789ab"
PROJECT = "marty-selfhost-disposable-k8s-" + NONCE
TRANSPORT_NONCE = "abcdef123456"
OTHER_ID = "20c184dc-712f-41c4-968d-d87027eb4981"


def write(path, value, mode=0o600):
    path.write_bytes(value)
    path.chmod(mode)


def archive(members, extra=None):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as output:
        for name, (value, mode) in members.items():
            entry = tarfile.TarInfo(name)
            entry.size, entry.mode = len(value), mode
            output.addfile(entry, io.BytesIO(value))
        if extra is not None:
            output.addfile(extra)
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
    identity_path = state / "renewal-identity"
    identity_path.mkdir(mode=0o700)
    binding = {"namespace": "marty-test", "namespaceUid": UID,
               "openbaoClusterId": CLUSTER, "workloadProject": PROJECT}
    receipt = {"schema": "marty.kubernetes-renewal-binding/v1", "binding": binding, "producerNonce": NONCE}
    args = SimpleNamespace(state_dir=state, operation_dir=tmp_path / "attempt",
        assets=tmp_path / "assets", gh=tmp_path / "gh", cosign=tmp_path / "cosign",
        runtime_source_sha="1" * 40, chart_source_sha="2" * 40,
        release_tag="v1.2.3-nightly.20261108.123", build_run_id=123, build_run_attempt=1)
    publication = {"schema": bootstrap.PUBLICATION_SCHEMA, "catalog": json.loads(
        (bootstrap.ROOT / "deploy-config/catalog/kubernetes-secrets.json").read_bytes())}
    application = json.loads(bootstrap.encoded(bootstrap.APPLICATION_TOKEN_SPEC))
    renewable = set(bootstrap.SELFHOST_TLS_FILES) | bootstrap.KEYCLOAK_FILES
    renewal = {"schema": "marty.kubernetes-renewal/v1",
        "enrollmentOperation": "kubernetes-renewal-enroll", "stagingOperation": "kubernetes-renewal-stage",
        "bindingSchema": "marty.kubernetes-renewal-binding/v1",
        "identityFiles": sorted(bootstrap.RENEWAL_IDENTITY_FILES),
        "minimumTtlSeconds": 3600, "operationBudgetSeconds": 900,
        "renewableFiles": sorted(renewable), "unchangedFiles": ["workload_identity_ca_cert"],
        "changedFiles": 39, "scopedLeafTokens": 21, "tlsMetadataFile": "selfhost-tls-kms-roles.json"}
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
        "credentialLifecycle": {"namespaceUid": UID, "workloadProject": PROJECT, "producerNonce": NONCE},
        "credentialPublication": publication, "applicationTokenContract": application,
        "renewalContract": renewal,
        "renewalAuthority": {"schema": "marty.kubernetes-renewal-authority/v1",
            "binding": binding, "identityDirectory": "renewal-identity",
            "files": sorted(bootstrap.RENEWAL_IDENTITY_FILES), "bindingFile": "renewal-binding.json"},
        "imagePullSecrets": ["registry-pull"]}
    write(state / "bootstrap-complete.json", bootstrap.encoded(complete))
    write(state / "marty-images.json", bootstrap.encoded(values))
    write(state / "renewal-binding.json", bootstrap.encoded(receipt))
    write(state / "marty-deploy", operator, 0o700)
    write(state / "kubeconfig", bootstrap.encoded({"current-context": "retained-fixture",
        "contexts": [{"name": "retained-fixture"}], "users": [{"token": "PRIVATE_KUBECONFIG_CANARY"}]}))
    for name in ("openbao-initialization.json", "static.key", "root.token"):
        write(state / name, b"PRIVATE_ROOT_CANARY_NEVER_READ", 0o400)
    inputs = renewable | set(bootstrap.TOKEN_FILES.values())
    snapshot = {name: (("PRIVATE_CURRENT_CANARY_" + name).encode(), 0o600) for name in inputs}
    snapshot["workload_identity_ca_cert"] = b"PUBLIC_WORKLOAD_CA_CANARY", 0o444
    snapshot["openbao_tls_ca_cert"] = b"PUBLIC_OPENBAO_CA_CANARY", 0o644
    snapshot["optional-empty"] = b"", 0o640
    snapshot["optional-scalar"] = b"PRIVATE_UNCHANGED_SCALAR_CANARY", 0o640
    for name, (value, mode) in snapshot.items():
        write(current / name, value, mode)
    identity = {
        "renewal-role-id": (b"PUBLIC_RENEWAL_ROLE_ID_CANARY", 0o600),
        "renewal-secret-id": (b"PRIVATE_RENEWAL_SECRET_ID_CANARY", 0o600),
        "renewal-leaf-policies.json": (bootstrap.encoded([f"scoped-leaf-{i:02}" for i in range(21)]), 0o600),
    }
    for name, (value, mode) in identity.items():
        write(identity_path / name, value, mode)
    changed = renewable - {"workload_identity_ca_cert"}
    minted = {name: (("PRIVATE_RENEWED_INPUT_CANARY_" + name).encode(), snapshot[name][1]) for name in changed}
    item = SimpleNamespace(args=args, binding=binding, receipt=receipt, values=values, operator=operator,
        contracts={"kubernetes-secrets-contract": publication,
                   "kubernetes-application-token-contract": application, "kubernetes-renewal-contract": renewal},
        snapshot=snapshot, identity=identity, changed=changed, minted=minted,
        candidate={**snapshot, **minted}, processes=[], events=[], creates=[], uploads=[], imported={},
        generation_calls=[], native_contexts=[], wire_timeouts=[], now=1000.0, advance={},
        namespace_reads=0, cluster_reads=0, stage_calls=0, cleanup_calls=0,
        native_finished=False, fail_at=None, bad_contract=None, batch_override=None,
        generation_override=None, export_override={}, namespace_ids=[UID] * 4, cluster_ids=[CLUSTER] * 4)

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
        assert key in item.contracts
        item.events.append(key)
        if item.bad_contract == key:
            return SimpleNamespace(returncode=2, stdout=b"PRIVATE_UNSUPPORTED_CANARY", stderr=b"PRIVATE_STDERR_CANARY")
        return SimpleNamespace(returncode=0, stdout=bootstrap.encoded(item.contracts[key]), stderr=b"")

    def generation(context, location):
        item.generation_calls.append((location, context))
        operation = context["operation"]
        if item.fail_at == location + "-" + operation:
            return b'{"error":"PRIVATE_NATIVE_REFUSAL_CANARY"}'
        if item.generation_override is not None:
            return bootstrap.encoded({"value": item.generation_override})
        if operation == "verify":
            assert location == "local" and context["ca_overlap"] is context["ca_retire"] is False
            old = staging.application.current_snapshot(Path(context["current"]))
            new = staging.application.current_snapshot(Path(context["candidate"]))
            # Closed native verifier double: preservation, mode and exact-change
            # checks are observable here; actual live KMS proofs belong to Rust.
            valid = set(old) == set(new) and all(old[name][1] == new[name][1]
                and ((old[name][0] != new[name][0]) if name in changed else old[name][0] == new[name][0])
                for name in old)
            if not valid:
                return b'{"error":"PRIVATE_NATIVE_GENERATION_PROOF_CANARY"}'
            return bootstrap.encoded({"value": [len(old), len(changed)]})
        assert operation == "application-check"
        return bootstrap.encoded({"value": len(snapshot)})

    def native_evidence():
        if item.stage_calls == 0:
            return archive({})
        evidence = {"pending.json": (bootstrap.encoded({"binding": binding}), 0o600),
                    "authority.token": (b"PRIVATE_TRANSIENT_AUTHORITY_CANARY", 0o600)}
        if item.native_finished:
            evidence.update({
                "validated.json": (b'{"fixture":"PRIVATE_VALIDATION_CANARY"}', 0o600),
                "session-retired.json": (bootstrap.encoded({
                    "schema": "marty.kubernetes-renewal-session-retirement/v1", "transientRevoked": True}), 0o600),
                "completed.json": (bootstrap.encoded({
                    "schema": "marty.kubernetes-renewal-staging/v1", "binding": binding,
                    "producerNonce": NONCE, "files": len(snapshot), "changedFiles": 39,
                    "scopedLeafTokens": 21, "transientRevoked": True, "activated": False, "caChanged": False}), 0o600),
                "tls/selfhost-tls-kms-roles.json": (b'{"fixture":"PRIVATE_TLS_METADATA_CANARY"}', 0o600),
            })
            evidence.update({"tls/" + name: (item.candidate[name][0], 0o600) for name in bootstrap.SELFHOST_TLS_FILES})
            evidence.update({"keycloak/" + name: (item.candidate[name][0], 0o600) for name in bootstrap.KEYCLOAK_FILES})
        return archive(evidence)

    def run(transport, operation, command, *, data=None, timeout=300, env=None):
        item.events.append(operation)
        item.wire_timeouts.append((operation, timeout, item.now))
        elapsed = item.advance.get(operation, 0)
        item.now += elapsed
        if elapsed > timeout:
            raise bootstrap.BootstrapError("native transport timed out")
        if operation == "native application generation validation":
            assert command == [str(args.operation_dir / "marty-deploy"), "operator", "generation"] and env == {}
            return generation(json.loads(data), "local")
        assert command[:len(transport.base)] == transport.base
        argv = command[len(transport.base):]
        if operation == "namespace identity":
            uid = item.namespace_ids[item.namespace_reads]
            item.namespace_reads += 1
            return bootstrap.encoded({"metadata": {"name": transport.namespace, "uid": uid}})
        if operation == "Kubernetes resource creation":
            resource = json.loads(data)
            assert resource["kind"] == "Pod" and item.namespace_reads == item.cluster_reads == 1
            item.creates.append(resource)
            return b""
        if operation == "native producer readiness":
            if item.fail_at == "readiness":
                raise bootstrap.BootstrapError("native readiness failed")
            return b""
        if operation == "native producer cleanup":
            item.cleanup_calls += 1
            if item.fail_at == "cleanup":
                raise bootstrap.BootstrapError("native cleanup failed")
            return b""
        assert operation == "Kubernetes command" and argv[0] == "exec", "unexpected Kubernetes mutation"
        command = argv[argv.index("--") + 1:]
        if command == ["bao", "status", "-format=json"]:
            cluster = item.cluster_ids[item.cluster_reads]
            item.cluster_reads += 1
            return bootstrap.encoded({"initialized": True, "sealed": False, "type": "static",
                "storage_type": "raft", "cluster_id": cluster})
        if command[:2] == ["/bin/sh", "-ec"]:
            if command[2].startswith("umask 077; for path"):
                return b""
            if command[2].startswith("umask 077; set -C; cat"):
                assert item.namespace_reads == item.cluster_reads == 2
                item.uploads.append((command[4], data))
                return b""
            assert command[2] == bootstrap.REMOTE_ARCHIVE_COMMAND
            source = command[4]
            if item.fail_at == "evidence" and source == staging.REMOTE_OPERATION:
                raise bootstrap.BootstrapError("private evidence unavailable")
            if source in item.export_override:
                return item.export_override[source]
            if source == staging.REMOTE_CANDIDATE:
                return archive(item.candidate)
            assert source == staging.REMOTE_OPERATION
            return native_evidence()
        if command == ["sha256sum", staging.REMOTE_OPERATOR]:
            return hashlib.sha256(operator).hexdigest().encode()
        if command[:3] == ["tar", "-xpf", "-"]:
            assert item.namespace_reads == item.cluster_reads == 2
            item.imported[command[-1]] = unpack(data)
            return b""
        if command == [staging.REMOTE_OPERATOR, "operator", "generation"]:
            return generation(json.loads(data), "remote")
        if command[:3] == [staging.REMOTE_OPERATOR, "operator", "kubernetes-renewal-stage"]:
            item.stage_calls += 1
            assert item.namespace_reads == item.cluster_reads == 3
            assert (args.operation_dir / staging.REQUEST).exists()
            context = json.loads(data)
            budget = context.pop("budget_seconds")
            assert type(budget) is int and 60 <= budget <= 900
            assert context == {"current": staging.REMOTE_CURRENT, "candidate": staging.REMOTE_CANDIDATE,
                "output": staging.REMOTE_OPERATION, "binding_file": staging.REMOTE_BINDING, "binding": binding}
            item.native_contexts.append({**context, "budget_seconds": budget})
            if item.fail_at == "native-stage":
                raise bootstrap.BootstrapError("native authority stage failed; private evidence retained")
            if item.fail_at == "native-timeout":
                raise bootstrap.subprocess.TimeoutExpired(command, timeout,
                    output=b"PRIVATE_UNCERTAIN_RESPONSE_CANARY")
            item.native_finished = True
            return bootstrap.encoded(item.batch_override if item.batch_override is not None else {
                "ready": True, "candidate": staging.REMOTE_CANDIDATE, "count": len(snapshot),
                "changed": 39, "transientRevoked": True})
        raise AssertionError("unexpected native operation")

    private_bytes = staging.application.private_bytes
    def guarded_private_bytes(path, *args, **kwargs):
        assert path.name not in {"openbao-initialization.json", "static.key", "root.token"}, "routine staging opened root authority"
        return private_bytes(path, *args, **kwargs)

    monkeypatch.setattr(bootstrap, "prepare", prepared)
    monkeypatch.setattr(bootstrap, "authenticated_bootstrap_inputs", lambda assets, identity: (operator, b"unused init"))
    monkeypatch.setattr(bootstrap.subprocess, "run", process)
    monkeypatch.setattr(staging.shutil, "which", lambda name: "/synthetic/kubectl" if name == "kubectl" else None)
    monkeypatch.setattr(bootstrap.secrets, "token_hex", lambda count: TRANSPORT_NONCE)
    monkeypatch.setattr(bootstrap.Transport, "run", run)
    monkeypatch.setattr(staging.application, "private_bytes", guarded_private_bytes)
    monkeypatch.setattr(staging, "time", SimpleNamespace(monotonic=lambda: item.now))
    item.native_evidence = native_evidence
    return item


def test_stages_full_candidate_with_retired_session_and_no_activation(flow, capsys):
    staging.stage(flow.args)
    before = flow.snapshot
    after = staging.application.current_snapshot(flow.args.operation_dir / "candidate")
    assert after == flow.candidate
    assert staging.application.current_snapshot(flow.args.state_dir / "credentials") == before
    assert len(after) > 40 and sum(before[name][0] != after[name][0] for name in before) == 39
    assert flow.imported[staging.REMOTE_CURRENT] == before
    assert flow.imported[staging.REMOTE_IDENTITY] == flow.identity
    assert all(before[name] == after[name] for name in set(before) - flow.changed)
    assert flow.stage_calls == flow.cleanup_calls == 1
    assert flow.namespace_reads == flow.cluster_reads == 4
    assert flow.events[:4] == ["authenticate", "kubernetes-secrets-contract",
                              "kubernetes-application-token-contract", "kubernetes-renewal-contract"]
    pod = flow.creates[0]
    assert pod["spec"]["automountServiceAccountToken"] is False
    assert pod["spec"]["activeDeadlineSeconds"] == 1200
    assert pod["spec"]["volumes"][0]["emptyDir"]["medium"] == "Memory"
    completion = json.loads((flow.args.operation_dir / staging.COMPLETE).read_bytes())
    assert completion["activation"] is completion["caChanged"] is False
    assert completion["transientRevoked"] is True and completion["status"] == "candidate-staged-not-activated"
    assert completion["producerNonce"] == NONCE != TRANSPORT_NONCE
    assert completion["files"] == len(before) and completion["changedFiles"] == 39
    assert flow.native_contexts[0]["budget_seconds"] == 840
    evidence = flow.args.operation_dir / "native-operation-evidence.tar"
    assert b"PRIVATE_TRANSIENT_AUTHORITY_CANARY" in evidence.read_bytes()
    assert stat.S_IMODE(evidence.stat().st_mode) == 0o600
    assert not (flow.args.state_dir / staging.application_state.SELECTOR).exists()
    assert "PRIVATE_" not in "".join(capsys.readouterr()) + json.dumps(pod) + json.dumps(completion)
    assert all(b"PRIVATE_ROOT_CANARY" not in contents for _destination, contents in flow.uploads)


@pytest.mark.parametrize("command", ["kubernetes-secrets-contract", "kubernetes-application-token-contract",
                                     "kubernetes-renewal-contract"])
def test_unsupported_signed_capability_stops_before_any_cluster_access(flow, command):
    flow.bad_contract = command
    with pytest.raises(bootstrap.BootstrapError) as error:
        staging.stage(flow.args)
    assert "PRIVATE_" not in str(error.value)
    assert flow.namespace_reads == flow.cluster_reads == flow.stage_calls == 0
    assert flow.creates == flow.uploads == []


@pytest.mark.parametrize("tampered", ["operator", "images", "identity", "no-authority", "contract", "binding", "nonce", "lifecycle-nonce"])
def test_retained_admission_or_enrollment_tampering_stops_before_cluster_access(flow, tampered):
    state = flow.args.state_dir
    if tampered == "operator":
        write(state / "marty-deploy", b"different unsigned operator", 0o700)
    elif tampered == "images":
        value = json.loads((state / "marty-images.json").read_bytes())
        value["images"]["services"] = "foreign"
        write(state / "marty-images.json", bootstrap.encoded(value))
    elif tampered == "identity":
        write(state / "renewal-identity/root.token", b"PRIVATE_ROOT_CANARY")
    elif tampered in {"binding", "nonce"}:
        value = json.loads((state / "renewal-binding.json").read_bytes())
        if tampered == "binding":
            value["binding"]["workloadProject"] = "marty-selfhost-disposable-k8s-aaaaaaaaaaaa"
        else:
            value["producerNonce"] = TRANSPORT_NONCE
        write(state / "renewal-binding.json", bootstrap.encoded(value))
    else:
        value = json.loads((state / "bootstrap-complete.json").read_bytes())
        if tampered == "no-authority":
            value.pop("renewalAuthority")
        elif tampered == "lifecycle-nonce":
            value["credentialLifecycle"]["producerNonce"] = TRANSPORT_NONCE
        else:
            value["renewalContract"]["changedFiles"] = 40
        write(state / "bootstrap-complete.json", bootstrap.encoded(value))
    with pytest.raises(bootstrap.BootstrapError):
        staging.stage(flow.args)
    assert flow.namespace_reads == flow.cluster_reads == flow.stage_calls == 0
    assert flow.creates == flow.uploads == []


@pytest.mark.parametrize("observation", [0, 1, 2, 3])
@pytest.mark.parametrize("identity", ["namespace", "cluster"])
def test_binding_drift_refuses_at_each_private_boundary(flow, observation, identity):
    (flow.namespace_ids if identity == "namespace" else flow.cluster_ids)[observation] = OTHER_ID
    with pytest.raises(bootstrap.BootstrapError):
        staging.stage(flow.args)
    assert not (flow.args.operation_dir / staging.COMPLETE).exists()
    assert flow.stage_calls == (1 if observation == 3 else 0)
    if observation <= 1:
        assert flow.uploads == [] and flow.imported == {}
    assert flow.cleanup_calls == (0 if observation == 0 else 1)


@pytest.mark.parametrize("phase", ["local-application-check", "readiness", "remote-application-check",
                                    "native-stage", "native-timeout", "local-verify", "evidence", "cleanup"])
def test_failure_retains_attempt_without_completion_or_activation(flow, phase, capsys):
    flow.fail_at = phase
    with pytest.raises(bootstrap.BootstrapError) as error:
        staging.stage(flow.args)
    assert "PRIVATE_" not in str(error.value) + "".join(capsys.readouterr())
    assert not (flow.args.operation_dir / staging.COMPLETE).exists()
    assert staging.application.current_snapshot(flow.args.state_dir / "credentials") == flow.snapshot
    if phase == "local-application-check":
        assert flow.creates == [] and flow.cleanup_calls == 0
    else:
        assert flow.cleanup_calls == (0 if phase in {"native-stage", "native-timeout", "evidence"} else 1)
        pointer = json.loads((flow.args.operation_dir / "transport-pod.json").read_bytes())
        assert pointer["activeDeadlineSeconds"] == 1200 and pointer["durableRecovery"] is False
        assert pointer["pod"] == flow.creates[0]["metadata"]["name"]
    if phase not in {"local-application-check", "readiness", "evidence"}:
        assert (flow.args.operation_dir / "native-operation-evidence.tar").exists()


@pytest.mark.parametrize("field,value", [("ready", 1), ("candidate", "/tmp/foreign"),
    ("count", 40), ("count", True), ("changed", 39.0), ("changed", 40), ("transientRevoked", False)])
def test_native_response_requires_exact_typed_cleanup_and_generation_proof(flow, field, value):
    flow.batch_override = {"ready": True, "candidate": staging.REMOTE_CANDIDATE,
        "count": len(flow.snapshot), "changed": 39, "transientRevoked": True, field: value}
    with pytest.raises(bootstrap.BootstrapError):
        staging.stage(flow.args)
    assert flow.stage_calls == 1 and flow.cleanup_calls == 0
    assert not (flow.args.operation_dir / staging.COMPLETE).exists()
    assert not (flow.args.operation_dir / "candidate").exists()


@pytest.mark.parametrize("invalid", ["extra", "missing", "mode", "duplicate", "symlink", "hardlink", "oversized", "truncated"])
def test_candidate_export_rejects_unclosed_or_unsafe_archives(flow, invalid):
    members = dict(flow.candidate)
    name = next(iter(members))
    extra = None
    if invalid == "extra":
        members["root.token"] = b"PRIVATE_FORBIDDEN_ROOT_CANARY", 0o600
    elif invalid == "missing":
        members.pop(name)
    elif invalid == "mode":
        members[name] = members[name][0], 0o777
    elif invalid == "oversized":
        members[name] = b"x" * 65537, 0o600
    elif invalid in {"duplicate", "symlink", "hardlink"}:
        extra = tarfile.TarInfo(name if invalid == "duplicate" else "root.token")
        extra.mode = 0o600
        if invalid != "duplicate":
            extra.type = tarfile.SYMTYPE if invalid == "symlink" else tarfile.LNKTYPE
            extra.linkname = "/private/root.token"
    payload = archive(members, extra)
    if invalid == "truncated":
        payload = payload[:1024]
    flow.export_override[staging.REMOTE_CANDIDATE] = payload
    with pytest.raises(bootstrap.BootstrapError):
        staging.stage(flow.args)
    assert flow.stage_calls == flow.cleanup_calls == 1
    assert not (flow.args.operation_dir / staging.COMPLETE).exists()
    assert not (flow.args.operation_dir / "candidate").exists()
    assert (flow.args.operation_dir / "native-operation-evidence.tar").exists()


@pytest.mark.parametrize("tampered", ["ca", "ordinary", "mode", "unchanged-renewal", "empty-extra"])
def test_native_local_verification_rejects_candidate_drift(flow, tampered):
    if tampered == "ca":
        name = "workload_identity_ca_cert"
    elif tampered == "ordinary":
        name = next(iter(set(bootstrap.TOKEN_FILES.values()) - flow.changed))
    elif tampered == "empty-extra":
        name = "optional-empty"
    else:
        name = next(iter(flow.changed))
    if tampered == "mode":
        flow.candidate[name] = flow.candidate[name][0], 0o400
    elif tampered == "unchanged-renewal":
        flow.candidate[name] = flow.snapshot[name]
    else:
        flow.candidate[name] = b"PRIVATE_UNEXPECTED_REPLACEMENT_CANARY", flow.candidate[name][1]
    with pytest.raises(bootstrap.BootstrapError, match="generation refused"):
        staging.stage(flow.args)
    assert flow.stage_calls == flow.cleanup_calls == 1
    assert not (flow.args.operation_dir / staging.COMPLETE).exists()


@pytest.mark.parametrize("invalid", ["missing-completion", "unexpected", "mode", "truncated", "retirement", "binding", "nonce", "count-type"])
def test_native_evidence_without_exact_retirement_and_binding_keeps_original_pod(flow, invalid):
    flow.stage_calls = 1
    flow.native_finished = True
    members = unpack(flow.native_evidence())
    flow.stage_calls = 0
    flow.native_finished = False
    if invalid == "missing-completion":
        members.pop("completed.json")
    elif invalid == "unexpected":
        members["root.token"] = b"PRIVATE_FORBIDDEN_ROOT_CANARY", 0o600
    elif invalid == "mode":
        members["authority.token"] = members["authority.token"][0], 0o644
    elif invalid != "truncated":
        name = "session-retired.json" if invalid == "retirement" else "completed.json"
        value = json.loads(members[name][0])
        if invalid == "retirement":
            value["transientRevoked"] = 1
        elif invalid == "binding":
            value["binding"]["namespaceUid"] = OTHER_ID
        elif invalid == "nonce":
            value["producerNonce"] = TRANSPORT_NONCE
        else:
            value["files"] = float(len(flow.snapshot))
        members[name] = bootstrap.encoded(value), 0o600
    payload = archive(members)
    if invalid == "truncated":
        payload = payload[:1024]
    flow.export_override[staging.REMOTE_OPERATION] = payload
    with pytest.raises(bootstrap.BootstrapError, match="remaining 1200-second total lifetime"):
        staging.stage(flow.args)
    assert flow.stage_calls == 1 and flow.cleanup_calls == 0
    assert not (flow.args.operation_dir / staging.COMPLETE).exists()


@pytest.mark.parametrize("file", ["native-operation-evidence.tar", staging.COMPLETE])
def test_failed_private_fsync_withholds_completion_and_preserves_recovery(flow, file, monkeypatch):
    fsync = os.fsync
    def failing_fsync(descriptor):
        if os.readlink(f"/proc/self/fd/{descriptor}").endswith("/" + file):
            raise OSError("PRIVATE_FSYNC_FAILURE_CANARY")
        fsync(descriptor)
    monkeypatch.setattr(os, "fsync", failing_fsync)
    with pytest.raises((bootstrap.BootstrapError, OSError)):
        staging.stage(flow.args)
    assert not (flow.args.operation_dir / staging.COMPLETE).exists()
    assert (flow.args.operation_dir / staging.REQUEST).exists()
    assert (flow.args.operation_dir / "candidate").exists()
    assert flow.cleanup_calls == (0 if file == "native-operation-evidence.tar" else 1)


def test_original_budget_includes_readiness_and_never_restarts_for_native_batch(flow):
    flow.advance["native producer readiness"] = 300
    staging.stage(flow.args)
    assert flow.native_contexts[0]["budget_seconds"] == 540
    assert max(timeout for operation, timeout, _ in flow.wire_timeouts
               if operation == "Kubernetes command") <= 600


def test_expired_original_budget_never_logs_in_or_claims_cleanup(flow):
    flow.advance["native producer readiness"] = 901
    with pytest.raises(bootstrap.BootstrapError):
        staging.stage(flow.args)
    assert flow.stage_calls == flow.cleanup_calls == 0
    assert not (flow.args.operation_dir / staging.COMPLETE).exists()
    assert (flow.args.operation_dir / "transport-pod.json").exists()


def test_same_private_attempt_is_never_replayed(flow):
    flow.fail_at = "native-stage"
    with pytest.raises(bootstrap.BootstrapError):
        staging.stage(flow.args)
    flow.fail_at = None
    with pytest.raises(bootstrap.BootstrapError, match="already exists"):
        staging.stage(flow.args)
    assert flow.stage_calls == 1 and flow.cleanup_calls == 0


def retained_application_activation(flow, *, complete=True):
    state = staging.application_state
    operation = flow.args.state_dir.parent / "prior-activation"
    operation.mkdir(mode=0o700)
    candidate = operation / "candidate"
    candidate.mkdir(mode=0o700)
    for name, (value, mode) in flow.snapshot.items():
        if name in set(bootstrap.TOKEN_FILES.values()):
            value = ("PRIVATE_ACTIVATED_ORDINARY_CANARY_" + name).encode()
        staging.application.write_preserved(candidate / name, value, mode)
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


def test_renewal_uses_selected_generation_and_keeps_latest_ordinary_inputs(flow):
    selected = retained_application_activation(flow)
    selected_snapshot = staging.application.current_snapshot(selected)
    flow.candidate = {**selected_snapshot, **flow.minted}
    selector_path = flow.args.state_dir / staging.application_state.SELECTOR
    selector = selector_path.read_bytes()
    staging.stage(flow.args)
    assert flow.imported[staging.REMOTE_CURRENT] == selected_snapshot
    assert flow.generation_calls[0][1]["current"] == str(selected)
    assert staging.application.current_snapshot(flow.args.operation_dir / "candidate") == flow.candidate
    assert staging.application.current_snapshot(selected) == selected_snapshot
    assert staging.application.current_snapshot(flow.args.state_dir / "credentials") == flow.snapshot
    assert selector_path.read_bytes() == selector


def test_pending_activation_blocks_renewal_before_artifact_or_cluster_activity(flow):
    retained_application_activation(flow, complete=False)
    with pytest.raises(bootstrap.BootstrapError, match="activation is pending"):
        staging.stage(flow.args)
    assert flow.events == flow.processes == flow.creates == []
    assert not flow.args.operation_dir.exists()


def test_shared_state_lock_blocks_renewal_before_artifact_or_cluster_activity(flow):
    with staging.application_state.locked(flow.args.state_dir):
        with pytest.raises(bootstrap.BootstrapError, match="holds this private state"):
            staging.stage(flow.args)
    assert flow.events == flow.processes == flow.creates == []
    assert not flow.args.operation_dir.exists()


@pytest.mark.parametrize("target", ["selected", "credentials", "renewal-identity"])
def test_attempt_cannot_overlap_any_retained_credential_directory(flow, target):
    selected = retained_application_activation(flow)
    root = selected if target == "selected" else flow.args.state_dir / target
    flow.args.operation_dir = root / "unsafe-operation"
    with pytest.raises(bootstrap.BootstrapError, match="overlaps retained credential inputs"):
        staging.stage(flow.args)
    assert not flow.args.operation_dir.exists()
    assert flow.events == flow.creates == []


@pytest.mark.parametrize("when", ["before-login", "after-cleanup"])
def test_observed_selector_inode_drift_withholds_native_use_or_completion(flow, when, monkeypatch):
    selected = retained_application_activation(flow)
    flow.candidate = {**staging.application.current_snapshot(selected), **flow.minted}
    check = bootstrap.check_application_binding
    remaining = staging.BoundedTransport.remaining
    changed = False
    def replace_selector():
        nonlocal changed
        selector = flow.args.state_dir / staging.application_state.SELECTOR
        replacement = selector.with_suffix(".replacement")
        write(replacement, selector.read_bytes())
        os.replace(replacement, selector)
        changed = True
    def checking(transport, binding):
        check(transport, binding)
        if when == "before-login" and flow.namespace_reads == 3:
            replace_selector()
    def remaining_checked(transport):
        result = remaining(transport)
        if when == "after-cleanup" and flow.cleanup_calls == 1 and not changed:
            replace_selector()
        return result
    monkeypatch.setattr(bootstrap, "check_application_binding", checking)
    monkeypatch.setattr(staging.BoundedTransport, "remaining", remaining_checked)
    with pytest.raises(bootstrap.BootstrapError, match="selected application generation changed"):
        staging.stage(flow.args)
    assert flow.stage_calls == (0 if when == "before-login" else 1)
    assert not (flow.args.operation_dir / staging.COMPLETE).exists()


def test_readonly_generic_renewal_identity_keeps_original_modes(flow):
    for name, (value, _mode) in flow.identity.items():
        flow.identity[name] = value, 0o400
        (flow.args.state_dir / "renewal-identity" / name).chmod(0o400)
    staging.stage(flow.args)
    assert flow.imported[staging.REMOTE_IDENTITY] == flow.identity
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o400
               for path in (flow.args.operation_dir / "renewal-identity").iterdir())


@pytest.mark.parametrize("target", ["candidate", "current", "identity", "identity-copy", "binding", "binding-copy"])
def test_custody_drift_during_evidence_retention_withholds_completion(flow, target, monkeypatch):
    remote_archive = bootstrap.remote_archive
    def exporting(transport, pod, source, maximum):
        payload = remote_archive(transport, pod, source, maximum)
        if source == staging.REMOTE_OPERATION:
            if target == "candidate":
                path = flow.args.operation_dir / "candidate/optional-scalar"
            elif target == "current":
                path = flow.args.state_dir / "credentials/optional-scalar"
            elif target in {"identity", "identity-copy"}:
                parent = flow.args.state_dir if target == "identity" else flow.args.operation_dir
                path = parent / "renewal-identity/renewal-secret-id"
            else:
                parent = flow.args.state_dir if target == "binding" else flow.args.operation_dir
                path = parent / "renewal-binding.json"
            write(path, b"PRIVATE_POST_PROOF_DRIFT_CANARY", stat.S_IMODE(path.stat().st_mode))
        return payload
    monkeypatch.setattr(bootstrap, "remote_archive", exporting)
    with pytest.raises(bootstrap.BootstrapError, match="changed before completion"):
        staging.stage(flow.args)
    assert flow.stage_calls == flow.cleanup_calls == 1
    assert (flow.args.operation_dir / "native-operation-evidence.tar").exists()
    assert not (flow.args.operation_dir / staging.COMPLETE).exists()
