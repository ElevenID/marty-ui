#!/usr/bin/env python3
"""Inspect the retained legacy Kubernetes credential generation without renewal.

Both original and selected recovery artifacts must have their complete signed
installer closure. This adapter authenticates those bytes, binds the observed
namespace and bounded producer pod, and transports private inputs to the native
inspection owner. It issues no credential and changes no application Secret.

The original retained initialization is trusted operator evidence, not a new
enrollment receipt. Only its root_token is uploaded; recovery keys and the
administrator kubeconfig stay on private operator storage. A private operation
directory is required for every attempt. Failed evidence export retains the pod
only within its original 1200-second lifetime and never claims completion.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tarfile
import uuid

import bootstrap_kubernetes_openbao as bootstrap
import kubernetes_legacy_recovery_sources as sources
import stage_kubernetes_application_credentials as private


LEGACY_RUNTIME = "3ff1328d163f2dca38e369f17bda77b6334808eb"
LEGACY_OPENBAO_CHART = "0.30.6"
INITIALIZER_SHA256 = "57adbf26ef7b6f22a47c1ec85b9de75b807e394a2d7de48f6550b374cc8ebe1f"
SCHEMA = "marty.kubernetes-legacy-recovery-inspection/v1"
TARGET_SCHEMA = "marty.kubernetes-legacy-recovery-target/v1"
REPORT_LIMIT = 8 * 1024 * 1024
EVIDENCE_LIMIT = REPORT_LIMIT + 64 * 1024
REMOTE_OPERATOR = "/tmp/marty-deploy"
REMOTE_PUBLIC = "/tmp/legacy-public"
REMOTE_CA = REMOTE_PUBLIC + "/openbao-ca.pem"
REMOTE_CURRENT = "/tmp/application-current"
REMOTE_IDENTITY = "/tmp/application-identity"
REMOTE_ROOT = REMOTE_IDENTITY + "/root-token"
REMOTE_OPERATION = "/tmp/application-operation"
REMOTE_REPORT = REMOTE_OPERATION + "/inspection.json"
CONTRACT = {
    "schema": SCHEMA, "legacyRuntimeSourceSha": LEGACY_RUNTIME,
    "readOnly": True, "mutationAvailable": False, "workloadIdentities": 16,
    "keycloakSigningCertificates": 2, "keycloakTokens": 5, "ordinaryRuntimeTokens": 12,
    "migrationTokenReplacement": False, "maximumReplacementTtlSeconds": 28800,
}


def decode(raw: bytes, maximum: int, description: str) -> dict:
    bootstrap.require(0 < len(raw) <= maximum, description + " is empty or oversized")
    value = json.loads(raw, object_pairs_hook=bootstrap.unique_json_members)
    bootstrap.require(isinstance(value, dict), description + " is invalid")
    return value


def same(actual: object, expected: object, description: str) -> None:
    # Keep bool and int distinct when comparing native contracts or receipts.
    bootstrap.require(bootstrap.encoded(actual) == bootstrap.encoded(expected), description)


def valid_uuid(value: object) -> bool:
    try:
        return isinstance(value, str) and str(uuid.UUID(value)) == value
    except ValueError:
        return False


@contextmanager
def retained_lock(state: Path):
    """Coordinate recovery callers without adding or modifying retained files."""
    private.existing_private_directory(state)
    descriptor = os.open(state, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor)
        linked = state.lstat()
        bootstrap.require((opened.st_dev, opened.st_ino) == (linked.st_dev, linked.st_ino),
                          "retained directory changed before locking")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise bootstrap.BootstrapError("another recovery operation holds the retained-state lock") from error
        yield
        private.existing_private_directory(state)
        linked = state.lstat()
        bootstrap.require((opened.st_dev, opened.st_ino) == (linked.st_dev, linked.st_ino),
                          "retained directory changed during inspection")
    finally:
        os.close(descriptor)


def retained_records(state: Path, chart_source_sha: str) -> tuple[dict, dict, dict, dict, list[str]]:
    complete = private.record(state / "bootstrap-complete.json")
    initialize = private.record(state / "initialize-requested.json")
    namespace = private.record(state / "namespace.json")
    metadata = private.record(state / "tls-key-metadata.json")
    bootstrap.require(complete.get("status") == "openbao-and-application-credentials-ready"
                      and complete.get("runtimeSourceSha") == LEGACY_RUNTIME
                      and complete.get("openbaoChart") == LEGACY_OPENBAO_CHART
                      and complete.get("chartSourceSha") == chart_source_sha
                      and "applicationAuthority" not in complete,
                      "retained bootstrap is not the supported legacy generation")
    lifecycle = complete["credentialLifecycle"]
    binding = bootstrap.application_binding({
        "namespace": complete["namespace"], "namespaceUid": lifecycle["namespaceUid"],
        "openbaoClusterId": complete["openbaoClusterId"], "workloadProject": lifecycle["workloadProject"],
    })
    bootstrap.require(valid_uuid(complete.get("bootstrapId"))
                      and lifecycle.get("schema") == "marty.kubernetes-credential-lifecycle/v1"
                      and re.fullmatch(r"[0-9a-f]{12}", lifecycle.get("producerNonce", "")) is not None
                      and binding["workloadProject"] == "marty-selfhost-disposable-k8s-" + lifecycle["producerNonce"],
                      "retained bootstrap identity is invalid")
    same(namespace, {"name": binding["namespace"], "uid": binding["namespaceUid"],
                     "bootstrapId": complete["bootstrapId"]}, "retained namespace receipt differs")
    same(initialize, {"bootstrapId": complete["bootstrapId"], "namespace": binding["namespace"],
        "namespaceUid": binding["namespaceUid"], "producerNonce": lifecycle["producerNonce"],
        "workloadProject": binding["workloadProject"], "operation": "bao operator init",
        "recoveryShares": 1, "recoveryThreshold": 1}, "retained initialization request differs")
    for name in ("application-identity", "renewal-role-id", "renewal-secret-id", "renewal-leaf-policies.json"):
        bootstrap.require(not (state / name).exists() and not (state / name).is_symlink(),
                          "retained routine renewal authority requires its existing recovery path")
    pull = private.record(state / "openbao-pull-secrets.json")
    entries = pull.get("global", {}).get("imagePullSecrets")
    bootstrap.require(isinstance(entries, list) and len(entries) <= 16
                      and all(isinstance(entry, dict) and set(entry) == {"name"}
                              and isinstance(entry["name"], str)
                              and re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", entry["name"])
                              for entry in entries), "retained image pull Secret names are invalid")
    pull_secrets = [entry["name"] for entry in entries]
    bootstrap.require(len(pull_secrets) == len(set(pull_secrets)), "retained image pull Secret names repeat")
    return complete, initialize, metadata, binding, pull_secrets


def authenticate(args: argparse.Namespace, complete: dict) -> tuple[dict, dict, bytes]:
    operation = args.operation_dir
    original, original_openbao = bootstrap.prepare(assets=args.original_assets,
        runtime_source_sha=LEGACY_RUNTIME, release_tag=args.original_release_tag,
        build_run_id=args.original_build_run_id, build_run_attempt=args.original_build_run_attempt,
        chart_source_sha=args.chart_source_sha, gh=args.gh, cosign=args.cosign,
        output=operation / "original-images.json", openbao_output=operation / "original-openbao-images.json")
    same(original, private.record(args.state_dir / "marty-images.json"),
         "authenticated original image inventory or provenance differs")
    same(original_openbao, private.record(args.state_dir / "openbao-images.json"),
         "authenticated original OpenBao image projection differs")
    bootstrap.require(complete.get("openbaoImage") == original["images"]["openbao_didcomm"],
                      "retained OpenBao image identity differs")
    original_operator, original_initializer = bootstrap.authenticated_bootstrap_inputs(args.original_assets, original["release"])
    retained_operator, _ = private.private_bytes(args.state_dir / "marty-deploy", private.OPERATOR_LIMIT, {0o700})
    bootstrap.require(retained_operator == original_operator
                      and hashlib.sha256(original_initializer).hexdigest() == INITIALIZER_SHA256,
                      "retained signed operator or original initializer differs")
    recovery, _ = bootstrap.prepare(assets=args.recovery_assets,
        runtime_source_sha=args.recovery_source_sha, release_tag=args.recovery_release_tag,
        build_run_id=args.recovery_build_run_id, build_run_attempt=args.recovery_build_run_attempt,
        chart_source_sha=args.chart_source_sha, gh=args.gh, cosign=args.cosign,
        output=operation / "recovery-images.json", openbao_output=operation / "recovery-openbao-images.json")
    operator_bytes, initializer = bootstrap.authenticated_bootstrap_inputs(args.recovery_assets, recovery["release"])
    bootstrap.require(0 < len(operator_bytes) <= private.OPERATOR_LIMIT and initializer == original_initializer,
                      "selected recovery operator bounds or initializer policy owner differ")
    operator = operation / "marty-deploy"
    bootstrap.write_new(operator, operator_bytes, 0o700)
    for command, expected in ((["--build-identity"], (args.recovery_source_sha + ":" + args.recovery_release_tag).encode()),
                              (["operator", "kubernetes-legacy-recovery-contract"], None)):
        result = subprocess.run([str(operator), *command], stdin=subprocess.DEVNULL,
                                capture_output=True, check=False, timeout=10, env={})
        bootstrap.require(result.returncode == 0 and 0 < len(result.stdout) <= 4096,
                          "selected signed recovery operator does not provide the required contract")
        if expected is not None:
            bootstrap.require(result.stdout.strip() == expected, "selected recovery operator build identity differs")
        else:
            same(decode(result.stdout, 4096, "native recovery contract"), CONTRACT,
                 "selected signed recovery inspection contract differs")
    return original, recovery, operator_bytes


def kubeconfig_bytes(state: Path) -> bytes:
    raw, _ = private.private_bytes(state / "kubeconfig", 1024 * 1024, {0o600})
    value = decode(raw, 1024 * 1024, "retained Kubernetes configuration")
    bootstrap.require(isinstance(value.get("current-context"), str) and value["current-context"]
                      and all(isinstance(value.get(field), list) and len(value[field]) == 1
                              for field in ("contexts", "clusters", "users")),
                      "retained Kubernetes context is ambiguous")
    context, cluster, user = value["contexts"][0], value["clusters"][0], value["users"][0]
    bootstrap.require(context.get("name") == value["current-context"]
                      and context.get("context", {}).get("cluster") == cluster.get("name")
                      and context.get("context", {}).get("user") == user.get("name")
                      and isinstance(user.get("user"), dict)
                      and not any(field in user["user"] for field in ("exec", "auth-provider", "tokenFile", "client-certificate", "client-key"))
                      and isinstance(cluster.get("cluster"), dict)
                      and str(cluster["cluster"].get("server", "")).startswith("https://")
                      and isinstance(cluster["cluster"].get("certificate-authority-data"), str)
                      and not any(field in cluster["cluster"] for field in ("insecure-skip-tls-verify", "certificate-authority", "proxy-url")),
                      "retained Kubernetes configuration is not a flattened TLS context")
    return raw


def producer_document(namespace: str, image: str, nonce: str, pull_secrets: list[str]) -> dict:
    bootstrap.require(re.fullmatch(r"[0-9a-f]{12}", nonce) is not None
                      and re.fullmatch(r"ghcr\.io/elevenid/marty-ui-oss/services@sha256:[0-9a-f]{64}", image) is not None,
                      "native recovery transport identity is invalid")
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {
        "name": "marty-legacy-inspect-" + nonce, "namespace": namespace,
        "labels": {"app.kubernetes.io/part-of": "marty-development", "marty.elevenid.com/recovery-nonce": nonce}},
        "spec": {"restartPolicy": "Never", "activeDeadlineSeconds": 1200,
            "terminationGracePeriodSeconds": 15, "automountServiceAccountToken": False,
            "enableServiceLinks": False, "hostNetwork": False, "hostPID": False, "hostIPC": False,
            "shareProcessNamespace": False, "serviceAccountName": "default", "dnsPolicy": "ClusterFirst",
            "securityContext": {"runAsUser": 10001, "runAsGroup": 10001, "fsGroup": 10001,
                "runAsNonRoot": True, "seccompProfile": {"type": "RuntimeDefault"}},
            "imagePullSecrets": [{"name": name} for name in pull_secrets],
            "containers": [{"name": "native-producers", "image": image, "imagePullPolicy": "IfNotPresent",
                "command": ["/bin/sh", "-ec", "umask 077; exec sleep 1200"],
                "resources": {"requests": {"cpu": "50m", "memory": "64Mi"}, "limits": {"cpu": "750m", "memory": "512Mi"}},
                "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                    "capabilities": {"drop": ["ALL"]}},
                "volumeMounts": [{"name": "private", "mountPath": "/tmp"}]}],
            "volumes": [{"name": "private", "emptyDir": {"medium": "Memory", "sizeLimit": "128Mi"}}]}}


def pod_identity(value: dict, expected: dict, *, uid: str | None = None, ready: bool = False) -> str:
    metadata, spec = value.get("metadata", {}), value.get("spec", {})
    actual_uid = metadata.get("uid")
    bootstrap.require(value.get("apiVersion") == "v1" and value.get("kind") == "Pod"
                      and metadata.get("name") == expected["metadata"]["name"]
                      and metadata.get("namespace") == expected["metadata"]["namespace"]
                      and valid_uuid(actual_uid) and (uid is None or uid == actual_uid)
                      and not metadata.get("deletionTimestamp") and not metadata.get("ownerReferences")
                      and not metadata.get("finalizers"), "observed producer pod identity differs")
    bootstrap.require(isinstance(spec, dict), "observed producer pod spec is invalid")
    # Only scheduling/defaulting fields may be added outside the submitted spec.
    # The entire observed spec is separately frozen after readiness.
    additions = {"nodeName", "schedulerName", "priority", "preemptionPolicy", "tolerations", "serviceAccount"}
    bootstrap.require(set(spec) <= set(expected["spec"]) | additions,
                      "observed producer pod has additional execution or storage fields")
    normalized = dict(spec)
    for field in additions:
        normalized.pop(field, None)
    # Kubernetes omits empty/default-valued non-pointer fields on readback.
    for field in ("hostNetwork", "hostPID", "hostIPC"):
        normalized.setdefault(field, False)
    if not expected["spec"]["imagePullSecrets"]:
        normalized.setdefault("imagePullSecrets", [])
    bootstrap.require(spec.get("serviceAccount", "default") == "default"
                      and isinstance(normalized.get("containers"), list) and len(normalized["containers"]) == 1,
                      "observed producer pod contains additional authority or containers")
    container = dict(normalized["containers"][0])
    for field, default in (("terminationMessagePath", "/dev/termination-log"), ("terminationMessagePolicy", "File")):
        bootstrap.require(container.get(field, default) == default, "producer termination output is redirected")
        container.pop(field, None)
    normalized["containers"] = [container]
    same(normalized, expected["spec"], "observed producer image, execution, security or memory-only storage differs")
    if ready:
        status = value.get("status", {})
        statuses = status.get("containerStatuses", [])
        bootstrap.require(status.get("phase") == "Running" and isinstance(statuses, list) and len(statuses) == 1
                          and statuses[0].get("name") == "native-producers" and statuses[0].get("ready") is True
                          and isinstance(statuses[0].get("state", {}).get("running"), dict)
                          and statuses[0].get("restartCount") == 0,
                          "observed producer container is not the original ready process")
    return actual_uid


def namespace_identity(transport: bootstrap.Transport, binding: dict) -> dict:
    observed = decode(transport.kubectl("legacy namespace identity", "get", "namespace", binding["namespace"], "-o", "json"),
                      256 * 1024, "namespace observation")
    metadata = observed.get("metadata", {})
    result = {"name": metadata.get("name"), "uid": metadata.get("uid")}
    same(result, {"name": binding["namespace"], "uid": binding["namespaceUid"]}, "retained namespace changed")
    bootstrap.require(not metadata.get("deletionTimestamp"), "retained namespace is terminating")
    return result


def openbao_identity(transport: bootstrap.Transport, image: str, *, uid: str | None = None) -> dict:
    value = decode(transport.kubectl("legacy OpenBao image identity", "get", "pod", "openbao-0", "-o", "json"),
                   1024 * 1024, "OpenBao pod observation")
    metadata = value.get("metadata", {})
    containers = value.get("spec", {}).get("containers", [])
    bootstrap.require(metadata.get("name") == "openbao-0" and metadata.get("namespace") == transport.namespace
                      and valid_uuid(metadata.get("uid")) and (uid is None or metadata["uid"] == uid)
                      and not metadata.get("deletionTimestamp") and isinstance(containers, list),
                      "retained OpenBao pod identity differs")
    selected = [container for container in containers if isinstance(container, dict) and container.get("name") == "openbao"]
    bootstrap.require(len(selected) == 1, "retained OpenBao container identity is ambiguous")
    repository, digest = image.split("@", 1)
    observed = selected[0].get("image", "")
    bootstrap.require(isinstance(observed, str) and re.fullmatch(
        re.escape(repository) + r"(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?@" + re.escape(digest), observed) is not None,
        "live OpenBao container repository or digest differs from the authenticated original runtime")
    return {"pod": "openbao-0", "uid": metadata["uid"], "container": "openbao", "image": image}


def observed_pod(transport: bootstrap.Transport, expected: dict, uid: str) -> dict:
    value = decode(transport.kubectl("legacy producer identity", "get", "pod", expected["metadata"]["name"], "-o", "json"),
                   1024 * 1024, "producer observation")
    pod_identity(value, expected, uid=uid, ready=True)
    return value


def delete_pod(transport: bootstrap.Transport, expected: dict, uid: str) -> None:
    # Raw DELETE accepts the native DeleteOptions body, including the UID
    # precondition; a same-name replacement cannot be deleted by this cleanup.
    name = expected["metadata"]["name"]
    uri = f"/api/v1/namespaces/{transport.namespace}/pods/{name}"
    transport.kubectl("legacy producer cleanup", "delete", "--raw", uri, "-f", "-",
        data=bootstrap.encoded({"apiVersion": "v1", "kind": "DeleteOptions",
                              "preconditions": {"uid": uid}, "gracePeriodSeconds": 15}), timeout=30)
    transport.kubectl("legacy producer cleanup wait", "wait", "--for=delete", "pod/" + name,
                      "--timeout=120s", timeout=135)


def inspect_locked(args: argparse.Namespace) -> None:
    state, operation = args.state_dir, args.operation_dir
    complete, initialize, metadata, binding, pull_secrets = retained_records(state, args.chart_source_sha)
    original, recovery, operator_bytes = authenticate(args, complete)
    source_binding = sources.authenticate(args.recovery_assets, recovery["release"])
    bootstrap.write_new(operation / "source-authenticated.json", bootstrap.encoded({
        "schema": sources.SCHEMA, "recoveryRuntime": recovery["release"], "files": source_binding,
    }))
    snapshot = private.current_snapshot(state / "credentials")
    bootstrap.require("openbao_tls_ca_cert" in snapshot, "retained OpenBao trust is unavailable")
    archive = private.archive_snapshot(snapshot)
    bootstrap.write_new(operation / "current-snapshot.tar", archive)
    config = kubeconfig_bytes(state)
    bootstrap.write_new(operation / "kubeconfig", config)
    initialization, _ = private.private_bytes(state / "openbao-initialization.json", 65536, {0o400})
    material = decode(initialization, 65536, "retained initialization")
    root = material.get("root_token")
    bootstrap.require(isinstance(root, str) and 20 <= len(root) <= 256
                      and all(33 <= ord(character) <= 126 for character in root)
                      and isinstance(material.get("recovery_keys_b64"), list) and len(material["recovery_keys_b64"]) == 1,
                      "retained initialization authority is invalid")
    root_bytes = root.encode()
    # Do not copy initialization bytes or recovery keys into an operation record.
    del root, material
    kubectl = shutil.which("kubectl")
    bootstrap.require(kubectl is not None, "kubectl must be installed")
    transport = bootstrap.Transport(operation, operation / "kubeconfig", binding["namespace"], kubectl)
    namespace = namespace_identity(transport, binding)
    openbao = openbao_identity(transport, original["images"]["openbao_didcomm"])
    expected = producer_document(binding["namespace"], recovery["images"]["services"], bootstrap.secrets.token_hex(6), pull_secrets)
    pod = expected["metadata"]["name"]
    bootstrap.write_new(operation / "inspection-requested.json", bootstrap.encoded({
        "schema": "marty.kubernetes-legacy-inspection-request/v1", "binding": binding,
        "originalRuntime": original["release"], "recoveryRuntime": recovery["release"],
        "openbao": openbao, "pod": expected, "credentialsIssued": False, "activation": False,
    }))
    uid = None
    remote_ready = False
    native_started = False
    native_complete = False
    exported = False
    try:
        created = transport.kubectl("legacy producer creation", "create", "-f", "-", "-o", "json", data=bootstrap.encoded(expected))
        bootstrap.require(0 < len(created) <= 1024 * 1024, "created producer response exceeds transport bounds")
        bootstrap.write_new(operation / "producer-created.json", created)
        admitted = decode(created, 1024 * 1024, "created producer")
        # Retain the API-assigned UID before further validation/cleanup decisions.
        candidate_uid = admitted.get("metadata", {}).get("uid")
        if valid_uuid(candidate_uid) and admitted.get("metadata", {}).get("name") == pod:
            uid = candidate_uid
        uid = pod_identity(admitted, expected)
        bootstrap.write_new(operation / "transport-pod.json", bootstrap.encoded({
            "schema": "marty.kubernetes-native-transport/v2", "namespace": binding["namespace"],
            "namespaceUid": binding["namespaceUid"], "pod": pod, "uid": uid,
            "activeDeadlineSeconds": 1200, "storage": "memory-backed-emptyDir", "durableRecovery": False,
        }))
        transport.kubectl("legacy producer readiness", "wait", "--for=condition=Ready", "pod/" + pod, "--timeout=300s", timeout=330)
        baseline = observed_pod(transport, expected, uid)["spec"]
        bootstrap.write_new(operation / "producer-admitted.json", bootstrap.encoded({"uid": uid, "spec": baseline}))

        def phase() -> dict:
            sources.recheck(source_binding)
            observed_namespace = namespace_identity(transport, binding)
            same(openbao_identity(transport, original["images"]["openbao_didcomm"], uid=openbao["uid"]), openbao,
                 "retained OpenBao pod changed during inspection")
            same(observed_pod(transport, expected, uid)["spec"], baseline, "producer pod spec changed during inspection")
            return observed_namespace

        phase()
        transport.execute(pod, ["/bin/sh", "-ec",
            'umask 077; for path in "$@"; do mkdir "$path"; chmod 700 "$path"; done', "--",
            REMOTE_PUBLIC, REMOTE_CURRENT, REMOTE_IDENTITY, REMOTE_OPERATION])
        remote_ready = True
        phase()
        transport.upload(pod, REMOTE_OPERATOR, operator_bytes, executable=True)
        observed_hash = transport.execute(pod, ["sha256sum", REMOTE_OPERATOR]).split()
        bootstrap.require(observed_hash and observed_hash[0].decode() == hashlib.sha256(operator_bytes).hexdigest(),
                          "copied recovery operator differs")
        phase()
        transport.upload(pod, REMOTE_CA, snapshot["openbao_tls_ca_cert"][0])
        target = decode(transport.execute(pod, [REMOTE_OPERATOR, "operator", "kubernetes-legacy-recovery-target",
                                              REMOTE_CA, binding["openbaoClusterId"]], timeout=30), 4096, "native target probe")
        same(target, {"schema": TARGET_SCHEMA, "ready": True, "clusterId": binding["openbaoClusterId"], "authenticated": False},
             "native unauthenticated target probe did not confirm the retained cluster")
        bootstrap.write_new(operation / "target-confirmed.json", bootstrap.encoded(target))
        # No credential-containing upload occurs before this target confirmation.
        namespace = phase()
        transport.execute(pod, ["tar", "-xpf", "-", "-C", REMOTE_CURRENT], data=archive)
        namespace = phase()
        transport.upload(pod, REMOTE_ROOT, root_bytes)
        namespace = phase()
        context = {"schema": SCHEMA, "bootstrap": complete, "initializeRequest": initialize,
            "tlsKeyMetadata": metadata, "namespaceObservation": namespace, "current": REMOTE_CURRENT,
            "rootTokenFile": REMOTE_ROOT, "retainedRootSha256": hashlib.sha256(root_bytes).hexdigest()}
        bootstrap.write_new(operation / "native-inspection-request.json", bootstrap.encoded(context))
        native_started = True
        raw = transport.execute(pod, [REMOTE_OPERATOR, "operator", "kubernetes-legacy-recovery-inspect", REMOTE_REPORT],
                                data=bootstrap.encoded(context), timeout=660)
        bootstrap.require(0 < len(raw) <= 4096, "native inspection summary exceeds transport bounds")
        bootstrap.write_new(operation / "native-summary.json", raw)
        same(decode(raw, 4096, "native inspection summary"), {
            "schema": SCHEMA, "status": "inspected-not-staged", "mutationAvailable": False,
            "namespace": binding["namespace"], "workloadIdentities": 16, "keycloakSigningCertificates": 2,
            "keycloakTokens": 5, "ordinaryRuntimeTokens": 12, "privateReportWritten": True,
        }, "native inspection did not confirm its closed read-only result")
        native_complete = True
        phase()
    finally:
        failures = []
        if remote_ready and uid is not None:
            try:
                # All report contents are private, including incomplete output.
                observed_pod(transport, expected, uid)
                payload = bootstrap.remote_archive(transport, pod, REMOTE_OPERATION, EVIDENCE_LIMIT)
                members = bootstrap.private_archive(payload, {"inspection.json": REPORT_LIMIT}, maximum=EVIDENCE_LIMIT,
                    modes={0o600}, directories={"."}, complete=native_complete, allow_empty=not native_complete)
                bootstrap.write_new(operation / "native-inspection-evidence.tar", payload)
                if native_complete:
                    report = decode(members["inspection.json"][0], REPORT_LIMIT, "private native inspection report")
                    same(report.get("inputBindings"), {name: {"sha256": hashlib.sha256(value).hexdigest(), "mode": mode}
                         for name, (value, mode) in snapshot.items()}, "native report binds different retained inputs")
                    bootstrap.require(report.get("schema") == SCHEMA and report.get("status") == "inspected-not-staged"
                                      and report.get("mutationAvailable") is False,
                                      "private native inspection report is incomplete")
                    same(report.get("binding"), {
                        "bootstrapId": complete["bootstrapId"], **binding,
                        "producerNonce": complete["credentialLifecycle"]["producerNonce"],
                        "runtimeSourceSha": LEGACY_RUNTIME, "chartSourceSha": args.chart_source_sha,
                    }, "private native report binds a different retained installation")
                    bootstrap.write_new(operation / "inspection.json", members["inspection.json"][0])
                exported = True
            except Exception:
                failures.append("private native inspection evidence could not be retained")
        if uid is not None and (not remote_ready or exported) and (not native_started or native_complete):
            try:
                delete_pod(transport, expected, uid)
            except Exception:
                failures.append("bounded producer cleanup did not confirm completion")
        elif uid is not None:
            failures.append("producer retained only within its remaining original 1200-second lifetime; preserve transport-pod.json")
        if failures:
            raise bootstrap.BootstrapError("; ".join(failures))
    bootstrap.require(private.current_snapshot(state / "credentials") == snapshot,
                      "retained credentials changed during inspection")
    bootstrap.require(private.private_bytes(state / "openbao-initialization.json", 65536, {0o400})[0] == initialization,
                      "retained initialization changed during inspection")
    sources.recheck(source_binding)
    namespace_identity(transport, binding)
    same(openbao_identity(transport, original["images"]["openbao_didcomm"], uid=openbao["uid"]), openbao,
         "retained OpenBao pod changed during inspection")
    bootstrap.write_new(operation / "inspection-complete.json", bootstrap.encoded({
        "schema": "marty.kubernetes-legacy-inspection-completion/v1", "binding": binding,
        "originalRuntime": original["release"], "recoveryRuntime": recovery["release"],
        "status": "inspected-not-staged", "credentialsIssued": False, "activation": False,
        "report": "inspection.json", "podRemoved": True,
    }))
    print("Retained Kubernetes credential inspection completed; the private report is ready for review.")
    print("Credentials and application Secrets were not changed.")


def inspect(args: argparse.Namespace) -> None:
    bootstrap.require(os.name == "posix", "this private transport requires Linux")
    bootstrap.require(not args.operation_dir.is_relative_to(args.state_dir)
                      and not args.state_dir.is_relative_to(args.operation_dir),
                      "operation directory must be separate from retained state")
    with retained_lock(args.state_dir):
        bootstrap.private_directory(args.operation_dir)
        inspect_locked(args)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("state-dir", "operation-dir", "original-assets", "recovery-assets", "gh", "cosign"):
        parser.add_argument("--" + name, required=True, type=Path)
    for name in ("chart-source-sha", "original-release-tag", "recovery-source-sha", "recovery-release-tag"):
        parser.add_argument("--" + name, required=True)
    for name in ("original-build-run-id", "original-build-run-attempt", "recovery-build-run-id", "recovery-build-run-attempt"):
        parser.add_argument("--" + name, required=True, type=int)
    try:
        inspect(parser.parse_args(argv))
    except (bootstrap.BootstrapError, ValueError, OSError, KeyError, TypeError,
            subprocess.TimeoutExpired, tarfile.TarError) as error:
        detail = str(error) if isinstance(error, bootstrap.BootstrapError) else type(error).__name__
        parser.exit(1, f"Legacy Kubernetes inspection stopped: {detail}. Preserve the private attempt; completion was not recorded.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
