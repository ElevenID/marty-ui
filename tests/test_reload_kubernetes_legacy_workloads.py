"""Internal reload contract tests; all API, process, clock and exec calls are doubled."""
from __future__ import annotations

import base64
from copy import deepcopy
import json
import math
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import uuid

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from test_recover_kubernetes_legacy_credentials import recovery_flow, activate, sealed_reload_fixture
from test_inspect_kubernetes_legacy_credentials import flow, BAO_UID, NAMESPACE_UID
import bootstrap_kubernetes_openbao as bootstrap
import recover_kubernetes_legacy_credentials as recovery
import reload_kubernetes_legacy_workloads as reload


@pytest.fixture
def reload_flow(recovery_flow, monkeypatch, capsys):
    item = recovery_flow
    activate(item)
    recovery.recover(item.args)
    capsys.readouterr()
    original = deepcopy(item.original)
    original["images"]["keycloak"] = "ghcr.io/elevenid/marty-ui-oss/keycloak@sha256:" + "a" * 64
    item.request = reload.ReloadRequest(item.args.operation_dir.with_name("reload"), original, item.bound, BAO_UID,
        item.plan_bytes, recovery.sha256(item.plan_bytes), {name: bootstrap.encoded(value) for name, value in item.secrets.items()})
    item.deployments, item.replica_sets, item.pods = {}, {}, {}
    item.reload_patches, item.execs, item.io, item.guard_calls = [], [], [], 0
    item.reload_failure = None
    item.reload_failure_index = 1
    item.preflight_tamper = item.pod_tamper = None
    source = yaml.safe_load((bootstrap.ROOT / "deploy/helm/marty/files/workloads.yaml").read_bytes())
    release_name = "marty-retained"
    for index, name in enumerate(reload.WORKLOADS):
        labels = {"app.kubernetes.io/instance": release_name, "app.kubernetes.io/component": name}
        annotations = {"marty.11id.dev/" + key: str(value) for key, value in original["release"].items()}
        annotations["checksum/config"] = "b" * 64
        security = {"runAsNonRoot": True, "runAsUser": 1000 if name == "keycloak" else 10001,
                    "fsGroup": 1000 if name == "keycloak" else 10001, "seccompProfile": {"type": "RuntimeDefault"}}
        main = {"name": name, "image": original["images"]["keycloak" if name == "keycloak" else "services"],
            "imagePullPolicy": "IfNotPresent", "securityContext": {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}},
            "envFrom": [{"configMapRef": {"name": "marty-config"}}]}
        spec = {"serviceAccountName": "marty-app", "automountServiceAccountToken": False,
                "securityContext": security, "containers": [main]}
        if name == "keycloak":
            main.update(command=["/opt/keycloak/bin/kc.sh"], args=["start", "--import-realm", "--features=organization"],
                env=[{"name": "BAO_TOKEN_FILE", "value": "/run/secrets/keycloak_signing_kms_token"}],
                volumeMounts=[{"name": "kms", "mountPath": "/run/secrets", "readOnly": True}])
            spec["volumes"] = [{"name": "kms", "secret": {"secretName": "keycloak-kms", "defaultMode": 288}}]
        else:
            security.update(runAsGroup=10001, fsGroupChangePolicy="OnRootMismatch")
            workload = source[name]
            main.update(command=["/app/services/entrypoint.sh"],
                env=[{"name": "SSL_CERT_FILE", "value": "/etc/marty/trust/ca-certificates.crt"},
                     {"name": "SERVICE_NAME", "value": workload["serviceName"]}, *deepcopy(workload.get("env", []))],
                volumeMounts=[{"name": "redis-trust", "mountPath": "/etc/marty/trust", "readOnly": True},
                              *deepcopy(workload.get("volumeMounts", []))])
            command = "cat /etc/ssl/certs/ca-certificates.crt /redis-ca/ca.crt"
            init_mounts = [{"name": "redis-ca", "mountPath": "/redis-ca", "readOnly": True}, {"name": "redis-trust", "mountPath": "/trust"}]
            volumes = [{"name": "redis-ca", "secret": {"secretName": "marty-redis-tls", "defaultMode": 292,
                       "items": [{"key": "ca.crt", "path": "ca.crt"}]}},
                       {"name": "redis-trust", "emptyDir": {"medium": "Memory", "sizeLimit": "2Mi"}}]
            if name == "flow":
                command += " /signing-ca/ca.crt"
                init_mounts.append({"name": "signing-ca", "mountPath": "/signing-ca", "readOnly": True})
                volumes.append({"name": "signing-ca", "secret": {"secretName": "signing-keys-integration-secret-ca", "defaultMode": 292,
                    "items": [{"key": "ca.crt", "path": "ca.crt"}]}})
            spec["initContainers"] = [{"name": "redis-trust", "image": original["images"]["services"],
                "command": ["/bin/sh", "-ec", command + " > /trust/ca-certificates.crt"], "volumeMounts": init_mounts,
                "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}}}]
            for volume in deepcopy(workload.get("volumes", [])):
                if "secret" in volume:
                    volume["secret"]["defaultMode"] = 288
                volumes.append(volume)
            spec["volumes"] = volumes
        item.deployments[name] = {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {
            "name": name, "namespace": item.binding["namespace"], "uid": str(uuid.UUID(int=10000 + index)),
            "resourceVersion": str(100 + index), "generation": 1,
            "labels": {**labels, "app.kubernetes.io/name": "marty", "app.kubernetes.io/managed-by": "Helm", "helm.sh/chart": "marty-0.1.0"},
            "annotations": {"meta.helm.sh/release-name": release_name, "meta.helm.sh/release-namespace": item.binding["namespace"], reload.REVISION: "1"}},
            "spec": {"replicas": 1, "strategy": {"type": "Recreate"}, "selector": {"matchLabels": labels},
                "template": {"metadata": {"labels": labels, "annotations": annotations}, "spec": spec}},
            "status": {"observedGeneration": 1, "replicas": 1, "updatedReplicas": 1, "readyReplicas": 0, "availableReplicas": 0}}
    item.original_deployments = deepcopy(item.deployments)

    def children(name):
        index = reload.WORKLOADS.index(name)
        deployed = item.deployments[name]
        template = deepcopy(deployed["spec"]["template"])
        template["metadata"]["labels"]["pod-template-hash"] = "abc" + str(index)
        replica_name = name + "-abc" + str(index)
        replica_uid = str(uuid.UUID(int=20000 + index))
        replica = {"apiVersion": "apps/v1", "kind": "ReplicaSet", "metadata": {"name": replica_name,
            "namespace": item.binding["namespace"], "uid": replica_uid, "resourceVersion": "300", "generation": 1,
            "annotations": {reload.REVISION: "2"}, "ownerReferences": [{"apiVersion": "apps/v1", "kind": "Deployment", "name": name,
                "uid": deployed["metadata"]["uid"], "controller": True, "blockOwnerDeletion": True}]},
            "spec": {"replicas": 1, "selector": {"matchLabels": deepcopy(template["metadata"]["labels"])}, "template": template},
            "status": {"replicas": 1, "readyReplicas": 1, "availableReplicas": 1}}
        pod = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": replica_name + "-new", "namespace": item.binding["namespace"],
            "uid": str(uuid.UUID(int=30000 + index)), "resourceVersion": "400", "labels": deepcopy(template["metadata"]["labels"]),
            "annotations": deepcopy(template["metadata"]["annotations"]), "ownerReferences": [{"apiVersion": "apps/v1",
                "kind": "ReplicaSet", "name": replica_name, "uid": replica_uid, "controller": True, "blockOwnerDeletion": True}]},
            "spec": deepcopy(template["spec"]), "status": {"phase": "Running", "conditions": [{"type": "Ready", "status": "True"}],
                "containerStatuses": [{"name": name, "ready": True, "restartCount": 0, "imageID": "containerd://runtime-platform-config",
                    "containerID": "containerd://main-" + name, "state": {"running": {"startedAt": "2026-11-09T00:00:00Z"}}}]}}
        pod["spec"].update(nodeName="retained-node", serviceAccount="marty-app", priority=0, preemptionPolicy="PreemptLowerPriority",
            dnsPolicy="ClusterFirst", restartPolicy="Always", schedulerName="default-scheduler", terminationGracePeriodSeconds=30, enableServiceLinks=True,
            tolerations=[{"key": "node.kubernetes.io/" + condition, "operator": "Exists", "effect": "NoExecute", "tolerationSeconds": 300}
                         for condition in ("not-ready", "unreachable")])
        for container in pod["spec"]["containers"] + pod["spec"].get("initContainers", []):
            container.update(terminationMessagePath="/dev/termination-log", terminationMessagePolicy="File")
        if name != "keycloak":
            pod["status"]["initContainerStatuses"] = [{"name": "redis-trust", "restartCount": 0,
                "imageID": "containerd://another-runtime-config", "containerID": "containerd://init-" + name,
                "state": {"terminated": {"exitCode": 0}}}]
        item.replica_sets[replica_name], item.pods[pod["metadata"]["name"]] = replica, pod

    def read_deployment(name):
        value = item.deployments[name]
        if name in item.reload_patches:
            value["metadata"]["annotations"][reload.REVISION] = "2"
            value["status"] = {"observedGeneration": 2, "replicas": 1, "updatedReplicas": 1,
                               "readyReplicas": 0 if item.reload_failure == "wait-timeout" else 1,
                               "availableReplicas": 0 if item.reload_failure == "wait-timeout" else 1}
            if item.reload_failure == "concurrent-rollout":
                value["spec"]["template"]["metadata"]["annotations"]["foreign-rollout"] = "unexpected"
                value["metadata"]["generation"] = 3
        elif item.preflight_tamper:
            item.preflight_tamper(value)
        if item.reload_failure == "freshness-expired" and name == reload.WORKLOADS[-1] and not item.reload_patches:
            item.clock.monotonic += 301
        return deepcopy(value)

    class Transport:
        namespace = item.binding["namespace"]
        base = ["/synthetic/kubectl", "--kubeconfig", str(item.args.operation_dir / "kubeconfig"), "--namespace", namespace]

        def kubectl(self, operation, *command, data=None, timeout=30):
            item.io.append((command, timeout, item.clock.monotonic))
            # Model slow bounded readiness calls for the timeout case. This
            # consumes the one real budget without thousands of synthetic
            # polling iterations over the growing private evidence inventory.
            elapsed = min(timeout, 25) if item.reload_failure == "wait-timeout" and len(item.reload_patches) == 16 else 0.001
            item.clock.monotonic += elapsed
            item.clock.wall += elapsed
            if command[:2] == ("get", "namespace"):
                return bootstrap.encoded({"metadata": {"name": self.namespace, "uid": NAMESPACE_UID}})
            if command[:3] == ("get", "pod", "openbao-0"):
                return bootstrap.encoded({"metadata": {"name": "openbao-0", "namespace": self.namespace, "uid": BAO_UID},
                    "spec": {"containers": [{"name": "openbao", "image": original["images"]["openbao_didcomm"]}]}})
            if command[:2] == ("get", "secret"):
                value = deepcopy(item.secrets[command[2]])
                if item.reload_failure == "secret-drift":
                    value["metadata"]["resourceVersion"] = "unexpected"
                return bootstrap.encoded(value)
            if command[:2] == ("get", "deployment"):
                return bootstrap.encoded(read_deployment(command[2]))
            if command[:2] in (("get", "replicasets"), ("get", "pods")):
                component = dict(part.split("=", 1) for part in command[3].split(","))["app.kubernetes.io/component"]
                if command[1] == "replicasets":
                    values = [deepcopy(value) for value in item.replica_sets.values() if value["metadata"]["ownerReferences"][0]["name"] == component]
                    return bootstrap.encoded({"apiVersion": "apps/v1", "kind": "ReplicaSetList", "items": values})
                values = [deepcopy(value) for value in item.pods.values() if value["metadata"]["labels"]["app.kubernetes.io/component"] == component]
                if item.pod_tamper:
                    for value in values:
                        item.pod_tamper(value)
                return bootstrap.encoded({"apiVersion": "v1", "kind": "PodList", "items": values})
            if command[:2] == ("get", "replicaset"):
                return bootstrap.encoded(item.replica_sets[command[2]])
            if command[:2] == ("get", "pod"):
                value = deepcopy(item.pods[command[2]])
                if item.pod_tamper:
                    item.pod_tamper(value)
                return bootstrap.encoded(value)
            if command[0] == "exec":
                pod_name, container = command[1], command[3]
                assert command[2] == "-c" and command[4:9] == ("--", "/bin/sh", "-ec", reload.PROBE_PROGRAM, "--")
                assert data is None and "PRIVATE_" not in repr(command)
                item.execs.append(command)
                if item.reload_failure == "missing-tools":
                    raise bootstrap.BootstrapError("synthetic probe utility unavailable")
                count, arguments = int(command[9]), list(command[10:])
                pod = item.pods[pod_name]
                main = pod["spec"]["containers"][0]
                assert main["name"] == container
                volumes = {volume["name"]: volume for volume in pod["spec"]["volumes"]}
                lines = []
                for path in arguments[:count]:
                    mount = max((mount for mount in main["volumeMounts"] if path.startswith(mount["mountPath"] + "/")), key=lambda mount: len(mount["mountPath"]))
                    source = volumes[mount["name"]]["secret"]
                    relative = path[len(mount["mountPath"]) + 1:]
                    field = next((entry["key"] for entry in source.get("items", []) if entry["path"] == relative), relative)
                    digest = recovery.sha256(base64.b64decode(item.secrets[source["secretName"]]["data"][field]))
                    if item.reload_failure == "file-hash":
                        digest = "0" * 64
                    lines.append(f"file {digest}  {path}\n")
                for variable in arguments[count:]:
                    source = next(entry for entry in main["env"] if entry["name"] == variable)["valueFrom"]["secretKeyRef"]
                    digest = recovery.sha256(base64.b64decode(item.secrets[source["name"]]["data"][source["key"]]) + b"\n")
                    if item.reload_failure == "env-hash":
                        digest = "0" * 64
                    lines.append(f"env {digest}  -\n")
                if item.reload_failure == "pod-replaced-during-exec":
                    pod["metadata"]["uid"] = str(uuid.UUID(int=999999))
                if item.reload_failure == "container-restarted-during-exec":
                    pod["status"]["containerStatuses"][0]["containerID"] += "-restarted"
                if item.reload_failure == "extra-pod-during-exec":
                    extra = deepcopy(pod)
                    extra["metadata"].update(name=pod_name + "-extra", uid=str(uuid.UUID(int=999998)))
                    item.pods[extra["metadata"]["name"]] = extra
                if item.reload_failure == "extra-replicaset-during-exec":
                    extra = deepcopy(item.replica_sets[pod["metadata"]["ownerReferences"][0]["name"]])
                    extra["metadata"].update(name=extra["metadata"]["name"] + "-extra", uid=str(uuid.UUID(int=999997)))
                    extra["spec"]["template"]["metadata"]["annotations"]["foreign-rollout"] = "unexpected"
                    item.replica_sets[extra["metadata"]["name"]] = extra
                if item.reload_failure == "wall-backwards-during-exec":
                    item.clock.wall -= 60
                return "".join(lines).encode()
            raise AssertionError("unexpected reload API operation")

    def process(command, **kwargs):
        assert command[5:7] == ["patch", "deployment"] and command[-4:] == ["--type=json", "--patch-file=/dev/stdin", "-o", "json"]
        name = command[7]
        assert name in reload.WORKLOADS and "PRIVATE_" not in repr(command)
        index = len(item.reload_patches)
        assert len(list(item.request.output.glob("deployment-before-*.json"))) == 16
        assert len(list(item.request.output.glob("secret-after-*.json"))) == 34
        assert (item.request.output / f"patch-intent-{index:02}.json").exists()
        patch = json.loads(kwargs["input"])
        old = item.deployments[name]
        failure = item.reload_failure if index == item.reload_failure_index else None
        item.reload_patches.append(name)
        if failure == "patch-nonzero":
            return SimpleNamespace(returncode=1, stdout=b"PRIVATE_FAILED_RELOAD", stderr=b"PRIVATE_DIAGNOSTIC")
        if failure in ("patch-stale-uid", "patch-stale-rv"):
            field = "uid" if failure == "patch-stale-uid" else "resourceVersion"
            old["metadata"][field] = str(uuid.UUID(int=999996)) if field == "uid" else "999999"
            tested = patch[0 if field == "uid" else 1]
            assert tested["op"] == "test" and tested["value"] != old["metadata"][field]
            return SimpleNamespace(returncode=1, stdout=b"", stderr=b"PRIVATE_PRECONDITION_FAILED")
        assert patch[:3] == [{"op": "test", "path": "/metadata/uid", "value": old["metadata"]["uid"]},
            {"op": "test", "path": "/metadata/resourceVersion", "value": old["metadata"]["resourceVersion"]},
            {"op": "test", "path": "/spec/template", "value": old["spec"]["template"]}]
        assert len(patch) == 4 and patch[3]["op"] == "add"
        key = patch[3]["path"].removeprefix("/spec/template/metadata/annotations/").replace("~1", "/").replace("~0", "~")
        assert key not in old["spec"]["template"]["metadata"]["annotations"]
        old["spec"]["template"]["metadata"]["annotations"][key] = patch[3]["value"]
        old["metadata"]["generation"] += 1
        old["metadata"]["resourceVersion"] = str(1000 + index)
        children(name)
        if failure == "patch-timeout":
            raise subprocess.TimeoutExpired(command, kwargs["timeout"], output=b"PRIVATE_PARTIAL_RELOAD", stderr=b"PRIVATE_TIMEOUT")
        reply = deepcopy(old)
        if failure == "patch-metadata":
            reply["metadata"]["labels"]["foreign"] = "changed"
        return SimpleNamespace(returncode=0, stdout=bootstrap.encoded(reply), stderr=b"")

    def guard(transport):
        assert isinstance(transport, reload.BudgetedTransport)
        item.guard_calls += 1
        transport.kubectl("caller bounded phase", "get", "namespace", item.binding["namespace"], "-o", "json", timeout=10000)
        assert recovery.private.current_snapshot(item.args.operation_dir / "candidate") == item.candidate

    def sleep(seconds):
        item.clock.monotonic += seconds
        item.clock.wall += seconds

    monkeypatch.setattr(reload, "time", SimpleNamespace(time=lambda: item.clock.wall,
        monotonic=lambda: item.clock.monotonic, sleep=sleep))
    monkeypatch.setattr(reload.subprocess, "run", process)
    item.transport, item.guard = Transport(), guard
    item.freshness = recovery.Freshness(int(item.clock.wall), int(item.clock.wall) + 300, item.clock.monotonic)
    return item


def run(item):
    return reload.reload_workloads(item.request, item.transport, item.freshness, item.guard)


def test_early_preflight_only_reads_all_original_profiles_without_requiring_ready_pods(reload_flow, capsys):
    item = reload_flow
    result = reload.preflight_workloads(item.request.original, item.request.binding, item.transport)
    assert result["status"] == "original-workload-profiles-admitted" and result["workloadCount"] == 16
    assert set(result["workloads"]) == set(reload.WORKLOADS)
    assert result["binding"] == item.bound and result["originalRuntime"] == item.request.original["release"]
    assert result["credentialsIssued"] is result["activation"] is result["readinessAssessed"] is False
    assert result["fullEnvironmentHealthAssessed"] is False
    assert all(value["status"]["readyReplicas"] == 0 for value in item.deployments.values())
    assert [args for args, _, _ in item.io] == [("get", "deployment", name, "-o", "json") for name in reload.WORKLOADS]
    assert all(timeout <= 30 for _, timeout, _ in item.io)
    assert not item.reload_patches and not item.execs and item.deployments == item.original_deployments
    assert not item.request.output.exists() and capsys.readouterr().out == ""


@pytest.mark.parametrize("failure", ["replicas", "paused", "image", "security", "ownership", "release", "uid"])
def test_last_workload_profile_refusal_has_no_mutations_or_partial_admission(reload_flow, failure):
    item = reload_flow
    value = item.deployments[reload.WORKLOADS[-1]]
    if failure == "replicas":
        value["spec"]["replicas"] = 0
    elif failure == "paused":
        value["spec"]["paused"] = True
    elif failure == "image":
        value["spec"]["template"]["spec"]["containers"][0]["image"] = "foreign@sha256:" + "f" * 64
    elif failure == "security":
        value["spec"]["template"]["spec"]["automountServiceAccountToken"] = True
    elif failure == "ownership":
        value["metadata"]["annotations"]["meta.helm.sh/release-name"] = "foreign"
    elif failure == "release":
        value["spec"]["template"]["metadata"]["annotations"]["marty.11id.dev/runtimeSourceSha"] = "f" * 40
    else:
        value["metadata"]["uid"] = item.deployments[reload.WORKLOADS[0]]["metadata"]["uid"]
    with pytest.raises(bootstrap.BootstrapError):
        reload.preflight_workloads(item.request.original, item.request.binding, item.transport)
    assert len(item.io) == 16 and not item.reload_patches and not item.execs
    assert not item.request.output.exists()


def test_preflight_uses_one_global_observation_budget(reload_flow, monkeypatch):
    item = reload_flow
    original = item.transport.kubectl

    def slow(*args, **kwargs):
        result = original(*args, **kwargs)
        item.clock.monotonic += 200
        item.clock.wall += 200
        return result

    monkeypatch.setattr(item.transport, "kubectl", slow)
    with pytest.raises(bootstrap.BootstrapError, match="reload budget expired"):
        reload.preflight_workloads(item.request.original, item.request.binding, item.transport)
    assert len(item.io) == 3 and not item.reload_patches and not item.execs


def test_successful_early_preflight_cannot_replace_final_live_reload_admission(reload_flow):
    item = reload_flow
    assert reload.preflight_workloads(item.request.original, item.request.binding, item.transport)["workloadCount"] == 16
    item.deployments[reload.WORKLOADS[-1]]["spec"]["replicas"] = 0
    with pytest.raises(bootstrap.BootstrapError, match="original owned single-replica"):
        run(item)
    assert not item.reload_patches and not item.execs
    assert not (item.request.output / "reload-complete.json").exists()
    assert (item.request.output / "reload-stopped.json").exists()


def test_fifth_restart_refreshes_controller_only_resource_version_without_retry(reload_flow, monkeypatch):
    item = reload_flow
    original_get, original_process = item.transport.kubectl, reload.subprocess.run
    changed = False
    target = reload.WORKLOADS[4]

    def get(*args, **kwargs):
        nonlocal changed
        if len(item.reload_patches) == 4 and not changed:
            value = item.deployments[target]
            value["metadata"]["resourceVersion"] = "900004"
            value["metadata"]["managedFields"] = [{"manager": "kube-controller-manager"}]
            value["metadata"]["annotations"][reload.REVISION] = "2"
            value["status"]["conditions"] = [{"type": "Available", "status": "False"}]
            changed = True
        return original_get(*args, **kwargs)

    def process(command, **kwargs):
        if command[7] == target:
            patch = json.loads(kwargs["input"])
            if patch[1]["value"] != item.deployments[target]["metadata"]["resourceVersion"]:
                item.reload_patches.append(target)
                return SimpleNamespace(returncode=1, stdout=b"", stderr=b"synthetic atomic resource-version refusal")
        return original_process(command, **kwargs)

    monkeypatch.setattr(item.transport, "kubectl", get)
    monkeypatch.setattr(reload.subprocess, "run", process)
    result = run(item)
    assert changed and result["reloadCount"] == 16
    assert item.reload_patches == list(reload.WORKLOADS)
    before = json.loads((item.request.output / "deployment-before-04.json").read_bytes())
    dispatch = json.loads((item.request.output / "deployment-dispatch-04.json").read_bytes())
    intent = json.loads((item.request.output / "patch-intent-04.json").read_bytes())
    assert before["metadata"]["resourceVersion"] == "104"
    assert dispatch["metadata"]["resourceVersion"] == intent["resourceVersion"] == "900004"
    assert before["metadata"]["uid"] == dispatch["metadata"]["uid"]
    assert before["metadata"]["generation"] == dispatch["metadata"]["generation"]
    assert before["spec"] == dispatch["spec"]
    assert intent["dispatchPreimageSha256"] == recovery.sha256(
        (item.request.output / "deployment-dispatch-04.json").read_bytes())
    assert before["metadata"]["annotations"][reload.REVISION] == "1"
    assert dispatch["metadata"]["annotations"][reload.REVISION] == "2"
    reload.verify_completed_evidence(item.request.output, result, item.bound, item.request.qualified_plan_sha256)


@pytest.mark.parametrize("field", ["uid", "generation", "generation-type", "template", "replicas", "ownership", "label"])
def test_fresh_preimage_cannot_adopt_changes_to_frozen_deployment(reload_flow, monkeypatch, field):
    item = reload_flow
    original_get = item.transport.kubectl
    changed = False

    def get(*args, **kwargs):
        nonlocal changed
        if len(item.reload_patches) == 4 and not changed:
            value = item.deployments[reload.WORKLOADS[4]]
            value["metadata"]["resourceVersion"] = "900004"
            if field == "uid":
                value["metadata"]["uid"] = str(uuid.UUID(int=999997))
            elif field == "generation":
                value["metadata"]["generation"] += 1
            elif field == "generation-type":
                value["metadata"]["generation"] = True
            elif field == "template":
                value["spec"]["template"]["metadata"]["annotations"]["foreign"] = "changed"
            elif field == "replicas":
                value["spec"]["replicas"] = 0
            elif field == "ownership":
                value["metadata"]["annotations"]["meta.helm.sh/release-name"] = "foreign"
            else:
                value["metadata"]["labels"]["foreign"] = "changed"
            changed = True
        return original_get(*args, **kwargs)

    monkeypatch.setattr(item.transport, "kubectl", get)
    with pytest.raises(bootstrap.BootstrapError):
        run(item)
    assert changed and item.reload_patches == list(reload.WORKLOADS[:4])
    assert not (item.request.output / "patch-intent-04.json").exists()
    assert not item.execs


@pytest.mark.parametrize("record", ["deployment-dispatch-04.json", "patch-request-04.json", "patch-intent-04.json",
                                    "deployment-patched-04.json", "patch-response-04.json", "reload-plan.json"])
def test_valid_journal_seal_cannot_hide_inconsistent_dispatch_bindings(reload_flow, monkeypatch, record):
    item = reload_flow
    original_write = reload.Evidence.write
    changed = False

    def write(evidence, name, raw, *args, **kwargs):
        nonlocal changed
        if name == record:
            value = json.loads(raw)
            if name == "patch-request-04.json":
                value[1]["value"] = "unrelated-version"
            elif name == "patch-intent-04.json":
                value["dispatchPreimageSha256"] = "f" * 64
            elif name == "patch-response-04.json":
                value["stdoutBase64"] = base64.b64encode(b"PRIVATE_UNRELATED_RESPONSE").decode()
            elif name == "reload-plan.json":
                value["patches"][reload.WORKLOADS[4]][1]["value"] = "unrelated-version"
            else:
                value["metadata"]["resourceVersion"] = "unrelated-version"
            raw = bootstrap.encoded(value)
            changed = True
        original_write(evidence, name, raw, *args, **kwargs)

    monkeypatch.setattr(reload.Evidence, "write", write)
    result = sealed_reload_fixture(item.request)
    assert changed
    completion = json.loads((item.request.output / "reload-complete.json").read_bytes())
    journal = completion["journalBindings"]
    files = {**journal["files"], "reload-complete.json": result["privateEvidence"]["completionRecord"]}
    # Every stored byte and file identity legitimately matches this seal. The
    # semantic cross-record check must still refuse the contradictory record.
    reload.journal_recheck(item.request.output, journal["directories"], files, full=True)
    with pytest.raises(bootstrap.BootstrapError):
        reload.verify_completed_evidence(item.request.output, result, item.bound, item.request.qualified_plan_sha256)


@pytest.mark.parametrize("build_run_id, annotation", [
    pytest.param(123, "123", id="decimal"),
    pytest.param(42418639332, "4.2418639332e+10", id="legacy-helm-scientific"),
])
def test_closed_reload_preserves_configuration_and_proves_new_projected_bytes(reload_flow, capsys, build_run_id, annotation):
    item = reload_flow
    item.request.original["release"]["buildRunId"] = build_run_id
    for deployments in (item.deployments, item.original_deployments):
        for value in deployments.values():
            value["spec"]["template"]["metadata"]["annotations"]["marty.11id.dev/buildRunId"] = annotation
    result = run(item)
    assert item.reload_patches == list(reload.WORKLOADS) and len(item.execs) == 16
    assert result["reloadCount"] == 16 and result["fullEnvironmentHealthAssessed"] is False
    assert result["inMemoryProviderUseProved"] is False
    assert (item.request.output / "reload-complete.json").exists()
    assert json.loads((item.request.output / "reload-complete.json").read_bytes())["evidenceLimits"] == {
        "maximumRecords": 16600, "maximumBytes": 96 * 1024 * 1024,
        "maximumObservations": 8192, "maximumSeconds": 600}
    for name, old in item.original_deployments.items():
        expected = deepcopy(old["spec"])
        actual = deepcopy(item.deployments[name]["spec"])
        added = set(actual["template"]["metadata"]["annotations"]) - set(expected["template"]["metadata"]["annotations"])
        assert len(added) == 1
        actual["template"]["metadata"]["annotations"].pop(added.pop())
        assert actual == expected
    assert {"postgres", "redis", "openbao", "applicant", "trust-profile", "device-registration", "ui"}.isdisjoint(item.reload_patches)
    assert any("OPENBAO_SERVICE_TOKEN" in command for command in item.execs)
    assert all(timeout <= 600 for _, timeout, _ in item.io)
    assert item.guard_calls > 16
    assert capsys.readouterr().out == ""
    assert "PRIVATE_" not in repr(item.execs)
    sealed = result["privateEvidence"]
    assert set(sealed) == {"schema", "completionSha256", "journalSha256", "recordCount", "totalBytes", "completionRecord"}
    assert sealed["schema"] == "marty.kubernetes-legacy-reload-evidence/v1"
    completion = (item.request.output / "reload-complete.json").read_bytes()
    assert sealed["completionSha256"] == recovery.sha256(completion)
    assert isinstance(sealed["completionRecord"], dict)
    assert type(sealed["recordCount"]) is int and sealed["recordCount"] > 0
    assert type(sealed["totalBytes"]) is int and sealed["totalBytes"] > 0
    assert set(json.loads(completion)["journalBindings"]) == {"schema", "directories", "files"}
    reload.verify_completed_evidence(item.request.output, result, item.request.binding, item.request.qualified_plan_sha256)
    wrong_receipt = deepcopy(result)
    wrong_receipt["privateEvidence"]["completionSha256"] = "0" * 64
    with pytest.raises(bootstrap.BootstrapError):
        reload.verify_completed_evidence(item.request.output, wrong_receipt, item.request.binding, item.request.qualified_plan_sha256)
    with pytest.raises(bootstrap.BootstrapError):
        reload.verify_completed_evidence(item.request.output, result, item.request.binding, "f" * 64)
    proof = item.request.output / "projection-proof-00.json"
    proof.write_bytes(proof.read_bytes() + b"\n")
    with pytest.raises(bootstrap.BootstrapError):
        reload.verify_completed_evidence(item.request.output, result, item.request.binding, item.request.qualified_plan_sha256)


@pytest.mark.parametrize("key", ["buildRunId", "buildRunAttempt"])
def test_numeric_release_annotations_require_exact_producer_integer_and_helm_spelling(reload_flow, key):
    item = reload_flow
    observed = deepcopy(item.deployments["auth"])
    annotations = observed["spec"]["template"]["metadata"]["annotations"]
    accepted = [
        (1, "1"), (999999, "999999"), (1000000, "1000000"), (1000000, "1e+06"),
        (1000001, "1.000001e+06"), (123450000, "1.2345e+08"),
        (42000000000, "4.2e+10"), (42418639332, "42418639332"),
        (42418639332, "4.2418639332e+10"),
        (2**53 - 1, "9007199254740991"), (2**53 - 1, "9.007199254740991e+15"),
    ]
    rejected = [(42418639332, value) for value in (
        "42418639333", "4.2418639333e+10", "4.241863933e+10", "4.24186393321e+10",
        "4.2418639332e+09", "42.418639332e+9", "4.24186393320e+10", "4.2418639332E+10",
        "4.2418639332e10", "4.2418639332e+010", "+4.2418639332e+10", " 4.2418639332e+10",
        "4.2418639332e+10\n", "042418639332", "42418639332.0", "424186393320e-1",
        "NaN", "Infinity", "-Inf", "", "4." + "0" * 1000 + "e+10", None, 42418639332, 42418639332.0, True,
    )]
    rejected.extend([
        (999999, "9.99999e+05"), (1, "1e+00"), (0, "0"), (-1, "-1"),
        (True, "True"), (False, "False"), (42418639332.0, "42418639332.0"),
        ("42418639332", "42418639332"), (2**53, "9007199254740992"),
        (2**53 + 1, "9.007199254740992e+15"), (10**1000, "1e+1000"),
    ])
    for expected, actual in accepted:
        item.request.original["release"][key] = expected
        annotations["marty.11id.dev/" + key] = actual
        assert reload.deployment(observed, "auth", item.request) == "marty-retained", (key, expected, actual)
    for expected, actual in rejected:
        item.request.original["release"][key] = expected
        annotations["marty.11id.dev/" + key] = actual
        with pytest.raises(bootstrap.BootstrapError, match="Deployment original release annotations differ"):
            reload.deployment(observed, "auth", item.request)
    assert not item.reload_patches and not item.execs


@pytest.mark.parametrize("annotation", ["4.2418639333e+10", "4.241863933e+10", "4.24186393320e+10"])
def test_late_workload_numeric_release_mismatch_precedes_every_restart(reload_flow, annotation):
    item = reload_flow
    item.request.original["release"]["buildRunId"] = 42418639332
    for value in item.deployments.values():
        value["spec"]["template"]["metadata"]["annotations"]["marty.11id.dev/buildRunId"] = "4.2418639332e+10"
    last = reload.WORKLOADS[-1]
    item.deployments[last]["spec"]["template"]["metadata"]["annotations"]["marty.11id.dev/buildRunId"] = annotation
    with pytest.raises(bootstrap.BootstrapError, match="Deployment original release annotations differ"):
        run(item)
    assert any(command[:3] == ("get", "deployment", last) for command, _, _ in item.io)
    assert not item.reload_patches and not item.execs


def test_other_release_annotations_remain_exact(reload_flow):
    item = reload_flow
    observed = deepcopy(item.deployments["auth"])
    annotations = observed["spec"]["template"]["metadata"]["annotations"]
    for key in ("runtimeSourceSha", "chartSourceSha", "tag", "inventorySha256", "imageLockSha256", "operatorSha256"):
        original = item.request.original["release"][key]
        annotations["marty.11id.dev/" + key] = original + " "
        with pytest.raises(bootstrap.BootstrapError, match="Deployment original release annotations differ"):
            reload.deployment(observed, "auth", item.request)
        annotations["marty.11id.dev/" + key] = original
    item.request.original["release"]["otherNumericMetadata"] = 42418639332
    annotations["marty.11id.dev/otherNumericMetadata"] = "4.2418639332e+10"
    with pytest.raises(bootstrap.BootstrapError, match="Deployment original release annotations differ"):
        reload.deployment(observed, "auth", item.request)
    assert not item.reload_patches and not item.execs


@pytest.mark.parametrize("tamper", [
    lambda value: value["spec"].update(replicas=2),
    lambda value: value["spec"].update(paused=True),
    lambda value: value["metadata"]["labels"].update({"app.kubernetes.io/managed-by": "other"}),
    lambda value: value["metadata"]["annotations"].update({"meta.helm.sh/release-name": "foreign"}),
    lambda value: value["spec"]["template"]["metadata"]["annotations"].update({"marty.11id.dev/runtimeSourceSha": "0" * 40}),
    lambda value: value["spec"]["template"]["spec"]["containers"][0].update(image="foreign/image:latest"),
    lambda value: value["spec"]["template"]["spec"]["containers"].append({"name": "sidecar"}),
    lambda value: value["spec"]["template"]["spec"].update(automountServiceAccountToken=True),
])
def test_closed_deployment_admission_precedes_every_restart(reload_flow, tamper):
    item = reload_flow
    item.preflight_tamper = tamper
    with pytest.raises(bootstrap.BootstrapError):
        run(item)
    assert not item.reload_patches and not item.execs


@pytest.mark.parametrize("failure", ["patch-nonzero", "patch-timeout", "patch-metadata", "patch-stale-uid", "patch-stale-rv"])
def test_partial_restart_retains_opaque_response_and_stops(reload_flow, failure):
    item = reload_flow
    item.reload_failure = failure
    with pytest.raises(bootstrap.BootstrapError):
        run(item)
    assert item.reload_patches == list(reload.WORKLOADS[:2])
    stopped = json.loads((item.request.output / "reload-stopped.json").read_bytes())
    assert stopped["verifiedPatches"] == [reload.WORKLOADS[0]] and stopped["reloadComplete"] is False
    response = json.loads((item.request.output / "patch-response-01.json").read_bytes())
    assert (response["stdoutBase64"] or response["stderrBase64"]) and not item.execs
    if failure == "patch-timeout":
        assert response["completed"] is False
    if failure in ("patch-stale-uid", "patch-stale-rv"):
        assert item.deployments[reload.WORKLOADS[1]]["spec"] == item.original_deployments[reload.WORKLOADS[1]]["spec"]
    assert not (item.request.output / "reload-complete.json").exists()


@pytest.mark.parametrize("failure", ["secret-drift", "freshness-expired"])
def test_secret_or_qualification_drift_refuses_restart(reload_flow, failure):
    item = reload_flow
    item.reload_failure = failure
    with pytest.raises(bootstrap.BootstrapError):
        run(item)
    assert not item.reload_patches


def consume_dispatch_time(item, monkeypatch, phase, elapsed, clock):
    """Model work inside the last scan or serialization before subprocess."""
    consumed = []

    def advance():
        if consumed:
            return
        if clock in ("wall", "both"):
            item.clock.wall += elapsed
        if clock in ("monotonic", "both"):
            item.clock.monotonic += elapsed
        consumed.append(phase)

    if phase == "scan":
        original = reload.Evidence.recheck

        def scanned(evidence, *args, **kwargs):
            original(evidence, *args, **kwargs)
            if sys._getframe(1).f_code.co_name == "captured_patch":
                advance()

        monkeypatch.setattr(reload.Evidence, "recheck", scanned)
    else:
        original = bootstrap.encoded

        def encoded(value):
            raw = original(value)
            if sys._getframe(1).f_code.co_name == "captured_patch" and isinstance(value, list):
                advance()
            return raw

        monkeypatch.setattr(bootstrap, "encoded", encoded)
    return consumed


@pytest.mark.parametrize("phase", ["scan", "payload"])
@pytest.mark.parametrize("clock", ["wall", "monotonic", "both"])
def test_dispatch_refuses_qualification_expired_during_final_preparation(reload_flow, monkeypatch, phase, clock):
    item = reload_flow
    consumed = consume_dispatch_time(item, monkeypatch, phase, 301, clock)
    with pytest.raises(bootstrap.BootstrapError, match="qualification expired"):
        run(item)
    assert consumed == [phase] and not item.reload_patches and not item.execs
    assert (item.request.output / "patch-intent-00.json").exists()
    assert not (item.request.output / "patch-response-00.json").exists()
    assert not (item.request.output / "reload-complete.json").exists()


@pytest.mark.parametrize("phase", ["scan", "payload"])
def test_dispatch_recomputes_the_remaining_qualification_timeout_after_preparation(reload_flow, monkeypatch, phase):
    item = reload_flow
    consumed = consume_dispatch_time(item, monkeypatch, phase, 289, "both")
    observed = []

    class DispatchObserved(Exception):
        pass

    def dispatch(command, **kwargs):
        assert command[5:7] == ["patch", "deployment"]
        expected = math.floor(min(item.freshness.deadline - item.clock.wall,
                                  item.freshness.monotonic_deadline - item.clock.monotonic,
                                  json.loads(item.plan_bytes)["validBeforeUnixSeconds"] - item.clock.wall))
        observed.append((kwargs["timeout"], expected))
        raise DispatchObserved()

    monkeypatch.setattr(reload.subprocess, "run", dispatch)
    with pytest.raises(DispatchObserved):
        run(item)
    assert consumed == [phase] and len(observed) == 1
    assert 0 < observed[0][1] < 30 and observed[0][0] == observed[0][1]
    assert not item.reload_patches and not (item.request.output / "reload-complete.json").exists()


@pytest.mark.parametrize("failure", ["wait-timeout", "concurrent-rollout"])
def test_global_wait_budget_and_concurrent_rollout_refuse_completion(reload_flow, failure):
    item = reload_flow
    item.reload_failure = failure
    started = item.clock.monotonic
    expected = "reload budget expired" if failure == "wait-timeout" else "Deployment spec or patched template changed concurrently"
    with pytest.raises(bootstrap.BootstrapError, match=expected):
        run(item)
    assert len(item.reload_patches) == 16 and not item.execs
    assert item.clock.monotonic - started <= 601
    if failure == "wait-timeout":
        assert item.clock.monotonic - started >= 599
    assert not (item.request.output / "reload-complete.json").exists()


@pytest.mark.parametrize("tamper", [
    lambda value: value["metadata"]["ownerReferences"][0].update(uid=str(uuid.UUID(int=999999))),
    lambda value: value["spec"]["containers"].append({"name": "injected"}),
    lambda value: value["spec"].update(hostNetwork=True),
    lambda value: value["spec"]["containers"][0]["securityContext"].update(privileged=True),
    lambda value: value["spec"]["volumes"].append({"name": "injected", "projected": {"sources": []}}),
    lambda value: value["spec"]["containers"][0]["volumeMounts"][0].update(subPath="foreign"),
])
def test_new_pod_ownership_and_projection_injection_are_refused(reload_flow, tamper):
    item = reload_flow
    item.pod_tamper = tamper
    with pytest.raises(bootstrap.BootstrapError):
        run(item)
    assert len(item.reload_patches) == 16 and not item.execs


@pytest.mark.parametrize("failure", ["file-hash", "env-hash", "missing-tools", "pod-replaced-during-exec", "container-restarted-during-exec",
    "extra-pod-during-exec", "extra-replicaset-during-exec", "wall-backwards-during-exec"])
def test_projection_mismatch_or_exec_identity_race_stops_without_claiming_recovery(reload_flow, failure):
    item = reload_flow
    item.reload_failure = failure
    with pytest.raises(bootstrap.BootstrapError):
        run(item)
    assert item.execs and not (item.request.output / "reload-complete.json").exists()
    assert "PRIVATE_" not in repr(item.execs)


def test_module_has_no_production_cli_dispatch():
    assert not hasattr(reload, "main")


def test_journal_hash_work_consumes_the_original_global_budget(tmp_path, monkeypatch):
    clock = SimpleNamespace(wall=1000.0, monotonic=0.0)
    monkeypatch.setattr(reload, "time", SimpleNamespace(time=lambda: clock.wall, monotonic=lambda: clock.monotonic))
    budget = reload.Budget()
    evidence = reload.Evidence(tmp_path / "evidence", budget)
    evidence.write("first.json", b"{}\n")
    evidence.write("second.json", b"{}\n")
    original = reload.private_record
    reads = []

    def slow(path, maximum):
        value = original(path, maximum)
        reads.append(path)
        clock.wall += 600
        clock.monotonic += 600
        return value

    monkeypatch.setattr(reload, "private_record", slow)
    with pytest.raises(bootstrap.BootstrapError, match="reload budget expired"):
        evidence.recheck(full=True)
    assert len(reads) == 1 and budget.deadline == clock.monotonic == 600
    assert not (evidence.output / "reload-complete.json").exists()


def tamper_journal_after_observation(item, monkeypatch, ready, mutate):
    """Inject a filesystem race after a real doubled API response is produced."""
    original = item.transport.kubectl
    state = SimpleNamespace(mutated=False, calls_after=0, patches_at_mutation=None)

    def observed(operation, *command, **kwargs):
        if state.mutated:
            state.calls_after += 1
        raw = original(operation, *command, **kwargs)
        if not state.mutated and ready():
            mutate()
            state.mutated = True
            state.patches_at_mutation = len(item.reload_patches)
        return raw

    monkeypatch.setattr(item.transport, "kubectl", observed)
    return state


@pytest.mark.parametrize("mutation", [
    "changed", "missing", "extra-record", "file-mode", "file-symlink", "file-hardlink",
    "directory-mode", "root-mode", "directory-symlink", "extra-directory",
])
def test_written_projection_evidence_is_rechecked_after_the_next_observation(reload_flow, monkeypatch, mutation):
    item = reload_flow
    proof = item.request.output / "projection-proof-00.json"
    observations = item.request.output / "observations"

    def mutate():
        if mutation == "changed":
            value = json.loads(proof.read_bytes())
            value["responseSha256"] = "0" * 64
            proof.write_bytes(bootstrap.encoded(value))
        elif mutation == "missing":
            proof.unlink()
        elif mutation == "extra-record":
            bootstrap.write_new(observations / "untracked.json", b"{}\n")
        elif mutation == "file-mode":
            proof.chmod(0o644)
        elif mutation == "file-symlink":
            detached = item.request.output.parent / "detached-projection-proof.json"
            proof.rename(detached)
            proof.symlink_to(detached)
        elif mutation == "file-hardlink":
            os.link(proof, item.request.output.parent / "linked-projection-proof.json")
        elif mutation == "directory-mode":
            observations.chmod(0o755)
        elif mutation == "root-mode":
            item.request.output.chmod(0o755)
        elif mutation == "directory-symlink":
            detached = item.request.output.parent / "detached-observations"
            observations.rename(detached)
            observations.symlink_to(detached, target_is_directory=True)
        elif mutation == "extra-directory":
            (item.request.output / "untracked-directory").mkdir(mode=0o700)
        else:
            raise AssertionError("unknown test mutation")

    state = tamper_journal_after_observation(item, monkeypatch, proof.exists, mutate)
    with pytest.raises(bootstrap.BootstrapError):
        run(item)
    assert state.mutated and state.calls_after == 0
    assert len(item.execs) == 1 and len(item.reload_patches) == state.patches_at_mutation == 16
    assert not (item.request.output / "reload-complete.json").exists()


@pytest.mark.parametrize("record", ["patch-intent-00.json", "patch-response-00.json"])
def test_prior_restart_intent_and_opaque_response_changes_prevent_the_next_patch(reload_flow, monkeypatch, record):
    item = reload_flow
    first_patch = item.request.output / "deployment-patched-00.json"

    def mutate():
        path = item.request.output / record
        path.write_bytes(path.read_bytes() + b"\n")

    state = tamper_journal_after_observation(item, monkeypatch, first_patch.exists, mutate)
    with pytest.raises(bootstrap.BootstrapError):
        run(item)
    assert state.mutated and state.calls_after == 0 and state.patches_at_mutation == 1
    assert item.reload_patches == [reload.WORKLOADS[0]] and not item.execs
    assert not (item.request.output / "patch-intent-01.json").exists()
    assert not (item.request.output / "reload-complete.json").exists()


def test_patch_result_is_retained_before_refusing_an_intent_changed_during_the_patch(reload_flow, monkeypatch):
    item = reload_flow
    original = reload.subprocess.run
    replies = []

    def patched(*args, **kwargs):
        result = original(*args, **kwargs)
        intent = item.request.output / "patch-intent-00.json"
        intent.write_bytes(intent.read_bytes() + b"\n")
        replies.append(result.stdout)
        return result

    monkeypatch.setattr(reload.subprocess, "run", patched)
    with pytest.raises(bootstrap.BootstrapError):
        run(item)
    assert len(replies) == 1 and item.reload_patches == [reload.WORKLOADS[0]] and not item.execs
    response = json.loads((item.request.output / "patch-response-00.json").read_bytes())
    assert response["completed"] is True and response["exitCode"] == 0
    assert base64.b64decode(response["stdoutBase64"], validate=True) == replies[0]
    assert not (item.request.output / "patch-intent-01.json").exists()
    assert not (item.request.output / "reload-complete.json").exists()


@pytest.mark.parametrize("record", ["projection-proof-00.json", "reload-complete.json"])
def test_completion_does_not_seal_changed_prior_or_completion_bytes(reload_flow, monkeypatch, record):
    item = reload_flow
    original = bootstrap.write_new
    completion = item.request.output / "reload-complete.json"
    changed = []

    def written(path, raw, *args, **kwargs):
        original(path, raw, *args, **kwargs)
        if path == completion:
            target = item.request.output / record
            target.write_bytes(target.read_bytes() + b"\n")
            changed.append(record)

    monkeypatch.setattr(bootstrap, "write_new", written)
    with pytest.raises(bootstrap.BootstrapError):
        run(item)
    assert changed == [record]
    assert len(item.reload_patches) == len(item.execs) == 16


@pytest.mark.parametrize("fault", [None, "foreign-owner", "namespace", "secret", "projection", "expired"])
def test_adoption_readback_reuses_owned_profiles_and_never_restarts_workloads(reload_flow, monkeypatch, fault):
    import adopt_kubernetes_renewal as coordinator
    import kubernetes_renewal_adoption_state as adoption
    item = reload_flow
    run(item)
    original_patches = list(item.reload_patches)
    _, after, changed = reload.admitted_inputs(item.request)
    verification = item.request.output.parent / "adoption-verification"
    verification.mkdir(mode=0o700)
    now = int(item.clock.wall)
    bootstrap.write_new(verification / "verified.json", bootstrap.encoded({"verification": {
        "validBeforeUnixSeconds": now - 1 if fault == "expired" else now + 900}}))
    intent = {"binding": item.binding, "adoptionId": "a" * 32,
              "candidateInputs": recovery.input_bindings(item.candidate)}
    legacy = {"after": after, "changed": changed, "bound": item.bound, "plan": item.plan_bytes}
    monkeypatch.setattr(coordinator, "time", SimpleNamespace(time=lambda: item.clock.wall,
        monotonic=lambda: item.clock.monotonic))
    if fault == "foreign-owner":
        def tamper(pod):
            pod["metadata"]["ownerReferences"][0]["uid"] = str(uuid.UUID(int=987654))
        item.pod_tamper = tamper
    elif fault == "namespace":
        previous = item.transport.kubectl
        def wrong_namespace(operation, *command, **kwargs):
            if command[:2] == ("get", "namespace"):
                return bootstrap.encoded({"metadata": {"name": item.binding["namespace"], "uid": str(uuid.UUID(int=987654))}})
            return previous(operation, *command, **kwargs)
        monkeypatch.setattr(item.transport, "kubectl", wrong_namespace)
    elif fault == "secret":
        secret = next(iter(item.secrets.values()))
        secret["data"][next(iter(secret["data"]))] = base64.b64encode(b"different-generation").decode()
    elif fault == "projection":
        item.reload_failure = "file-hash"
    if fault is not None:
        with pytest.raises(bootstrap.BootstrapError):
            coordinator.delivery(verification, intent, item.request.original, legacy, item.transport, lambda: None)
        assert not (verification / "delivery.json").exists()
    else:
        coordinator.delivery(verification, intent, item.request.original, legacy, item.transport, lambda: None)
        receipt = json.loads((verification / "delivery.json").read_bytes())
        assert receipt["schema"] == adoption.DELIVERY_SCHEMA
        assert receipt["secretCount"] == 34 and receipt["workloadCount"] == 16
        assert receipt["credentialDeliveryVerified"] is True and receipt["credentialConsumptionVerified"] is False
        assert set(receipt["workloads"]) == set(reload.WORKLOADS)
        assert len(receipt["observationHashes"]) > 100
    assert item.reload_patches == original_patches
