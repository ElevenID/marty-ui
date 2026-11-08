"""Private activation control flow against closed native/process/API doubles.

The literal delivery probes are executed by a real POSIX shell. Chart bindings
are compared with the real Helm render. Native Rust validation has separate
actual-source tests; these doubles expose transport ordering and recovery.
"""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import activate_kubernetes_application_credentials as activation
import bootstrap_kubernetes_openbao as bootstrap
import kubernetes_application_state as selection
import stage_kubernetes_application_credentials as staging
from test_stage_kubernetes_application_credentials import archive, flow as stage_flow, unpack


pytestmark = pytest.mark.skipif(os.name != "posix", reason="Linux private activation contract")
ROOT = Path(__file__).resolve().parents[1]


def encoded_token(value):
    return base64.b64encode(value[:-1] if value.endswith(b"\n") else value).decode()


def put(path, value, mode=0o600):
    path.write_bytes(value)
    path.chmod(mode)


def owner(kind, name, uid):
    return [{"kind": kind, "name": name, "uid": uid, "controller": True}]


def resource_metadata(kind, name, namespace, *, uid=None):
    return {"name": name, "namespace": namespace, "uid": uid or kind.lower() + "-" + name,
            "resourceVersion": "10"}


def rendered_workloads(namespace, values, *, canvas=True):
    source = yaml.safe_load((ROOT / "deploy/helm/marty/files/workloads.yaml").read_text())
    result = []
    for name in sorted(activation.REQUIRED | ({"canvas-sync-worker"} if canvas else set())):
        workload = source[name]
        labels = {"app.kubernetes.io/instance": "marty", "app.kubernetes.io/component": name}
        annotations = {"marty.11id.dev/" + key: str(value) for key, value in values["release"].items()}
        container = {"name": name, "image": values["images"]["services"],
            "command": ["/app/services/entrypoint.sh"],
            "envFrom": [{"configMapRef": {"name": "marty-config"}}],
            "env": [{"name": "SERVICE_NAME", "value": workload["serviceName"]}, *deepcopy(workload["env"])],
            "volumeMounts": deepcopy(workload.get("volumeMounts", []))}
        if "readinessProbe" in workload:
            container["readinessProbe"] = deepcopy(workload["readinessProbe"])
        deployment = {"apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {**resource_metadata("Deployment", name, namespace), "generation": 1,
                "labels": {**labels, "app.kubernetes.io/name": "marty", "app.kubernetes.io/managed-by": "Helm"},
                "annotations": {"deployment.kubernetes.io/revision": "1", "meta.helm.sh/release-name": "marty",
                                "meta.helm.sh/release-namespace": namespace}},
            "spec": {"replicas": 1, "selector": {"matchLabels": labels}, "strategy": {"type": "Recreate"},
                "template": {"metadata": {"labels": labels, "annotations": annotations},
                    "spec": {"containers": [container], "volumes": deepcopy(workload.get("volumes", []))}}},
            "status": {"observedGeneration": 1, "replicas": 1, "updatedReplicas": 1,
                       "readyReplicas": 1, "availableReplicas": 1}}
        result.append(deployment)
        rs, pod = workload_children(deployment, "old")
        result += [rs, pod]
    result.append({"apiVersion": "batch/v1", "kind": "Job",
        "metadata": {**resource_metadata("Job", "marty-migrate-1", namespace),
            "labels": {"app.kubernetes.io/instance": "marty", "app.kubernetes.io/component": "migrations"}},
        "spec": {"template": {"metadata": {"annotations": annotations}, "spec": {
            "containers": [{"name": "issuance-native", "image": values["images"]["services"],
                            "command": ["/usr/local/bin/marty-issuance-service", "migrate"]}],
            "initContainers": [{"name": "redis-trust", "image": values["images"]["services"]},
                *[{"name": name, "command": command,
                   "image": values["images"]["migrations" if name == "bootstrap-notification" else "services"]}
                  for name, command in activation.MIGRATION_COMMANDS.items()],
                *[{"name": name, "image": values["images"]["services"]}
                  for name in ("ready-organization", "ready-credential-template")]],
            "volumes": [{"name": "bootstrap-secrets", "secret": {"secretName": "marty-secrets",
                "items": [{"key": "NOTIFICATION_OPENBAO_TOKEN", "path": "notification_openbao_token"}]}}]}}},
        "status": {"succeeded": 1, "conditions": [{"type": "Complete", "status": "True"}]}})
    return result


def workload_children(deployment, suffix):
    name = deployment["metadata"]["name"]
    namespace = deployment["metadata"]["namespace"]
    revision = deployment["metadata"]["annotations"]["deployment.kubernetes.io/revision"]
    rs_name = name + "-" + suffix
    rs = {"apiVersion": "apps/v1", "kind": "ReplicaSet",
        "metadata": {**resource_metadata("ReplicaSet", rs_name, namespace),
            "ownerReferences": owner("Deployment", name, deployment["metadata"]["uid"]),
            "annotations": {"deployment.kubernetes.io/revision": revision}},
        "spec": {"replicas": 1, "template": deepcopy(deployment["spec"]["template"])}}
    pod_name = rs_name + "-pod"
    pod = {"apiVersion": "v1", "kind": "Pod",
        "metadata": {**resource_metadata("Pod", pod_name, namespace),
            **deepcopy(deployment["spec"]["template"]["metadata"]),
            "ownerReferences": owner("ReplicaSet", rs_name, rs["metadata"]["uid"])},
        "spec": deepcopy(deployment["spec"]["template"]["spec"]),
        "status": {"phase": "Running", "conditions": [{"type": "Ready", "status": "True"}],
                   "containerStatuses": [{"name": name, "ready": True}]}}
    return rs, pod


def apply_patch(original, patch):
    """A transactional API double; failed JSON Patch tests never commit a prefix."""
    value = deepcopy(original)
    for operation in patch:
        parts = [piece.replace("~1", "/").replace("~0", "~") for piece in operation["path"].split("/")[1:]]
        parent = value
        for part in parts[:-1]:
            parent = parent[part]
        key = parts[-1]
        if operation["op"] == "test":
            if parent.get(key) != operation["value"]:
                raise bootstrap.BootstrapError("synthetic Kubernetes precondition conflict")
        elif operation["op"] in {"add", "replace"}:
            parent[key] = deepcopy(operation["value"])
        else:
            raise AssertionError("unplanned patch operation")
    return value


@pytest.fixture
def flow(stage_flow, tmp_path, monkeypatch):
    staged = stage_flow
    staged.values["images"]["migrations"] = "ghcr.io/elevenid/marty-ui-oss/migrations@sha256:" + "6" * 64
    put(staged.args.state_dir / "marty-images.json", bootstrap.encoded(staged.values))
    staging.stage(staged.args)
    args = SimpleNamespace(**vars(staged.args))
    args.stage_dir = staged.args.operation_dir
    args.operation_dir = tmp_path / "activation"
    args.reconcile = False
    expected_contract = activation.activation_contract(staged.publication, staged.application)
    initial_data = {entry["key"]: encoded_token(staged.snapshot[entry["file"]][0])
                    for entry in expected_contract["inputs"]}
    initial_data["DATABASE_SYNC_URL"] = encoded_token(b"PRIVATE_UNCHANGED_DATABASE_CANARY")
    world = SimpleNamespace(args=args, staged=staged, contract=expected_contract,
        resources=rendered_workloads(staged.binding["namespace"], staged.values),
        secret={"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
            "metadata": resource_metadata("Secret", "marty-secrets", staged.binding["namespace"]),
            "data": initial_data},
        fail=None, bad_contract=False, argv=[], events=[], secret_patches=0,
        deployment_patches={}, secret_observations=0, proofs=0, delivered=[], deadline=None)
    old_process = activation.subprocess.run

    def process(command, **kwargs):
        if command[-1] == "kubernetes-application-activation-contract":
            world.events.append("activation-contract")
            return SimpleNamespace(returncode=2 if world.bad_contract else 0,
                stdout=b"PRIVATE_BAD_CONTRACT_CANARY" if world.bad_contract else bootstrap.encoded(expected_contract), stderr=b"")
        return old_process(command, **kwargs)

    def replacement_values(candidate):
        snapshot = staging.current_snapshot(Path(candidate))
        return {entry["key"]: encoded_token(snapshot[entry["file"]][0]) for entry in expected_contract["inputs"]}

    class Transport:
        deadline = None

        def __init__(self, state, kubeconfig, namespace, kubectl):
            self.state, self.namespace = state, namespace
            assert kubeconfig == state / "kubeconfig" and namespace == staged.binding["namespace"]

        def run(self, label, command, *, data=None, **kwargs):
            world.argv.append(command)
            payload = json.loads(data)
            if label == "native application generation validation":
                assert command[-2:] == ["operator", "generation"] and payload["operation"] == "application-verify"
                assert kwargs["env"] == {}
                if staging.current_snapshot(Path(payload["candidate"])) != staged.candidate:
                    raise bootstrap.BootstrapError("synthetic native generation refused")
                return bootstrap.encoded({"value": [len(staged.snapshot), 11]})
            assert label == "native application Secret validation"
            assert command[-2:] == ["operator", "kubernetes-application-publication"] and kwargs["env"] == {}
            assert payload["namespace"] == self.namespace
            original = json.loads(Path(payload["observed"]).read_bytes())
            replacements = replacement_values(payload["candidate"])
            if payload["operation"] == "prepare":
                assert set(payload) == {"operation", "namespace", "current", "candidate", "observed", "output", "activationId"}
                patch = [{"op": "test", "path": "/metadata/uid", "value": original["metadata"]["uid"]},
                         {"op": "test", "path": "/metadata/resourceVersion", "value": original["metadata"]["resourceVersion"]}]
                patch += [{"op": "replace", "path": "/data/" + key, "value": value} for key, value in sorted(replacements.items())]
                patch += [{"op": "add", "path": "/metadata/annotations", "value": {
                    **original["metadata"].get("annotations", {}), activation.ANNOTATION: payload["activationId"]}}]
                bootstrap.write_new(Path(payload["output"]), bootstrap.encoded(patch))
                return bootstrap.encoded({"ready": True, "secret": "marty-secrets", "count": 11})
            assert payload["operation"] == "verify"
            assert set(payload) == {"operation", "namespace", "current", "candidate", "observed", "result", "activationId"}
            current = json.loads(Path(payload["result"]).read_bytes())
            if current == original:
                status = "unchanged"
            else:
                expected = deepcopy(original)
                expected["data"].update(replacements)
                expected["metadata"]["annotations"] = {**original["metadata"].get("annotations", {}), activation.ANNOTATION: payload["activationId"]}
                expected["metadata"]["resourceVersion"] = current["metadata"]["resourceVersion"]
                if expected != current:
                    raise bootstrap.BootstrapError("synthetic native publication refused")
                status = "candidate"
            return bootstrap.encoded({"ready": True, "secret": "marty-secrets", "count": 11, "state": status})

        def execute(self, pod, command, **kwargs):
            assert pod == "openbao-0" and command == ["bao", "status", "-format=json"]
            return bootstrap.encoded({"initialized": True, "sealed": False, "type": "static",
                "storage_type": "raft", "cluster_id": staged.binding["openbaoClusterId"]})

        def kubectl(self, label, *command, data=None, **kwargs):
            world.argv.append(list(command))
            world.events.append(label)
            if command[:2] == ("get", "namespace"):
                return bootstrap.encoded({"metadata": {"name": self.namespace, "uid": staged.binding["namespaceUid"]}})
            if command[:2] == ("get", "secret"):
                world.secret_observations += 1
                if world.fail == "secret-drift" and world.secret_observations == 2:
                    world.secret["metadata"]["resourceVersion"] = "foreign-version"
                return bootstrap.encoded(world.secret)
            if command[:2] == ("get", activation.RESOURCE_TYPES):
                return bootstrap.encoded({"apiVersion": "v1", "kind": "List", "items": world.resources})
            if command[:2] in {("get", "deployment"), ("get", "pod")}:
                kind = "Deployment" if command[1] == "deployment" else "Pod"
                found = next(item for item in world.resources if item["kind"] == kind and item["metadata"]["name"] == command[2])
                if world.fail == "status-only-version" and kind == "Deployment" and not world.deployment_patches.get(command[2]):
                    found["metadata"]["resourceVersion"] = "11"
                    found["status"]["conditions"] = [{"type": "Available", "status": "True"}]
                return bootstrap.encoded(found)
            if command[:2] == ("patch", "secret"):
                assert (args.state_dir / selection.PENDING).is_file()
                assert (args.operation_dir / "secret-patch-requested.json").is_file()
                world.secret_patches += 1
                assert world.secret_patches == 1, "a Secret request was repeated"
                patch = json.loads(Path(command[5]).read_bytes())
                if world.fail == "secret-rejected":
                    world.secret["metadata"]["resourceVersion"] = "foreign-version"
                if world.fail == "secret-never-applied":
                    raise bootstrap.BootstrapError("synthetic uncertain Secret request")
                world.secret = apply_patch(world.secret, patch)
                world.secret["metadata"]["resourceVersion"] = "20"
                if world.fail == "secret-lost-response":
                    raise bootstrap.BootstrapError("synthetic lost Secret response")
                return bootstrap.encoded(world.secret)
            if command[:2] == ("patch", "deployment"):
                name = command[2]
                world.deployment_patches[name] = world.deployment_patches.get(name, 0) + 1
                assert world.deployment_patches[name] == 1, "a Deployment request was repeated"
                assert (args.operation_dir / (name + "-rollout-requested.json")).is_file()
                before = next(item for item in world.resources if item["kind"] == "Deployment" and item["metadata"]["name"] == name)
                patch = json.loads(Path(command[5]).read_bytes())
                if world.fail == "rollout-never-applied":
                    raise bootstrap.BootstrapError("synthetic uncertain Deployment request")
                replacement = apply_patch(before, patch)
                replacement["metadata"]["resourceVersion"] = "21"
                replacement["metadata"]["generation"] += 1
                replacement["metadata"]["annotations"]["deployment.kubernetes.io/revision"] = "2"
                replacement["status"]["observedGeneration"] = 2
                world.resources[world.resources.index(before)] = replacement
                old_rs = [item for item in world.resources if item["kind"] == "ReplicaSet"
                          and activation.controller(item) == ("Deployment", name, before["metadata"]["uid"])]
                for item in old_rs:
                    item["spec"]["replicas"] = 0
                old_uids = {item["metadata"]["uid"] for item in old_rs}
                if world.fail != "old-pod":
                    world.resources = [item for item in world.resources if not (item["kind"] == "Pod"
                        and activation.controller(item)[2] in old_uids)]
                world.resources.extend(workload_children(replacement, "new"))
                if world.fail == "foreign-rollout":
                    replacement["spec"]["template"]["metadata"]["annotations"][activation.ANNOTATION] = "foreign"
                    replacement["metadata"]["generation"] += 1
                if world.fail == "rollout-lost-response":
                    raise bootstrap.BootstrapError("synthetic lost Deployment response")
                return bootstrap.encoded(replacement)
            if command[:2] == ("rollout", "status"):
                assert command[3] == "--revision=2" and command[4].startswith("--timeout=")
                if world.fail == "rollout-timeout":
                    raise bootstrap.BootstrapError("synthetic pinned rollout timeout")
                if world.fail == "revision-changed-after-wait":
                    name = command[2].split("/", 1)[1]
                    target = next(item for item in world.resources if item["kind"] == "Deployment" and item["metadata"]["name"] == name)
                    target["metadata"]["annotations"]["deployment.kubernetes.io/revision"] = "3"
                return b"synthetic native rollout complete\n"
            if command[:2] == ("exec", "-i"):
                assert label == "private application credential delivery" and command[3] == "--container"
                name = command[4]
                script = command[8]
                path = command[10] if len(command) == 11 else None
                assert script == (activation.DELIVERY_ENV if path is None else activation.DELIVERY_NOTIFICATION_FILE
                                  if name == "notification" else activation.DELIVERY_FILE)
                key = next(key for key, (_variable, target) in activation.BINDINGS[name].items() if target == path)
                assert data == base64.b64decode(world.secret["data"][key]) + b"\n"
                world.delivered.append((command[2], name, key))
                if world.fail in {"stale-file", "wrong-env"} and ((world.fail == "wrong-env") == (path is None)):
                    raise bootstrap.BootstrapError("synthetic credential delivery mismatch")
                if world.fail == "delivery-output":
                    return activation.DELIVERY_OK + b"PRIVATE_EXTRA_OUTPUT_CANARY"
                if world.fail == "delivery-pod-replaced":
                    target = next(item for item in world.resources if item["kind"] == "Pod" and item["metadata"]["name"] == command[2])
                    target["metadata"]["uid"] = "foreign-pod-uid"
                return activation.DELIVERY_OK
            raise AssertionError("unexpected Kubernetes command: " + repr(command))

    def proof(context, current, candidate):
        world.proofs += 1
        world.events.append("fresh-native-proof")
        assert (args.state_dir / selection.PENDING).is_file()
        assert current == staged.snapshot and candidate == staged.candidate
        if world.fail == "proof":
            raise bootstrap.BootstrapError("synthetic fresh verification refused")
        world.deadline = time.monotonic() + activation.ACTIVATION_SECONDS
        context["transport"].deadline = world.deadline
        return world.deadline

    monkeypatch.setattr(activation.subprocess, "run", process)
    monkeypatch.setattr(activation, "BoundedTransport", Transport)
    monkeypatch.setattr(activation, "fresh_proof", proof)
    sequence = iter(range(1000))
    monkeypatch.setattr(bootstrap.secrets, "token_hex", lambda count: format(next(sequence), "0" + str(count * 2) + "x"))
    return world


def test_complete_activation_preserves_unrelated_data_verifies_delivery_and_advances_selection(flow, capsys):
    before = deepcopy(flow.secret["data"])
    activation.activate(flow.args)
    assert flow.secret_patches == 1 and len(flow.deployment_patches) == 6
    assert all(count == 1 for count in flow.deployment_patches.values())
    assert len(flow.delivered) == 12
    assert flow.secret["data"]["DATABASE_SYNC_URL"] == before["DATABASE_SYNC_URL"]
    assert not (flow.args.state_dir / selection.PENDING).exists()
    assert staging.current_snapshot(flow.args.state_dir / "credentials") == flow.staged.snapshot
    with selection.locked(flow.args.state_dir) as held:
        selected = held.current(flow.staged.binding)
        assert selected.directory == flow.args.operation_dir / "candidate"
        assert selected.activation_id == flow.secret["metadata"]["annotations"][activation.ANNOTATION]
    proof = staging.record(flow.args.operation_dir / activation.VERIFIED)
    assert proof["credentialDeliveryVerified"] is True
    assert proof["credentialConsumptionVerified"] is False
    assert flow.events.index("activation-contract") < flow.events.index("namespace identity")
    assert flow.events.index("fresh-native-proof") < flow.events.index("application Secret activation")
    output = capsys.readouterr()
    assert "PRIVATE_" not in output.out + output.err
    assert "PRIVATE_" not in json.dumps(flow.argv)


def test_completed_attempt_reconcile_is_idempotent_without_another_cluster_write(flow):
    activation.activate(flow.args)
    before = len(flow.argv), flow.proofs, deepcopy(flow.deployment_patches)
    flow.args.reconcile = True
    activation.activate(flow.args)
    assert flow.secret_patches == 1 and flow.proofs == before[1]
    assert flow.deployment_patches == before[2]


@pytest.mark.parametrize("fault", ["proof", "secret-drift", "secret-rejected", "secret-never-applied",
    "secret-lost-response", "rollout-never-applied", "rollout-lost-response", "rollout-timeout",
    "foreign-rollout", "old-pod", "stale-file", "wrong-env", "delivery-output", "delivery-pod-replaced",
    "revision-changed-after-wait"])
def test_failed_or_uncertain_activation_retains_pending_without_selecting_candidate(flow, fault, capsys):
    flow.fail = fault
    with pytest.raises(bootstrap.BootstrapError):
        activation.activate(flow.args)
    assert (flow.args.state_dir / selection.PENDING).exists()
    assert not (flow.args.state_dir / selection.SELECTOR).exists()
    assert not (flow.args.operation_dir / activation.COMPLETE).exists()
    with selection.locked(flow.args.state_dir) as held:
        with pytest.raises(bootstrap.BootstrapError, match="pending"):
            held.current(flow.staged.binding)
    assert staging.current_snapshot(flow.args.state_dir / "credentials") == flow.staged.snapshot
    assert "PRIVATE_" not in capsys.readouterr().out + json.dumps(flow.argv)


@pytest.mark.parametrize("fault", ["secret-lost-response", "rollout-lost-response", "rollout-timeout", "stale-file"])
def test_reconcile_observes_applied_secret_and_finishes_only_remaining_rollouts(flow, fault):
    flow.fail = fault
    with pytest.raises(bootstrap.BootstrapError):
        activation.activate(flow.args)
    previous = dict(flow.deployment_patches)
    flow.fail, flow.args.reconcile = None, True
    activation.activate(flow.args)
    assert flow.secret_patches == 1 and all(count == 1 for count in flow.deployment_patches.values())
    assert set(previous) <= set(flow.deployment_patches)
    assert not (flow.args.state_dir / selection.PENDING).exists()


@pytest.mark.parametrize("fault", ["secret-never-applied", "secret-rejected", "rollout-never-applied", "foreign-rollout"])
def test_reconcile_never_repeats_unchanged_or_foreign_mutations(flow, fault):
    flow.fail = fault
    with pytest.raises(bootstrap.BootstrapError):
        activation.activate(flow.args)
    writes = flow.secret_patches, dict(flow.deployment_patches)
    flow.fail, flow.args.reconcile = None, True
    with pytest.raises(bootstrap.BootstrapError):
        activation.activate(flow.args)
    assert (flow.secret_patches, flow.deployment_patches) == writes
    assert (flow.args.state_dir / selection.PENDING).exists()


def test_unknown_native_activation_contract_refuses_before_any_cluster_access(flow):
    flow.bad_contract = True
    with pytest.raises(bootstrap.BootstrapError):
        activation.activate(flow.args)
    assert not flow.argv and not flow.secret_patches
    assert not (flow.args.state_dir / selection.PENDING).exists()


@pytest.mark.parametrize("fault", ["missing-consumer", "foreign-helm", "wrong-image", "wrong-mount",
    "wrong-entrypoint", "wrong-service-role", "extra-consumer", "missing-migration", "active-migration",
    "wrong-migration-image", "wrong-migration-command", "previous-marker"])
def test_cluster_preflight_stops_before_fresh_authority_or_secret_mutation(flow, fault):
    first = next(item for item in flow.resources if item["kind"] == "Deployment" and item["metadata"]["name"] == "gateway")
    migration = next(item for item in flow.resources if item["kind"] == "Job")
    if fault == "missing-consumer":
        flow.resources.remove(first)
    elif fault == "foreign-helm":
        first["metadata"]["annotations"]["meta.helm.sh/release-name"] = "other"
    elif fault == "wrong-image":
        first["spec"]["template"]["spec"]["containers"][0]["image"] = "unsigned:latest"
    elif fault == "wrong-mount":
        first["spec"]["template"]["spec"]["volumes"][-1]["secret"]["secretName"] = "other-secret"
    elif fault == "wrong-entrypoint":
        first["spec"]["template"]["spec"]["containers"][0]["command"] = ["/bin/true"]
    elif fault == "wrong-service-role":
        first["spec"]["template"]["spec"]["containers"][0]["env"][0]["value"] = "signing_keys"
    elif fault == "extra-consumer":
        extra = deepcopy(first)
        extra["metadata"]["name"], extra["metadata"]["uid"] = "foreign", "foreign-uid"
        flow.resources.append(extra)
    elif fault == "missing-migration":
        flow.resources.remove(migration)
    elif fault == "active-migration":
        migration["status"]["active"] = 1
    elif fault == "wrong-migration-image":
        migration["spec"]["template"]["spec"]["initContainers"][2]["image"] = "unsigned:latest"
    elif fault == "wrong-migration-command":
        migration["spec"]["template"]["spec"]["containers"][0]["command"] = ["/bin/true"]
    else:
        flow.secret["metadata"]["annotations"] = {activation.ANNOTATION: "foreign"}
    with pytest.raises(bootstrap.BootstrapError):
        activation.activate(flow.args)
    assert flow.proofs == flow.secret_patches == 0
    assert not (flow.args.state_dir / selection.PENDING).exists()


@pytest.mark.parametrize("name,alias", [(name, alias) for name, aliases in activation.COMPETING_SOURCES.items()
                                      for alias in sorted(aliases)])
@pytest.mark.parametrize("source", ["inline", "empty", "reference"])
def test_explicit_competing_credential_sources_refuse_before_activation(flow, name, alias, source):
    deployment = next(item for item in flow.resources
                      if item["kind"] == "Deployment" and item["metadata"]["name"] == name)
    setting = ({"valueFrom": {"configMapKeyRef": {"name": "other", "key": "token"}}}
               if source == "reference" else {"value": "" if source == "empty" else "PRIVATE_SHADOW_TOKEN_CANARY"})
    deployment["spec"]["template"]["spec"]["containers"][0]["env"].append({"name": alias, **setting})
    with pytest.raises(bootstrap.BootstrapError, match="competing credential source"):
        activation.activate(flow.args)
    assert flow.proofs == flow.secret_patches == 0
    assert not (flow.args.state_dir / selection.PENDING).exists()


def test_stage_snapshot_must_match_selected_current_before_cluster_access(flow):
    put(flow.args.stage_dir / "current-snapshot.tar", staging.archive_snapshot({
        **flow.staged.snapshot, "optional-scalar": (b"PRIVATE_OTHER_CURRENT_CANARY", 0o640)}))
    with pytest.raises(bootstrap.BootstrapError, match="another current"):
        activation.activate(flow.args)
    assert not flow.argv and flow.secret_patches == 0


def test_optional_canvas_worker_is_not_required_but_is_rolled_when_present(flow):
    removed = {item["metadata"]["uid"] for item in flow.resources
               if item["metadata"]["name"].startswith("canvas-sync-worker")}
    flow.resources = [item for item in flow.resources if item["metadata"]["uid"] not in removed]
    activation.activate(flow.args)
    assert len(flow.deployment_patches) == 5 and len(flow.delivered) == 11


def test_status_only_deployment_version_refresh_is_guarded_and_secret_version_is_unchanged(flow):
    flow.fail = "status-only-version"
    activation.activate(flow.args)
    for name in flow.deployment_patches:
        request = staging.record(flow.args.operation_dir / (name + "-rollout-requested.json"))
        assert request["resourceVersion"] == "11"
    patch = json.loads((flow.args.operation_dir / "secret-patch.json").read_bytes())
    assert patch[1] == {"op": "test", "path": "/metadata/resourceVersion", "value": "10"}


def test_same_operation_cannot_be_restarted_as_a_new_activation(flow):
    flow.fail = "secret-lost-response"
    with pytest.raises(bootstrap.BootstrapError):
        activation.activate(flow.args)
    before = len(flow.argv)
    with pytest.raises(bootstrap.BootstrapError, match="pending"):
        activation.activate(flow.args)
    assert len(flow.argv) == before and flow.secret_patches == 1


def test_after_selector_partial_completion_is_repaired_by_same_attempt(flow, monkeypatch):
    original = selection.LockedState.complete
    failures = []

    def interrupted(held, binding, operation):
        if not failures:
            proof = staging.record(operation / activation.VERIFIED)
            expected = {**proof, "schema": "marty.kubernetes-application-activation-completion/v1",
                        "status": "application-generation-selected"}
            put(operation / activation.COMPLETE, bootstrap.encoded(expected)[:37])
            failures.append(True)
            raise OSError("synthetic interrupted completion")
        return original(held, binding, operation)

    monkeypatch.setattr(selection.LockedState, "complete", interrupted)
    with pytest.raises(OSError):
        activation.activate(flow.args)
    assert (flow.args.state_dir / selection.SELECTOR).exists()
    assert (flow.args.state_dir / selection.PENDING).exists()
    flow.args.reconcile = True
    activation.activate(flow.args)
    assert not (flow.args.state_dir / selection.PENDING).exists()
    assert len(list(flow.args.operation_dir.glob("application-activation-complete-interrupted-*.partial"))) == 1
    assert flow.secret_patches == 1 and all(count == 1 for count in flow.deployment_patches.values())


@pytest.mark.parametrize("actual", [b"", b"different-private-token-value", b"correct-private-token-value\n",
    b"correct-private-token-value\0", b"correct-private-token-valuex", b"correct-private-token-value\n\n"])
def test_literal_file_delivery_probe_rejects_different_bytes_without_disclosure(tmp_path, actual):
    path = tmp_path / "token"
    path.write_bytes(actual)
    expected = b"correct-private-token-value"
    result = subprocess.run(["/bin/sh", "-ec", activation.DELIVERY_FILE, "--", str(path)],
                            input=expected + b"\n", capture_output=True, check=False)
    assert result.returncode != 0 and not result.stdout
    assert expected not in result.stderr
    assert actual not in result.stderr if actual else not result.stderr


def test_literal_file_delivery_probe_checks_projection_symlink_and_never_writes(tmp_path):
    value = b"correct-private-token-value"
    source, projected = tmp_path / "data", tmp_path / "token"
    source.write_bytes(value)
    projected.symlink_to(source)
    before = source.stat()
    result = subprocess.run(["/bin/sh", "-ec", activation.DELIVERY_FILE, "--", str(projected)],
                            input=value + b"\n", capture_output=True, check=False)
    assert result.returncode == 0 and result.stdout == activation.DELIVERY_OK and not result.stderr
    assert source.read_bytes() == value and source.stat().st_mtime_ns == before.st_mtime_ns


@pytest.mark.parametrize("actual", ["correct-private-token-value", "stale-private-token-value", ""])
def test_literal_environment_delivery_probe_compares_original_container_alias(actual):
    value = b"correct-private-token-value"
    result = subprocess.run(["/bin/sh", "-ec", activation.DELIVERY_ENV, "--"],
        input=value + b"\n", capture_output=True, check=False,
        env={"OPENBAO_SERVICE_TOKEN": actual})
    assert (result.returncode == 0) == (actual == value.decode())
    assert result.stdout == (activation.DELIVERY_OK if result.returncode == 0 else b"")
    assert value not in result.stderr


@pytest.mark.parametrize("name,alias", [(name, alias) for name, aliases in activation.COMPETING_SOURCES.items()
                                      for alias in sorted(aliases)])
@pytest.mark.parametrize("source", ["explicit", "configmap-env-from"])
@pytest.mark.parametrize("shadow", ["PRIVATE_SHADOW_TOKEN_CANARY", ""])
def test_literal_delivery_refuses_resolved_competing_sources(tmp_path, name, alias, source, shadow):
    value = b"correct-private-token-value"
    path = tmp_path / "token"
    path.write_bytes(value)
    primary = ("OPENBAO_SERVICE_TOKEN", value.decode()) if name == "signing-keys" else (
        "NOTIFICATION_OPENBAO_TOKEN_FILE", str(path))
    container = {"envFrom": [{"configMapRef": {"name": "marty-config"}}],
                 "env": [{"name": primary[0], "value": primary[1]}]}
    config_map = {"metadata": {"name": "marty-config"}, "data": {}}
    if source == "explicit":
        container["env"].append({"name": alias, "value": shadow})
    else:
        config_map["data"][alias] = shadow
        assert alias not in {entry["name"] for entry in container["env"]}
    # kubectl exec receives the original resolved container environment. Explicit
    # env wins over envFrom, but a competing alias remains independently present.
    environment = {}
    for entry in container["envFrom"]:
        assert entry["configMapRef"]["name"] == config_map["metadata"]["name"]
        environment.update(config_map["data"])
    environment.update({entry["name"]: entry["value"] for entry in container["env"]})
    script = activation.DELIVERY_ENV if name == "signing-keys" else activation.DELIVERY_NOTIFICATION_FILE
    arguments = [] if name == "signing-keys" else [str(path)]
    result = subprocess.run(["/bin/sh", "-ec", script, "--", *arguments], input=value + b"\n",
                            capture_output=True, check=False, env=environment)
    assert result.returncode != 0 and not result.stdout and not result.stderr
    assert path.read_bytes() == value


@pytest.mark.parametrize("path_source", ["expected", "missing", "different"])
def test_notification_probe_requires_unambiguous_actual_file_source(tmp_path, path_source):
    value = b"correct-private-token-value"
    path = tmp_path / "token"
    path.write_bytes(value)
    environment = {} if path_source == "missing" else {
        "NOTIFICATION_OPENBAO_TOKEN_FILE": str(path if path_source == "expected" else tmp_path / "other")}
    result = subprocess.run(["/bin/sh", "-ec", activation.DELIVERY_NOTIFICATION_FILE, "--", str(path)],
                            input=value + b"\n", capture_output=True, check=False, env=environment)
    assert (result.returncode == 0) == (path_source == "expected")
    assert result.stdout == (activation.DELIVERY_OK if path_source == "expected" else b"")
    assert not result.stderr


def test_file_delivery_ignores_env_from_path_override(tmp_path):
    path = tmp_path / "token"
    path.write_bytes(b"different-private-token-value")
    executable = tmp_path / "cmp"
    executable.write_text("#!/bin/sh\nexit 0\n")
    executable.chmod(0o700)
    value = b"correct-private-token-value"
    result = subprocess.run(["/bin/sh", "-ec", activation.DELIVERY_FILE, "--", str(path)],
        input=value + b"\n", capture_output=True, check=False, env={"PATH": str(tmp_path)})
    assert result.returncode != 0 and not result.stdout and not result.stderr
    assert path.read_bytes() == b"different-private-token-value"


def test_total_deadline_is_not_reset_for_each_rollout(monkeypatch):
    monkeypatch.setattr(activation.time, "monotonic", lambda: 100.0)
    assert activation.remaining(112.0) == 12
    with pytest.raises(bootstrap.BootstrapError, match="deadline"):
        activation.remaining(105.0)


def test_bounded_transport_clamps_all_commands_to_shared_deadline(tmp_path, monkeypatch):
    observed = []
    monkeypatch.setattr(activation.time, "monotonic", lambda: 100.0)
    monkeypatch.setattr(bootstrap.Transport, "run", lambda _self, _operation, _command, **kwargs:
                        observed.append(kwargs["timeout"]) or b"fixed")
    transport = activation.BoundedTransport(tmp_path, tmp_path / "kubeconfig", "marty-test", "/synthetic/kubectl")
    transport.deadline = 112.0
    assert transport.kubectl("bounded", "get", "pod", timeout=60) == b"fixed"
    assert transport.execute("pod", ["fixed"], timeout=8) == b"fixed"
    assert observed == [12, 8]
    transport.deadline = 105.0
    with pytest.raises(bootstrap.BootstrapError, match="deadline"):
        transport.kubectl("expired", "get", "pod")
    assert observed == [12, 8]


@pytest.fixture
def proof_flow(tmp_path, monkeypatch):
    binding = {"namespace": "marty-test", "namespaceUid": "c647e5d2-85d7-409b-8729-94b8f8cf29ab",
        "openbaoClusterId": "9347f7a0-aae1-4ecf-9e77-165626c051c2",
        "workloadProject": "marty-selfhost-disposable-k8s-0123456789ab"}
    state = tmp_path / "private"
    state.mkdir(mode=0o700)
    current = {"openbao_tls_ca_cert": (b"PUBLIC_CA_CERTIFICATE", 0o644),
               "old-token": (b"PRIVATE_OLD_TOKEN_CANARY", 0o600)}
    candidate = {**current, "old-token": (b"PRIVATE_CANDIDATE_TOKEN_CANARY", 0o600)}
    authority = {"application-secret-id": (b"PRIVATE_APPROLE_CANARY", 0o600)}
    operator = b"synthetic authenticated native operator"
    world = SimpleNamespace(binding=binding, current=current, candidate=candidate, fail=None, reply=None,
                            creates=[], cleanups=0, calls=[], uploads=[], imported={}, clock=100.0)

    class Transport:
        deadline = None
        namespace = binding["namespace"]

        def __init__(self):
            self.state = state

        def create(self, resource):
            world.creates.append(resource)

        def kubectl(self, operation, *command, **kwargs):
            world.calls.append(list(command))
            if operation == "namespace identity":
                return bootstrap.encoded({"metadata": {"name": self.namespace, "uid": binding["namespaceUid"]}})
            if operation == "native verifier readiness":
                if world.fail == "readiness":
                    raise bootstrap.BootstrapError("synthetic verifier unavailable")
                return b""
            assert operation == "native verifier cleanup"
            assert command[:2] == ("delete", "pod") and command[-1] == "--timeout=120s"
            world.cleanups += 1
            if world.fail == "cleanup":
                raise bootstrap.BootstrapError("synthetic cleanup failure")
            return b""

        def upload(self, pod, destination, contents, **kwargs):
            world.calls.append(["upload", pod, destination])
            world.uploads.append((destination, contents))

        def execute(self, pod, command, *, data=None, **kwargs):
            world.calls.append(command)
            if command == ["bao", "status", "-format=json"]:
                return bootstrap.encoded({"initialized": True, "sealed": False, "type": "static",
                    "storage_type": "raft", "cluster_id": binding["openbaoClusterId"]})
            if command[:2] == ["/bin/sh", "-ec"]:
                if command[2].startswith("umask 077; for path"):
                    return b""
                assert command[2] == bootstrap.REMOTE_ARCHIVE_COMMAND
                assert command[4] == activation.REMOTE_PROOF
                if world.fail == "export":
                    raise bootstrap.BootstrapError("synthetic export failure")
                evidence = {"attempt.json": (bootstrap.encoded({"binding": binding}), 0o600),
                    "login-response.json": (b"PRIVATE_VERIFIER_RESPONSE_CANARY", 0o600)}
                if world.fail not in {"native", "timeout", "missing-completion"}:
                    evidence["complete.json"] = bootstrap.encoded({"ready": True}), 0o600
                if world.fail == "unexpected-mint":
                    evidence["mint-response-00.json"] = b"PRIVATE_UNEXPECTED_TOKEN", 0o600
                if world.fail == "unsafe-evidence":
                    evidence["complete.json"] = b"PRIVATE_UNSAFE_EVIDENCE", 0o644
                return archive(evidence)
            if command == ["sha256sum", activation.REMOTE_OPERATOR]:
                return hashlib.sha256(operator).hexdigest().encode()
            if command[:3] == ["tar", "-xpf", "-"]:
                world.imported[command[-1]] = unpack(data)
                return b""
            assert command == [activation.REMOTE_OPERATOR, "operator", "application-token-verify",
                               "https://openbao:8200", "/tmp/ca.crt", activation.REMOTE_IDENTITY]
            assert json.loads(data) == {"current": activation.REMOTE_CURRENT,
                "candidate": activation.REMOTE_CANDIDATE, "output": activation.REMOTE_PROOF, "binding": binding}
            assert kwargs["timeout"] == 600 and self.deadline == 100.0 + activation.ACTIVATION_SECONDS
            world.clock = 250.0
            if world.fail == "native":
                raise bootstrap.BootstrapError("synthetic native verification failure")
            if world.fail == "timeout":
                raise subprocess.TimeoutExpired(command, 600, output=b"PRIVATE_TIMEOUT_CANARY")
            return world.reply if world.reply is not None else bootstrap.encoded({
                "ready": True, "count": 11, "minimumTtlSeconds": activation.MINIMUM_TTL})

    world.transport = Transport()
    world.context = {"binding": binding, "transport": world.transport, "authority": authority,
        "operatorBytes": operator, "pullSecrets": ["registry-pull"],
        "values": {"images": {"services": "services@sha256:" + "1" * 64}}}
    monkeypatch.setattr(activation.time, "monotonic", lambda: world.clock)
    return world


def test_fresh_proof_uses_actual_closed_export_and_preserves_private_evidence(proof_flow, capsys):
    flow = proof_flow
    deadline = activation.fresh_proof(flow.context, flow.current, flow.candidate)
    assert deadline == 100.0 + activation.ACTIVATION_SECONDS and flow.cleanups == 1
    assert len(flow.creates) == 1
    pod = flow.creates[0]
    assert pod["metadata"]["name"].startswith("marty-kms-application-activation-")
    assert pod["spec"]["activeDeadlineSeconds"] == 1200
    assert pod["spec"]["automountServiceAccountToken"] is False
    assert pod["spec"]["volumes"] == [{"name": "private", "emptyDir": {"medium": "Memory", "sizeLimit": "128Mi"}}]
    assert flow.imported[activation.REMOTE_CURRENT] == flow.current
    assert flow.imported[activation.REMOTE_CANDIDATE] == flow.candidate
    assert flow.imported[activation.REMOTE_IDENTITY] == flow.context["authority"]
    path = flow.transport.state / "native-verification-evidence.tar"
    assert path.stat().st_mode & 0o777 == 0o600
    assert set(unpack(path.read_bytes())) == {"attempt.json", "login-response.json", "complete.json"}
    assert "PRIVATE_" not in json.dumps(flow.calls) + json.dumps(pod)
    assert "PRIVATE_" not in capsys.readouterr().out


@pytest.mark.parametrize("fault", ["native", "timeout", "export", "missing-completion", "unexpected-mint", "unsafe-evidence"])
def test_fresh_proof_failure_keeps_bounded_pod_and_never_claims_success(proof_flow, fault, capsys):
    proof_flow.fail = fault
    with pytest.raises(bootstrap.BootstrapError) as failure:
        activation.fresh_proof(proof_flow.context, proof_flow.current, proof_flow.candidate)
    assert proof_flow.cleanups == 0 and len(proof_flow.creates) == 1
    assert (proof_flow.transport.state / "transport-pod.json").is_file()
    if fault in {"native", "timeout"}:
        assert (proof_flow.transport.state / "native-verification-evidence.tar").is_file()
    assert "PRIVATE_" not in str(failure.value) + capsys.readouterr().out


@pytest.mark.parametrize("reply", [b'{"ready":true,"count":true,"minimumTtlSeconds":1800}',
    b'{"ready":true,"count":11,"minimumTtlSeconds":1800,"extra":1}',
    b'{"ready":true,"count":11,"minimumTtlSeconds":1800,"count":11}',
    b'PRIVATE_UNEXPECTED_NATIVE_OUTPUT'])
def test_fresh_proof_requires_exact_native_success_response(proof_flow, reply):
    proof_flow.reply = reply
    with pytest.raises(bootstrap.BootstrapError, match="uncertain"):
        activation.fresh_proof(proof_flow.context, proof_flow.current, proof_flow.candidate)
    assert proof_flow.cleanups == 0


def test_real_chart_consumers_match_activation_bindings(tmp_path):
    import test_marty_helm_chart as chart
    if chart.HELM is None:
        pytest.skip("actual Helm client required")
    values = chart.installation_values()
    values["release"] = {"runtimeSourceSha": "1" * 40, "chartSourceSha": "2" * 40,
                         "tag": "v1.2.3-nightly.20261108.123", "buildRunId": 123, "buildRunAttempt": 1}
    values["canvasWorker"] = {"enabled": True}
    documents = chart.render(tmp_path, values)
    actual = {item["metadata"]["name"]: item for item in documents if item["kind"] == "Deployment"}
    for name in activation.BINDINGS:
        activation.consumer_bindings(actual[name]["spec"]["template"]["spec"], name, values["images"]["services"])
    for item in documents:
        if item["kind"] in {"Deployment", "StatefulSet", "Job"}:
            keys = activation.token_references(item["spec"]["template"]["spec"])
            if keys:
                assert (item["kind"] == "Deployment" and item["metadata"]["name"] in activation.BINDINGS) or item["kind"] == "Job"
        if item["kind"] == "Job" and item["metadata"]["name"].startswith("marty-migrate-"):
            item["metadata"].update({"uid": "migration-uid", "resourceVersion": "1"})
            item["status"] = {"succeeded": 1, "conditions": [{"type": "Complete", "status": "True"}]}
            assert activation.migration_complete(item, item["metadata"]["namespace"],
                item["metadata"]["labels"]["app.kubernetes.io/instance"], values["release"], values["images"])
