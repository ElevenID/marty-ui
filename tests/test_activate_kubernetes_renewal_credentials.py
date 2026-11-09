"""Renewal publication and rollout recovery through closed process/API doubles.

These tests run the real adapter and private state transitions. Native command
doubles expose dispatch ordering and data custody; the Rust suite separately
proves token, certificate, catalog, and generation policy. The real Helm render
and POSIX byte-delivery probe are exercised without those doubles.
"""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from types import SimpleNamespace

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import activate_kubernetes_application_credentials as application
import activate_kubernetes_renewal_credentials as activation
import bootstrap_kubernetes_openbao as bootstrap
import kubernetes_application_state as selection
import stage_kubernetes_application_credentials as staging
import stage_kubernetes_renewal_credentials as renewal
from test_activate_kubernetes_application_credentials import (
    apply_patch, owner, put, rendered_workloads, resource_metadata, workload_children,
)
from test_stage_kubernetes_renewal_credentials import archive, flow as renewal_flow, unpack


pytestmark = pytest.mark.skipif(os.name != "posix", reason="Linux private activation contract")
ROOT = Path(__file__).resolve().parents[1]


def encoded_value(value):
    return base64.b64encode(value.replace(b"\r", b"").rstrip(b"\n")).decode()


def resources(namespace, values):
    source = yaml.safe_load((ROOT / "deploy/helm/marty/files/workloads.yaml").read_text())
    result = []
    for name in sorted(activation.REQUIRED):
        labels = {"app.kubernetes.io/instance": "marty", "app.kubernetes.io/component": name}
        annotations = {"marty.11id.dev/" + key: str(value) for key, value in values["release"].items()}
        if name == "keycloak":
            container = {"name": name, "image": values["images"]["keycloak"],
                "command": ["/opt/keycloak/bin/kc.sh"],
                "args": ["start", "--import-realm", "--features=organization"],
                "envFrom": [{"configMapRef": {"name": "marty-config"}}],
                "env": [{"name": key, "value": value} for key, value in {
                    "BAO_CACERT": "/run/secrets/openbao_tls_ca_cert",
                    "BAO_TOKEN_FILE": "/run/secrets/keycloak_signing_kms_token",
                    "MARTY_KEYCLOAK_RS256_CERT_DIR": "/run/secrets",
                    "MARTY_KEYCLOAK_JWE_TOKEN_DIR": "/run/secrets"}.items()],
                "volumeMounts": [{"name": "kms", "mountPath": "/run/secrets", "readOnly": True}]}
            volumes = [{"name": "kms", "secret": {"secretName": "keycloak-kms", "defaultMode": 0o440}}]
        else:
            workload = source[name]
            container = {"name": name, "image": values["images"]["services"],
                "command": ["/app/services/entrypoint.sh"],
                "envFrom": [{"configMapRef": {"name": "marty-config"}}],
                "env": [{"name": "SERVICE_NAME", "value": workload["serviceName"]}, *deepcopy(workload["env"])],
                "volumeMounts": deepcopy(workload.get("volumeMounts", []))}
            volumes = deepcopy(workload.get("volumes", []))
        deployment = {"apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {**resource_metadata("Deployment", name, namespace), "generation": 1,
                "labels": {**labels, "app.kubernetes.io/name": "marty", "app.kubernetes.io/managed-by": "Helm"},
                "annotations": {"deployment.kubernetes.io/revision": "1", "meta.helm.sh/release-name": "marty",
                                "meta.helm.sh/release-namespace": namespace}},
            "spec": {"replicas": 1, "selector": {"matchLabels": labels}, "strategy": {"type": "Recreate"},
                "template": {"metadata": {"labels": labels, "annotations": annotations},
                    "spec": {"containers": [container], "volumes": volumes}}},
            "status": {"observedGeneration": 1, "replicas": 1, "updatedReplicas": 1,
                       "readyReplicas": 1, "availableReplicas": 1}}
        if name == "keycloak":
            # The real chart has the component on the selector and Pod, but not
            # on this Deployment's metadata. Preserve that distinction.
            del deployment["metadata"]["labels"]["app.kubernetes.io/component"]
        result.append(deployment)
        result.extend(workload_children(deployment, "old"))
    result.append(rendered_workloads(namespace, values)[-1])
    result.append({"apiVersion": "batch/v1", "kind": "Job",
        "metadata": {**resource_metadata("Job", "marty-keycloak-1", namespace),
            "labels": {"app.kubernetes.io/instance": "marty", "app.kubernetes.io/component": "keycloak-configurator"}},
        "spec": {"template": {"spec": {"containers": [{"name": "configure", "image": values["images"]["keycloak"],
            "command": ["/bin/bash", "/scripts/setup-keycloak-selfhost-production.sh"],
            "envFrom": [{"configMapRef": {"name": "marty-config"}}],
            "env": [{"name": key, "value": value} for key, value in {
                "KC_URL": "http://keycloak:8080", "KEYCLOAK_SETUP_STRICT": "true",
                "KEYCLOAK_REMOVE_DEMO_USERS": "true", "KEYCLOAK_REPLACE_UI_ORIGINS": "true",
                "CANVAS_DEMO_ADMIN_ENABLED": "false"}.items()],
            "volumeMounts": [{"name": "scripts", "mountPath": "/scripts", "readOnly": True}]}],
            "volumes": [{"name": "scripts", "configMap": {"name": "keycloak-setup-scripts", "defaultMode": 0o555}}]}}},
        "status": {"succeeded": 1, "conditions": [{"type": "Complete", "status": "True"}]}})
    return result


@pytest.fixture
def flow(renewal_flow, tmp_path, monkeypatch):
    staged = renewal_flow
    staged.values["images"].update({
        "migrations": "ghcr.io/elevenid/marty-ui-oss/migrations@sha256:" + "6" * 64,
        "keycloak": "ghcr.io/elevenid/marty-ui-oss/keycloak@sha256:" + "7" * 64})
    # The generation's raw certificate bytes may include CRLF and trailing
    # newlines. Native publication has a distinct normalized byte contract.
    for name in staged.changed:
        if name.endswith("_cert"):
            value = ("-----BEGIN CERTIFICATE-----\r\nPRIVATE_RENEWED_PEM_" + name +
                     "\r\n-----END CERTIFICATE-----\r\n\r\n").encode()
            staged.minted[name] = value, staged.snapshot[name][1]
            staged.candidate[name] = staged.minted[name]
    put(staged.args.state_dir / "marty-images.json", bootstrap.encoded(staged.values))
    renewal.stage(staged.args)
    args = SimpleNamespace(**vars(staged.args))
    args.stage_dir = staged.args.operation_dir
    args.operation_dir = tmp_path / "activation"
    args.reconcile = False
    publication = staged.contracts["kubernetes-secrets-contract"]
    contract = activation.activation_contract(publication)
    staged.contracts["kubernetes-renewal-activation-contract"] = contract
    secrets = {}
    for secret in publication["catalog"]["secrets"]:
        if secret["name"] not in activation.secret_names(contract):
            continue
        data = {}
        for key, field in secret["fields"].items():
            filename = field["env"].lower()
            if filename == "marty_workload_identity_ca_cert":
                filename = "workload_identity_ca_cert"
            data[key] = encoded_value(staged.snapshot[filename][0])
        secrets[secret["name"]] = {"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
            "metadata": {**resource_metadata("Secret", secret["name"], staged.binding["namespace"]),
                "labels": {"preserved": "label"}, "annotations": {"preserved": "annotation"}},
            "data": data}
    world = SimpleNamespace(args=args, staged=staged, contract=contract, secrets=secrets,
        originals=deepcopy(secrets), resources=resources(staged.binding["namespace"], staged.values),
        fail=None, fault_secret=sorted(secrets)[5], fault_deployment="auth",
        argv=[], events=[], secret_patches={}, deployment_patches={}, delivered=[],
        proofs=0, completed_proofs=set(), proof_started=set(), creates=[], cleanups=0,
        imported={}, uploads=[], timeouts=[], now=1000.0, advance={}, reply=None,
        evidence_override=None, namespace_uid=staged.binding["namespaceUid"],
        cluster_id=staged.binding["openbaoClusterId"])

    def replacement_values(command):
        snapshot = staging.current_snapshot(Path(command["candidate"]))
        return {entry["key"]: encoded_value(snapshot[entry["file"]][0])
                for entry in contract["inputs"] if entry["secret"] == command["secret"]}

    def generation(command):
        old = staging.current_snapshot(Path(command["current"]))
        new = staging.current_snapshot(Path(command["candidate"]))
        valid = set(old) == set(new) and all(old[name][1] == new[name][1]
            and ((old[name][0] != new[name][0]) if name in staged.changed else old[name][0] == new[name][0])
            for name in old)
        if not valid:
            raise bootstrap.BootstrapError("synthetic complete generation refused")
        return len(old), len(staged.changed)

    def native_publication(command):
        name = command["secret"]
        world.events.append("native-" + command["operation"] + ":" + name)
        assert command["namespace"] == staged.binding["namespace"] and name in secrets
        assert set(command) == {"operation", "namespace", "secret", "current", "candidate", "observed",
                                "activationId", "output" if command["operation"] == "prepare" else "result"}
        generation(command)
        original = json.loads(Path(command["observed"]).read_bytes())
        assert stat.S_IMODE(Path(command["observed"]).stat().st_mode) == 0o600
        replacements = replacement_values(command)
        if command["operation"] == "prepare":
            patch = [{"op": "test", "path": "/metadata/uid", "value": original["metadata"]["uid"]},
                     {"op": "test", "path": "/metadata/resourceVersion", "value": original["metadata"]["resourceVersion"]}]
            patch += [{"op": "replace", "path": "/data/" + key.replace("~", "~0").replace("/", "~1"), "value": value}
                      for key, value in sorted(replacements.items())]
            patch += [{"op": "add", "path": "/metadata/annotations", "value": {
                **original["metadata"].get("annotations", {}), activation.ANNOTATION: command["activationId"]}}]
            bootstrap.write_new(Path(command["output"]), bootstrap.encoded(patch))
            return {"ready": True, "secret": name, "count": len(replacements)}
        current = json.loads(Path(command["result"]).read_bytes())
        if current == original:
            status = "unchanged"
        else:
            expected = deepcopy(original)
            expected["data"].update(replacements)
            expected["metadata"]["annotations"] = {
                **original["metadata"].get("annotations", {}), activation.ANNOTATION: command["activationId"]}
            expected["metadata"]["resourceVersion"] = current["metadata"]["resourceVersion"]
            if expected != current:
                raise bootstrap.BootstrapError("synthetic native publication conflict")
            status = "candidate"
        return {"ready": True, "secret": name, "count": len(replacements), "state": status}

    def native_evidence(transport):
        if world.evidence_override is not None:
            return world.evidence_override
        evidence = {}
        if transport.state in world.proof_started:
            evidence = {"pending.json": (bootstrap.encoded({"binding": staged.binding}), 0o600),
                        "authority.token": (b"PRIVATE_TRANSIENT_VERIFIER_CANARY", 0o600)}
        if transport.state in world.completed_proofs:
            evidence.update({
                "validated.json": (b'{"fixture":"PRIVATE_FRESH_PROOF_CANARY"}', 0o600),
                "session-retired.json": (bootstrap.encoded({
                    "schema": "marty.kubernetes-renewal-session-retirement/v1", "transientRevoked": True}), 0o600),
                "completed.json": (bootstrap.encoded({
                    "schema": "marty.kubernetes-renewal-verification/v1", "binding": staged.binding,
                    "producerNonce": staged.receipt["producerNonce"], "files": len(staged.snapshot),
                    "changedFiles": 39, "scopedLeafTokens": 21, "transientRevoked": True, "activated": False,
                    "caChanged": False, "minimumTtlSeconds": 3600}), 0o600)})
        return archive(evidence)

    def run(transport, label, command, *, data=None, timeout=300, env=None):
        world.argv.append(command)
        world.events.append(label)
        world.timeouts.append((label, timeout, world.now))
        elapsed = world.advance.get(label, 0)
        world.now += elapsed
        if elapsed > timeout:
            raise bootstrap.BootstrapError("synthetic bounded transport timed out")
        if label == "native application generation validation":
            assert command[-2:] == ["operator", "generation"] and env == {}
            payload = json.loads(data)
            assert payload["operation"] == "verify" and payload["ca_overlap"] is payload["ca_retire"] is False
            return bootstrap.encoded({"value": list(generation(payload))})
        if label == "native Renewal Secret validation":
            assert command[-2:] == ["operator", "kubernetes-renewal-publication"] and env == {}
            return bootstrap.encoded(native_publication(json.loads(data)))
        assert command[:len(transport.base)] == transport.base
        argv = command[len(transport.base):]
        if argv[:2] == ["get", "namespace"]:
            return bootstrap.encoded({"metadata": {"name": transport.namespace, "uid": world.namespace_uid}})
        if argv[:2] == ["get", "secret"]:
            name = argv[2]
            world.events.append("observe:" + name)
            if world.fail == "secret-drift" and transport.state in world.completed_proofs and name == world.fault_secret:
                world.secrets[name]["metadata"]["resourceVersion"] = "foreign-version"
            if world.fail == "before-rollout-secret-drift" and len(world.secret_patches) == 33 and name == world.fault_secret:
                world.secrets[name]["metadata"]["uid"] = "foreign-secret-uid"
            return bootstrap.encoded(world.secrets[name])
        if argv[:2] == ["get", application.RESOURCE_TYPES]:
            return bootstrap.encoded({"kind": "List", "apiVersion": "v1", "items": world.resources})
        if argv[:2] in (["get", "deployment"], ["get", "pod"]):
            kind = "Deployment" if argv[1] == "deployment" else "Pod"
            found = next(item for item in world.resources if item["kind"] == kind and item["metadata"]["name"] == argv[2])
            if world.fail == "status-only-version" and kind == "Deployment" and not world.deployment_patches.get(argv[2]):
                found["metadata"]["resourceVersion"] = "11"
            return bootstrap.encoded(found)
        if argv[:2] == ["create", "-f"]:
            document = json.loads(data)
            assert document["kind"] == "Pod" and document["metadata"]["name"].startswith("marty-kms-renewal-activation-")
            assert (args.operation_dir / activation.REQUEST).is_file()
            assert (args.state_dir / selection.PENDING).is_file()
            assert all(activation.patch_path(args.operation_dir, name).is_file() for name in secrets)
            world.creates.append(document)
            return b""
        if argv[0] == "wait":
            if world.fail == "proof-readiness":
                raise bootstrap.BootstrapError("synthetic verifier readiness failed")
            return b""
        if argv[:2] == ["delete", "pod"]:
            world.cleanups += 1
            if world.fail == "proof-cleanup":
                raise bootstrap.BootstrapError("synthetic verifier cleanup failed")
            return b""
        if argv[:2] == ["patch", "secret"]:
            name = argv[2]
            assert (args.state_dir / selection.PENDING).is_file()
            assert (args.operation_dir / ("secret-" + name + "-requested.json")).is_file()
            assert not world.deployment_patches
            world.secret_patches[name] = world.secret_patches.get(name, 0) + 1
            assert world.secret_patches[name] == 1, "a requested Renewal Secret was replayed"
            world.events.append("patch:" + name)
            if name == world.fault_secret and world.fail == "secret-never-applied":
                raise bootstrap.BootstrapError("synthetic uncertain Secret request")
            if name == world.fault_secret and world.fail == "secret-rejected":
                world.secrets[name]["metadata"]["resourceVersion"] = "foreign-version"
            patch = json.loads(Path(argv[5]).read_bytes())
            world.secrets[name] = apply_patch(world.secrets[name], patch)
            world.secrets[name]["metadata"]["resourceVersion"] = "20"
            if name == world.fault_secret and world.fail == "secret-lost-response":
                raise bootstrap.BootstrapError("synthetic lost Secret response")
            return bootstrap.encoded(world.secrets[name])
        if argv[:2] == ["patch", "deployment"]:
            name = argv[2]
            assert len(world.secret_patches) == 33
            assert (args.operation_dir / (name + "-rollout-requested.json")).is_file()
            assert all(secret["metadata"]["annotations"].get(activation.ANNOTATION)
                       for secret in world.secrets.values())
            world.deployment_patches[name] = world.deployment_patches.get(name, 0) + 1
            assert world.deployment_patches[name] == 1, "a requested Deployment was replayed"
            world.events.append("rollout:" + name)
            original = next(item for item in world.resources if item["kind"] == "Deployment" and item["metadata"]["name"] == name)
            if name == world.fault_deployment and world.fail == "rollout-never-applied":
                raise bootstrap.BootstrapError("synthetic uncertain Deployment request")
            replacement = apply_patch(original, json.loads(Path(argv[5]).read_bytes()))
            replacement["metadata"]["resourceVersion"] = "21"
            replacement["metadata"]["generation"] += 1
            replacement["metadata"]["annotations"]["deployment.kubernetes.io/revision"] = "2"
            replacement["status"]["observedGeneration"] = 2
            world.resources[world.resources.index(original)] = replacement
            old_sets = [item for item in world.resources if item["kind"] == "ReplicaSet"
                        and application.controller(item) == ("Deployment", name, original["metadata"]["uid"])]
            for item in old_sets:
                item["spec"]["replicas"] = 0
            old_uids = {item["metadata"]["uid"] for item in old_sets}
            if world.fail != "old-pod":
                world.resources = [item for item in world.resources if not (item["kind"] == "Pod"
                    and application.controller(item)[2] in old_uids)]
            world.resources.extend(workload_children(replacement, "new"))
            if name == world.fault_deployment and world.fail == "foreign-rollout":
                replacement["spec"]["template"]["metadata"]["annotations"][activation.ANNOTATION] = "foreign"
            if name == world.fault_deployment and world.fail == "rollout-lost-response":
                raise bootstrap.BootstrapError("synthetic lost Deployment response")
            return bootstrap.encoded(replacement)
        if argv[:2] == ["rollout", "status"]:
            assert argv[3] == "--revision=2" and argv[4].startswith("--timeout=")
            if world.fail == "rollout-timeout":
                raise bootstrap.BootstrapError("synthetic pinned rollout timeout")
            if world.fail == "revision-changed-after-wait":
                name = argv[2].split("/", 1)[1]
                found = next(item for item in world.resources if item["kind"] == "Deployment" and item["metadata"]["name"] == name)
                found["metadata"]["annotations"]["deployment.kubernetes.io/revision"] = "3"
            return b"native pinned rollout complete\n"
        assert argv[0] == "exec", "unexpected mutation: " + repr(argv)
        if label == "private Renewal credential delivery":
            assert data is None and "-i" not in argv and argv[2] == "--container"
            pod_name, name, script, path = argv[1], argv[3], argv[7], argv[9]
            pod = next(item for item in world.resources if item["kind"] == "Pod" and item["metadata"]["name"] == pod_name)
            paths = activation.projected_paths(pod["spec"], name, contract)
            key = next(key for key, value in paths.items() if value == path)
            entry = next(entry for entry in contract["inputs"] if (entry["secret"], entry["key"]) == key)
            assert script == activation.delivery_script(name, entry)
            world.delivered.append((pod_name, name, key))
            actual = base64.b64decode(world.secrets[key[0]]["data"][key[1]])
            if world.fail == "stale-file":
                return actual + b"PRIVATE_STALE_SUFFIX"
            if world.fail == "delivery-pod-replaced":
                pod["metadata"]["uid"] = "foreign-pod"
            if world.fail == "late-custody":
                put(args.state_dir / "credentials" / "optional-scalar", b"PRIVATE_CHANGED_CANARY", 0o640)
            if world.fail == "late-secret-drift":
                world.secrets[world.fault_secret]["metadata"]["uid"] = "foreign-secret-uid"
            return actual
        remote = argv[argv.index("--") + 1:]
        if remote == ["bao", "status", "-format=json"]:
            return bootstrap.encoded({"initialized": True, "sealed": False, "type": "static",
                "storage_type": "raft", "cluster_id": world.cluster_id})
        if remote[:2] == ["/bin/sh", "-ec"]:
            if remote[2].startswith("umask 077; for path"):
                return b""
            if remote[2].startswith("umask 077; set -C; cat"):
                world.uploads.append((remote[4], data))
                return b""
            assert remote[2] == bootstrap.REMOTE_ARCHIVE_COMMAND and remote[4] == activation.REMOTE_PROOF
            if world.fail == "proof-export":
                raise bootstrap.BootstrapError("synthetic private evidence unavailable")
            return native_evidence(transport)
        if remote == ["sha256sum", activation.REMOTE_OPERATOR]:
            return hashlib.sha256(staged.operator).hexdigest().encode()
        if remote[:3] == ["tar", "-xpf", "-"]:
            world.imported[remote[-1]] = unpack(data)
            return b""
        assert remote == [activation.REMOTE_OPERATOR, "operator", "kubernetes-renewal-verify",
                          "https://openbao:8200", "/tmp/ca.crt", activation.REMOTE_IDENTITY]
        assert json.loads(data) == {"current": activation.REMOTE_CURRENT, "candidate": activation.REMOTE_CANDIDATE,
            "output": activation.REMOTE_PROOF, "binding_file": activation.REMOTE_BINDING,
            "binding": staged.binding, "budget_seconds": 600}
        assert timeout <= 600 and world.imported[activation.REMOTE_CURRENT] == staged.snapshot
        assert world.imported[activation.REMOTE_CANDIDATE] == staged.candidate
        world.proofs += 1
        world.proof_started.add(transport.state)
        if world.fail == "proof":
            raise bootstrap.BootstrapError("synthetic fresh verification refused")
        world.completed_proofs.add(transport.state)
        return bootstrap.encoded(world.reply if world.reply is not None else {
            "ready": True, "count": 39, "minimumTtlSeconds": 3600})

    monkeypatch.setattr(bootstrap.Transport, "run", run)
    clock = SimpleNamespace(monotonic=lambda: world.now, sleep=lambda seconds: setattr(world, "now", world.now + seconds))
    monkeypatch.setattr(activation, "time", clock)
    monkeypatch.setattr(application, "time", clock)
    sequence = iter(range(10000))
    monkeypatch.setattr(bootstrap.secrets, "token_hex", lambda count: format(next(sequence), "0" + str(count * 2) + "x"))
    return world


def read_selection(flow):
    with selection.locked(flow.args.state_dir) as held:
        return held.current(flow.staged.binding, domain="renewal")


def no_selection(flow):
    assert not (flow.args.state_dir / selection.SELECTOR).exists()
    assert (flow.args.state_dir / selection.PENDING).is_file()
    assert not (flow.args.operation_dir / activation.COMPLETE).exists()


def test_complete_activation_publishes_all_33_before_18_rollouts_and_selects_delivery_proof(flow, capsys):
    activation.activate(flow.args)
    assert flow.secret_patches == {name: 1 for name in flow.secrets}
    assert flow.deployment_patches == {name: 1 for name in activation.REQUIRED}
    first_rollout = min(flow.events.index("rollout:" + name) for name in activation.REQUIRED)
    assert all(flow.events.index("patch:" + name) < first_rollout for name in flow.secrets)
    assert len(flow.delivered) == 43  # 39 native fields plus four shared CA-only projections.
    assert len({name for _, name, _ in flow.delivered}) == 18
    assert flow.proofs == flow.cleanups == len(flow.creates) == 1
    pod = flow.creates[0]
    assert pod["spec"]["automountServiceAccountToken"] is False
    assert pod["spec"]["activeDeadlineSeconds"] == 1200
    assert pod["spec"]["volumes"][0]["emptyDir"]["medium"] == "Memory"
    proof = json.loads((flow.args.operation_dir / activation.VERIFIED).read_bytes())
    assert proof["credentialDeliveryVerified"] is True and proof["credentialConsumptionVerified"] is False
    assert proof["status"] == "secrets-and-rollouts-verified"
    assert {item["name"] for item in proof["secrets"]} == set(flow.secrets)
    assert {item["name"] for item in proof["deployments"]} == activation.REQUIRED
    selected = read_selection(flow)
    assert selected.directory == flow.args.operation_dir / "candidate"
    assert selected.activation_id is None and selected.renewal_activation_id == proof["activationId"]
    assert selected.generation_activation_id == proof["activationId"]
    assert not (flow.args.state_dir / selection.PENDING).exists()
    for name, value in flow.secrets.items():
        changed = {entry["key"] for entry in flow.contract["inputs"] if entry["secret"] == name}
        assert {key: item for key, item in value["data"].items() if key not in changed} == {
            key: item for key, item in flow.originals[name]["data"].items() if key not in changed}
        assert value["metadata"]["annotations"]["preserved"] == "annotation"
    assert staging.current_snapshot(flow.args.state_dir / "credentials") == flow.staged.snapshot
    assert all(b"PRIVATE_ROOT_CANARY" not in value for _, value in flow.uploads)
    assert "PRIVATE_" not in "".join(capsys.readouterr()) + json.dumps(flow.argv) + json.dumps(proof)
    for path in flow.args.operation_dir.rglob("*"):
        if path.is_file() and not path.is_relative_to(flow.args.operation_dir / "candidate"):
            assert stat.S_IMODE(path.stat().st_mode) in {0o600, 0o700}


@pytest.mark.parametrize("fault", ["secret-lost-response", "rollout-lost-response"])
def test_reconciliation_observes_requested_success_and_dispatches_only_remaining_work(flow, fault):
    flow.fail = fault
    with pytest.raises(bootstrap.BootstrapError, match="lost"):
        activation.activate(flow.args)
    previous_secrets, previous_rollouts = deepcopy(flow.secret_patches), deepcopy(flow.deployment_patches)
    no_selection(flow)
    flow.fail, flow.args.reconcile = None, True
    activation.activate(flow.args)
    assert flow.proofs == 2
    assert flow.secret_patches == {name: 1 for name in flow.secrets}
    assert flow.deployment_patches == {name: 1 for name in activation.REQUIRED}
    assert all(flow.secret_patches[name] == count for name, count in previous_secrets.items())
    assert all(flow.deployment_patches[name] == count for name, count in previous_rollouts.items())
    assert read_selection(flow).directory == flow.args.operation_dir / "candidate"


@pytest.mark.parametrize("fault", ["secret-never-applied", "secret-rejected", "rollout-never-applied"])
def test_reconciliation_never_replays_an_uncertain_or_rejected_request(flow, fault):
    flow.fail = fault
    with pytest.raises(bootstrap.BootstrapError):
        activation.activate(flow.args)
    before = deepcopy(flow.secret_patches), deepcopy(flow.deployment_patches)
    flow.fail, flow.args.reconcile = None, True
    with pytest.raises(bootstrap.BootstrapError, match="unchanged or uncertain|publication conflict|will not be repeated"):
        activation.activate(flow.args)
    assert before == (flow.secret_patches, flow.deployment_patches)
    no_selection(flow)


@pytest.mark.parametrize("fault", ["secret-drift", "foreign-rollout", "old-pod", "stale-file",
                                    "delivery-pod-replaced", "late-custody", "rollout-timeout",
                                    "revision-changed-after-wait", "late-secret-drift"])
def test_live_drift_or_incomplete_delivery_cannot_select_the_candidate(flow, fault):
    flow.fail = fault
    with pytest.raises(bootstrap.BootstrapError):
        activation.activate(flow.args)
    no_selection(flow)


@pytest.mark.parametrize("fault", ["secret-never-applied", "before-rollout-secret-drift"])
def test_all_destinations_must_be_confirmed_before_any_workload_rollout(flow, fault):
    flow.fault_secret = sorted(flow.secrets)[-1]
    flow.fail = fault
    with pytest.raises(bootstrap.BootstrapError):
        activation.activate(flow.args)
    assert len(flow.secret_patches) == 33 and not flow.deployment_patches
    no_selection(flow)


@pytest.mark.parametrize("fault", ["proof", "proof-readiness", "proof-cleanup", "proof-export"])
def test_fresh_verification_failures_prevent_every_secret_and_rollout(flow, fault):
    flow.fail = fault
    with pytest.raises(bootstrap.BootstrapError):
        activation.activate(flow.args)
    assert not flow.secret_patches and not flow.deployment_patches
    if fault in {"proof", "proof-export"}:
        assert flow.cleanups == 0
    no_selection(flow)


@pytest.mark.parametrize("reply", [
    {"ready": True, "count": 39, "minimumTtlSeconds": 3600, "extra": True},
    {"ready": True, "count": True, "minimumTtlSeconds": 3600},
    {"ready": True, "count": 39, "minimumTtlSeconds": 4500},
    {"ready": True, "count": 38, "minimumTtlSeconds": 3600},
])
def test_native_fresh_proof_requires_the_exact_public_contract(flow, reply):
    flow.reply = reply
    with pytest.raises(bootstrap.BootstrapError, match="uncertain"):
        activation.activate(flow.args)
    assert flow.cleanups == 0 and not flow.secret_patches
    no_selection(flow)


def test_outer_deadline_starts_before_pod_setup_and_refuses_late_login(flow):
    flow.advance["native Renewal verifier readiness"] = 245
    with pytest.raises(bootstrap.BootstrapError, match="insufficient original budget"):
        activation.activate(flow.args)
    assert flow.proofs == 0 and not flow.secret_patches
    assert flow.cleanups == 1
    no_selection(flow)


@pytest.mark.parametrize("method", ["publish", "complete"])
def test_deadline_expiration_during_final_selection_keeps_pending_for_reconciliation(flow, monkeypatch, method):
    original = getattr(selection.LockedState, method)

    def delayed(held, *args, **kwargs):
        result = original(held, *args, **kwargs)
        flow.now += 901
        return result

    monkeypatch.setattr(selection.LockedState, method, delayed)
    with pytest.raises(bootstrap.BootstrapError, match="deadline"):
        activation.activate(flow.args)
    assert (flow.args.state_dir / selection.PENDING).is_file()
    assert (flow.args.operation_dir / activation.VERIFIED).is_file()
    assert (flow.args.state_dir / selection.SELECTOR).is_file()
    monkeypatch.setattr(selection.LockedState, method, original)
    flow.args.reconcile = True
    activation.activate(flow.args)
    assert all(count == 1 for count in flow.secret_patches.values())
    assert all(count == 1 for count in flow.deployment_patches.values())
    assert not (flow.args.state_dir / selection.PENDING).exists()


def test_deadline_expiration_during_proof_durability_prevents_selection(flow, monkeypatch):
    original = bootstrap.write_new

    def delayed(path, *args, **kwargs):
        result = original(path, *args, **kwargs)
        if path == flow.args.operation_dir / activation.VERIFIED:
            flow.now += 901
        return result

    monkeypatch.setattr(bootstrap, "write_new", delayed)
    with pytest.raises(bootstrap.BootstrapError, match="deadline"):
        activation.activate(flow.args)
    assert (flow.args.operation_dir / activation.VERIFIED).is_file()
    no_selection(flow)


def test_completed_reconciliation_revalidates_retained_selection_without_cluster_calls(flow):
    activation.activate(flow.args)
    before = len(flow.argv), flow.proofs, deepcopy(flow.secret_patches), deepcopy(flow.deployment_patches)
    flow.args.reconcile = True
    activation.activate(flow.args)
    assert before == (len(flow.argv), flow.proofs, flow.secret_patches, flow.deployment_patches)


def test_status_only_deployment_updates_remain_compatible_with_guarded_rollout(flow):
    flow.fail = "status-only-version"
    activation.activate(flow.args)
    assert len(flow.deployment_patches) == 18


@pytest.mark.parametrize("fault", ["missing-consumer", "foreign-helm", "foreign-owner", "wrong-image", "missing-configurator",
    "active-configurator", "unsafe-configurator", "unknown-reader", "renamed-secret", "subpath", "shadowed-file"])
def test_preflight_refuses_unreviewed_consumers_or_incomplete_config_before_durable_intent(flow, fault):
    target = next(item for item in flow.resources if item["kind"] == "Deployment" and item["metadata"]["name"] == "auth")
    config = next(item for item in flow.resources if item["kind"] == "Job" and item["metadata"]["name"] == "marty-keycloak-1")
    spec = target["spec"]["template"]["spec"]
    if fault == "missing-consumer":
        flow.resources.remove(target)
    elif fault == "foreign-helm":
        target["metadata"]["annotations"]["meta.helm.sh/release-name"] = "foreign"
    elif fault == "foreign-owner":
        target["metadata"]["ownerReferences"] = [{"kind": "CustomResource", "name": "foreign", "uid": "foreign-owner"}]
    elif fault == "wrong-image":
        spec["containers"][0]["image"] = "unreviewed-image"
    elif fault == "missing-configurator":
        flow.resources.remove(config)
    elif fault == "active-configurator":
        config["status"]["active"] = 1
    elif fault == "unsafe-configurator":
        config["spec"]["template"]["spec"]["containers"][0]["env"][1]["value"] = "false"
    elif fault == "unknown-reader":
        reader = deepcopy(target)
        reader["metadata"].update({"name": "foreign-reader", "uid": "foreign-reader"})
        flow.resources.append(reader)
    elif fault == "renamed-secret":
        spec["volumes"][0]["secret"]["secretName"] = "foreign-secret"
    elif fault == "subpath":
        spec["containers"][0]["volumeMounts"][0]["subPath"] = "tls.crt"
    else:
        path = spec["containers"][0]["volumeMounts"][0]["mountPath"] + "/tls.crt"
        spec["containers"][0]["volumeMounts"].append({"name": "shadow", "mountPath": path})
        spec["volumes"].append({"name": "shadow", "emptyDir": {}})
    with pytest.raises(bootstrap.BootstrapError):
        activation.activate(flow.args)
    assert not (flow.args.state_dir / selection.PENDING).exists()
    assert not flow.secret_patches and not flow.deployment_patches and not flow.creates


@pytest.mark.parametrize("group", ["initContainers", "ephemeralContainers"])
@pytest.mark.parametrize("projected", [False, True])
def test_extra_containers_cannot_read_existing_or_duplicate_projected_renewal_volumes(flow, group, projected):
    target = next(item for item in flow.resources if item["kind"] == "Deployment" and item["metadata"]["name"] == "trust-profile")
    spec = target["spec"]["template"]["spec"]
    name = spec["volumes"][0]["name"]
    if projected:
        name = "duplicate-renewal-projection"
        secret = spec["volumes"][0]["secret"]["secretName"]
        spec["volumes"].append({"name": name, "projected": {"sources": [{"secret": {"name": secret}}]}})
    spec[group] = [{"name": "unreviewed-reader", "image": flow.staged.values["images"]["services"],
                   "volumeMounts": [{"name": name, "mountPath": "/copy", "readOnly": True}]}]
    with pytest.raises(bootstrap.BootstrapError, match="additional"):
        activation.activate(flow.args)
    assert not (flow.args.state_dir / selection.PENDING).exists() and not flow.secret_patches


@pytest.mark.parametrize("input_name", ["renewal-identity", "credentials"])
def test_operation_cannot_overlap_retained_private_inputs(flow, input_name):
    flow.args.operation_dir = flow.args.state_dir / input_name / "unsafe-operation"
    with pytest.raises(bootstrap.BootstrapError, match="overlaps"):
        activation.activate(flow.args)
    assert not flow.args.operation_dir.exists() and not flow.argv


def test_retained_patch_tampering_is_rejected_before_an_undispatched_secret(flow):
    flow.fail = "secret-lost-response"
    with pytest.raises(bootstrap.BootstrapError):
        activation.activate(flow.args)
    untouched = sorted(set(flow.secrets) - set(flow.secret_patches))[0]
    path = activation.patch_path(flow.args.operation_dir, untouched)
    patch = json.loads(path.read_bytes())
    patch[-1]["value"]["unreviewed"] = "injected"
    put(path, bootstrap.encoded(patch))
    before = deepcopy(flow.secret_patches)
    flow.fail, flow.args.reconcile = None, True
    with pytest.raises(bootstrap.BootstrapError, match="patch changed"):
        activation.activate(flow.args)
    assert flow.secret_patches == before
    no_selection(flow)


@pytest.mark.parametrize("fault", ["extra-member", "wrong-mode", "unretired", "wrong-ttl"])
def test_private_native_verification_evidence_is_closed_and_retirement_is_required(flow, fault):
    members = {
        "pending.json": (b"{}", 0o600), "authority.token": (b"PRIVATE_AUTHORITY", 0o600),
        "validated.json": (b"{}", 0o600),
        "session-retired.json": (bootstrap.encoded({
            "schema": "marty.kubernetes-renewal-session-retirement/v1", "transientRevoked": fault != "unretired"}), 0o600),
        "completed.json": (bootstrap.encoded({
            "schema": "marty.kubernetes-renewal-verification/v1", "binding": flow.staged.binding,
            "producerNonce": flow.staged.receipt["producerNonce"], "files": len(flow.staged.snapshot),
            "changedFiles": 39, "scopedLeafTokens": 21, "transientRevoked": True, "activated": False,
            "caChanged": False, "minimumTtlSeconds": 1 if fault == "wrong-ttl" else 3600}), 0o600)}
    if fault == "extra-member":
        members["unexpected.json"] = b"{}", 0o600
    if fault == "wrong-mode":
        members["authority.token"] = b"PRIVATE_AUTHORITY", 0o644
    flow.evidence_override = archive(members)
    with pytest.raises(bootstrap.BootstrapError, match="evidence"):
        activation.activate(flow.args)
    assert flow.cleanups == 0 and not flow.secret_patches
    no_selection(flow)


def test_real_chart_matches_closed_renewal_consumer_graph_and_completed_jobs(tmp_path):
    import test_marty_helm_chart as chart
    if chart.HELM is None:
        pytest.skip("actual Helm client required")
    values = chart.installation_values()
    values["release"] = {"runtimeSourceSha": "1" * 40, "chartSourceSha": "2" * 40,
        "tag": "v1.2.3-nightly.20261108.123", "buildRunId": 123, "buildRunAttempt": 1}
    values["canvasWorker"] = {"enabled": True}
    documents = chart.render(tmp_path, values)
    publication = {"catalog": json.loads((ROOT / "deploy-config/catalog/kubernetes-secrets.json").read_bytes())}
    contract = activation.activation_contract(publication)
    actual = []
    consumers = set()
    for item in documents:
        kind = item["kind"]
        if kind not in {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet", "Pod"}:
            continue
        meta = item["metadata"]
        meta.update({"uid": kind.lower() + "-" + meta["name"], "resourceVersion": "10"})
        if kind == "Deployment":
            meta["generation"] = 1
            meta.setdefault("annotations", {}).update({
                "deployment.kubernetes.io/revision": "1",
                "meta.helm.sh/release-name": meta["labels"]["app.kubernetes.io/instance"],
                "meta.helm.sh/release-namespace": meta["namespace"]})
            if activation.references(application.pod_spec(item), activation.secret_names(contract)):
                consumers.add(meta["name"])
        if kind == "Job":
            item["status"] = {"succeeded": 1, "conditions": [{"type": "Complete", "status": "True"}]}
        actual.append(item)
    assert consumers == activation.REQUIRED and len(consumers) == 18
    graph = activation.preflight_resources({"kind": "List", "items": actual}, "isolated-install",
        values["images"], values["release"], contract)
    assert set(graph["deployments"]) == activation.REQUIRED
    assert len(graph["migrationUids"]) == 2


@pytest.mark.parametrize("value", [
    b"PRIVATE_TOKEN_CANARY",
    b"-----BEGIN CERTIFICATE-----\nMULTILINE_PRIVATE_CANARY\nSECOND_LINE\n-----END CERTIFICATE-----",
    b"PRIVATE_BYTES_WITHOUT_TRAILING_NEWLINE",
])
def test_literal_delivery_probe_reads_complete_bounded_bytes_without_expected_argv_or_writes(tmp_path, value):
    actual = tmp_path / "native-secret"
    actual.write_bytes(value)
    projected = tmp_path / "projected-secret"
    projected.symlink_to(actual)
    before = actual.stat()
    result = subprocess.run(["/bin/sh", "-ec", activation.DELIVERY_FILE, "--", str(projected)],
                            input=b"", capture_output=True, check=False)
    assert result.returncode == 0 and result.stdout == value and not result.stderr
    after = actual.stat()
    assert (before.st_size, before.st_mtime_ns, before.st_mode) == (after.st_size, after.st_mtime_ns, after.st_mode)


@pytest.mark.parametrize("size", [0, 65537])
def test_literal_delivery_probe_rejects_empty_and_oversized_files_before_disclosure(tmp_path, size):
    actual = tmp_path / "secret"
    actual.write_bytes(b"x" * size)
    result = subprocess.run(["/bin/sh", "-ec", activation.DELIVERY_FILE, "--", str(actual)],
                            capture_output=True, check=False)
    assert result.returncode != 0 and result.stdout == b""


@pytest.mark.parametrize("correct", [False, True])
def test_literal_delivery_probe_checks_actual_container_file_setting(tmp_path, correct):
    actual = tmp_path / "certificate"
    actual.write_bytes(b"PEM_LINE_ONE\nPEM_LINE_TWO")
    entry = {"input": "AUTH_WORKLOAD_CLIENT_CERT"}
    result = subprocess.run(["/bin/sh", "-ec", activation.delivery_script("auth", entry), "--", str(actual)],
        env={**os.environ, "GRPC_WORKLOAD_TLS_CLIENT_CERT": str(actual) if correct else "/foreign/path"},
        capture_output=True, check=False)
    assert (result.returncode == 0) is correct
    assert result.stdout == (actual.read_bytes() if correct else b"")
