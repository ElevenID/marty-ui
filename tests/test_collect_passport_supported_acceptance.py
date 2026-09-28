"""Supported passport evidence remains blocked without disposable live acceptance."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from scripts import collect_passport_supported_acceptance as gate


COMMIT = "a" * 40
DIGEST = "sha256:" + "b" * 64
REFERENCE = "ghcr.io/elevenid/marty-ui-oss/services@" + DIGEST
BASE = "marty-passport-acceptance-base-abcdef"
SELFHOST = "marty-passport-acceptance-selfhost-abcdef"
NAMESPACE = "marty-passport-acceptance-abcdef"
CONTEXT = "marty-passport-acceptance-testxyz"
RUN_ID = "123456"


def manifest(tmp_path: Path) -> Path:
    path = tmp_path / "stack-manifest.json"
    path.write_text(json.dumps({
        "schema": "marty.stack/v1", "release": "marty-ui@1.2.3",
        "components": [{"name": "marty-ui", "repository": "ElevenID/marty-ui",
                        "commit": COMMIT, "artifacts": [
                            {"type": "oci", "uri": f"ghcr.io/elevenid/marty-ui-oss/{role}",
                             "digest": "sha256:" + letter * 64}
                            for role, letter in (("ui", "c"), ("services", "b"),
                                                 ("migrations", "d"))
                        ]}],
    }), encoding="utf-8")
    return path


@pytest.mark.parametrize("surface,target", [
    ("base", "marty-selfhost-prod"),
    ("base", "elevenid-beta"),
    ("selfhost", "marty-passport-acceptance-base-abcdef"),
    ("kubernetes", "marty-prod"),
    ("kubernetes", "default"),
])
def test_production_and_wrong_disposable_targets_are_rejected(
    tmp_path: Path, surface: str, target: str
) -> None:
    kwargs = {"base": "base_project", "selfhost": "selfhost_project",
              "kubernetes": "namespace"}
    with pytest.raises(gate.SupportedEvidenceError, match="disposable"):
        gate.collect(manifest(tmp_path), COMMIT, **{kwargs[surface]: target},
                     kubernetes_context=CONTEXT if surface == "kubernetes" else None,
                     attest=lambda *args: True)


def test_production_origin_is_rejected_before_runtime_probe(tmp_path: Path) -> None:
    with pytest.raises(gate.SupportedEvidenceError, match="loopback"):
        gate.collect(manifest(tmp_path), COMMIT,
                     base_origin="https://elevenidllc.com", attest=lambda *args: True)


def docker_runner(project: str, *, wrong_image: bool = False):
    def run(args: list[str]) -> str:
        if args[:2] == ["docker", "ps"]:
            service = args[-1].split("=")[-1]
            return service + "-container\n"
        service = args[-1].removesuffix("-container")
        flags = [f"{name}=true" for name in gate.COMPOSE_FLAGS[service]]
        record = {
            "Image": "sha256:" + "e" * 64,
            "Config": {
                "Image": ("ghcr.io/other/unreleased@" + DIGEST)
                if wrong_image else REFERENCE,
                "Labels": {"com.docker.compose.project": project,
                           "com.docker.compose.service": service},
                "Env": flags,
            },
            "State": {"Running": True, "Status": "running",
                      "Health": {"Status": "healthy"}},
            "NetworkSettings": {"Ports": {"8000/tcp": [{
                "HostIp": "127.0.0.1", "HostPort": "28000",
            }]}} if service == "gateway" else {},
        }
        return json.dumps([record])
    return run


def test_compose_runtime_reads_five_exact_running_service_images() -> None:
    observed = gate.observe_compose("base", BASE, REFERENCE, docker_runner(BASE))
    assert set(observed) == set(gate.COMPOSE_SERVICES)
    assert all(item["oci_reference"] == REFERENCE for item in observed.values())
    with pytest.raises(gate.SupportedEvidenceError, match="released services image"):
        gate.observe_compose("base", BASE, REFERENCE, docker_runner(BASE, wrong_image=True))


def test_missing_targets_and_runtime_proof_remain_blocked(tmp_path: Path) -> None:
    report = gate.collect(manifest(tmp_path), COMMIT, attest=lambda *args: True)
    assert report["status"] == "blocked"
    assert set(report["surfaces"]) == {"base", "selfhost", "kubernetes"}
    assert all(surface["runtime_accepted"] is False
               and surface["rollback_accepted"] is False
               for surface in report["surfaces"].values())


def test_live_compose_prerequisite_still_does_not_claim_routes_or_rollback(
    tmp_path: Path
) -> None:
    report = gate.collect(
        manifest(tmp_path), COMMIT, base_project=BASE,
        compose_probe=lambda name, project, image: {
            "gateway": {"oci_reference": image, "container_id": "gateway-container"}
        },
        attest=lambda *args: True,
    )
    base = report["surfaces"]["base"]
    assert base["probes"]["released_image"]["verified"] is True
    assert base["probes"]["released_image"]["evidence"] == {
        "oci_reference": REFERENCE,
        "source_commit": COMMIT,
        "container_id": "gateway-container",
    }
    assert base["probes"]["nine_route_gateway_flow"]["verified"] is False
    assert base["probes"]["signed_bureau_callback"]["verified"] is False
    assert base["rollback_accepted"] is False
    assert report["status"] == "blocked"
    assert report["physical_claim"] == "not_claimed"


def kubernetes_runner(*, mixed_provider: bool = False,
                       wrong_profile: bool = False,
                       provider_enabled: bool = False,
                       stale_pod_profile: bool = False,
                       indirect_profile: bool = False,
                       wrong_owner: bool = False,
                       wrong_route: bool = False,
                       wrong_endpoint: bool = False,
                       wrong_source: bool = False,
                       foreign_address: bool = False,
                       historical_replicaset: bool = False,
                       dual_stack: bool = False,
                       external_ip: bool = False,
                       template_host_network: bool = False,
                       pod_host_network: bool = False,
                       template_host_port: bool = False,
                       pod_host_port: bool = False):
    def container_for(service: str, *, is_pod: bool = False) -> dict:
        values = {flag: "true" for flag in gate.KUBERNETES_FLAGS[service]}
        if service == "gateway":
            values.update({"PASSPORT_PROVIDER_INGRESS_GATEWAY_ENABLED":
                           "true" if provider_enabled else "false",
                           "PASSPORT_PROVIDER_INGRESS_SERVICE_URL": ""})
        if service == "issuance-native":
            values.update({"PERSONALIZATION_BUREAU_URL":
                           "http://passport-beta-bureau:8020",
                           "PERSONALIZATION_BUREAU_PROVIDER_PROFILE_ID":
                           "external-provider" if wrong_profile else
                           "passport-beta-bureau"})
        if service == "passport-beta-bureau":
            values.update({
                "SIGNING_KEYS_INTERNAL_URL":
                    "http://passport-callback-signer:8018/internal/documents",
                "PASSPORT_BUREAU_CALLBACK_URL":
                    "http://issuance-native:8005/v1/passport/webhooks/personalization",
            })
        container = {"image": REFERENCE,
                     "env": [{"name": name, "value": value}
                             for name, value in values.items()]}
        if service in ("passport-beta-bureau", "passport-callback-signer"):
            port = 8020 if service == "passport-beta-bureau" else 8018
            binding = {"name": "http", "containerPort": port}
            if (pod_host_port if is_pod else template_host_port):
                binding["hostPort"] = port
            container["ports"] = [binding]
        return container

    def metadata_for(service: str, kind: str) -> dict:
        labels = {"app": service,
                  "com.marty.passport.acceptance.owner": "supported-consumer",
                  "com.marty.passport.acceptance.run-id": RUN_ID,
                  "com.marty.passport.acceptance.source-commit": COMMIT}
        name = (service + "-rs" if kind == "ReplicaSet" else service)
        uid = service + "-" + kind.lower() + "-uid"
        metadata = {"name": name, "namespace": NAMESPACE,
                    "uid": uid, "labels": labels}
        if wrong_source and kind == "Pod" and service == "passport-beta-bureau":
            metadata["labels"]["com.marty.passport.acceptance.source-commit"] = "f" * 40
        if kind == "ReplicaSet":
            metadata["ownerReferences"] = [{
                "kind": "Deployment", "name": service,
                "uid": service + "-deployment-uid", "controller": True}]
        elif kind == "Pod":
            metadata["labels"]["pod-template-hash"] = "owned-hash"
            metadata["ownerReferences"] = [{
                "kind": "ReplicaSet", "name": service + "-rs",
                "uid": ("foreign" if wrong_owner else service + "-replicaset-uid"),
                "controller": True}]
        elif kind == "EndpointSlice":
            metadata["labels"]["kubernetes.io/service-name"] = service
            metadata["ownerReferences"] = [{
                "kind": "Service", "name": service,
                "uid": service + "-service-uid", "controller": True}]
        return metadata

    def run(args: list[str]) -> str:
        assert args[1:5] == ["--context", CONTEXT, "-n", NAMESPACE]
        if args[6] in ("deployment", "service") and args[7] == "passport-provider-ingress":
            return json.dumps({"kind": args[6]}) if mixed_provider else ""
        if args[6] == "replicasets":
            service = args[8].removeprefix("app=")
            selector = {"app": service,
                        "com.marty.passport.acceptance.owner": "supported-consumer",
                        "com.marty.passport.acceptance.run-id": RUN_ID,
                        "pod-template-hash": "owned-hash"}
            current = {
                "metadata": metadata_for(service, "ReplicaSet"),
                "spec": {"selector": {"matchLabels": selector}},
            }
            old = {"metadata": {**metadata_for(service, "ReplicaSet"),
                                "name": service + "-old-rs",
                                "uid": service + "-old-rs-uid"},
                   "spec": {"replicas": 0}}
            return json.dumps({"items": [current, old] if historical_replicaset
                               else [current]})
        if args[6] == "pods":
            service = args[8].removeprefix("app=")
            if service == "passport-provider-ingress":
                return json.dumps({"items": []})
            pod_container = container_for(service, is_pod=True)
            if service == "issuance-native" and stale_pod_profile:
                next(entry for entry in pod_container["env"] if entry["name"] ==
                     "PERSONALIZATION_BUREAU_PROVIDER_PROFILE_ID")["value"] = "external-provider"
            return json.dumps({"items": [{
                "metadata": metadata_for(service, "Pod"),
                "spec": {"hostNetwork": pod_host_network,
                         "containers": [pod_container]},
                "status": {"phase": "Running", "podIP": "10.1.2.3",
                           "podIPs": ([{"ip": "10.1.2.3"}, {"ip": "fd00::3"}]
                                      if dual_stack else [{"ip": "10.1.2.3"}]),
                           "containerStatuses": [{
                    "ready": True, "imageID": "docker-pullable://" + REFERENCE,
                    "containerID": "containerd://" + service + "-container",
                }]},
            }]})
        if args[6] == "service":
            service = args[7]
            port = 8020 if service == "passport-beta-bureau" else 8018
            selector = {"app": service,
                        "com.marty.passport.acceptance.owner": "supported-consumer",
                        "com.marty.passport.acceptance.run-id": RUN_ID}
            if wrong_route and service == "passport-beta-bureau":
                selector["com.marty.passport.acceptance.run-id"] = "999999"
            return json.dumps({
                "metadata": metadata_for(service, "Service"),
                "spec": {"type": "ClusterIP", "selector": selector,
                         "externalIPs": (["198.51.100.32"] if external_ip and service ==
                                         "passport-beta-bureau" else []),
                         "ports": [{"name": "http", "port": port,
                                    "protocol": "TCP", "targetPort": port}]},
            })
        if args[6] == "endpointslices":
            service = args[8].removeprefix("kubernetes.io/service-name=")
            port = 8020 if service == "passport-beta-bureau" else 8018
            items = []
            for family, address in ([('IPv4', '10.1.2.3'), ('IPv6', 'fd00::3')]
                                    if dual_stack else [('IPv4', '10.1.2.3')]):
                metadata = metadata_for(service, "EndpointSlice")
                metadata["uid"] += "-" + family.lower()
                metadata["labels"]["endpointslice.kubernetes.io/managed-by"] = (
                    "endpointslice-controller.k8s.io")
                items.append({
                    "metadata": metadata, "addressType": family,
                    "ports": [{"name": "http", "port": port, "protocol": "TCP"}],
                    "endpoints": [{"addresses": [
                        "10.9.9.9" if foreign_address and service ==
                        "passport-beta-bureau" else address],
                        "conditions": {"ready": True},
                        "targetRef": {"kind": "Pod", "namespace": NAMESPACE,
                                      "uid": ("foreign" if wrong_endpoint
                                              and service == "passport-beta-bureau"
                                              else service + "-pod-uid")}}],
                })
            return json.dumps({"items": items})
        service = args[7]
        container = container_for(service)
        if service == "issuance-native" and indirect_profile:
            entry = next(entry for entry in container["env"] if entry["name"] ==
                         "PERSONALIZATION_BUREAU_PROVIDER_PROFILE_ID")
            entry.pop("value")
            entry["valueFrom"] = {"configMapKeyRef": {
                "name": "marty-config", "key": "PERSONALIZATION_BUREAU_PROVIDER_PROFILE_ID"}}
        return json.dumps({
            "metadata": metadata_for(service, "Deployment"),
            "status": {"readyReplicas": 1},
            "spec": {"selector": {"matchLabels": {
                "app": service,
                "com.marty.passport.acceptance.owner": "supported-consumer",
                "com.marty.passport.acceptance.run-id": RUN_ID}},
                     "template": {"metadata": {"labels": metadata_for(
                         service, "Deployment")["labels"]},
                                  "spec": {"hostNetwork": template_host_network,
                                           "containers": [container]}}},
        })
    return run


def test_kubernetes_inspection_is_bounded_to_disposable_namespace() -> None:
    observed = gate.observe_kubernetes(NAMESPACE, CONTEXT, REFERENCE, COMMIT,
                                       kubernetes_runner())
    assert set(observed) == set(gate.KUBERNETES_SERVICES)
    assert observed["passport-beta-bureau"]["service_uid"] == (
        "passport-beta-bureau-service-uid")
    assert observed["passport-callback-signer"]["replicaset_uid"] == (
        "passport-callback-signer-replicaset-uid")


def test_kubernetes_accepts_retained_replicasets_and_dual_stack_routes() -> None:
    observed = gate.observe_kubernetes(
        NAMESPACE, CONTEXT, REFERENCE, COMMIT,
        kubernetes_runner(historical_replicaset=True, dual_stack=True))
    assert len(observed["passport-beta-bureau"]["endpoint_slice_uids"]) == 2


@pytest.mark.parametrize("defect,pattern", [
    ("wrong_owner", "Pod ReplicaSet is missing"),
    ("wrong_route", "Service route is outside"),
    ("wrong_endpoint", "Service targets another Pod"),
    ("foreign_address", "Service routes to another address"),
    ("external_ip", "Service route is outside"),
    ("wrong_source", "owner labels are invalid"),
    ("template_host_network", "private Pod uses the host network"),
    ("pod_host_network", "private Pod uses the host network"),
    ("template_host_port", "private port is exposed"),
    ("pod_host_port", "private port is exposed"),
])
def test_kubernetes_rejects_foreign_pod_or_routing(
    defect: str, pattern: str,
) -> None:
    with pytest.raises(gate.SupportedEvidenceError, match=pattern):
        gate.observe_kubernetes(NAMESPACE, CONTEXT, REFERENCE, COMMIT,
                                kubernetes_runner(**{defect: True}))


def test_kubernetes_mixed_provider_is_rejected() -> None:
    with pytest.raises(gate.SupportedEvidenceError, match="physical provider ingress"):
        gate.observe_kubernetes(NAMESPACE, CONTEXT, REFERENCE, COMMIT,
                                kubernetes_runner(mixed_provider=True))
    with pytest.raises(gate.SupportedEvidenceError, match="bound to the Marty simulator"):
        gate.observe_kubernetes(NAMESPACE, CONTEXT, REFERENCE, COMMIT,
                                kubernetes_runner(wrong_profile=True))
    with pytest.raises(gate.SupportedEvidenceError, match="bound to the Marty simulator"):
        gate.observe_kubernetes(NAMESPACE, CONTEXT, REFERENCE, COMMIT,
                                kubernetes_runner(provider_enabled=True))
    with pytest.raises(gate.SupportedEvidenceError, match="requires one literal"):
        gate.observe_kubernetes(NAMESPACE, CONTEXT, REFERENCE, COMMIT,
                                kubernetes_runner(indirect_profile=True))


def test_kubernetes_rejects_pod_with_stale_provider_profile() -> None:
    with pytest.raises(gate.SupportedEvidenceError, match="Pod is not bound"):
        gate.observe_kubernetes(NAMESPACE, CONTEXT, REFERENCE, COMMIT,
                                kubernetes_runner(stale_pod_profile=True))


def test_capability_origin_must_match_inspected_gateway_port(tmp_path: Path) -> None:
    called = []
    report = gate.collect(
        manifest(tmp_path), COMMIT, base_project=BASE,
        base_origin="http://127.0.0.1:28001", api_key="private",
        compose_probe=lambda *args: {"gateway": {
            "loopback_port": 28000, "oci_reference": REFERENCE,
            "container_id": "gateway-container",
        }},
        capability_probe=lambda *args: called.append(args),
        attest=lambda *args: True,
    )
    assert called == []
    assert "capabilities_http" not in report["surfaces"]["base"]
    assert report["surfaces"]["base"]["blocker"] == (
        "probe origin is not bound to the inspected gateway"
    )


def test_duplicate_released_oci_role_is_rejected(tmp_path: Path) -> None:
    path = manifest(tmp_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    data["components"][0]["artifacts"].append(data["components"][0]["artifacts"][0])
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(gate.SupportedEvidenceError, match="image roles"):
        gate.collect(path, COMMIT, attest=lambda *args: True)


def test_protected_workflow_is_read_only_and_artifact_matches_verifier() -> None:
    path = gate.ROOT / ".github/workflows/passport-supported-consumer-acceptance.yml"
    source = path.read_text(encoding="utf-8")
    workflow = yaml.safe_load(source)
    triggers = workflow.get("on", workflow.get(True))
    assert set(triggers) == {"workflow_dispatch"}
    job = workflow["jobs"]["collect"]
    assert job["if"] == "github.ref == 'refs/heads/main'"
    steps = job["steps"]
    upload = steps[-1]
    assert steps[-2]["id"] == "collect"
    assert 'rm -f "$report"' in steps[-2]["run"]
    assert '.status == "accepted"' in steps[-2]["run"]
    assert upload["if"] == (
        "always() && (steps.collect.outcome == 'success' || "
        "steps.collect.outcome == 'failure')"
    )
    assert upload["with"]["name"] == (
        "passport-supported-consumer-acceptance-${{ github.run_id }}"
    )
    assert upload["with"]["path"] == (
        "passport-supported-consumer-acceptance-${{ github.run_id }}.json"
    )
    assert "--exercise-kubernetes-rollback" not in source
    assert "docker compose up" not in source
    assert "kubectl set env" not in source
