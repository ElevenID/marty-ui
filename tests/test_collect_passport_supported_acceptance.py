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
PLAN_RUN_ID = "123456"


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
                      second_configmap: bool = False,
                      bad_owner: bool = False,
                      mutable_config: bool = False,
                      stale_pod: bool = False,
                      incomplete_rollout: bool = False,
                      stale_process_env: bool = False,
                      stale_native_url: bool = False):
    def run(args: list[str]) -> str:
        assert args[1:5] == ["--context", CONTEXT, "-n", NAMESPACE]
        if args[5] == "exec":
            assert args[6].endswith("-pod")
            assert args[7:9] == ["-c", args[6].removesuffix("-pod")]
            assert "/proc/1/environ" in args[-1]
            if args[8] in ("gateway", "flow"):
                assert "ISSUANCE_NATIVE_SERVICE_URL=http://issuance-native:8005" in args[-1]
                if stale_native_url:
                    return "stale"
            return "stale" if stale_process_env else "verified"
        if args[6] == "configmap":
            data = {flag: "true" for names in gate.KUBERNETES_FLAGS.values()
                    for flag in names}
            data.update({"PASSPORT_PROVIDER_INGRESS_GATEWAY_ENABLED":
                         "true" if provider_enabled else "false",
                         "PASSPORT_PROVIDER_INGRESS_SERVICE_URL": "",
                         "ISSUANCE_NATIVE_SERVICE_URL": "http://issuance-native:8005",
                         "PERSONALIZATION_BUREAU_URL":
                         "http://passport-beta-bureau:8020",
                         "PERSONALIZATION_BUREAU_PROVIDER_PROFILE_ID":
                         "external-provider" if wrong_profile else "passport-beta-bureau"})
            return json.dumps({"data": data, "immutable": not mutable_config,
                               "metadata": {"creationTimestamp":
                                            "2026-09-28T12:00:00.123Z"}})
        if args[6] in ("deployment", "service") and args[7] == "passport-provider-ingress":
            return json.dumps({"kind": args[6]}) if mixed_provider else ""
        if args[6] == "pods":
            service = args[8].removeprefix("app=")
            if service == "passport-provider-ingress":
                return json.dumps({"items": []})
            selected = gate.selector_for(service, PLAN_RUN_ID)
            return json.dumps({"items": [{
                "metadata": {"name": service + "-pod", "namespace": NAMESPACE,
                             "uid": service + "-pod",
                             "creationTimestamp": ("2026-09-28T11:59:59Z" if stale_pod
                                                   else "2026-09-28T12:00:01+00:00"),
                             "labels": selected,
                             "ownerReferences": [{"kind": "ReplicaSet",
                                                  "name": service + "-rs",
                                                  "uid": service + "-rs-uid",
                                                  "controller": True}]},
                "spec": {"containers": [{"name": service, "image": REFERENCE}]},
                "status": {"phase": "Running", "containerStatuses": [{
                    "name": service,
                    "ready": True, "imageID": "docker-pullable://" + REFERENCE,
                    "containerID": "containerd://" + service + "-container",
                }]},
            }]})
        if args[6] == "replicaset":
            service = args[7].removesuffix("-rs")
            return json.dumps({"metadata": {
                "name": args[7], "namespace": NAMESPACE, "uid": service + "-rs-uid",
                "labels": gate.selector_for(service, PLAN_RUN_ID),
                "ownerReferences": [{"kind": "Deployment", "name": service,
                                     "uid": ("wrong-uid" if bad_owner else service + "-uid"),
                                     "controller": True}],
            }})
        service = args[7]
        container = {
            "image": REFERENCE,
            "env": [{"name": flag, "value": "true"}
                    for flag in gate.KUBERNETES_FLAGS[service]],
        }
        if service in ("gateway", "flow"):
            container["envFrom"] = [{"configMapRef": {"name": "marty-config"}}]
            if service == "gateway" and second_configmap:
                container["envFrom"].append({"configMapRef": {"name": "override-config"}})
        if service == "issuance-native":
            container["env"].extend({"name": name,
                                     "valueFrom": {"configMapKeyRef": {
                                         "name": "marty-config", "key": name}}}
                                    for name in ("PERSONALIZATION_BUREAU_URL",
                                                 "PERSONALIZATION_BUREAU_PROVIDER_PROFILE_ID"))
        return json.dumps({
            "metadata": {"namespace": NAMESPACE, "uid": service + "-uid",
                         "generation": 2,
                         "labels": {gate.RUN_LABEL: PLAN_RUN_ID}},
            "status": {"observedGeneration": 1 if incomplete_rollout else 2,
                       "replicas": 1, "updatedReplicas": 1,
                       "readyReplicas": 1, "availableReplicas": 1},
            "spec": {"replicas": 1,
                     "selector": {"matchLabels": gate.selector_for(service, PLAN_RUN_ID)},
                     "template": {"metadata": {"labels":
                                               gate.selector_for(service, PLAN_RUN_ID)},
                                  "spec": {"containers": [{"name": service, **container}]}}},
        })
    return run


def test_kubernetes_inspection_is_bounded_to_disposable_namespace() -> None:
    observed = gate.observe_kubernetes(NAMESPACE, CONTEXT, REFERENCE,
                                       kubernetes_runner())
    assert set(observed) == set(gate.KUBERNETES_SERVICES)


def test_kubernetes_pod_must_be_owned_by_expected_deployment() -> None:
    with pytest.raises(gate.SupportedEvidenceError, match="ReplicaSet owner"):
        gate.observe_kubernetes(
            NAMESPACE, CONTEXT, REFERENCE, kubernetes_runner(bad_owner=True))


def test_kubernetes_runtime_rejects_stale_configuration_or_rollout() -> None:
    with pytest.raises(gate.SupportedEvidenceError, match="ConfigMap must be immutable"):
        gate.observe_kubernetes(NAMESPACE, CONTEXT, REFERENCE,
                                kubernetes_runner(mutable_config=True))
    with pytest.raises(gate.SupportedEvidenceError, match="predates the immutable ConfigMap"):
        gate.observe_kubernetes(NAMESPACE, CONTEXT, REFERENCE,
                                kubernetes_runner(stale_pod=True))
    with pytest.raises(gate.SupportedEvidenceError, match="rollout is incomplete"):
        gate.observe_kubernetes(NAMESPACE, CONTEXT, REFERENCE,
                                kubernetes_runner(incomplete_rollout=True))
    with pytest.raises(gate.SupportedEvidenceError, match="running process routing"):
        gate.observe_kubernetes(NAMESPACE, CONTEXT, REFERENCE,
                                kubernetes_runner(stale_process_env=True))
    with pytest.raises(gate.SupportedEvidenceError, match="running process routing"):
        gate.observe_kubernetes(NAMESPACE, CONTEXT, REFERENCE,
                                kubernetes_runner(stale_native_url=True))


def test_kubernetes_mixed_provider_is_rejected() -> None:
    with pytest.raises(gate.SupportedEvidenceError, match="physical provider ingress"):
        gate.observe_kubernetes(NAMESPACE, CONTEXT, REFERENCE,
                                kubernetes_runner(mixed_provider=True))
    with pytest.raises(gate.SupportedEvidenceError, match="bound to the Marty simulator"):
        gate.observe_kubernetes(NAMESPACE, CONTEXT, REFERENCE,
                                kubernetes_runner(wrong_profile=True))
    with pytest.raises(gate.SupportedEvidenceError, match="bound to the Marty simulator"):
        gate.observe_kubernetes(NAMESPACE, CONTEXT, REFERENCE,
                                kubernetes_runner(provider_enabled=True))
    with pytest.raises(gate.SupportedEvidenceError, match="ConfigMap source is ambiguous"):
        gate.observe_kubernetes(NAMESPACE, CONTEXT, REFERENCE,
                                kubernetes_runner(second_configmap=True))


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
