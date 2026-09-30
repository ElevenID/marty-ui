"""Supported passport evidence remains blocked without disposable live acceptance."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import ssl
from threading import Thread

import pytest
import yaml

from scripts import collect_passport_supported_acceptance as gate
from scripts.passport_supported_infra_images import qualified_images
from scripts.stage_passport_disposable_tls import stage_tls

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


def docker_runner(project: str, *, wrong_image: bool = False,
                  signer_selector: bool = True, signer_process: bool = True):
    def run(args: list[str]) -> str:
        if args[:2] == ["docker", "ps"]:
            service = args[-1].split("=")[-1]
            return service + "-container\n"
        if args[:2] == ["docker", "exec"]:
            return "verified" if signer_process else "unverified"
        service = args[-1].removesuffix("-container")
        flags = [f"{name}=true" for name in gate.COMPOSE_FLAGS.get(service, ())]
        if service == "signing-keys" and signer_selector:
            flags.append("SERVICE_NAME=signing_keys")
        image = (qualified_images(verify_registry=False)["edge"]
                 if service == "edge" else REFERENCE)
        edge_binding = [{"HostIp": "127.0.0.1", "HostPort": "28000"}]
        record = {
            "Image": "sha256:" + "e" * 64,
            "Config": {
                "Image": ("ghcr.io/other/unreleased@" + DIGEST)
                if wrong_image else image,
                "Labels": {"com.docker.compose.project": project,
                           "com.docker.compose.service": service},
                "Env": flags,
            },
            "State": {"Running": True, "Status": "running",
                      "Health": {"Status": "healthy"}},
            "NetworkSettings": {"Ports": {"8443/tcp": edge_binding}}
            if service == "edge" else {"Ports": {}},
            "HostConfig": {"PortBindings": {"8443/tcp": edge_binding}}
            if service == "edge" else {"PortBindings": {}},
        }
        return json.dumps([record])
    return run


def test_compose_runtime_reads_six_exact_running_service_images() -> None:
    observed = gate.observe_compose("base", BASE, REFERENCE, docker_runner(BASE))
    assert len(gate.COMPOSE_SERVICES) == 6
    assert set(observed) == set(gate.COMPOSE_SERVICES) | {"edge"}
    assert all(item["oci_reference"] == REFERENCE
               for service, item in observed.items() if service != "edge")
    assert observed["edge"]["oci_reference"] == qualified_images(
        verify_registry=False)["edge"]
    with pytest.raises(gate.SupportedEvidenceError, match="released services image"):
        gate.observe_compose("base", BASE, REFERENCE, docker_runner(BASE, wrong_image=True))
    with pytest.raises(gate.SupportedEvidenceError, match="Signing Keys selector"):
        gate.observe_compose("base", BASE, REFERENCE,
                             docker_runner(BASE, signer_selector=False))
    with pytest.raises(gate.SupportedEvidenceError, match="Signing Keys process"):
        gate.observe_compose("base", BASE, REFERENCE,
                             docker_runner(BASE, signer_process=False))


def test_disposable_https_capability_probe_uses_scoped_ca(tmp_path: Path) -> None:
    stage_tls(tmp_path)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            assert self.path == "/v1/passport/capabilities"
            body = b'{"supported":true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args) -> None:
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(tmp_path / "passport_edge_tls_cert"),
                            str(tmp_path / "passport_edge_tls_key"))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        origin = f"https://localhost:{server.server_port}"
        with pytest.raises(gate.SupportedEvidenceError, match="no CA"):
            gate.capability_status(origin, None)
        assert gate.capability_status(
            origin, None, tmp_path / "workload_identity_ca_cert"
        ) == (200, {"supported": True})
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_missing_targets_and_runtime_proof_remain_blocked(tmp_path: Path) -> None:
    report = gate.collect(manifest(tmp_path), COMMIT, attest=lambda *args: True)
    assert report["status"] == "blocked"
    assert set(report["surfaces"]) == {"base", "selfhost", "kubernetes"}
    assert all(surface["runtime_accepted"] is False
               and surface["probes"]["rust_restart_resume"]["verified"] is False
               and "rollback_accepted" not in surface
               for surface in report["surfaces"].values())


def test_live_compose_prerequisite_still_does_not_claim_routes_or_restart(
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
    assert base["probes"]["rust_restart_resume"]["verified"] is False
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
                       template_host_aliases: bool = False,
                       pod_host_aliases: bool = False,
                       template_custom_dns: bool = False,
                       pod_custom_dns: bool = False,
                       template_proxy_env: bool = False,
                       pod_proxy_env: bool = False,
                       template_resolver_env: bool = False,
                       pod_resolver_env: bool = False,
                       template_lifecycle_exec: bool = False,
                       pod_lifecycle_exec: bool = False,
                       template_probe_exec: bool = False,
                       pod_probe_exec: bool = False,
                       proxy_config: bool = False,
                       resolver_config: bool = False,
                       template_host_port: bool = False,
                       pod_host_port: bool = False,
                       foreign_core_address: bool = False,
                       manual_core_slice: bool = False,
                       wrong_binary: bool = False,
                       wrong_pod_command: bool = False,
                       wrong_template_command: bool = False,
                       inspection_utility_mount: bool = False,
                       second_configmap: bool = False,
                       mutable_config: bool = False,
                       stale_pod: bool = False,
                       incomplete_rollout: bool = False,
                       stale_process_env: bool = False,
                       stale_native_url: bool = False):
    def container_for(service: str, *, is_pod: bool = False) -> dict:
        values = {flag: "true" for flag in gate.KUBERNETES_FLAGS[service]}
        if service == "gateway":
            values.update({"PASSPORT_PROVIDER_INGRESS_GATEWAY_ENABLED":
                           "true" if provider_enabled else "false",
                           "PASSPORT_PROVIDER_INGRESS_SERVICE_URL": ""})
        if service in ("gateway", "flow"):
            container_sources = [{"configMapRef": {"name": "marty-config"}}]
            if service == "gateway" and second_configmap:
                container_sources.append({"configMapRef": {"name": "override-config"}})
        else:
            container_sources = []
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
        container = {"name": service, "image": REFERENCE,
                     "securityContext": {
                         "readOnlyRootFilesystem": True,
                         "allowPrivilegeEscalation": False,
                         "capabilities": {"drop": ["ALL"]}},
                     "env": [{"name": name, "value": value}
                             for name, value in values.items()],
                     "envFrom": container_sources}
        if (pod_proxy_env if is_pod else template_proxy_env) and service == "flow":
            container["env"].append({"name": "HTTP_PROXY", "value": "http://evil"})
        if (pod_resolver_env if is_pod else template_resolver_env) and service == "flow":
            container["env"].append({"name": "HOSTALIASES",
                                     "value": "/run/secrets/aliases"})
        if (pod_lifecycle_exec if is_pod else template_lifecycle_exec) and service == "flow":
            container["lifecycle"] = {"postStart": {"exec": {"command": ["/bin/sh"]}}}
        if (pod_probe_exec if is_pod else template_probe_exec) and service == "flow":
            container["readinessProbe"] = {"exec": {"command": ["/bin/sh"]}}
        if (wrong_pod_command and is_pod and service == "issuance-native"
                or wrong_template_command and not is_pod and service == "issuance-native"):
            container["command"] = ["/bin/sh"]
        if inspection_utility_mount and is_pod and service == "issuance-native":
            container["volumeMounts"] = [{"name": "proof-override",
                                          "mountPath": "/bin/sh",
                                          "readOnly": True}]
        if service == "issuance-native":
            for name in ("PERSONALIZATION_BUREAU_URL",
                         "PERSONALIZATION_BUREAU_PROVIDER_PROFILE_ID"):
                container["env"] = [entry for entry in container["env"]
                                    if entry["name"] != name]
                container["env"].append({"name": name,
                                          "valueFrom": {"configMapKeyRef": {
                                              "name": "marty-config", "key": name}}})
            if indirect_profile:
                container["env"][-1]["valueFrom"]["configMapKeyRef"]["name"] = "override-config"
        if service in ("signing-keys", "passport-beta-bureau", "passport-callback-signer") or (
                service == "flow" and (pod_host_port if is_pod else template_host_port)):
            port = ({"signing-keys": 8017, "passport-beta-bureau": 8020,
                     "passport-callback-signer": 8018}.get(service, 8011))
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
        name = (service + "-rs" if kind == "ReplicaSet" else
                service + "-pod" if kind == "Pod" else service)
        uid = service + "-" + kind.lower() + "-uid"
        metadata = {"name": name, "namespace": NAMESPACE,
                    "uid": uid, "labels": labels}
        if kind == "Deployment":
            metadata["generation"] = 2
        if kind == "Pod":
            metadata["creationTimestamp"] = (
                "2026-09-28T11:59:00Z" if stale_pod else "2026-09-28T12:01:00Z")
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
        if args[5] == "exec":
            assert args[6].endswith("-pod")
            assert args[7:9] == ["-c", args[6].removesuffix("-pod")]
            if gate.KUBERNETES_FLAGS[args[8]]:
                assert "/proc/1/environ" in args[-1]
            assert "/proc/1/exe" in args[-1]
            assert "/proc/1/cmdline" in args[-1]
            assert gate.KUBERNETES_BINARIES[args[8]] in args[-1]
            if wrong_binary and args[8] == "issuance-native":
                return "stale"
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
            if proxy_config:
                data["HTTPS_PROXY"] = "http://evil"
            if resolver_config:
                data["RES_OPTIONS"] = "ndots:0"
            return json.dumps({"data": data, "immutable": not mutable_config,
                               "metadata": {"creationTimestamp":
                                            "2026-09-28T12:00:00.123Z"}})
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
                entry = next(entry for entry in pod_container["env"] if entry["name"] ==
                             "PERSONALIZATION_BUREAU_PROVIDER_PROFILE_ID")
                del entry["valueFrom"]
                entry["value"] = "external-provider"
            return json.dumps({"items": [{
                "metadata": metadata_for(service, "Pod"),
                "spec": {"hostNetwork": pod_host_network,
                         **({"hostAliases": [{"ip": "10.0.0.9", "hostnames":
                                             ["issuance-native"]}]}
                            if pod_host_aliases and service == "flow" else {}),
                         **({"dnsPolicy": "None"}
                            if pod_custom_dns and service == "flow" else {}),
                         "automountServiceAccountToken": False,
                         "securityContext": {"runAsNonRoot": True,
                                             "runAsUser": 10001,
                                             "runAsGroup": 10001},
                         "volumes": ([{"name": "proof-override", "secret": {
                             "secretName": "passport-acceptance-proof-override"}}]
                                     if inspection_utility_mount and service ==
                                     "issuance-native" else []),
                         "containers": [pod_container]},
                "status": {"phase": "Running", "podIP": "10.1.2.3",
                           "podIPs": ([{"ip": "10.1.2.3"}, {"ip": "fd00::3"}]
                                      if dual_stack else [{"ip": "10.1.2.3"}]),
                           "containerStatuses": [{
                    "name": service, "ready": True,
                    "imageID": "docker-pullable://" + REFERENCE,
                    "containerID": "containerd://" + service + "-container",
                }]},
            }]})
        if args[6] == "service":
            service = args[7]
            ports = gate.KUBERNETES_SERVICE_PORTS[service]
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
                         "ports": [{"name": name, "port": port,
                                    "protocol": "TCP", "targetPort": port}
                                   for name, port in ports]},
            })
        if args[6] == "endpointslices":
            service = args[8].removeprefix("kubernetes.io/service-name=")
            ports = gate.KUBERNETES_SERVICE_PORTS[service]
            items = []
            for family, address in ([('IPv4', '10.1.2.3'), ('IPv6', 'fd00::3')]
                                    if dual_stack else [('IPv4', '10.1.2.3')]):
                metadata = metadata_for(service, "EndpointSlice")
                metadata["uid"] += "-" + family.lower()
                metadata["labels"]["endpointslice.kubernetes.io/managed-by"] = (
                    "manual" if manual_core_slice and service == "issuance-native" else
                    "endpointslice-controller.k8s.io")
                items.append({
                    "metadata": metadata, "addressType": family,
                    "ports": [{"name": name, "port": port, "protocol": "TCP"}
                              for name, port in ports],
                    "endpoints": [{"addresses": [
                        "10.9.9.9" if ((foreign_address and service ==
                        "passport-beta-bureau") or (foreign_core_address and service ==
                        "issuance-native")) else address],
                        "conditions": {"ready": True},
                        "targetRef": {"kind": "Pod", "namespace": NAMESPACE,
                                      "uid": ("foreign" if wrong_endpoint
                                              and service == "passport-beta-bureau"
                                              else service + "-pod-uid")}}],
                })
            return json.dumps({"items": items})
        service = args[7]
        container = container_for(service)
        return json.dumps({
            "metadata": metadata_for(service, "Deployment"),
            "status": {"observedGeneration": 2,
                       "replicas": 1, "updatedReplicas": 1,
                       "readyReplicas": 0 if incomplete_rollout else 1,
                       "availableReplicas": 1},
            "spec": {"selector": {"matchLabels": {
                "app": service,
                "com.marty.passport.acceptance.owner": "supported-consumer",
                "com.marty.passport.acceptance.run-id": RUN_ID}},
                     "replicas": 1,
                     "template": {"metadata": {"labels": metadata_for(
                         service, "Deployment")["labels"]},
                                  "spec": {"hostNetwork": template_host_network,
                                           **({"hostAliases": [{"ip": "10.0.0.9",
                                                                "hostnames": [
                                                                    "issuance-native"]}]}
                                              if template_host_aliases and service == "flow"
                                              else {}),
                                           **({"dnsPolicy": "None"}
                                              if template_custom_dns and service == "flow"
                                              else {}),
                                           "automountServiceAccountToken": False,
                                           "securityContext": {"runAsNonRoot": True,
                                                               "runAsUser": 10001,
                                                               "runAsGroup": 10001},
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
    ("foreign_core_address", "Service routes to another address"),
    ("manual_core_slice", "EndpointSlice is outside"),
    ("external_ip", "Service route is outside"),
    ("wrong_source", "owner labels are invalid"),
    ("template_host_network", "Deployment runtime is unsafe"),
    ("pod_host_network", "Pod runtime is unsafe"),
    ("template_host_aliases", "Deployment runtime is unsafe"),
    ("pod_host_aliases", "Pod runtime is unsafe"),
    ("template_custom_dns", "Deployment runtime is unsafe"),
    ("pod_custom_dns", "Pod runtime is unsafe"),
    ("template_proxy_env", "flow entrypoint is overridden"),
    ("pod_proxy_env", "flow entrypoint is overridden"),
    ("template_resolver_env", "flow entrypoint is overridden"),
    ("pod_resolver_env", "flow entrypoint is overridden"),
    ("template_lifecycle_exec", "flow entrypoint is overridden"),
    ("pod_lifecycle_exec", "flow entrypoint is overridden"),
    ("template_probe_exec", "flow entrypoint is overridden"),
    ("pod_probe_exec", "flow entrypoint is overridden"),
    ("template_host_port", "Deployment runtime is unsafe"),
    ("pod_host_port", "Pod runtime is unsafe"),
])
def test_kubernetes_rejects_foreign_pod_or_routing(
    defect: str, pattern: str,
) -> None:
    with pytest.raises(gate.SupportedEvidenceError, match=pattern):
        gate.observe_kubernetes(NAMESPACE, CONTEXT, REFERENCE, COMMIT,
                                kubernetes_runner(**{defect: True}))


def test_kubernetes_rejects_proxy_configmap() -> None:
    for defect in ("proxy_config", "resolver_config"):
        with pytest.raises(gate.SupportedEvidenceError, match="overrides runtime tools"):
            gate.observe_kubernetes(NAMESPACE, CONTEXT, REFERENCE, COMMIT,
                                    kubernetes_runner(**{defect: True}))


def test_kubernetes_pod_must_be_owned_by_expected_deployment() -> None:
    with pytest.raises(gate.SupportedEvidenceError, match="Pod ReplicaSet is missing"):
        gate.observe_kubernetes(
            NAMESPACE, CONTEXT, REFERENCE, COMMIT,
            kubernetes_runner(wrong_owner=True))


def test_kubernetes_runtime_rejects_stale_configuration_or_rollout() -> None:
    with pytest.raises(gate.SupportedEvidenceError, match="ConfigMap must be immutable"):
        gate.observe_kubernetes(NAMESPACE, CONTEXT, REFERENCE,
                                COMMIT, kubernetes_runner(mutable_config=True))
    with pytest.raises(gate.SupportedEvidenceError, match="predates the immutable ConfigMap"):
        gate.observe_kubernetes(NAMESPACE, CONTEXT, REFERENCE,
                                COMMIT, kubernetes_runner(stale_pod=True))
    with pytest.raises(gate.SupportedEvidenceError, match="rollout is incomplete"):
        gate.observe_kubernetes(NAMESPACE, CONTEXT, REFERENCE,
                                COMMIT, kubernetes_runner(incomplete_rollout=True))
    with pytest.raises(gate.SupportedEvidenceError, match="running process routing"):
        gate.observe_kubernetes(NAMESPACE, CONTEXT, REFERENCE,
                                COMMIT, kubernetes_runner(stale_process_env=True))
    with pytest.raises(gate.SupportedEvidenceError, match="running process routing"):
        gate.observe_kubernetes(NAMESPACE, CONTEXT, REFERENCE,
                                COMMIT, kubernetes_runner(stale_native_url=True))
    with pytest.raises(gate.SupportedEvidenceError, match="running process routing"):
        gate.observe_kubernetes(NAMESPACE, CONTEXT, REFERENCE,
                                COMMIT, kubernetes_runner(wrong_binary=True))
    for defect in ("wrong_pod_command", "wrong_template_command",
                   "inspection_utility_mount"):
        with pytest.raises(gate.SupportedEvidenceError, match="entrypoint is overridden"):
            gate.observe_kubernetes(NAMESPACE, CONTEXT, REFERENCE,
                                    COMMIT, kubernetes_runner(**{defect: True}))


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
    with pytest.raises(gate.SupportedEvidenceError, match="configuration source is invalid"):
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
        base_origin="https://localhost:28001", api_key="private",
        compose_probe=lambda *args: {"gateway": {
            "oci_reference": REFERENCE,
            "container_id": "gateway-container",
        }, "edge": {"loopback_port": 28000}},
        capability_probe=lambda *args: called.append(args),
        attest=lambda *args: True,
    )
    assert called == []
    assert "capabilities_http" not in report["surfaces"]["base"]
    assert report["surfaces"]["base"]["blocker"] == (
        "probe origin is not bound to the inspected HTTPS edge"
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
    assert "docker compose up" not in source
    assert "kubectl set env" not in source
