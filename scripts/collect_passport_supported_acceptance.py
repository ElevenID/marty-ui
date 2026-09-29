#!/usr/bin/env python3
"""Inspect disposable supported passport Rust runtimes.

This collector records running service, image, and selector observations.
Signed simulator callback and nine-route acceptance require a later protected harness.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import subprocess
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

if __package__:
    from .collect_passport_beta_acceptance import digest_file, verify_attestations
else:
    from collect_passport_beta_acceptance import digest_file, verify_attestations


SHA = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
RUN_ID = re.compile(r"[1-9][0-9]{0,19}\Z")
ROOT = Path(__file__).resolve().parents[1]
PROJECT = re.compile(r"marty-passport-acceptance-(base|selfhost)-[a-z0-9]{6,32}\Z")
NAMESPACE = re.compile(r"marty-passport-acceptance-[a-z0-9]{6,32}\Z")
KUBE_CONTEXT = re.compile(r"marty-passport-acceptance-[a-z0-9]{6,32}\Z")
COMPOSE_SERVICES = (
    "gateway", "flow", "issuance-native", "passport-callback-signer",
    "passport-beta-bureau",
)
KUBERNETES_SERVICES = COMPOSE_SERVICES
PRIVATE_KUBERNETES_PORTS = {"passport-beta-bureau": 8020,
                            "passport-callback-signer": 8018}
COMMON_FLAGS = {
    "gateway": ("PASSPORT_NATIVE_GATEWAY_ENABLED", "PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED"),
    "flow": ("PASSPORT_NATIVE_FLOW_ENABLED", "PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED"),
    "issuance-native": (
        "PASSPORT_NATIVE_HTTP_ENABLED", "PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED",
        "PASSPORT_MANAGED_ISSUER_SIGNING_ENABLED", "PASSPORT_KMS_ARTIFACTS_ENABLED",
        "PASSPORT_KMS_CALLBACKS_ENABLED",
    ),
}
COMPOSE_FLAGS = COMMON_FLAGS | {
    "passport-callback-signer": ("PASSPORT_CALLBACK_SIGNER_ENABLED",),
    "passport-beta-bureau": ("PASSPORT_BETA_BUREAU_ENABLED",),
}
KUBERNETES_FLAGS = COMPOSE_FLAGS
PROBES = (
    "nine_route_gateway_flow", "managed_signer", "signed_bureau_callback",
    "released_image", "rust_restart_resume",
)


class SupportedEvidenceError(ValueError):
    pass


def require(ok: bool, message: str) -> None:
    if not ok:
        raise SupportedEvidenceError(message)


def command(args: list[str]) -> str:
    try:
        result = subprocess.run(args, capture_output=True, text=True, encoding="utf-8",
                                check=True, timeout=25)
    except (OSError, subprocess.SubprocessError) as exc:
        # Docker and Kubernetes output may contain secret-bearing environments.
        raise SupportedEvidenceError("Supported runtime inspection failed") from exc
    require(len(result.stdout) <= 1024 * 1024, "Supported runtime inspection is oversized")
    return result.stdout


def json_command(args: list[str], runner: Callable[[list[str]], str]) -> dict[str, Any]:
    try:
        value = json.loads(runner(args))
    except ValueError as exc:
        raise SupportedEvidenceError("Supported runtime response is invalid") from exc
    require(isinstance(value, dict), "Supported runtime response is not an object")
    return value


def disposable_project(value: str, surface: str) -> str:
    match = PROJECT.fullmatch(value)
    require(match is not None and match.group(1) == surface,
            "Only a disposable passport acceptance Compose project is allowed")
    return value


def disposable_namespace(value: str) -> str:
    require(NAMESPACE.fullmatch(value) is not None,
            "Only a disposable passport acceptance Kubernetes namespace is allowed")
    return value


def disposable_context(value: str) -> str:
    require(KUBE_CONTEXT.fullmatch(value) is not None,
            "Only a disposable passport acceptance Kubernetes context is allowed")
    return value


def environment_flags(values: object, service: str,
                      flags: dict[str, tuple[str, ...]]) -> dict[str, bool]:
    require(isinstance(values, list), f"Missing {service} runtime environment")
    result: dict[str, bool] = {}
    for name in flags[service]:
        matches = [entry.partition("=")[2] for entry in values
                   if isinstance(entry, str) and entry.partition("=")[0] == name]
        require(len(matches) == 1 and matches[0] in ("true", "false"),
                f"Missing or ambiguous {service} passport selector")
        result[name] = matches[0] == "true"
    return result


def kubernetes_literal_value(container: dict, name: str) -> object:
    """Read a Pod-bound value, never a mutable ConfigMap snapshot."""
    entries = container.get("env", [])
    require(isinstance(entries, list), "Kubernetes passport environment is invalid")
    matches = [entry for entry in entries
               if isinstance(entry, dict) and entry.get("name") == name]
    require(len(matches) == 1 and "value" in matches[0]
            and "valueFrom" not in matches[0]
            and isinstance(matches[0]["value"], str),
            f"Kubernetes passport {name} requires one literal Pod environment value")
    return matches[0]["value"]


def kubernetes_owner(item: dict, kind: str, name: str, uid: str) -> bool:
    metadata = item.get("metadata")
    references = metadata.get("ownerReferences") if isinstance(metadata, dict) else None
    return (isinstance(references, list)
            and len([ref for ref in references if isinstance(ref, dict)
                     and ref.get("controller") is True]) == 1
            and any(isinstance(ref, dict) and ref.get("kind") == kind
                    and ref.get("name") == name and ref.get("uid") == uid
                    and ref.get("controller") is True for ref in references))


def kubernetes_labels(item: dict, namespace: str, service: str,
                      run_id: str, source_commit: str) -> str:
    metadata = item.get("metadata")
    require(isinstance(metadata, dict) and metadata.get("namespace") == namespace,
            f"Kubernetes {service} namespace or metadata is invalid")
    labels = metadata.get("labels")
    require(isinstance(labels, dict) and labels.get("app") == service
            and labels.get("com.marty.passport.acceptance.owner") == "supported-consumer"
            and labels.get("com.marty.passport.acceptance.run-id") == run_id
            and labels.get("com.marty.passport.acceptance.source-commit") == source_commit,
            f"Kubernetes {service} owner labels are invalid")
    uid = metadata.get("uid")
    require(isinstance(uid, str) and bool(uid),
            f"Kubernetes {service} UID is missing")
    return uid


def kubernetes_pod_ips(pod: dict, service: str) -> set:
    status = pod.get("status")
    require(isinstance(status, dict) and isinstance(status.get("podIP"), str),
            f"Kubernetes {service} Pod has no IP address")
    values = status.get("podIPs")
    require(values is None or (isinstance(values, list) and bool(values)
            and all(isinstance(item, dict) and isinstance(item.get("ip"), str)
                    for item in values)),
            f"Kubernetes {service} Pod IP set is invalid")
    try:
        primary = ipaddress.ip_address(status["podIP"])
        addresses = ({ipaddress.ip_address(item["ip"]) for item in values}
                     if values is not None else {primary})
    except ValueError as error:
        raise SupportedEvidenceError(
            f"Kubernetes {service} Pod IP set is invalid") from error
    require(primary in addresses, f"Kubernetes {service} Pod IP set is inconsistent")
    return addresses


def kubernetes_private_network(spec: object, service: str, port: int) -> None:
    require(isinstance(spec, dict) and spec.get("hostNetwork") in (None, False),
            f"Kubernetes {service} private Pod uses the host network")
    containers = spec.get("containers")
    require(isinstance(containers, list) and len(containers) == 1
            and isinstance(containers[0], dict),
            f"Kubernetes {service} private container is invalid")
    ports = containers[0].get("ports")
    require(isinstance(ports, list) and len(ports) == 1
            and isinstance(ports[0], dict)
            and ports[0].get("containerPort") == port
            and ports[0].get("hostPort") in (None, 0),
            f"Kubernetes {service} private port is exposed on the host")


def observe_compose(
    surface: str, project: str, services_reference: str,
    runner: Callable[[list[str]], str] = command,
) -> dict[str, Any]:
    disposable_project(project, surface)
    observed: dict[str, Any] = {}
    for service in COMPOSE_SERVICES:
        ids = runner(["docker", "ps", "-aq", "--filter",
                      f"label=com.docker.compose.project={project}", "--filter",
                      f"label=com.docker.compose.service={service}"]).split()
        require(len(ids) == 1, f"{surface} {service} container is missing or ambiguous")
        payload = json.loads(runner(["docker", "inspect", ids[0]]))
        require(isinstance(payload, list) and len(payload) == 1
                and isinstance(payload[0], dict),
                f"{surface} {service} container inspection is ambiguous")
        record = payload[0]
        config, state = record.get("Config"), record.get("State")
        require(isinstance(config, dict) and isinstance(state, dict),
                f"{surface} {service} has no runtime state")
        labels = config.get("Labels")
        require(isinstance(labels, dict)
                and labels.get("com.docker.compose.project") == project
                and labels.get("com.docker.compose.service") == service,
                f"{surface} {service} is outside the disposable project")
        require(state.get("Running") is True and state.get("Status") == "running"
                and (not isinstance(state.get("Health"), dict)
                     or state["Health"].get("Status") == "healthy"),
                f"{surface} {service} is not ready")
        require(config.get("Image") == services_reference
                and isinstance(record.get("Image"), str)
                and DIGEST.fullmatch(record["Image"]) is not None,
                f"{surface} {service} is not running the released services image")
        flags = environment_flags(config.get("Env"), service, COMPOSE_FLAGS)
        require(all(flags.values()), f"{surface} {service} did not select Rust passport")
        observed[service] = {"container_id": ids[0], "image_id": record["Image"],
                             "oci_reference": services_reference, "selectors": flags}
        if service == "gateway":
            ports = record.get("NetworkSettings", {}).get("Ports", {}).get("8000/tcp")
            require(isinstance(ports, list) and len(ports) == 1
                    and isinstance(ports[0], dict)
                    and ports[0].get("HostIp") == "127.0.0.1"
                    and str(ports[0].get("HostPort", "")).isdigit(),
                    f"{surface} gateway has no unique loopback port")
            observed[service]["loopback_port"] = int(ports[0]["HostPort"])
    return observed


def observe_kubernetes(
    namespace: str, context: str, services_reference: str, source_commit: str,
    runner: Callable[[list[str]], str] = command,
) -> dict[str, Any]:
    disposable_namespace(namespace)
    disposable_context(context)
    require(SHA.fullmatch(source_commit) is not None,
            "Kubernetes release source commit is invalid")
    for kind in ("deployment", "service"):
        provider = runner(["kubectl", "--context", context, "-n", namespace,
                           "get", kind, "passport-provider-ingress",
                           "--ignore-not-found", "-o", "json"])
        require(not provider.strip(),
                "Kubernetes physical provider ingress remains in simulator namespace")
    provider_pods = json_command(["kubectl", "--context", context, "-n", namespace,
                                  "get", "pods", "-l", "app=passport-provider-ingress",
                                  "-o", "json"], runner)
    require(provider_pods.get("items") == [],
            "Kubernetes physical provider Pod remains in simulator namespace")
    observed: dict[str, Any] = {}
    pod_ips: dict[str, set] = {}
    run_id: str | None = None
    for service in KUBERNETES_SERVICES:
        deployment = json_command(["kubectl", "--context", context, "-n", namespace,
                                   "get", "deployment",
                                   service, "-o", "json"], runner)
        metadata = deployment.get("metadata")
        status = deployment.get("status")
        spec = deployment.get("spec")
        require(isinstance(metadata, dict)
                and isinstance(status, dict) and status.get("readyReplicas", 0) >= 1
                and isinstance(spec, dict),
                f"Kubernetes {service} is not ready in the disposable namespace")
        labels = metadata.get("labels")
        candidate_run_id = (labels.get("com.marty.passport.acceptance.run-id")
                            if isinstance(labels, dict) else None)
        require(isinstance(candidate_run_id, str)
                and RUN_ID.fullmatch(candidate_run_id) is not None,
                f"Kubernetes {service} acceptance run ID is invalid")
        if run_id is None:
            run_id = candidate_run_id
        require(candidate_run_id == run_id,
                f"Kubernetes {service} belongs to another acceptance run")
        deployment_uid = kubernetes_labels(
            deployment, namespace, service, run_id, source_commit)
        selector = {"app": service,
                    "com.marty.passport.acceptance.owner": "supported-consumer",
                    "com.marty.passport.acceptance.run-id": run_id}
        template = spec.get("template")
        template_labels = (template.get("metadata", {}).get("labels")
                           if isinstance(template, dict)
                           and isinstance(template.get("metadata"), dict) else None)
        require(isinstance(template, dict)
                and spec.get("selector", {}).get("matchLabels") == selector
                and isinstance(template_labels, dict)
                and all(template_labels.get(name) == value
                        for name, value in {**selector,
                            "com.marty.passport.acceptance.source-commit": source_commit}.items()),
                f"Kubernetes {service} Deployment selector or template is unowned")
        containers = spec.get("template", {}).get("spec", {}).get("containers")
        if service in PRIVATE_KUBERNETES_PORTS:
            kubernetes_private_network(
                template.get("spec"), service, PRIVATE_KUBERNETES_PORTS[service])
        require(isinstance(containers, list) and len(containers) == 1
                and containers[0].get("image") == services_reference,
                f"Kubernetes {service} is not pinned to the released services image")
        selected = {}
        for flag in KUBERNETES_FLAGS[service]:
            require(kubernetes_literal_value(containers[0], flag) == "true",
                    f"Kubernetes {service} did not select Rust passport")
            selected[flag] = True
        expected = ({
            "PASSPORT_PROVIDER_INGRESS_GATEWAY_ENABLED": "false",
            "PASSPORT_PROVIDER_INGRESS_SERVICE_URL": "",
        } if service == "gateway" else {
            "PERSONALIZATION_BUREAU_URL": "http://passport-beta-bureau:8020",
            "PERSONALIZATION_BUREAU_PROVIDER_PROFILE_ID": "passport-beta-bureau",
        } if service == "issuance-native" else {
            "SIGNING_KEYS_INTERNAL_URL":
                "http://passport-callback-signer:8018/internal/documents",
            "PASSPORT_BUREAU_CALLBACK_URL":
                "http://issuance-native:8005/v1/passport/webhooks/personalization",
        } if service == "passport-beta-bureau" else {})
        require(all(kubernetes_literal_value(containers[0], name) == value
                    for name, value in expected.items()),
                f"Kubernetes {service} is not bound to the Marty simulator")
        replicasets = json_command(["kubectl", "--context", context, "-n", namespace,
                                    "get", "replicasets", "-l", f"app={service}",
                                    "-o", "json"], runner)
        replica_items = replicasets.get("items")
        require(isinstance(replica_items, list)
                and all(isinstance(item, dict) for item in replica_items),
                f"Kubernetes {service} ReplicaSet list is invalid")
        pods = json_command(["kubectl", "--context", context, "-n", namespace,
                             "get", "pods", "-l",
                             f"app={service}", "-o", "json"], runner)
        pod_items = pods.get("items")
        require(isinstance(pod_items, list) and len(pod_items) == 1
                and isinstance(pod_items[0], dict),
                f"Kubernetes {service} pod is missing or ambiguous")
        pod = pod_items[0]
        pod_uid = kubernetes_labels(pod, namespace, service, run_id, source_commit)
        matching_replicas = [item for item in replica_items
                             if isinstance(item.get("metadata"), dict)
                             and isinstance(item["metadata"].get("uid"), str)
                             and isinstance(item["metadata"].get("name"), str)
                             and kubernetes_owner(pod, "ReplicaSet",
                                                  item["metadata"]["name"],
                                                  item["metadata"]["uid"])]
        require(len(matching_replicas) == 1,
                f"Kubernetes {service} Pod ReplicaSet is missing or ambiguous")
        replica = matching_replicas[0]
        replica_uid = kubernetes_labels(
            replica, namespace, service, run_id, source_commit)
        replica_name = replica["metadata"]["name"]
        replica_selector = replica.get("spec", {}).get("selector", {}).get("matchLabels")
        require(kubernetes_owner(replica, "Deployment", service, deployment_uid)
                and isinstance(replica_selector, dict)
                and all(replica_selector.get(name) == value
                        for name, value in selector.items()),
                f"Kubernetes {service} ReplicaSet is not owned by the Deployment")
        require(kubernetes_owner(pod, "ReplicaSet", replica_name, replica_uid)
                and all(pod["metadata"]["labels"].get(name) == value
                        for name, value in replica_selector.items()),
                f"Kubernetes {service} Pod is not owned by the ReplicaSet")
        statuses = pod.get("status", {}).get("containerStatuses")
        require(pod.get("status", {}).get("phase") == "Running"
                and isinstance(statuses, list) and len(statuses) == 1
                and statuses[0].get("ready") is True
                and isinstance(statuses[0].get("containerID"), str)
                and bool(statuses[0]["containerID"])
                and isinstance(statuses[0].get("imageID"), str)
                and statuses[0]["imageID"].endswith(services_reference.split("@", 1)[1]),
                f"Kubernetes {service} pod is not ready on the released image")
        pod_containers = pod.get("spec", {}).get("containers")
        if service in PRIVATE_KUBERNETES_PORTS:
            kubernetes_private_network(
                pod.get("spec"), service, PRIVATE_KUBERNETES_PORTS[service])
        require(isinstance(pod_containers, list) and len(pod_containers) == 1
                and pod_containers[0].get("image") == services_reference,
                f"Kubernetes {service} Pod spec is not pinned to the released image")
        require(all(kubernetes_literal_value(pod_containers[0], flag) == "true"
                    for flag in KUBERNETES_FLAGS[service]),
                f"Kubernetes {service} Pod did not select Rust passport")
        require(all(kubernetes_literal_value(pod_containers[0], name) == value
                    for name, value in expected.items()),
                f"Kubernetes {service} Pod is not bound to the Marty simulator")
        pod_ips[service] = kubernetes_pod_ips(pod, service)
        observed[service] = {"deployment_uid": deployment_uid,
                             "replicaset_uid": replica_uid, "pod_uid": pod_uid,
                             "container_id": statuses[0]["containerID"],
                             "image_id": statuses[0]["imageID"],
                             "oci_reference": services_reference, "selectors": selected}
    require(run_id is not None, "Kubernetes acceptance run is missing")
    for service, port in (("passport-beta-bureau", 8020),
                          ("passport-callback-signer", 8018)):
        route = json_command(["kubectl", "--context", context, "-n", namespace,
                              "get", "service", service, "-o", "json"], runner)
        route_uid = kubernetes_labels(route, namespace, service, run_id, source_commit)
        route_spec = route.get("spec")
        selector = {"app": service,
                    "com.marty.passport.acceptance.owner": "supported-consumer",
                    "com.marty.passport.acceptance.run-id": run_id}
        route_ports = route_spec.get("ports") if isinstance(route_spec, dict) else None
        require(isinstance(route_spec, dict)
                and route_spec.get("type") == "ClusterIP"
                and not route_spec.get("externalIPs")
                and route_spec.get("selector") == selector
                and isinstance(route_ports, list) and len(route_ports) == 1
                and isinstance(route_ports[0], dict)
                and all(route_ports[0].get(name) == value for name, value in {
                    "name": "http", "port": port, "protocol": "TCP",
                    "targetPort": port}.items()),
                f"Kubernetes {service} Service route is outside the simulator run")
        slices = json_command(["kubectl", "--context", context, "-n", namespace,
                               "get", "endpointslices", "-l",
                               f"kubernetes.io/service-name={service}",
                               "-o", "json"], runner)
        items = slices.get("items")
        require(isinstance(items, list) and bool(items)
                and all(isinstance(item, dict) for item in items),
                f"Kubernetes {service} EndpointSlice is missing or ambiguous")
        ready_addresses = 0
        slice_uids = []
        for endpoint_slice in items:
            slice_metadata = endpoint_slice.get("metadata")
            endpoints = endpoint_slice.get("endpoints")
            slice_ports = endpoint_slice.get("ports")
            address_type = endpoint_slice.get("addressType")
            require(isinstance(slice_metadata, dict)
                    and slice_metadata.get("namespace") == namespace
                    and isinstance(slice_metadata.get("uid"), str)
                    and bool(slice_metadata["uid"])
                    and isinstance(slice_metadata.get("labels"), dict)
                    and slice_metadata["labels"].get("kubernetes.io/service-name")
                    == service
                    and slice_metadata["labels"].get(
                        "endpointslice.kubernetes.io/managed-by")
                    == "endpointslice-controller.k8s.io"
                    and kubernetes_owner(endpoint_slice, "Service", service, route_uid)
                    and address_type in ("IPv4", "IPv6")
                    and isinstance(slice_ports, list) and len(slice_ports) == 1
                    and isinstance(slice_ports[0], dict)
                    and all(slice_ports[0].get(name) == value for name, value in {
                        "name": "http", "port": port, "protocol": "TCP"}.items())
                    and isinstance(endpoints, list),
                    f"Kubernetes {service} EndpointSlice is outside the owned Service")
            family = 4 if address_type == "IPv4" else 6
            for endpoint in endpoints:
                require(isinstance(endpoint, dict)
                        and isinstance(endpoint.get("targetRef"), dict)
                        and endpoint["targetRef"].get("kind") == "Pod"
                        and endpoint["targetRef"].get("uid") == observed[service]["pod_uid"]
                        and endpoint["targetRef"].get("namespace") == namespace
                        and isinstance(endpoint.get("conditions"), dict)
                        and isinstance(endpoint.get("addresses"), list)
                        and bool(endpoint["addresses"])
                        and all(isinstance(value, str)
                                for value in endpoint["addresses"]),
                        f"Kubernetes {service} Service targets another Pod")
                try:
                    addresses = {ipaddress.ip_address(value)
                                 for value in endpoint["addresses"]}
                except ValueError as error:
                    raise SupportedEvidenceError(
                        f"Kubernetes {service} EndpointSlice address is invalid") from error
                require(len(addresses) == len(endpoint["addresses"])
                        and all(address.version == family
                                and address in pod_ips[service] for address in addresses),
                        f"Kubernetes {service} Service routes to another address")
                if endpoint["conditions"].get("ready") is True:
                    ready_addresses += len(addresses)
            slice_uids.append(slice_metadata["uid"])
        require(ready_addresses > 0,
                f"Kubernetes {service} Service has no ready owned address")
        observed[service]["service_uid"] = route_uid
        observed[service]["endpoint_slice_uids"] = slice_uids
    return observed


def loopback_origin(origin: str) -> str:
    parsed = urlsplit(origin)
    require(parsed.scheme == "http" and parsed.hostname == "127.0.0.1"
            and parsed.port is not None and not parsed.path and not parsed.query
            and not parsed.fragment and not parsed.username and not parsed.password,
            "Supported probe origin must be an isolated loopback forward")
    return origin


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def capability_status(origin: str, api_key: str | None) -> tuple[int, dict | None]:
    loopback_origin(origin)
    headers = {"Accept": "application/json", "Cache-Control": "no-cache"}
    if api_key:
        headers["x-api-key"] = api_key
    url = origin + "/v1/passport/capabilities"
    try:
        with build_opener(NoRedirect).open(Request(url, headers=headers, method="GET"),
                                          timeout=20) as response:
            require(response.geturl() == url, "Supported passport capability redirected")
            raw = response.read(64 * 1024 + 1)
            require(len(raw) <= 64 * 1024, "Supported passport capability is oversized")
            body = json.loads(raw)
            return response.status, body if isinstance(body, dict) else None
    except HTTPError as exc:
        return exc.code, None
    except (OSError, URLError, ValueError) as exc:
        raise SupportedEvidenceError("Supported passport capability probe failed") from exc


def report_surface(runtime: dict | None, blocker: str | None, source_commit: str) -> dict:
    probes = {name: {"verified": False, "evidence": None} for name in PROBES}
    if runtime is not None:
        gateway = runtime["gateway"]
        probes["released_image"] = {
            "verified": True,
            "evidence": {"oci_reference": gateway["oci_reference"],
                         "source_commit": source_commit,
                         "container_id": gateway["container_id"]},
        }
    return {"runtime_accepted": False,
            "probes": probes, "runtime_images": runtime, "blocker": blocker}


def collect(
    manifest_path: Path, source_commit: str, *,
    base_project: str | None = None, selfhost_project: str | None = None,
    namespace: str | None = None,
    kubernetes_context: str | None = None,
    base_origin: str | None = None, selfhost_origin: str | None = None,
    kubernetes_origin: str | None = None, api_key: str | None = None,
    compose_probe: Callable[[str, str, str], dict] = observe_compose,
    kubernetes_probe: Callable[[str, str, str, str], dict] = observe_kubernetes,
    capability_probe: Callable[[str, str | None], tuple[int, dict | None]] = capability_status,
    attest: Callable[[Path, dict[str, str], str], bool] = verify_attestations,
) -> dict:
    require(SHA.fullmatch(source_commit) is not None, "Protected source commit is invalid")
    if base_project is not None:
        disposable_project(base_project, "base")
    if selfhost_project is not None:
        disposable_project(selfhost_project, "selfhost")
    if namespace is not None:
        disposable_namespace(namespace)
        require(kubernetes_context is not None,
                "Disposable Kubernetes context is required")
    if kubernetes_context is not None:
        disposable_context(kubernetes_context)
    for origin in (base_origin, selfhost_origin, kubernetes_origin):
        if origin is not None:
            loopback_origin(origin)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    require(isinstance(manifest, dict) and manifest.get("schema") == "marty.stack/v1",
            "Official stack manifest is missing")
    ui = [item for item in manifest.get("components", []) if isinstance(item, dict)
          and item.get("name") == "marty-ui" and item.get("repository") == "ElevenID/marty-ui"]
    require(len(ui) == 1 and ui[0].get("commit") == source_commit,
            "Supported source differs from official release")
    artifacts = ui[0].get("artifacts")
    require(isinstance(artifacts, list), "Released UI artifacts are missing")
    oci = [item for item in artifacts if isinstance(item, dict)
           and item.get("type") == "oci"]
    images = {item.get("uri"): item.get("digest") for item in oci}
    require(len(oci) == 3 and len(images) == 3 and set(images) == {
        "ghcr.io/elevenid/marty-ui-oss/ui", "ghcr.io/elevenid/marty-ui-oss/services",
        "ghcr.io/elevenid/marty-ui-oss/migrations",
    } and all(isinstance(value, str) and DIGEST.fullmatch(value) is not None
              for value in images.values()), "Released UI image roles are incomplete")
    signed = attest(manifest_path, images, source_commit)
    require(signed is True, "Released image attestations are unverified")
    services_reference = ("ghcr.io/elevenid/marty-ui-oss/services@"
                          + images["ghcr.io/elevenid/marty-ui-oss/services"])
    surfaces = {}
    for name, target, origin in (("base", base_project, base_origin),
                                 ("selfhost", selfhost_project, selfhost_origin),
                                 ("kubernetes", namespace, kubernetes_origin)):
        if target is None:
            surfaces[name] = report_surface(None, "disposable runtime target is absent",
                                            source_commit)
            continue
        try:
            runtime = (kubernetes_probe(target, kubernetes_context,
                                        services_reference, source_commit)
                       if name == "kubernetes" else compose_probe(name, target, services_reference))
        except (SupportedEvidenceError, OSError, ValueError):
            surfaces[name] = report_surface(None, "disposable runtime probe failed",
                                            source_commit)
        else:
            pending = ("nine-route/Kubernetes simulator/restart acceptance is pending"
                       if name == "kubernetes" else
                       "nine-route/simulator/restart acceptance is pending")
            observed = report_surface(runtime, pending, source_commit)
            bound_port = runtime.get("gateway", {}).get("loopback_port")
            parsed_origin = urlsplit(origin) if origin is not None else None
            if (name != "kubernetes" and origin is not None and api_key is not None
                    and parsed_origin.port == bound_port):
                try:
                    anonymous, _ = capability_probe(origin, None)
                    authenticated, body = capability_probe(origin, api_key)
                    require(anonymous in (401, 403)
                            and authenticated == 200 and isinstance(body, dict)
                            and body.get("supported") is True
                            and body.get("encrypted_artifact_store") is True
                            and body.get("bureau_configured") is True
                            and isinstance(body.get("signer"), dict)
                            and body["signer"].get("mode") == "MANAGED_ISSUER_PROFILE",
                            "Supported passport capability or authentication failed")
                except (SupportedEvidenceError, OSError, ValueError):
                    observed["blocker"] = "supported capability/authentication probe failed"
                else:
                    observed["capabilities_http"] = {"verified": True,
                                                      "evidence": {"http_status": 200}}
                    observed["unauthenticated_denial"] = {"verified": True,
                                                            "evidence": {"http_status": anonymous}}
            elif origin is not None:
                observed["blocker"] = "probe origin is not bound to the inspected gateway"
            surfaces[name] = observed
    return {"schema": "marty.passport-supported-consumer-acceptance/v1",
            "status": "blocked", "source_commit": source_commit,
            "physical_claim": "not_claimed",
            "stack_manifest_sha256": digest_file(manifest_path).removeprefix("sha256:"),
            "oci_digests": images, "surfaces": surfaces}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stack-manifest", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--base-project")
    parser.add_argument("--selfhost-project")
    parser.add_argument("--kubernetes-namespace")
    parser.add_argument("--kubernetes-context")
    parser.add_argument("--base-origin")
    parser.add_argument("--selfhost-origin")
    parser.add_argument("--kubernetes-origin")
    parser.add_argument("--api-key-file", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        api_key = (args.api_key_file.read_text(encoding="utf-8").strip()
                   if args.api_key_file else None)
        report = collect(args.stack_manifest, args.source_commit,
                         base_project=args.base_project,
                         selfhost_project=args.selfhost_project,
                         namespace=args.kubernetes_namespace,
                         kubernetes_context=args.kubernetes_context,
                         base_origin=args.base_origin,
                         selfhost_origin=args.selfhost_origin,
                         kubernetes_origin=args.kubernetes_origin,
                         api_key=api_key)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                               encoding="utf-8")
    except (SupportedEvidenceError, OSError, ValueError) as exc:
        # A failed probe is not an accepted report and must not disclose runtime data.
        args.output.write_text(json.dumps({"schema": "marty.passport-supported-consumer-acceptance/v1",
                                           "status": "blocked", "blocker": str(exc)}) + "\n",
                               encoding="utf-8")
        parser.exit(1, f"Supported passport evidence blocked: {exc}\n")
    print("Wrote blocked supported passport prerequisite evidence")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
