#!/usr/bin/env python3
"""Inspect disposable supported passport runtimes; never qualify Python deletion.

This collector records running service, image, and selector observations.
It has no rollback transition command.
Physical provider and nine-route acceptance require a later protected harness.
"""

from __future__ import annotations

import argparse
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
ROOT = Path(__file__).resolve().parents[1]
PROJECT = re.compile(r"marty-passport-acceptance-(base|selfhost)-[a-z0-9]{6,32}\Z")
NAMESPACE = re.compile(r"marty-passport-acceptance-[a-z0-9]{6,32}\Z")
KUBE_CONTEXT = re.compile(r"marty-passport-acceptance-[a-z0-9]{6,32}\Z")
SERVICES = (
    "gateway", "flow", "issuance-native", "passport-callback-signer-supported",
    "passport-provider-ingress",
)
FLAGS = {
    "gateway": ("PASSPORT_NATIVE_GATEWAY_ENABLED", "PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED"),
    "flow": ("PASSPORT_NATIVE_FLOW_ENABLED", "PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED"),
    "issuance-native": (
        "PASSPORT_NATIVE_HTTP_ENABLED", "PASSPORT_INTERNAL_SERVICE_AUTH_ENABLED",
        "PASSPORT_MANAGED_ISSUER_SIGNING_ENABLED", "PASSPORT_KMS_ARTIFACTS_ENABLED",
        "PASSPORT_KMS_CALLBACKS_ENABLED",
    ),
    "passport-callback-signer-supported": ("PASSPORT_SUPPORTED_CALLBACK_SIGNER_ENABLED",),
    "passport-provider-ingress": ("PASSPORT_PROVIDER_INGRESS_ENABLED",),
}
PROBES = (
    "nine_route_gateway_flow", "managed_signer", "physical_bureau_callback",
    "released_image", "rollback",
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


def environment_flags(values: object, service: str) -> dict[str, bool]:
    require(isinstance(values, list), f"Missing {service} runtime environment")
    result: dict[str, bool] = {}
    for name in FLAGS[service]:
        matches = [entry.partition("=")[2] for entry in values
                   if isinstance(entry, str) and entry.partition("=")[0] == name]
        require(len(matches) == 1 and matches[0] in ("true", "false"),
                f"Missing or ambiguous {service} passport selector")
        result[name] = matches[0] == "true"
    return result


def observe_compose(
    surface: str, project: str, services_reference: str,
    runner: Callable[[list[str]], str] = command,
) -> dict[str, Any]:
    disposable_project(project, surface)
    observed: dict[str, Any] = {}
    for service in SERVICES:
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
        flags = environment_flags(config.get("Env"), service)
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
    namespace: str, context: str, services_reference: str,
    runner: Callable[[list[str]], str] = command,
) -> dict[str, Any]:
    disposable_namespace(namespace)
    disposable_context(context)
    config = json_command(["kubectl", "--context", context, "-n", namespace,
                           "get", "configmap", "marty-config",
                           "-o", "json"], runner)
    data = config.get("data")
    require(isinstance(data, dict), "Kubernetes passport ConfigMap is missing")
    observed: dict[str, Any] = {}
    for service in SERVICES:
        deployment = json_command(["kubectl", "--context", context, "-n", namespace,
                                   "get", "deployment",
                                   service, "-o", "json"], runner)
        metadata = deployment.get("metadata")
        status = deployment.get("status")
        spec = deployment.get("spec")
        require(isinstance(metadata, dict) and metadata.get("namespace") == namespace
                and isinstance(status, dict) and status.get("readyReplicas", 0) >= 1
                and isinstance(spec, dict),
                f"Kubernetes {service} is not ready in the disposable namespace")
        containers = spec.get("template", {}).get("spec", {}).get("containers")
        require(isinstance(containers, list) and len(containers) == 1
                and containers[0].get("image") == services_reference,
                f"Kubernetes {service} is not pinned to the released services image")
        container_env = containers[0].get("env", [])
        require(isinstance(container_env, list),
                f"Kubernetes {service} environment is invalid")
        selected = {}
        for flag in FLAGS[service]:
            matching = [entry for entry in container_env
                        if isinstance(entry, dict) and entry.get("name") == flag]
            require(len(matching) == 1,
                    f"Kubernetes {service} passport selector is missing or ambiguous")
            entry = matching[0]
            value_from = entry.get("valueFrom")
            source = value_from.get("configMapKeyRef") if isinstance(value_from, dict) else None
            value = (entry.get("value") if "value" in entry else
                     data.get(flag) if isinstance(source, dict)
                     and source.get("name") == "marty-config"
                     and source.get("key") == flag else None)
            require(value == "true", f"Kubernetes {service} did not select Rust passport")
            selected[flag] = True
        pods = json_command(["kubectl", "--context", context, "-n", namespace,
                             "get", "pods", "-l",
                             f"app={service}", "-o", "json"], runner)
        pod_items = pods.get("items")
        require(isinstance(pod_items, list) and len(pod_items) == 1
                and isinstance(pod_items[0], dict),
                f"Kubernetes {service} pod is missing or ambiguous")
        pod = pod_items[0]
        statuses = pod.get("status", {}).get("containerStatuses")
        require(pod.get("metadata", {}).get("namespace") == namespace
                and pod.get("status", {}).get("phase") == "Running"
                and isinstance(statuses, list) and len(statuses) == 1
                and statuses[0].get("ready") is True
                and isinstance(statuses[0].get("containerID"), str)
                and bool(statuses[0]["containerID"])
                and isinstance(statuses[0].get("imageID"), str)
                and statuses[0]["imageID"].endswith(services_reference.split("@", 1)[1]),
                f"Kubernetes {service} pod is not ready on the released image")
        observed[service] = {"deployment_uid": metadata.get("uid"),
                             "pod_uid": pod.get("metadata", {}).get("uid"),
                             "container_id": statuses[0]["containerID"],
                             "image_id": statuses[0]["imageID"],
                             "oci_reference": services_reference, "selectors": selected}
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
    return {"runtime_accepted": False, "rollback_accepted": False,
            "probes": probes, "runtime_images": runtime, "blocker": blocker}


def collect(
    manifest_path: Path, source_commit: str, *,
    base_project: str | None = None, selfhost_project: str | None = None,
    namespace: str | None = None,
    kubernetes_context: str | None = None,
    base_origin: str | None = None, selfhost_origin: str | None = None,
    kubernetes_origin: str | None = None, api_key: str | None = None,
    compose_probe: Callable[[str, str, str], dict] = observe_compose,
    kubernetes_probe: Callable[[str, str, str], dict] = observe_kubernetes,
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
            runtime = (kubernetes_probe(target, kubernetes_context, services_reference)
                       if name == "kubernetes" else compose_probe(name, target, services_reference))
        except (SupportedEvidenceError, OSError, ValueError):
            surfaces[name] = report_surface(None, "disposable runtime probe failed",
                                            source_commit)
        else:
            observed = report_surface(runtime,
                                      "nine-route/provider/rollback acceptance is pending",
                                      source_commit)
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
