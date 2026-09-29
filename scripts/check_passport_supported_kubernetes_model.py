#!/usr/bin/env python3
"""Read-only disposable Kubernetes identity preflight.

An operator-supplied identity plan is only an expected model. It is not a
protected attestation, rollout authorization, or runtime acceptance.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import subprocess
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlsplit

COMMIT = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
NAME = re.compile(r"marty-passport-acceptance-[a-z0-9]{6,32}\Z")
UID = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9-]{7,127}\Z")
RUN_ID = re.compile(r"[1-9][0-9]{0,19}\Z")
SERVICES = (
    "gateway",
    "flow",
    "issuance-native",
    "passport-callback-signer",
    "passport-beta-bureau",
)
RESOURCES = (
    ("configmap", "marty-config"),
    *(("deployment", name) for name in SERVICES),
    *(("service", name) for name in SERVICES),
)
FLAGS = {
    "gateway": "PASSPORT_NATIVE_GATEWAY_ENABLED",
    "flow": "PASSPORT_NATIVE_FLOW_ENABLED",
    "issuance-native": "PASSPORT_NATIVE_HTTP_ENABLED",
}
OWNER_LABEL = "com.marty.passport.acceptance.owner"
SOURCE_LABEL = "com.marty.passport.acceptance.source-commit"
RUN_LABEL = "com.marty.passport.acceptance.run-id"
SIMULATOR_SERVICES = frozenset({"passport-callback-signer", "passport-beta-bureau"})


class KubernetesPreflightError(ValueError):
    pass


def require(ok: bool, message: str) -> None:
    if not ok:
        raise KubernetesPreflightError(message)


def selector_for(name: str, plan_run_id: str) -> dict[str, str]:
    selector = {"app": name}
    if name in SIMULATOR_SERVICES:
        selector.update({OWNER_LABEL: "supported-consumer", RUN_LABEL: plan_run_id})
    return selector


def kubernetes_config_value(container: dict, data: dict, name: str) -> object:
    """Resolve a required setting without accepting an envFrom override."""
    entries = container.get("env", [])
    require(isinstance(entries, list), "Kubernetes passport environment is invalid")
    matches = [entry for entry in entries
               if isinstance(entry, dict) and entry.get("name") == name]
    require(len(matches) <= 1, "Kubernetes passport environment is ambiguous")
    if matches:
        entry = matches[0]
        if "value" in entry:
            require("valueFrom" not in entry,
                    "Kubernetes passport configuration source is ambiguous")
            return entry["value"]
        value_from = entry.get("valueFrom")
        source = value_from.get("configMapKeyRef") if isinstance(value_from, dict) else None
        require(isinstance(source, dict) and source.get("name") == "marty-config"
                and source.get("key") == name,
                "Kubernetes passport configuration source is invalid")
        return data.get(name)
    env_from = container.get("envFrom", [])
    require(isinstance(env_from, list), "Kubernetes passport environment source is invalid")
    require(len(env_from) == 1 and isinstance(env_from[0], dict)
            and isinstance(env_from[0].get("configMapRef"), dict)
            and env_from[0]["configMapRef"].get("name") == "marty-config",
            "Kubernetes passport ConfigMap source is ambiguous")
    return data.get(name)


def command(args: list[str]) -> str:
    try:
        result = subprocess.run(
            args,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=25,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise KubernetesPreflightError(
            "Disposable Kubernetes inspection failed"
        ) from exc
    require(
        len(result.stdout) <= 1024 * 1024,
        "Disposable Kubernetes inspection is oversized",
    )
    return result.stdout


def object_command(args: list[str], runner: Callable[[list[str]], str]) -> dict:
    try:
        value = json.loads(runner(args))
    except ValueError as exc:
        raise KubernetesPreflightError(
            "Disposable Kubernetes response is invalid"
        ) from exc
    require(isinstance(value, dict), "Disposable Kubernetes response is not an object")
    return value


def validate_plan(plan: dict, source_commit: str, services_reference: str) -> None:
    """Freeze the operator's exact read-only target without trusting it as proof."""
    require(
        isinstance(plan, dict)
        and set(plan)
        == {
            "schema",
            "status",
            "source_commit",
            "plan_run_id",
            "services_reference",
            "cluster",
            "namespace",
            "resources",
        }
        and plan["schema"] == "marty.passport-supported-kubernetes-model/v1"
        and plan["status"] == "blocked"
        and COMMIT.fullmatch(source_commit) is not None
        and plan["source_commit"] == source_commit
        and isinstance(plan["plan_run_id"], str)
        and RUN_ID.fullmatch(plan["plan_run_id"]) is not None
        and plan["services_reference"] == services_reference
        and re.fullmatch(
            r"ghcr\.io/elevenid/marty-ui-oss/services@sha256:[0-9a-f]{64}",
            services_reference,
        )
        is not None,
        "Disposable Kubernetes plan source or images are invalid",
    )
    cluster = plan["cluster"]
    namespace = plan["namespace"]
    require(
        isinstance(cluster, dict)
        and set(cluster)
        == {
            "context",
            "name",
            "server",
            "ca_sha256",
        }
        and all(isinstance(cluster[key], str) for key in cluster)
        and NAME.fullmatch(cluster["context"]) is not None
        and NAME.fullmatch(cluster["name"]) is not None
        and urlsplit(cluster["server"]).scheme == "https"
        and urlsplit(cluster["server"]).hostname is not None
        and not urlsplit(cluster["server"]).username
        and not urlsplit(cluster["server"]).password
        and not urlsplit(cluster["server"]).path.strip("/")
        and not urlsplit(cluster["server"]).query
        and DIGEST.fullmatch(cluster["ca_sha256"]) is not None,
        "Disposable Kubernetes cluster identity is invalid",
    )
    require(
        isinstance(namespace, dict)
        and set(namespace) == {"name", "uid"}
        and isinstance(namespace["name"], str)
        and NAME.fullmatch(namespace["name"]) is not None
        and isinstance(namespace["uid"], str)
        and UID.fullmatch(namespace["uid"]) is not None,
        "Disposable Kubernetes namespace identity is invalid",
    )
    resources = plan["resources"]
    require(
        isinstance(resources, dict)
        and set(resources) == {f"{kind}/{name}" for kind, name in RESOURCES}
        and all(
            isinstance(uid, str) and UID.fullmatch(uid) is not None
            for uid in resources.values()
        )
        and len(set(resources.values())) == len(resources),
        "Disposable Kubernetes resource identities are invalid",
    )


def inspect(
    plan: dict,
    source_commit: str,
    services_reference: str,
    runner: Callable[[list[str]], str] = command,
) -> dict:
    """Check exact context, CA, namespace and resource IDs without mutation."""
    validate_plan(plan, source_commit, services_reference)
    cluster = plan["cluster"]
    namespace = plan["namespace"]
    context = cluster["context"]
    config = object_command(
        [
            "kubectl",
            "--context",
            context,
            "config",
            "view",
            "--minify",
            "--raw",
            "--flatten",
            "-o",
            "json",
        ],
        runner,
    )
    contexts, clusters = config.get("contexts"), config.get("clusters")
    require(
        config.get("current-context") == context
        and isinstance(contexts, list)
        and len(contexts) == 1
        and isinstance(contexts[0], dict)
        and contexts[0].get("name") == context
        and isinstance(contexts[0].get("context"), dict)
        and contexts[0].get("context", {}).get("cluster") == cluster["name"]
        and isinstance(clusters, list)
        and len(clusters) == 1
        and isinstance(clusters[0], dict)
        and clusters[0].get("name") == cluster["name"],
        "Disposable Kubernetes context or cluster changed",
    )
    connection = clusters[0].get("cluster")
    require(
        isinstance(connection, dict)
        and connection.get("server") == cluster["server"]
        and connection.get("insecure-skip-tls-verify") is not True
        and isinstance(connection.get("certificate-authority-data"), str),
        "Disposable Kubernetes server or TLS authority changed",
    )
    try:
        ca = base64.b64decode(connection["certificate-authority-data"], validate=True)
    except ValueError as exc:
        raise KubernetesPreflightError("Disposable Kubernetes CA is invalid") from exc
    require(
        bool(ca) and "sha256:" + hashlib.sha256(ca).hexdigest() == cluster["ca_sha256"],
        "Disposable Kubernetes CA digest changed",
    )
    prefix = ["kubectl", "--context", context]
    ns = object_command(
        [*prefix, "get", "namespace", namespace["name"], "-o", "json"], runner
    )
    metadata = ns.get("metadata")
    require(
        isinstance(metadata, dict)
        and metadata.get("name") == namespace["name"]
        and metadata.get("uid") == namespace["uid"]
        and isinstance(metadata.get("labels"), dict)
        and metadata["labels"].get(OWNER_LABEL) == "supported-consumer"
        and metadata["labels"].get(RUN_LABEL) == plan["plan_run_id"]
        and metadata["labels"].get(SOURCE_LABEL) == source_commit
        and isinstance(ns.get("status"), dict)
        and ns["status"].get("phase") == "Active",
        "Disposable Kubernetes namespace identity changed",
    )
    observed = {}
    config_data: dict | None = None
    for kind in ("deployment", "service"):
        provider = runner([*prefix, "-n", namespace["name"], "get", kind,
                           "passport-provider-ingress", "--ignore-not-found",
                           "-o", "json"])
        require(not provider.strip(),
                "Disposable Kubernetes physical provider ingress remains")
        python_issuance = runner([*prefix, "-n", namespace["name"], "get", kind,
                                  "issuance", "--ignore-not-found", "-o", "json"])
        require(not python_issuance.strip(),
                "Disposable Kubernetes Python issuance remains")
    provider_pods = object_command(
        [*prefix, "-n", namespace["name"], "get", "pods", "-l",
         "app=passport-provider-ingress", "-o", "json"], runner)
    require(provider_pods.get("items") == [],
            "Disposable Kubernetes physical provider Pod remains")
    issuance_pods = object_command(
        [*prefix, "-n", namespace["name"], "get", "pods", "-l",
         "app=issuance", "-o", "json"], runner)
    require(issuance_pods.get("items") == [],
            "Disposable Kubernetes Python issuance Pod remains")
    for kind, name in RESOURCES:
        item = object_command(
            [*prefix, "-n", namespace["name"], "get", kind, name, "-o", "json"], runner
        )
        metadata = item.get("metadata")
        require(
            isinstance(metadata, dict)
            and metadata.get("name") == name
            and metadata.get("namespace") == namespace["name"]
            and metadata.get("uid") == plan["resources"][f"{kind}/{name}"]
            and isinstance(metadata.get("labels"), dict)
            and metadata["labels"].get(OWNER_LABEL) == "supported-consumer"
            and metadata["labels"].get(RUN_LABEL) == plan["plan_run_id"]
            and metadata["labels"].get(SOURCE_LABEL) == source_commit,
            f"Disposable Kubernetes {kind}/{name} identity changed",
        )
        if kind == "deployment":
            deployment = item.get("spec")
            template = (
                deployment.get("template") if isinstance(deployment, dict) else None
            )
            spec = template.get("spec") if isinstance(template, dict) else None
            containers = spec.get("containers") if isinstance(spec, dict) else None
            require(
                isinstance(containers, list)
                and len(containers) == 1
                and isinstance(containers[0], dict)
                and containers[0].get("name") == name
                and containers[0].get("image") == services_reference
                and spec.get("hostNetwork") is not True
                and spec.get("hostPID") is not True
                and spec.get("automountServiceAccountToken") is False,
                f"Disposable Kubernetes deployment/{name} is unsafe",
            )
            selector = deployment.get("selector")
            labels = template.get("metadata", {}).get("labels")
            expected = selector_for(name, plan["plan_run_id"])
            require(isinstance(selector, dict)
                    and selector.get("matchLabels") == expected
                    and isinstance(labels, dict)
                    and all(labels.get(key) == value for key, value in expected.items()),
                    f"Disposable Kubernetes deployment/{name} selector is invalid")
            if name in ("gateway", "flow", "issuance-native"):
                require(isinstance(config_data, dict),
                        "Disposable Kubernetes ConfigMap is unavailable")
                expected_config = ({
                    "PASSPORT_PROVIDER_INGRESS_GATEWAY_ENABLED": "false",
                    "PASSPORT_PROVIDER_INGRESS_SERVICE_URL": "",
                    "ISSUANCE_NATIVE_SERVICE_URL": "http://issuance-native:8005",
                } if name == "gateway" else {
                    "ISSUANCE_NATIVE_SERVICE_URL": "http://issuance-native:8005",
                } if name == "flow" else {
                    "PERSONALIZATION_BUREAU_URL": "http://passport-beta-bureau:8020",
                    "PERSONALIZATION_BUREAU_PROVIDER_PROFILE_ID": "passport-beta-bureau",
                })
                require(all(kubernetes_config_value(containers[0], config_data, key) == value
                            for key, value in expected_config.items()),
                        f"Disposable Kubernetes deployment/{name} is not simulator-bound")
        elif kind == "service":
            spec = item.get("spec")
            require(
                isinstance(spec, dict)
                and spec.get("type") == "ClusterIP"
                and spec.get("selector") == selector_for(name, plan["plan_run_id"])
                and isinstance(spec.get("clusterIP"), str)
                and bool(spec["clusterIP"])
                and not spec.get("externalIPs")
                and not spec.get("loadBalancerIP")
                and not spec.get("loadBalancerSourceRanges")
                and isinstance(spec.get("ports", []), list)
                and all(
                    isinstance(port, dict) and "nodePort" not in port
                    for port in spec.get("ports", [])
                ),
                f"Disposable Kubernetes service/{name} is not private",
            )
        else:
            require(item.get("immutable") is True,
                    "Disposable Kubernetes ConfigMap must be immutable")
            data = item.get("data")
            require(
                isinstance(data, dict)
                and all(data.get(flag) == "true" for flag in FLAGS.values())
                and data.get("ISSUANCE_NATIVE_SERVICE_URL")
                == "http://issuance-native:8005"
                and data.get("PASSPORT_PROVIDER_INGRESS_GATEWAY_ENABLED") == "false"
                and data.get("PASSPORT_PROVIDER_INGRESS_SERVICE_URL") == ""
                and data.get("PERSONALIZATION_BUREAU_URL")
                == "http://passport-beta-bureau:8020"
                and data.get("PERSONALIZATION_BUREAU_PROVIDER_PROFILE_ID")
                == "passport-beta-bureau",
                "Disposable Kubernetes Rust selector model is invalid",
            )
            config_data = data
        observed[f"{kind}/{name}"] = metadata["uid"]
    return {
        "schema": "marty.passport-supported-kubernetes-preflight/v1",
        "status": "blocked",
        "cluster_context": context,
        "namespace": namespace["name"],
        "namespace_uid": namespace["uid"],
        "resource_uids": observed,
        "static_identity_verified": True,
        "runtime_accepted": False,
        "blocker": "protected plan attestation and live Rust route proof are absent",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--services-reference", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        plan = json.loads(args.plan.read_text(encoding="utf-8"))
        report = inspect(plan, args.source_commit, args.services_reference)
    except (OSError, ValueError) as exc:
        report = {
            "schema": "marty.passport-supported-kubernetes-preflight/v1",
            "status": "blocked",
            "static_identity_verified": False,
            "runtime_accepted": False,
            "blocker": str(exc),
        }
    args.output.write_text(
        json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
