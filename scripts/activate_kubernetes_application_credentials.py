#!/usr/bin/env python3
"""Activate a staged ordinary-token generation with native Kubernetes resources.

The signed native operator owns credential validation and the restricted Secret
patch. Kubernetes owns Deployment replacement and readiness. This Linux adapter
keeps one private, explicit attempt, and selects its immutable candidate only
after observing that attempt's Secret and workload revisions. Reconciliation
never repeats a Secret patch or mints replacement tokens.

Keep the bootstrap, staging and activation directories on private encrypted
operator storage. Ready Pods prove the selected rollout, not that every runtime
credential operation was exercised. TLS/Keycloak renewal and expiry recovery
remain separate operations.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import time

import bootstrap_kubernetes_openbao as bootstrap
import kubernetes_application_state as application_state
import stage_kubernetes_application_credentials as staging


ANNOTATION = "marty.elevenid.com/application-activation"
MINIMUM_TTL = 1800
ACTIVATION_SECONDS = 900
API_LIMIT = 8 * 1024 * 1024
API_ITEMS = 2048
PROOF_ARCHIVE_LIMIT = 3 * 1024 * 1024
REMOTE_CANDIDATE = "/tmp/application-candidate"
REMOTE_CURRENT = "/tmp/application-current"
REMOTE_IDENTITY = "/tmp/application-identity"
REMOTE_PROOF = "/tmp/application-operation"
REMOTE_OPERATOR = "/tmp/marty-deploy"
REQUEST = "application-activation-requested.json"
VERIFIED = "application-activation-verified.json"
COMPLETE = "application-activation-complete.json"
RESOURCE_TYPES = "deployments,statefulsets,daemonsets,jobs,cronjobs,replicasets,pods"

# This is the existing chart's consumption graph, not a second token inventory.
# Its union must equal the two authenticated native catalogs. Rendering tests
# compare these bindings to the chart, including the signing-keys env alias.
BINDINGS = {
    "signing-keys": {
        "SIGNING_KEYS_OPENBAO_TOKEN": ("OPENBAO_SERVICE_TOKEN", None),
        "DIDCOMM_ISSUANCE_OPENBAO_TOKEN": ("DIDCOMM_KMS_TOKEN_FILE", "/run/secrets/didcomm-kms/token"),
        "SIGNING_KEYS_GRANT_VERIFY_TOKEN": ("SIGNING_KEYS_GRANT_VERIFY_TOKEN_FILE", "/run/secrets/signing-grant-verify/token"),
    },
    "notification": {"NOTIFICATION_OPENBAO_TOKEN": ("NOTIFICATION_OPENBAO_TOKEN_FILE", "/run/secrets/notification_openbao_token")},
    "gateway": {
        "GATEWAY_SIGN_GRANT_MINT_TOKEN": ("GATEWAY_SIGN_GRANT_MINT_TOKEN_FILE", "/var/run/secrets/marty/gateway-sign-grant/token"),
        "GATEWAY_ISSUER_CSR_GRANT_MINT_TOKEN": ("GATEWAY_ISSUER_CSR_GRANT_MINT_TOKEN_FILE", "/var/run/secrets/marty/gateway-issuer-csr-grant/token"),
    },
    "flow": {"FLOW_SIGN_GRANT_MINT_TOKEN": ("FLOW_SIGN_GRANT_MINT_TOKEN_FILE", "/var/run/secrets/marty/flow-sign-grant/token")},
    "issuance-native": {
        "ISSUANCE_CREDENTIAL_SIGN_GRANT_MINT_TOKEN": ("ISSUANCE_CREDENTIAL_SIGN_GRANT_MINT_TOKEN_FILE", "/run/secrets/issuance-sign-grants/credential"),
        "ISSUANCE_CANVAS_SIGN_GRANT_MINT_TOKEN": ("ISSUANCE_CANVAS_SIGN_GRANT_MINT_TOKEN_FILE", "/run/secrets/issuance-sign-grants/canvas"),
        "ISSUANCE_READINESS_SIGN_GRANT_MINT_TOKEN": ("ISSUANCE_READINESS_SIGN_GRANT_MINT_TOKEN_FILE", "/run/secrets/issuance-sign-grants/readiness"),
        "ISSUANCE_PASSPORT_SIGN_GRANT_MINT_TOKEN": ("ISSUANCE_PASSPORT_SIGN_GRANT_MINT_TOKEN_FILE", "/run/secrets/issuance-sign-grants/passport"),
    },
    "canvas-sync-worker": {"ISSUANCE_CANVAS_SIGN_GRANT_MINT_TOKEN": ("ISSUANCE_CANVAS_SIGN_GRANT_MINT_TOKEN_FILE", "/var/run/secrets/marty/issuance-canvas-sign-grant/token")},
}
REQUIRED = set(BINDINGS) - {"canvas-sync-worker"}
RUNTIME_KEYS = set().union(*(set(value) for value in BINDINGS.values()))
# These aliases take precedence in the signed runtime or its entrypoint. The
# probe also checks the resolved container environment because envFrom can
# introduce a competing source without an explicit env entry in the Pod spec.
COMPETING_SOURCES = {
    "signing-keys": {"BAO_TOKEN", "BAO_TOKEN_FILE", "OPENBAO_SERVICE_TOKEN_FILE"},
    "notification": {"NOTIFICATION_OPENBAO_TOKEN"},
}
MIGRATION_COMMANDS = {
    "revocation-profile": ["/usr/local/bin/marty-revocation-profile"],
    "bootstrap-notification": ["/app/run-migrations-with-secrets.sh"],
    "organization": ["/usr/local/bin/marty-organization", "migrate"],
    "credential-template": ["/usr/local/bin/marty-credential-template", "migrate"],
    "flow": ["/usr/local/bin/marty-flow", "migrate"],
    "device-registration": ["/usr/local/bin/marty-device-registration", "migrate"],
    "verification": ["/usr/local/bin/marty-verification-service", "migrate"],
}
DELIVERY_OK = b"marty-application-delivery-ok\n"
DELIVERY_ENV = (
    'IFS= read -r expected; '
    '[ "${#expected}" -ge 20 ]; [ "${#expected}" -le 1024 ]; '
    '[ -z "${BAO_TOKEN+x}" ]; [ -z "${BAO_TOKEN_FILE+x}" ]; '
    '[ -z "${OPENBAO_SERVICE_TOKEN_FILE+x}" ]; '
    '[ "${OPENBAO_SERVICE_TOKEN-}" = "$expected" ]; '
    'printf "marty-application-delivery-ok\\n"'
)
DELIVERY_FILE = (
    'IFS= read -r expected; '
    '[ "${#expected}" -ge 20 ]; [ "${#expected}" -le 1024 ]; '
    '[ -f "$1" ]; '
    'printf "%s" "$expected" | /usr/bin/cmp -s -n 1025 - "$1"; '
    'printf "marty-application-delivery-ok\\n"'
)
DELIVERY_NOTIFICATION_FILE = (
    '[ -z "${NOTIFICATION_OPENBAO_TOKEN+x}" ]; '
    '[ "${NOTIFICATION_OPENBAO_TOKEN_FILE-}" = "$1" ]; '
) + DELIVERY_FILE


class BoundedTransport(bootstrap.Transport):
    """Apply one monotonic deadline to every command after fresh proof begins."""

    deadline: float | None = None

    def run(self, operation: str, command: list[str], *, data: bytes | None = None,
            timeout: int = 300, env: dict[str, str] | None = None) -> bytes:
        if self.deadline is not None:
            timeout = min(timeout, remaining(self.deadline))
        return super().run(operation, command, data=data, timeout=timeout, env=env)


def json_bytes(raw: bytes, maximum: int = API_LIMIT) -> dict:
    bootstrap.require(0 < len(raw) <= maximum, "private observation size is invalid")
    value = json.loads(raw, object_pairs_hook=bootstrap.unique_json_members,
                       parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("nonfinite JSON")))
    bootstrap.require(isinstance(value, dict), "private observation is not an object")
    return value


def private_json(path: Path, maximum: int = API_LIMIT) -> dict:
    return json_bytes(staging.private_bytes(path, maximum, {0o600})[0], maximum)


def list_items(value: dict) -> list[dict]:
    entries = value.get("items")
    bootstrap.require(value.get("kind") == "List" and isinstance(entries, list)
                      and len(entries) <= API_ITEMS and all(isinstance(item, dict) for item in entries),
                      "Kubernetes workload inventory differs")
    identities = [(item.get("kind"), item.get("metadata", {}).get("name")) for item in entries]
    bootstrap.require(len(set(identities)) == len(identities), "Kubernetes workload inventory repeats an object")
    return entries


def metadata(resource: dict, kind: str, namespace: str) -> dict:
    result = resource.get("metadata")
    bootstrap.require(resource.get("kind") == kind and isinstance(result, dict)
                      and result.get("namespace") == namespace
                      and isinstance(result.get("name"), str)
                      and isinstance(result.get("uid"), str) and result["uid"]
                      and isinstance(result.get("resourceVersion"), str) and result["resourceVersion"]
                      and result.get("deletionTimestamp") is None,
                      "Kubernetes resource identity differs")
    return result


def controller(resource: dict) -> tuple[str, str, str] | None:
    owners = resource.get("metadata", {}).get("ownerReferences", [])
    bootstrap.require(isinstance(owners, list) and all(isinstance(owner, dict) for owner in owners),
                      "Kubernetes owner references differ")
    selected = [owner for owner in owners if owner.get("controller") is True]
    bootstrap.require(len(selected) <= 1, "Kubernetes controlling owner is ambiguous")
    if not selected:
        return None
    owner = selected[0]
    bootstrap.require(all(isinstance(owner.get(key), str) and owner[key] for key in ("kind", "name", "uid")),
                      "Kubernetes controlling owner is invalid")
    return owner["kind"], owner["name"], owner["uid"]


def pod_spec(resource: dict) -> dict:
    kind = resource.get("kind")
    if kind == "Pod":
        value = resource.get("spec")
    elif kind == "CronJob":
        value = resource.get("spec", {}).get("jobTemplate", {}).get("spec", {}).get("template", {}).get("spec")
    else:
        value = resource.get("spec", {}).get("template", {}).get("spec")
    bootstrap.require(isinstance(value, dict), "Kubernetes pod template is invalid")
    return value


def token_references(spec: dict) -> set[str]:
    """Identify any direct/default Secret projection of the rotating keys."""
    result = set()
    for group in ("containers", "initContainers", "ephemeralContainers"):
        entries = spec.get(group, [])
        bootstrap.require(isinstance(entries, list), "Kubernetes container inventory is invalid")
        for entry in entries:
            bootstrap.require(isinstance(entry, dict), "Kubernetes container entry is invalid")
            for setting in entry.get("env", []):
                reference = setting.get("valueFrom", {}).get("secretKeyRef", {})
                if reference.get("name") == "marty-secrets" and reference.get("key") in RUNTIME_KEYS:
                    result.add(reference["key"])
            for setting in entry.get("envFrom", []):
                if setting.get("secretRef", {}).get("name") == "marty-secrets":
                    result |= RUNTIME_KEYS
    for volume in spec.get("volumes", []):
        sources = []
        direct = volume.get("secret")
        if isinstance(direct, dict) and direct.get("secretName") == "marty-secrets":
            sources.append(direct)
        for source in volume.get("projected", {}).get("sources", []):
            projection = source.get("secret")
            if isinstance(projection, dict) and projection.get("name") == "marty-secrets":
                sources.append(projection)
        for source in sources:
            if "items" not in source:
                result |= RUNTIME_KEYS
            else:
                result |= {item.get("key") for item in source["items"] if item.get("key") in RUNTIME_KEYS}
    return result


def consumer_bindings(spec: dict, name: str, image: str) -> None:
    expected = BINDINGS[name]
    bootstrap.require(token_references(spec) == set(expected), "application token consumer inventory differs")
    containers = spec.get("containers")
    bootstrap.require(isinstance(containers, list) and len(containers) == 1
                      and containers[0].get("name") == name and containers[0].get("image") == image,
                      "application consumer image or container differs")
    owner = containers[0]
    environments = owner.get("env", [])
    bootstrap.require(isinstance(environments, list)
                      and len({item.get("name") for item in environments}) == len(environments),
                      "application consumer environment is ambiguous")
    env = {item["name"]: item for item in environments}
    bootstrap.require(not (set(env) & COMPETING_SOURCES.get(name, set())),
                      "application consumer has a competing credential source")
    bootstrap.require(owner.get("command") == ["/app/services/entrypoint.sh"]
                      and owner.get("args", []) == []
                      and env.get("SERVICE_NAME") == {"name": "SERVICE_NAME", "value": name.replace("-", "_")},
                      "application consumer entrypoint differs")
    mounts = owner.get("volumeMounts", [])
    volumes = spec.get("volumes", [])
    bootstrap.require(len({item.get("name") for item in volumes}) == len(volumes),
                      "application consumer volume names repeat")
    for key, (variable, path) in expected.items():
        setting = env.get(variable)
        if path is None:
            bootstrap.require(setting == {"name": variable, "valueFrom": {
                "secretKeyRef": {"name": "marty-secrets", "key": key}}},
                "application environment token binding differs")
            continue
        bootstrap.require(setting == {"name": variable, "value": path},
                          "application token file setting differs")
        matches = []
        for mount in mounts:
            prefix = mount.get("mountPath", "").rstrip("/") + "/"
            if not path.startswith(prefix):
                continue
            for volume in volumes:
                secret = volume.get("secret", {})
                if (volume.get("name") == mount.get("name")
                        and secret.get("secretName") == "marty-secrets"
                        and any(item.get("key") == key and item.get("path") == path[len(prefix):]
                                for item in secret.get("items", []))):
                    matches.append((mount, secret))
        bootstrap.require(len(matches) == 1 and matches[0][0].get("readOnly") is True
                          and "subPath" not in matches[0][0] and "subPathExpr" not in matches[0][0]
                          and matches[0][1].get("optional", False) is False,
                          "application token projection differs")
    token_volumes = {volume["name"] for volume in volumes
                     if token_references({"volumes": [volume]})}
    bootstrap.require(not any(token_references({"containers": [entry]})
        or any(mount.get("name") in token_volumes for mount in entry.get("volumeMounts", []))
        for entry in spec.get("initContainers", []) + spec.get("ephemeralContainers", [])),
        "application token has an additional container consumer")


def release_annotations(template: dict, runtime: dict) -> None:
    annotations = template.get("metadata", {}).get("annotations", {})
    bootstrap.require(isinstance(annotations, dict) and all(
        annotations.get("marty.11id.dev/" + key) == str(value) for key, value in runtime.items()),
        "application runtime provenance differs")


def deployment_snapshot(value: dict, namespace: str, image: str, runtime: dict, *,
                        allowed_names: set[str] | None = None, consumer_validator=None,
                        component_label_required: bool = True) -> tuple[str, dict]:
    meta = metadata(value, "Deployment", namespace)
    name = meta["name"]
    bootstrap.require(name in (BINDINGS if allowed_names is None else allowed_names),
                      "unknown application token consumer")
    labels = meta.get("labels", {})
    release_name = labels.get("app.kubernetes.io/instance")
    bootstrap.require(labels.get("app.kubernetes.io/name") == "marty"
                      and meta.get("ownerReferences", []) == []
                      and (labels.get("app.kubernetes.io/component") == name
                           or (not component_label_required and "app.kubernetes.io/component" not in labels))
                      and labels.get("app.kubernetes.io/managed-by") == "Helm"
                      and isinstance(release_name, str)
                      and re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,61}[a-z0-9]|[a-z0-9]", release_name),
                      "application Helm ownership differs")
    annotations = meta.get("annotations", {})
    ownership = {key: annotations.get(key) for key in
                 ("meta.helm.sh/release-name", "meta.helm.sh/release-namespace")}
    bootstrap.require(ownership == {"meta.helm.sh/release-name": release_name,
                                    "meta.helm.sh/release-namespace": namespace},
                      "application Helm ownership annotations differ")
    spec = value.get("spec", {})
    template = spec.get("template", {})
    replicas = spec.get("replicas")
    selector = {"app.kubernetes.io/instance": release_name, "app.kubernetes.io/component": name}
    bootstrap.require(type(replicas) is int and 0 < replicas <= 100
                      and spec.get("paused", False) is False
                      and type(meta.get("generation")) is int and meta["generation"] > 0
                      and spec.get("selector") == {"matchLabels": selector}
                      and all(template.get("metadata", {}).get("labels", {}).get(key) == item
                              for key, item in selector.items()),
                      "application Deployment selection differs")
    release_annotations(template, runtime)
    (consumer_bindings if consumer_validator is None else consumer_validator)(pod_spec(value), name, image)
    revision = meta.get("annotations", {}).get("deployment.kubernetes.io/revision")
    bootstrap.require(isinstance(revision, str) and re.fullmatch(r"[1-9][0-9]{0,9}", revision),
                      "application Deployment revision is unavailable")
    return release_name, {"name": name, "uid": meta["uid"], "resourceVersion": meta["resourceVersion"],
        "generation": meta["generation"], "revision": int(revision), "replicas": replicas,
        "spec": spec, "labels": labels, "ownership": ownership}


def migration_complete(job: dict, namespace: str, release_name: str, runtime: dict, images: dict) -> bool:
    meta = metadata(job, "Job", namespace)
    labels = meta.get("labels", {})
    bootstrap.require(labels.get("app.kubernetes.io/instance") == release_name
                      and labels.get("app.kubernetes.io/component") == "migrations"
                      and re.fullmatch(r"marty-migrate-[1-9][0-9]*", meta["name"]),
                      "migration Job ownership differs")
    release_annotations(job.get("spec", {}).get("template", {}), runtime)
    spec = pod_spec(job)
    main = spec.get("containers", [])
    initial = spec.get("initContainers", [])
    bootstrap.require(len(main) == 1 and main[0].get("name") == "issuance-native"
                      and main[0].get("image") == images["services"]
                      and main[0].get("command") == ["/usr/local/bin/marty-issuance-service", "migrate"]
                      and main[0].get("args", []) == [], "migration container differs")
    expected_names = ["redis-trust", *MIGRATION_COMMANDS, "ready-organization", "ready-credential-template"]
    bootstrap.require([item.get("name") for item in initial] == expected_names
                      and not spec.get("ephemeralContainers"), "migration container order differs")
    for entry in initial:
        name = entry["name"]
        bootstrap.require(entry.get("image") == images["migrations" if name == "bootstrap-notification" else "services"],
                          "migration image differs")
        if name in MIGRATION_COMMANDS:
            bootstrap.require(entry.get("command") == MIGRATION_COMMANDS[name] and entry.get("args", []) == [],
                              "migration command differs")
    status = job.get("status", {})
    conditions = status.get("conditions", [])
    return (status.get("active", 0) == 0 and status.get("succeeded") == 1
            and any(item.get("type") == "Complete" and item.get("status") == "True" for item in conditions)
            and not any(item.get("type") == "Failed" and item.get("status") == "True" for item in conditions))


def preflight_resources(value: dict, namespace: str, images: dict, runtime: dict) -> dict:
    image = images["services"]
    entries = list_items(value)
    deployments = {item["metadata"]["name"]: item for item in entries if item.get("kind") == "Deployment"}
    bootstrap.require(REQUIRED <= set(deployments), "required application Deployment is missing")
    names = REQUIRED | ({"canvas-sync-worker"} if "canvas-sync-worker" in deployments else set())
    targets, releases = {}, set()
    for name in sorted(names):
        release_name, target = deployment_snapshot(deployments[name], namespace, image, runtime)
        targets[name] = target
        releases.add(release_name)
    bootstrap.require(len(releases) == 1, "application Deployments belong to different Helm releases")
    release_name = next(iter(releases))
    migration_jobs = {}
    for item in entries:
        if item.get("kind") == "Job" and item.get("metadata", {}).get("labels", {}).get("app.kubernetes.io/component") == "migrations":
            bootstrap.require(migration_complete(item, namespace, release_name, runtime, images),
                              "application migrations are not complete")
            migration_jobs[item["metadata"]["uid"]] = item
    bootstrap.require(migration_jobs, "completed application migration evidence is unavailable")
    replica_sets = {item.get("metadata", {}).get("uid"): item for item in entries if item.get("kind") == "ReplicaSet"}
    for item in entries:
        kind = item.get("kind")
        bootstrap.require(kind in {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet", "Pod"},
                          "unsupported Kubernetes workload kind")
        metadata(item, kind, namespace)
        keys = token_references(pod_spec(item))
        if not keys:
            continue
        if kind == "Deployment" and item.get("metadata", {}).get("name") in targets:
            continue
        if kind == "Job" and item.get("metadata", {}).get("uid") in migration_jobs:
            bootstrap.require(keys == {"NOTIFICATION_OPENBAO_TOKEN"}, "migration credential consumption differs")
            continue
        owner = controller(item)
        if kind == "ReplicaSet" and owner and owner[0] == "Deployment" and owner[1] in targets:
            bootstrap.require(owner[2] == targets[owner[1]]["uid"], "ReplicaSet belongs to another Deployment")
            consumer_bindings(pod_spec(item), owner[1], image)
            continue
        if kind == "Pod" and owner and owner[0] == "ReplicaSet" and owner[2] in replica_sets:
            rs_owner = controller(replica_sets[owner[2]])
            bootstrap.require(rs_owner and rs_owner[0] == "Deployment" and rs_owner[1] in targets
                              and rs_owner[2] == targets[rs_owner[1]]["uid"],
                              "application Pod belongs to another Deployment")
            consumer_bindings(pod_spec(item), rs_owner[1], image)
            continue
        if kind == "Pod" and owner and owner[0] == "Job" and owner[2] in migration_jobs:
            bootstrap.require(keys == {"NOTIFICATION_OPENBAO_TOKEN"}
                              and item.get("status", {}).get("phase") == "Succeeded",
                              "migration Pod is still consuming credentials")
            continue
        raise bootstrap.BootstrapError("an unsupported workload consumes application tokens")
    return {"releaseName": release_name, "deployments": targets,
            "migrationUids": sorted(migration_jobs)}


def activation_contract(publication: dict, application: dict) -> dict:
    secrets = [item for item in publication["catalog"]["secrets"] if item["name"] == "marty-secrets"]
    bootstrap.require(len(secrets) == 1, "native application Secret destination differs")
    inputs = []
    for token in application["tokens"]:
        if token["replacementRole"] is None:
            continue
        keys = [key for key, field in secrets[0]["fields"].items() if field.get("env") == token["input"]]
        bootstrap.require(len(keys) == 1 and keys[0] == token["input"], "native application Secret mapping differs")
        inputs.append({"input": token["input"], "file": token["file"], "key": keys[0]})
    bootstrap.require(len(inputs) == 11 and {entry["key"] for entry in inputs} == RUNTIME_KEYS,
                      "native application consumption inventory differs")
    return {"schema": "marty.kubernetes-application-activation/v1", "destination": "marty-secrets",
            "activationAnnotation": ANNOTATION, "minimumTtlSeconds": MINIMUM_TTL,
            "inputs": sorted(inputs, key=lambda entry: entry["input"])}


def original_binding(state: Path) -> tuple[dict, dict]:
    complete = staging.record(state / "bootstrap-complete.json")
    bootstrap.require(complete.get("status") == "openbao-and-application-credentials-ready",
                      "original Kubernetes bootstrap is not complete")
    authority = complete.get("applicationAuthority")
    bootstrap.require(isinstance(authority, dict) and set(authority) == {
        "schema", "binding", "identityDirectory", "files"}
        and authority["schema"] == "marty.kubernetes-application-authority/v1"
        and authority["identityDirectory"] == "application-identity"
        and authority["files"] == sorted(bootstrap.APPLICATION_IDENTITY_FILES),
        "original bootstrap has no supported application authority")
    binding = bootstrap.application_binding(authority["binding"])
    lifecycle = complete["credentialLifecycle"]
    bootstrap.require(binding == {"namespace": complete["namespace"],
        "namespaceUid": lifecycle["namespaceUid"], "openbaoClusterId": complete["openbaoClusterId"],
        "workloadProject": lifecycle["workloadProject"]}, "original application binding differs")
    return complete, binding


def authenticated_context(args: argparse.Namespace, work: Path, complete: dict, binding: dict) -> dict:
    bootstrap.require(complete["runtimeSourceSha"] == args.runtime_source_sha
                      and complete["chartSourceSha"] == args.chart_source_sha,
                      "explicit runtime or chart identity differs from original bootstrap")
    values, _ = bootstrap.prepare(assets=args.assets, runtime_source_sha=args.runtime_source_sha,
        release_tag=args.release_tag, build_run_id=args.build_run_id, build_run_attempt=args.build_run_attempt,
        chart_source_sha=args.chart_source_sha, gh=args.gh, cosign=args.cosign,
        output=work / "marty-images.json", openbao_output=work / "openbao-images.json")
    bootstrap.require(bootstrap.encoded(values) == bootstrap.encoded(staging.record(args.state_dir / "marty-images.json")),
                      "authenticated original runtime differs")
    operator_bytes, _ = bootstrap.authenticated_bootstrap_inputs(args.assets, values["release"])
    retained, _ = staging.private_bytes(args.state_dir / "marty-deploy", staging.OPERATOR_LIMIT, {0o700})
    bootstrap.require(operator_bytes == retained and len(operator_bytes) <= staging.OPERATOR_LIMIT,
                      "retained signed operator differs")
    operator = work / "marty-deploy"
    bootstrap.write_new(operator, operator_bytes, 0o700)
    identity = subprocess.run([str(operator), "--build-identity"], stdin=subprocess.DEVNULL,
                             capture_output=True, check=False, timeout=10, env={})
    bootstrap.require(identity.returncode == 0 and identity.stdout.strip().decode()
                      == args.runtime_source_sha + ":" + args.release_tag, "signed operator build identity differs")
    publication = bootstrap.publication_contract(operator)
    application = bootstrap.application_token_contract(operator)
    bootstrap.require(publication == complete["credentialPublication"]
                      and application == complete["applicationTokenContract"],
                      "original compiled publication contracts differ")
    activation = bootstrap.compiled_contract(operator, "kubernetes-application-activation-contract",
        activation_contract(publication, application), "application activation")
    source = args.state_dir / "application-identity"
    staging.existing_private_directory(source)
    bootstrap.require({path.name for path in source.iterdir()} == bootstrap.APPLICATION_IDENTITY_FILES,
                      "application authority identity inventory differs")
    authority = {name: staging.private_bytes(source / name, bound, {0o400, 0o600})
                 for name, bound in bootstrap.APPLICATION_IDENTITY_LIMITS.items()}
    identity_dir = work / "application-identity"
    bootstrap.private_directory(identity_dir)
    bootstrap.take_application_identity(staging.archive_snapshot(authority), identity_dir, binding, modes={0o400, 0o600})
    kubeconfig, _ = staging.private_bytes(args.state_dir / "kubeconfig", 1024 * 1024, {0o600})
    scoped = json_bytes(kubeconfig, 1024 * 1024)
    bootstrap.require(isinstance(scoped.get("current-context"), str) and scoped["current-context"]
                      and len(scoped.get("contexts", [])) == 1
                      and scoped["contexts"][0].get("name") == scoped["current-context"],
                      "retained Kubernetes context is ambiguous")
    bootstrap.write_new(work / "kubeconfig", kubeconfig)
    kubectl = shutil.which("kubectl")
    bootstrap.require(kubectl is not None, "kubectl must be installed")
    pull_secrets = complete.get("imagePullSecrets")
    bootstrap.require(isinstance(pull_secrets, list) and all(isinstance(name, str) and re.fullmatch(
        r"[a-z0-9][a-z0-9.-]{0,251}[a-z0-9]|[a-z0-9]", name) for name in pull_secrets),
        "retained image pull Secret names are invalid")
    return {"binding": binding, "values": values, "operator": operator, "operatorBytes": operator_bytes,
            "authority": authority, "activation": activation, "pullSecrets": pull_secrets,
            "transport": BoundedTransport(work, work / "kubeconfig", binding["namespace"], kubectl)}


def copy_snapshot(destination: Path, snapshot: dict) -> None:
    bootstrap.private_directory(destination)
    for name, (value, mode) in snapshot.items():
        staging.write_preserved(destination / name, value, mode)
    bootstrap.require(staging.current_snapshot(destination) == snapshot, "private generation copy differs")


def staged_candidate(stage: Path, context: dict, current: dict, destination: Path) -> None:
    staging.existing_private_directory(stage)
    complete = staging.record(stage / "application-stage-complete.json")
    files = {entry["file"] for entry in context["activation"]["inputs"]}
    bootstrap.require(complete.get("schema") == "marty.kubernetes-application-stage-completion/v1"
                      and complete.get("status") == "candidate-staged-not-activated"
                      and complete.get("activation") is False and complete.get("binding") == context["binding"]
                      and complete.get("runtime") == context["values"]["release"]
                      and complete.get("candidateDirectory") == "candidate"
                      and type(complete.get("files")) is int and complete["files"] == len(current)
                      and complete.get("replacedInputs") == sorted(files), "staged application receipt differs")
    original, _ = staging.private_bytes(stage / "current-snapshot.tar", staging.GENERATION_ARCHIVE_LIMIT, {0o600})
    captured = bootstrap.flat_archive(original, set(current), maximum=staging.GENERATION_ARCHIVE_LIMIT,
                                     modes=staging.FILE_MODES, allow_empty=True)
    bootstrap.require(captured == current, "staged candidate belongs to another current generation")
    copy_snapshot(destination, staging.current_snapshot(stage / "candidate"))


def native_publication(context: dict, command: dict) -> dict:
    raw = context["transport"].run("native application Secret validation",
        [str(context["operator"]), "operator", "kubernetes-application-publication"],
        data=bootstrap.encoded(command), env={}, timeout=120)
    result = json_bytes(raw, 4096)
    expected = {"ready": True, "secret": "marty-secrets", "count": 11}
    if command["operation"] == "verify":
        expected["state"] = result.get("state")
        bootstrap.require(expected["state"] in {"candidate", "unchanged"}, "native publication state differs")
    bootstrap.require(result == expected and result.get("ready") is True
                      and type(result.get("count")) is int,
                      "native application publication refused")
    return result


def observe(context: dict, destination: Path, *, secret: bool, timeout: int = 60) -> dict:
    transport = context["transport"]
    args = ["get", "secret", "marty-secrets", "-o", "json"] if secret else ["get", RESOURCE_TYPES, "-o", "json"]
    raw = transport.kubectl("application Secret observation" if secret else "application workload observation",
                            *args, timeout=timeout)
    value = json_bytes(raw)
    bootstrap.write_new(destination, raw)
    return value


def publication_state(context: dict, operation: Path, request: dict, result: Path) -> str:
    return native_publication(context, {"operation": "verify", "namespace": context["binding"]["namespace"],
        "current": request["previousDirectory"], "candidate": str(operation / "candidate"),
        "observed": str(operation / "secret-before.json"), "result": str(result),
        "activationId": request["activationId"]})["state"]


def fresh_proof(context: dict, current: dict, candidate: dict) -> float:
    transport = context["transport"]
    nonce = bootstrap.secrets.token_hex(6)
    bootstrap.check_application_binding(transport, context["binding"])
    pod = bootstrap.create_producer_pod(transport, image=context["values"]["images"]["services"],
        nonce=nonce, pull_secrets=context["pullSecrets"], purpose="application-activation")
    remote_ready, uncertain, complete = False, False, False
    proof_started = None
    try:
        bootstrap.retain_producer_pointer(transport, pod)
        transport.kubectl("native verifier readiness", "wait", "--for=condition=Ready", "pod/" + pod,
                          "--timeout=300s", timeout=330)
        bootstrap.check_application_binding(transport, context["binding"])
        transport.execute(pod, ["/bin/sh", "-ec",
            'umask 077; for path in "$@"; do mkdir "$path"; chmod 700 "$path"; done', "--",
            REMOTE_CURRENT, REMOTE_CANDIDATE, REMOTE_IDENTITY, REMOTE_PROOF])
        remote_ready = True
        transport.upload(pod, REMOTE_OPERATOR, context["operatorBytes"], executable=True)
        copied = transport.execute(pod, ["sha256sum", REMOTE_OPERATOR]).decode().split()
        bootstrap.require(copied and copied[0] == hashlib.sha256(context["operatorBytes"]).hexdigest(),
                          "copied native verifier differs")
        for directory, values in ((REMOTE_CURRENT, current), (REMOTE_CANDIDATE, candidate),
                                  (REMOTE_IDENTITY, context["authority"])):
            transport.execute(pod, ["tar", "-xpf", "-", "-C", directory], data=staging.archive_snapshot(values))
        transport.upload(pod, "/tmp/ca.crt", current["openbao_tls_ca_cert"][0])
        bootstrap.check_application_binding(transport, context["binding"])
        proof_started = time.monotonic()
        transport.deadline = proof_started + ACTIVATION_SECONDS
        uncertain = True
        raw = transport.execute(pod, [REMOTE_OPERATOR, "operator", "application-token-verify",
            "https://openbao:8200", "/tmp/ca.crt", REMOTE_IDENTITY],
            data=bootstrap.encoded({"current": REMOTE_CURRENT, "candidate": REMOTE_CANDIDATE,
                                   "output": REMOTE_PROOF, "binding": context["binding"]}), timeout=600)
        result = json_bytes(raw, 4096)
        bootstrap.require(result == {"ready": True, "count": 11, "minimumTtlSeconds": MINIMUM_TTL}
                          and result.get("ready") is True
                          and type(result.get("count")) is int
                          and type(result.get("minimumTtlSeconds")) is int,
                          "fresh native candidate proof did not confirm readiness")
        uncertain, complete = False, True
    finally:
        retained = not remote_ready
        failures = []
        if remote_ready:
            try:
                evidence = bootstrap.remote_archive(transport, pod, REMOTE_PROOF, PROOF_ARCHIVE_LIMIT)
                bootstrap.private_archive(evidence, {"attempt.json": 8193,
                    "login-response.json": 2 * 1024 * 1024 + 1, "complete.json": 4097},
                    maximum=PROOF_ARCHIVE_LIMIT, modes={0o600}, directories={"."},
                    complete=complete, allow_empty=not complete)
                bootstrap.write_new(transport.state / "native-verification-evidence.tar", evidence)
                retained = True
            except Exception:
                failures.append("private native verification evidence export failed")
        if uncertain:
            failures.append("native verification outcome is uncertain")
        if retained and not uncertain:
            try:
                transport.kubectl("native verifier cleanup", "delete", "pod", pod,
                                  "--wait=true", "--timeout=120s", timeout=150)
            except Exception:
                failures.append("native verifier cleanup failed")
        else:
            failures.append("native verifier retained within its remaining original 1200-second lifetime")
        if failures:
            raise bootstrap.BootstrapError("; ".join(failures) + "; preserve the private attempt")
    bootstrap.require(complete and proof_started is not None, "native verification was not completed")
    return proof_started + ACTIVATION_SECONDS


def remaining(deadline: float) -> int:
    seconds = math.floor(deadline - time.monotonic())
    bootstrap.require(seconds > 5, "application activation total deadline expired")
    return seconds


def target_spec(before: dict, activation_id: str, *, annotation: str = ANNOTATION) -> dict:
    result = json.loads(bootstrap.encoded(before["spec"]))
    annotations = result["template"].setdefault("metadata", {}).setdefault("annotations", {})
    bootstrap.require(isinstance(annotations, dict) and annotations.get(annotation) != activation_id,
                      "application activation marker already exists in its original template")
    annotations[annotation] = activation_id
    return result


def context_deployment_snapshot(context: dict, resource: dict) -> tuple[str, dict]:
    """Reuse the same guarded Deployment protocol for another closed consumer graph."""
    if "deploymentSnapshot" in context:
        return context["deploymentSnapshot"](resource)
    return deployment_snapshot(resource, context["binding"]["namespace"],
        context["values"]["images"]["services"], context["values"]["release"])


def same_target(resource: dict, before: dict, activation_id: str, context: dict) -> dict:
    _, observed = context_deployment_snapshot(context, resource)
    bootstrap.require(observed["uid"] == before["uid"] and observed["labels"] == before["labels"]
                      and observed["ownership"] == before["ownership"]
                      and observed["spec"] == target_spec(before, activation_id, annotation=context.get("activationAnnotation", ANNOTATION))
                      and observed["generation"] == before["generation"] + 1,
                      "application rollout was changed by another writer")
    return observed


def deployment_get(context: dict, name: str, deadline: float) -> dict:
    return json_bytes(context["transport"].kubectl("application Deployment observation", "get",
        "deployment", name, "-o", "json", timeout=min(60, remaining(deadline))))


def rollout_one(context: dict, operation: Path, before: dict, activation_id: str, deadline: float) -> int:
    name = before["name"]
    dispatched = operation / (name + "-rollout-requested.json")
    live = deployment_get(context, name, deadline)
    marker = live.get("spec", {}).get("template", {}).get("metadata", {}).get("annotations", {}).get(context.get("activationAnnotation", ANNOTATION))
    if not dispatched.exists():
        _, observed = context_deployment_snapshot(context, live)
        bootstrap.require(observed == {**before, "resourceVersion": observed["resourceVersion"]},
                          "application Deployment changed before its rollout")
        bootstrap.write_new(operation / (name + "-before-rollout.json"), bootstrap.encoded(live))
        patch = [{"op": "test", "path": "/metadata/uid", "value": before["uid"]},
                 {"op": "test", "path": "/metadata/resourceVersion", "value": observed["resourceVersion"]},
                 {"op": "add", "path": "/spec/template/metadata/annotations",
                  "value": target_spec(before, activation_id, annotation=context.get("activationAnnotation", ANNOTATION))["template"]["metadata"]["annotations"]}]
        patch_file = operation / (name + "-rollout-patch.json")
        bootstrap.write_new(patch_file, bootstrap.encoded(patch))
        bootstrap.write_new(dispatched, bootstrap.encoded({"schema": context.get("rolloutRequestSchema", "marty.kubernetes-application-rollout-request/v1"),
            "activationId": activation_id, "name": name, "uid": before["uid"],
            "resourceVersion": observed["resourceVersion"], "generation": before["generation"] + 1}))
        response = context["transport"].kubectl("application Deployment rollout", "patch", "deployment", name,
            "--type=json", "--patch-file", str(patch_file), "-o", "json", timeout=min(60, remaining(deadline)))
        json_bytes(response)
        bootstrap.write_new(operation / (name + "-rollout-response.json"), response)
    else:
        retained = private_json(operation / (name + "-before-rollout.json"))
        _, guarded = context_deployment_snapshot(context, retained)
        bootstrap.require(guarded == {**before, "resourceVersion": guarded["resourceVersion"]},
                          "retained rollout precondition differs")
        receipt = staging.record(dispatched)
        bootstrap.require(receipt == {"schema": context.get("rolloutRequestSchema", "marty.kubernetes-application-rollout-request/v1"),
            "activationId": activation_id, "name": name, "uid": before["uid"],
            "resourceVersion": guarded["resourceVersion"], "generation": before["generation"] + 1},
            "retained rollout request differs")
        bootstrap.require(marker == activation_id,
                          "previous rollout request is uncertain; it will not be repeated")
    while True:
        live = deployment_get(context, name, deadline)
        observed = same_target(live, before, activation_id, context)
        status = live.get("status", {})
        if (type(status.get("observedGeneration")) is int
                and status["observedGeneration"] >= observed["generation"]
                and observed["revision"] > before["revision"]):
            break
        time.sleep(min(1, remaining(deadline)))
    budget = remaining(deadline)
    revision_record = operation / (name + "-rollout-revision.json")
    revision_proof = {"name": name, "uid": observed["uid"], "generation": observed["generation"],
                      "revision": observed["revision"], "activationId": activation_id}
    if revision_record.exists():
        bootstrap.require(staging.record(revision_record) == revision_proof,
                          "application pinned rollout revision changed")
    else:
        bootstrap.write_new(revision_record, bootstrap.encoded(revision_proof))
    context["transport"].kubectl("application pinned rollout readiness", "rollout", "status", "deployment/" + name,
        "--revision=" + str(observed["revision"]), "--timeout=" + str(budget - 5) + "s", timeout=budget)
    final = same_target(deployment_get(context, name, deadline), before, activation_id, context)
    bootstrap.require(final["revision"] == observed["revision"], "application pinned rollout revision changed")
    return observed["revision"]


def verified_workloads(value: dict, context: dict, original: dict, activation_id: str,
                       revisions: dict[str, int]) -> list[dict]:
    observed_graph = (context["preflightResources"](value) if "preflightResources" in context else
        preflight_resources(value, context["binding"]["namespace"],
            context["values"]["images"], context["values"]["release"]))
    bootstrap.require(observed_graph["releaseName"] == original["releaseName"]
                      and observed_graph["migrationUids"] == original["migrationUids"]
                      and set(observed_graph["deployments"]) == set(original["deployments"]),
                      "application consumer or migration membership changed")
    entries = list_items(value)
    result = []
    for name, before in sorted(original["deployments"].items()):
        resource = next(item for item in entries if item.get("kind") == "Deployment" and item["metadata"]["name"] == name)
        selected = same_target(resource, before, activation_id, context)
        status = resource.get("status", {})
        count = before["replicas"]
        bootstrap.require(type(status.get("observedGeneration")) is int
                          and status["observedGeneration"] >= selected["generation"]
                          and selected["revision"] == revisions[name] > before["revision"]
                          and all(type(status.get(key)) is int and status[key] == count
                                  for key in ("replicas", "updatedReplicas", "readyReplicas", "availableReplicas"))
                          and status.get("unavailableReplicas", 0) == 0,
                          "application Deployment rollout is incomplete")
        replica_sets = [item for item in entries if item.get("kind") == "ReplicaSet"
                        and controller(item) == ("Deployment", name, before["uid"])]
        target_sets = [item for item in replica_sets
                       if item.get("spec", {}).get("template", {}).get("metadata", {}).get("annotations", {}).get(context.get("activationAnnotation", ANNOTATION)) == activation_id]
        bootstrap.require(len(target_sets) == 1, "application rollout ReplicaSet is ambiguous")
        selected_set = target_sets[0]
        set_meta = metadata(selected_set, "ReplicaSet", context["binding"]["namespace"])
        bootstrap.require(set_meta.get("annotations", {}).get("deployment.kubernetes.io/revision") == str(selected["revision"])
                          and selected_set.get("spec", {}).get("replicas") == count,
                          "application rollout ReplicaSet revision differs")
        all_uids = {item["metadata"]["uid"] for item in replica_sets}
        pods = [item for item in entries if item.get("kind") == "Pod"
                and (owner := controller(item)) and owner[0] == "ReplicaSet" and owner[2] in all_uids
                and item.get("status", {}).get("phase") not in {"Succeeded", "Failed"}]
        bootstrap.require(len(pods) == count, "application rollout still has old or missing Pods")
        pod_uids = []
        for pod in pods:
            pod_meta = metadata(pod, "Pod", context["binding"]["namespace"])
            bootstrap.require(controller(pod) == ("ReplicaSet", set_meta["name"], set_meta["uid"])
                              and pod_meta.get("annotations", {}).get(context.get("activationAnnotation", ANNOTATION)) == activation_id
                              and pod.get("status", {}).get("phase") == "Running"
                              and any(item.get("type") == "Ready" and item.get("status") == "True"
                                      for item in pod.get("status", {}).get("conditions", [])),
                              "application rollout Pod identity or readiness differs")
            statuses = pod.get("status", {}).get("containerStatuses", [])
            bootstrap.require(len(statuses) == 1 and statuses[0].get("name") == name
                              and statuses[0].get("ready") is True,
                              "application rollout container is not ready")
            release_annotations({"metadata": pod_meta}, context["values"]["release"])
            pod_uids.append(pod_meta["uid"])
        result.append({"name": name, "uid": before["uid"], "generation": selected["generation"],
                       "revision": selected["revision"], "podUids": sorted(pod_uids)})
    return result


def delivered_credentials(context: dict, resources: dict, workloads: list[dict], candidate: dict,
                          deadline: float) -> None:
    """Observe delivered bytes privately; never infer authenticated workflow use."""
    pods = {item.get("metadata", {}).get("uid"): item for item in list_items(resources)
            if item.get("kind") == "Pod"}
    files = {entry["key"]: entry["file"] for entry in context["activation"]["inputs"]}
    for workload in workloads:
        name = workload["name"]
        for uid in workload["podUids"]:
            selected = pods[uid]
            pod_name = selected["metadata"]["name"]
            before = json_bytes(context["transport"].kubectl("application Pod delivery identity", "get", "pod",
                pod_name, "-o", "json", timeout=min(60, remaining(deadline))))
            bootstrap.require(before.get("metadata", {}).get("uid") == uid
                              and controller(before) == controller(selected)
                              and before.get("spec") == selected.get("spec")
                              and before.get("metadata", {}).get("annotations") == selected.get("metadata", {}).get("annotations"),
                              "application Pod changed before private delivery proof")
            for key, (_variable, path) in BINDINGS[name].items():
                value = candidate[files[key]][0]
                value = value[:-1] if value.endswith(b"\n") else value
                bootstrap.require(20 <= len(value) <= 1024 and all(33 <= byte <= 126 for byte in value),
                                  "native-verified candidate token format differs")
                script = (DELIVERY_ENV if path is None else DELIVERY_NOTIFICATION_FILE
                          if key == "NOTIFICATION_OPENBAO_TOKEN" else DELIVERY_FILE)
                arguments = [] if path is None else [path]
                raw = context["transport"].kubectl("private application credential delivery", "exec", "-i", pod_name,
                    "--container", name, "--", "/bin/sh", "-ec", script, "--", *arguments,
                    data=value + b"\n", timeout=min(60, remaining(deadline)))
                bootstrap.require(raw == DELIVERY_OK, "application credential delivery differs")
            after = json_bytes(context["transport"].kubectl("application Pod delivery identity", "get", "pod",
                pod_name, "-o", "json", timeout=min(60, remaining(deadline))))
            bootstrap.require(after.get("metadata", {}).get("uid") == uid
                              and controller(after) == controller(selected)
                              and after.get("spec") == selected.get("spec")
                              and after.get("metadata", {}).get("annotations") == selected.get("metadata", {}).get("annotations"),
                              "application Pod changed during private delivery proof")


def validate_request(request: dict, context: dict, operation: Path, selected: object) -> None:
    bootstrap.require(set(request) == {"schema", "binding", "runtime", "activationId", "operationDirectory",
        "candidateDirectory", "previousDirectory", "stageDirectory", "currentFiles"}
        and request["schema"] == "marty.kubernetes-application-activation-request/v1"
        and request["binding"] == context["binding"] and request["runtime"] == context["values"]["release"]
        and re.fullmatch(r"[0-9a-f]{32}", request["activationId"])
        and request["operationDirectory"] == str(operation)
        and request["candidateDirectory"] == str(operation / "candidate")
        and request["previousDirectory"] == str(selected.directory)
        and type(request["currentFiles"]) is int and 0 < request["currentFiles"] <= staging.MAX_FILES,
        "retained activation request differs")


def activate(args: argparse.Namespace) -> None:
    bootstrap.require(os.name == "posix", "this development transport requires Linux")
    state, operation = args.state_dir, args.operation_dir
    staging.existing_private_directory(state)
    bootstrap.require(operation.is_absolute() and operation.resolve() == operation
                      and operation != state and not operation.is_relative_to(state / "credentials")
                      and not operation.is_relative_to(state / "application-identity")
                      and not operation.is_relative_to(state / "renewal-identity"),
                      "activation operation overlaps retained private inputs")
    with application_state.locked(state) as held:
        complete, binding = original_binding(state)
        pending = held.pending(binding) if args.reconcile else None
        selected = held.current(binding,
            pending_operation=operation if args.reconcile and pending is not None else None)
        if args.reconcile:
            staging.existing_private_directory(operation)
        else:
            bootstrap.require(args.stage_dir is not None, "a completed staging directory is required")
            bootstrap.require(not operation.is_relative_to(selected.directory)
                              and not operation.is_relative_to(args.stage_dir),
                              "activation operation overlaps current or staged inputs")
            bootstrap.private_directory(operation)
        work = operation / ("inspection-" + bootstrap.secrets.token_hex(6))
        bootstrap.private_directory(work)
        context = authenticated_context(args, work, complete, binding)
        if args.reconcile and pending is None:
            proof = staging.record(operation / VERIFIED)
            finished = staging.record(operation / COMPLETE)
            bootstrap.require(selected.directory == operation / "candidate"
                              and selected.activation_id == proof.get("activationId")
                              and proof.get("binding") == binding
                              and proof.get("runtime") == context["values"]["release"]
                              and finished == {**proof, "schema": "marty.kubernetes-application-activation-completion/v1",
                                               "status": "application-generation-selected"},
                              "completed activation selection differs")
            print("Application activation was already recorded; no new cluster mutation was requested.")
            return
        current = staging.current_snapshot(selected.directory)
        bootstrap.require("openbao_tls_ca_cert" in current, "retained OpenBao trust is unavailable")
        if not args.reconcile:
            staged_candidate(args.stage_dir, context, current, operation / "candidate")
            bootstrap.write_new(operation / "current-snapshot.tar", staging.archive_snapshot(current))
        else:
            captured = bootstrap.flat_archive(staging.private_bytes(operation / "current-snapshot.tar",
                staging.GENERATION_ARCHIVE_LIMIT, {0o600})[0], set(current),
                maximum=staging.GENERATION_ARCHIVE_LIMIT, modes=staging.FILE_MODES, allow_empty=True)
            bootstrap.require(captured == current, "retained previous generation changed")
        candidate = staging.current_snapshot(operation / "candidate")
        staging.verify_result(staging.native_generation(context["transport"], str(context["operator"]), {
            "operation": "application-verify", "current": str(selected.directory),
            "candidate": str(operation / "candidate")}), len(current), 11)
        bootstrap.check_application_binding(context["transport"], binding)
        if not args.reconcile:
            secret = observe(context, operation / "secret-before.json", secret=True)
            bootstrap.require(secret.get("metadata", {}).get("annotations", {}).get(ANNOTATION) == selected.activation_id,
                              "active Secret marker differs from current generation selection")
            resources = observe(context, operation / "workloads-before.json", secret=False)
            graph = preflight_resources(resources, binding["namespace"], context["values"]["images"],
                                        context["values"]["release"])
            activation_id = bootstrap.secrets.token_hex(16)
            native_publication(context, {"operation": "prepare", "namespace": binding["namespace"],
                "current": str(selected.directory), "candidate": str(operation / "candidate"),
                "observed": str(operation / "secret-before.json"), "output": str(operation / "secret-patch.json"),
                "activationId": activation_id})
            request = {"schema": "marty.kubernetes-application-activation-request/v1", "binding": binding,
                "runtime": context["values"]["release"], "activationId": activation_id,
                "operationDirectory": str(operation), "candidateDirectory": str(operation / "candidate"),
                "previousDirectory": str(selected.directory), "stageDirectory": str(args.stage_dir),
                "currentFiles": len(current)}
            bootstrap.write_new(operation / REQUEST, bootstrap.encoded(request))
            held.begin(binding, operation, operation / "candidate", activation_id, expected=selected)
        else:
            request = staging.record(operation / REQUEST)
            validate_request(request, context, operation, selected)
            graph = preflight_resources(private_json(operation / "workloads-before.json"), binding["namespace"],
                context["values"]["images"], context["values"]["release"])
            original = private_json(operation / "secret-before.json")
            bootstrap.require(original.get("metadata", {}).get("annotations", {}).get(ANNOTATION) == selected.activation_id,
                              "retained Secret marker differs from previous generation selection")
        deadline = fresh_proof(context, current, candidate)
        bootstrap.require(staging.current_snapshot(selected.directory) == current
                          and staging.current_snapshot(operation / "candidate") == candidate,
                          "local credential generations changed during fresh proof")
        bootstrap.check_application_binding(context["transport"], binding)
        before_dispatch = work / "secret-before-dispatch.json"
        observe(context, before_dispatch, secret=True, timeout=min(60, remaining(deadline)))
        state_now = publication_state(context, operation, request, before_dispatch)
        dispatched = operation / "secret-patch-requested.json"
        if args.reconcile:
            bootstrap.require(dispatched.exists() and state_now == "candidate",
                              "Secret publication is unchanged or uncertain; its request will not be repeated")
            bootstrap.require(staging.record(dispatched) == {"schema": "marty.kubernetes-application-secret-request/v1",
                "activationId": request["activationId"], "secret": "marty-secrets"},
                "retained Secret request differs")
        else:
            bootstrap.require(state_now == "unchanged", "Secret changed before activation dispatch")
            bootstrap.write_new(dispatched, bootstrap.encoded({"schema": "marty.kubernetes-application-secret-request/v1",
                "activationId": request["activationId"], "secret": "marty-secrets"}))
            response = context["transport"].kubectl("application Secret activation", "patch", "secret", "marty-secrets",
                "--type=json", "--patch-file", str(operation / "secret-patch.json"), "-o", "json",
                timeout=min(60, remaining(deadline)))
            json_bytes(response)
            bootstrap.write_new(operation / "secret-patch-response.json", response)
            after_dispatch = work / "secret-after-dispatch.json"
            observe(context, after_dispatch, secret=True, timeout=min(60, remaining(deadline)))
            bootstrap.require(publication_state(context, operation, request, after_dispatch) == "candidate",
                              "Secret activation did not confirm the candidate")
        # The Secret request is never repeated. A remaining Deployment can be
        # patched only from its original UID/specification/generation with a
        # guarded current resourceVersion. A dispatched one must already carry
        # this attempt's marker before reconciliation waits.
        revisions = {target["name"]: rollout_one(context, operation, target, request["activationId"], deadline)
                     for target in graph["deployments"].values()}
        final_resources = observe(context, work / "workloads-final.json", secret=False,
                                  timeout=min(60, remaining(deadline)))
        workloads = verified_workloads(final_resources, context, graph, request["activationId"], revisions)
        delivered_credentials(context, final_resources, workloads, candidate, deadline)
        after_delivery = observe(context, work / "workloads-after-delivery.json", secret=False,
                                 timeout=min(60, remaining(deadline)))
        bootstrap.require(verified_workloads(after_delivery, context, graph, request["activationId"], revisions) == workloads,
                          "application workloads changed during private delivery proof")
        final_secret_path = work / "secret-final.json"
        final_secret = observe(context, final_secret_path, secret=True, timeout=min(60, remaining(deadline)))
        bootstrap.require(publication_state(context, operation, request, final_secret_path) == "candidate",
                          "application Secret changed during rollout")
        bootstrap.check_application_binding(context["transport"], binding)
        remaining(deadline)
        bootstrap.require(staging.current_snapshot(selected.directory) == current
                          and staging.current_snapshot(operation / "candidate") == candidate,
                          "local credential generations changed during activation")
        proof = {"schema": "marty.kubernetes-application-activation-verified/v1", "binding": binding,
            "activationId": request["activationId"], "operationDirectory": str(operation),
            "candidateDirectory": str(operation / "candidate"), "previousDirectory": str(selected.directory),
            "runtime": context["values"]["release"], "secret": {"name": "marty-secrets",
                "uid": final_secret["metadata"]["uid"], "resourceVersion": final_secret["metadata"]["resourceVersion"]},
            "deployments": workloads, "status": "secret-and-rollouts-verified",
            "credentialDeliveryVerified": True, "credentialConsumptionVerified": False}
        if (operation / VERIFIED).exists():
            bootstrap.require(staging.record(operation / VERIFIED) == proof,
                              "previous activation proof no longer matches live observations")
        else:
            bootstrap.write_new(operation / VERIFIED, bootstrap.encoded(proof))
        remaining(deadline)
        held.publish(binding, operation, expected=selected)
        remaining(deadline)
        held.complete(binding, operation)
        remaining(deadline)
        held.finish(binding, operation, check_deadline=lambda: remaining(deadline))
    print("Application Secret and the selected Deployment rollouts were verified; the candidate generation is current.")
    print("Keep the private activation attempt. Runtime credential-use acceptance, TLS/Keycloak renewal and expiry recovery remain separate.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("state-dir", "operation-dir", "assets", "gh", "cosign"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--stage-dir", type=Path)
    parser.add_argument("--reconcile", action="store_true")
    for name in ("runtime-source-sha", "chart-source-sha", "release-tag"):
        parser.add_argument("--" + name, required=True)
    for name in ("build-run-id", "build-run-attempt"):
        parser.add_argument("--" + name, required=True, type=int)
    try:
        activate(parser.parse_args(argv))
    except (bootstrap.BootstrapError, ValueError, OSError, subprocess.TimeoutExpired,
            KeyError, TypeError, tarfile.TarError) as error:
        detail = str(error) if isinstance(error, bootstrap.BootstrapError) else type(error).__name__
        parser.exit(1, f"Kubernetes application activation stopped: {detail}. "
                    "Preserve the private attempt; the cluster may have changed. "
                    "Reconcile this same operation; do not repeat Secret publication.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
