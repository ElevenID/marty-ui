#!/usr/bin/env python3
"""Activate a staged TLS/Keycloak generation through existing Kubernetes owners.

The signed operator validates the complete generation and prepares each closed
Secret update. Kubernetes Deployment controllers own adoption. One retained
attempt records every Secret request before dispatch; reconciliation observes a
requested update without replaying it and may dispatch only untouched remaining
Secrets. Completion proves credential delivery, not authenticated runtime use.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import time

import activate_kubernetes_application_credentials as application
import bootstrap_kubernetes_openbao as bootstrap
import kubernetes_application_state as selection
import stage_kubernetes_application_credentials as staging
import stage_kubernetes_renewal_credentials as renewal

ANNOTATION = "marty.elevenid.com/renewal-activation"
MINIMUM_TTL = 3600
ACTIVATION_SECONDS = 900
VERIFICATION_SECONDS = 600
REQUEST = "renewal-activation-requested.json"
VERIFIED = "renewal-activation-verified.json"
COMPLETE = "renewal-activation-complete.json"
EVIDENCE_LIMIT = 512 * 1024
REMOTE_CURRENT = renewal.REMOTE_CURRENT
REMOTE_CANDIDATE = renewal.REMOTE_CANDIDATE
REMOTE_IDENTITY = renewal.REMOTE_IDENTITY
REMOTE_BINDING = renewal.REMOTE_BINDING
REMOTE_PROOF = renewal.REMOTE_OPERATION
REMOTE_OPERATOR = renewal.REMOTE_OPERATOR

# Runtime consumption graph only. Input/file/Secret/key mappings remain owned by
# the authenticated native publication catalog and existing producer inventories.
TLS_BINDINGS = (
    ("auth", "AUTH_WORKLOAD_CLIENT_CERT", "GRPC_WORKLOAD_TLS_CLIENT_CERT",
     "AUTH_TLS_KMS_TOKEN", "GRPC_WORKLOAD_TLS_CLIENT_KMS_TOKEN_FILE"),
    ("auth", "AUTH_WORKLOAD_SERVER_CERT", "GRPC_WORKLOAD_TLS_SERVER_CERT",
     "AUTH_SERVER_TLS_KMS_TOKEN", "GRPC_WORKLOAD_TLS_SERVER_KMS_TOKEN_FILE"),
    ("flow", "FLOW_WORKLOAD_CLIENT_CERT", "GRPC_WORKLOAD_TLS_CLIENT_CERT",
     "FLOW_CLIENT_TLS_KMS_TOKEN", "GRPC_WORKLOAD_TLS_CLIENT_KMS_TOKEN_FILE"),
    ("flow", "FLOW_WORKLOAD_SERVER_CERT", "GRPC_WORKLOAD_TLS_SERVER_CERT",
     "FLOW_SERVER_TLS_KMS_TOKEN", "GRPC_WORKLOAD_TLS_SERVER_KMS_TOKEN_FILE"),
    ("gateway", "GATEWAY_WORKLOAD_CLIENT_CERT", "GRPC_WORKLOAD_TLS_CLIENT_CERT",
     "GATEWAY_TLS_KMS_TOKEN", "GRPC_WORKLOAD_TLS_CLIENT_KMS_TOKEN_FILE"),
    ("organization", "ORG_WORKLOAD_SERVER_CERT", "GRPC_WORKLOAD_TLS_SERVER_CERT",
     "ORG_TLS_KMS_TOKEN", "GRPC_WORKLOAD_TLS_SERVER_KMS_TOKEN_FILE"),
    ("credential-template", "CT_WORKLOAD_SERVER_CERT", "GRPC_WORKLOAD_TLS_SERVER_CERT",
     "CT_TLS_KMS_TOKEN", "GRPC_WORKLOAD_TLS_SERVER_KMS_TOKEN_FILE"),
    ("revocation-profile", "RP_WORKLOAD_SERVER_CERT", "GRPC_WORKLOAD_TLS_SERVER_CERT",
     "RP_TLS_KMS_TOKEN", "GRPC_WORKLOAD_TLS_SERVER_KMS_TOKEN_FILE"),
    ("event-stream", "ES_WORKLOAD_SERVER_CERT", "GRPC_WORKLOAD_TLS_SERVER_CERT",
     "ES_TLS_KMS_TOKEN", "GRPC_WORKLOAD_TLS_SERVER_KMS_TOKEN_FILE"),
    ("notification", "NOTIFICATION_WORKLOAD_SERVER_CERT", "GRPC_TLS_CERT",
     "NOTIFICATION_TLS_KMS_TOKEN", "GRPC_TLS_KMS_TOKEN_FILE"),
    ("presentation-policy", "PP_WORKLOAD_SERVER_CERT", "GRPC_WORKLOAD_TLS_SERVER_CERT",
     "PP_TLS_KMS_TOKEN", "GRPC_WORKLOAD_TLS_SERVER_KMS_TOKEN_FILE"),
    ("issuance-native", "ISSUANCE_WORKLOAD_SERVER_CERT", "GRPC_WORKLOAD_TLS_SERVER_CERT",
     "ISSUANCE_TLS_KMS_TOKEN", "GRPC_WORKLOAD_TLS_SERVER_KMS_TOKEN_FILE"),
    ("verification", "VERIFICATION_WORKLOAD_CLIENT_CERT", "GRPC_WORKLOAD_TLS_CLIENT_CERT",
     "VERIFICATION_TLS_KMS_TOKEN", "GRPC_WORKLOAD_TLS_KMS_TOKEN_FILE"),
    ("deployment-profile", "DEPLOYMENT_PROFILE_WORKLOAD_CLIENT_CERT", "GRPC_WORKLOAD_TLS_CLIENT_CERT",
     "DEPLOYMENT_PROFILE_TLS_KMS_TOKEN", "GRPC_WORKLOAD_TLS_KMS_TOKEN_FILE"),
    ("compliance-profile", "COMPLIANCE_PROFILE_WORKLOAD_CLIENT_CERT", "GRPC_WORKLOAD_TLS_CLIENT_CERT",
     "COMPLIANCE_PROFILE_TLS_KMS_TOKEN", "GRPC_WORKLOAD_TLS_KMS_TOKEN_FILE"),
    ("signing-keys", "SIGNING_KEYS_WORKLOAD_SERVER_CERT", "SIGNING_KEYS_INTEGRATION_SECRET_TLS_CERT_FILE",
     "SIGNING_KEYS_TLS_KMS_TOKEN", "SIGNING_KEYS_INTEGRATION_SECRET_TLS_KMS_TOKEN_FILE"),
)
CA_PROJECTIONS = {
    "gateway": ("ORG_WORKLOAD_SERVER_CERT", ("GRPC_TLS_CA_CERT", "ORG_GRPC_CA_CERT", "ES_GRPC_CA_CERT")),
    "trust-profile": ("ORG_WORKLOAD_SERVER_CERT", ("ORG_GRPC_CA_CERT",)),
    "device-registration": ("ORG_WORKLOAD_SERVER_CERT", ("ORG_GRPC_CA_CERT",)),
    "applicant": ("ES_WORKLOAD_SERVER_CERT", ("ES_GRPC_CA_CERT",)),
}
REQUIRED = {row[0] for row in TLS_BINDINGS} | set(CA_PROJECTIONS) | {"keycloak"}
# Both signed service and Keycloak images already qualify these GNU utilities.
# Expected credential bytes never enter argv or diagnostics. stdout is retained
# privately by Transport and compared as complete bytes, including PEM newlines.
DELIVERY_FILE = (
    'resolved=$(readlink -f -- "$1"); [ -f "$resolved" ]; '
    'size=$(stat -c "%s" -- "$resolved"); [ "$size" -gt 0 ]; [ "$size" -le 65536 ]; '
    'identity=$(stat -c "%d:%i:%s:%Y:%Z" -- "$resolved"); '
    'dd if="$resolved" iflag=nofollow,nonblock,count_bytes count=65537 status=none; '
    '[ "$(readlink -f -- "$1")" = "$resolved" ]; '
    '[ "$(stat -c "%d:%i:%s:%Y:%Z" -- "$resolved")" = "$identity" ]'
)


def activation_contract(publication: dict) -> dict:
    changed = (set(bootstrap.SELFHOST_TLS_FILES) | bootstrap.KEYCLOAK_FILES) - {"workload_identity_ca_cert"}
    inputs = []
    for name in sorted(changed):
        variable = name.upper()
        matches = [{"input": variable, "file": name, "secret": secret["name"], "key": key}
                   for secret in publication["catalog"]["secrets"]
                   for key, field in secret["fields"].items() if field.get("env") == variable]
        bootstrap.require(len(matches) == 1, "native Renewal Secret mapping differs")
        inputs.extend(matches)
    bootstrap.require(len(inputs) == 39 and len({item["secret"] for item in inputs}) == 33,
                      "native Renewal activation inventory differs")
    return {"schema": "marty.kubernetes-renewal-activation/v1", "minimumTtlSeconds": MINIMUM_TTL,
            "secretCount": 33, "changedFiles": 39, "activationAnnotation": ANNOTATION,
            "inputs": sorted(inputs, key=lambda item: item["input"])}


def input_map(contract: dict) -> dict:
    return {entry["input"]: entry for entry in contract["inputs"]}


def secret_names(contract: dict) -> set[str]:
    return {entry["secret"] for entry in contract["inputs"]}


def references(spec: dict, names: set[str]) -> set[str]:
    result = set()
    for group in ("containers", "initContainers", "ephemeralContainers"):
        entries = spec.get(group, [])
        bootstrap.require(isinstance(entries, list) and all(isinstance(item, dict) for item in entries),
                          "Renewal container inventory differs")
        for entry in entries:
            for env in entry.get("env", []):
                name = env.get("valueFrom", {}).get("secretKeyRef", {}).get("name")
                if name in names:
                    result.add(name)
            for env in entry.get("envFrom", []):
                name = env.get("secretRef", {}).get("name")
                if name in names:
                    result.add(name)
    for volume in spec.get("volumes", []):
        name = volume.get("secret", {}).get("secretName")
        if name in names:
            result.add(name)
        for source in volume.get("projected", {}).get("sources", []):
            name = source.get("secret", {}).get("name")
            if name in names:
                result.add(name)
    return result


def expected_secrets(name: str, contract: dict) -> set[str]:
    inputs = input_map(contract)
    if name == "keycloak":
        return {inputs[filename.upper()]["secret"] for filename in bootstrap.KEYCLOAK_FILES}
    expected = {inputs[variable]["secret"] for row in TLS_BINDINGS if row[0] == name
                for variable in (row[1], row[3])}
    if name in CA_PROJECTIONS:
        expected.add(inputs[CA_PROJECTIONS[name][0]]["secret"])
    return expected


def projected_paths(spec: dict, name: str, contract: dict) -> dict[tuple[str, str], str]:
    names = secret_names(contract)
    expected = expected_secrets(name, contract)
    bootstrap.require(references(spec, names) == expected, "Renewal consumer Secret inventory differs")
    containers = spec.get("containers", [])
    bootstrap.require(isinstance(containers, list) and len(containers) == 1
                      and containers[0].get("name") == name, "Renewal consumer container differs")
    container = containers[0]
    bootstrap.require(not references({"containers": [container]}, names),
                      "Renewal credentials must use the existing file projections")
    volumes, mounts = spec.get("volumes", []), container.get("volumeMounts", [])
    bootstrap.require(isinstance(volumes, list) and isinstance(mounts, list)
                      and all(isinstance(item, dict) for item in volumes + mounts)
                      and len({item.get("name") for item in volumes}) == len(volumes)
                      and len({item.get("name") for item in mounts}) == len(mounts),
                      "Renewal volume identity is ambiguous")
    selected = {}
    volume_names = set()
    for volume in volumes:
        secret = volume.get("secret", {})
        if secret.get("secretName") not in expected:
            continue
        secret_name = secret["secretName"]
        chosen = [item for item in mounts if item.get("name") == volume.get("name")]
        bootstrap.require(len(chosen) == 1 and "items" not in secret
                          and secret.get("optional", False) is False
                          and secret_name not in selected,
                          "Renewal Secret projection differs")
        mount = chosen[0]
        path = mount.get("mountPath")
        bootstrap.require(isinstance(path, str) and path.startswith("/")
                          and str(PurePosixPath(path)) == path and ".." not in PurePosixPath(path).parts
                          and path != "/" and mount.get("readOnly") is True
                          and "subPath" not in mount and "subPathExpr" not in mount,
                          "Renewal read-only projection path differs")
        bootstrap.require(not any(other is not mount and isinstance(other.get("mountPath"), str)
            and (other["mountPath"] == path or other["mountPath"].startswith(path + "/"))
            for other in mounts), "Renewal file projection is shadowed")
        selected[secret_name] = path
        volume_names.add(volume["name"])
    bootstrap.require(set(selected) == expected, "Renewal simple Secret projection is missing")
    bootstrap.require(volume_names == {volume.get("name") for volume in volumes
                                       if references({"volumes": [volume]}, names)},
                      "Renewal Secret has an additional or projected volume")
    for entry in spec.get("initContainers", []) + spec.get("ephemeralContainers", []):
        bootstrap.require(not references({"containers": [entry]}, names)
                          and not any(item.get("name") in volume_names for item in entry.get("volumeMounts", [])),
                          "Renewal Secret has an additional container consumer")
    return {(entry["secret"], entry["key"]): selected[entry["secret"]] + "/" + entry["key"]
            for entry in contract["inputs"] if entry["secret"] in selected}


def consumer_bindings(spec: dict, name: str, image: str, contract: dict) -> None:
    paths = projected_paths(spec, name, contract)
    container = spec["containers"][0]
    bootstrap.require(container.get("image") == image, "Renewal consumer signed image differs")
    environments = container.get("env", [])
    bootstrap.require(isinstance(environments, list)
                      and all(isinstance(item, dict) and isinstance(item.get("name"), str) for item in environments)
                      and len({item["name"] for item in environments}) == len(environments),
                      "Renewal consumer environment is ambiguous")
    env = {item["name"]: item for item in environments}
    inputs = input_map(contract)
    if name == "keycloak":
        bootstrap.require(container.get("command") == ["/opt/keycloak/bin/kc.sh"]
                          and container.get("args") == ["start", "--import-realm", "--features=organization"]
                          and container.get("envFrom") == [{"configMapRef": {"name": "marty-config"}}],
                          "Keycloak command or configuration source differs")
        fixed = {"BAO_TOKEN_FILE": "/run/secrets/keycloak_signing_kms_token",
                 "MARTY_KEYCLOAK_RS256_CERT_DIR": "/run/secrets",
                 "MARTY_KEYCLOAK_JWE_TOKEN_DIR": "/run/secrets",
                 "BAO_CACERT": "/run/secrets/openbao_tls_ca_cert"}
        bootstrap.require(all(env.get(key) == {"name": key, "value": value}
                              for key, value in fixed.items())
                          and all(path == "/run/secrets/" + key for (_, key), path in paths.items()),
                          "Keycloak credential projection settings differ")
    else:
        bootstrap.require(container.get("command") == ["/app/services/entrypoint.sh"]
                          and container.get("args", []) == []
                          and env.get("SERVICE_NAME") == {"name": "SERVICE_NAME", "value": name.replace("-", "_")},
                          "Renewal service entrypoint differs")
        for row in TLS_BINDINGS:
            if row[0] != name:
                continue
            for variable, setting in ((row[1], row[2]), (row[3], row[4])):
                entry = inputs[variable]
                path = paths[(entry["secret"], entry["key"])]
                bootstrap.require(env.get(setting) == {"name": setting, "value": path},
                                  "Renewal runtime certificate or token file differs")
        if name in CA_PROJECTIONS:
            variable, settings = CA_PROJECTIONS[name]
            entry = inputs[variable]
            directory = str(PurePosixPath(paths[(entry["secret"], entry["key"])]).parent)
            bootstrap.require(all(env.get(setting) == {"name": setting, "value": directory + "/ca.crt"}
                                  for setting in settings), "Renewal CA-only projection differs")


def deployment_snapshot(value: dict, namespace: str, images: dict, runtime: dict, contract: dict) -> tuple[str, dict]:
    name = value.get("metadata", {}).get("name")
    image = images["keycloak" if name == "keycloak" else "services"]
    return application.deployment_snapshot(value, namespace, image, runtime, allowed_names=REQUIRED,
        component_label_required=name != "keycloak",
        consumer_validator=lambda spec, component, selected: consumer_bindings(spec, component, selected, contract))


def configurator_complete(job: dict, namespace: str, release_name: str, images: dict) -> bool:
    meta = application.metadata(job, "Job", namespace)
    labels = meta.get("labels", {})
    bootstrap.require(labels.get("app.kubernetes.io/instance") == release_name
                      and labels.get("app.kubernetes.io/component") == "keycloak-configurator"
                      and re.fullmatch(r"marty-keycloak-[1-9][0-9]*", meta["name"]),
                      "Keycloak configurator ownership differs")
    spec = application.pod_spec(job)
    containers = spec.get("containers", [])
    bootstrap.require(len(containers) == 1 and containers[0].get("name") == "configure"
                      and containers[0].get("image") == images["keycloak"]
                      and containers[0].get("command") == ["/bin/bash", "/scripts/setup-keycloak-selfhost-production.sh"]
                      and containers[0].get("args", []) == []
                      and not spec.get("initContainers") and not spec.get("ephemeralContainers"),
                      "Keycloak configurator command or signed image differs")
    env = containers[0].get("env", [])
    bootstrap.require(isinstance(env, list) and len({item.get("name") for item in env}) == len(env),
                      "Keycloak configurator environment is ambiguous")
    entries = {item["name"]: item for item in env}
    for key, value in {"KC_URL": "http://keycloak:8080", "KEYCLOAK_SETUP_STRICT": "true",
                       "KEYCLOAK_REMOVE_DEMO_USERS": "true", "KEYCLOAK_REPLACE_UI_ORIGINS": "true",
                       "CANVAS_DEMO_ADMIN_ENABLED": "false"}.items():
        bootstrap.require(entries.get(key) == {"name": key, "value": value},
                          "Keycloak configurator safety settings differ")
    bootstrap.require(containers[0].get("envFrom") == [{"configMapRef": {"name": "marty-config"}}]
                      and containers[0].get("volumeMounts") == [
                          {"name": "scripts", "mountPath": "/scripts", "readOnly": True}]
                      and spec.get("volumes") == [
                          {"name": "scripts", "configMap": {"name": "keycloak-setup-scripts", "defaultMode": 0o555}}],
                      "Keycloak configurator script projection differs")
    status = job.get("status", {})
    return (status.get("active", 0) == 0 and status.get("succeeded") == 1
            and any(item.get("type") == "Complete" and item.get("status") == "True"
                    for item in status.get("conditions", []))
            and not any(item.get("type") == "Failed" and item.get("status") == "True"
                        for item in status.get("conditions", [])))


def preflight_resources(value: dict, namespace: str, images: dict, runtime: dict, contract: dict) -> dict:
    entries = application.list_items(value)
    deployments = {item["metadata"]["name"]: item for item in entries if item.get("kind") == "Deployment"}
    bootstrap.require(REQUIRED <= set(deployments), "required Renewal Deployment is missing")
    targets, releases = {}, set()
    for name in sorted(REQUIRED):
        release, target = deployment_snapshot(deployments[name], namespace, images, runtime, contract)
        targets[name] = target
        releases.add(release)
    bootstrap.require(len(releases) == 1, "Renewal Deployments belong to different Helm releases")
    release = next(iter(releases))
    migrations, configurators = {}, {}
    for item in entries:
        if item.get("kind") != "Job":
            continue
        component = item.get("metadata", {}).get("labels", {}).get("app.kubernetes.io/component")
        if component == "migrations":
            bootstrap.require(application.migration_complete(item, namespace, release, runtime, images),
                              "application migrations are incomplete")
            migrations[item["metadata"]["uid"]] = item
        elif component == "keycloak-configurator":
            bootstrap.require(configurator_complete(item, namespace, release, images),
                              "Keycloak configuration has not completed")
            configurators[item["metadata"]["uid"]] = item
    bootstrap.require(migrations and configurators, "completed migration or Keycloak evidence is unavailable")
    replica_sets = {item.get("metadata", {}).get("uid"): item for item in entries if item.get("kind") == "ReplicaSet"}
    names = secret_names(contract)
    for item in entries:
        kind = item.get("kind")
        bootstrap.require(kind in {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet", "Pod"},
                          "unsupported Renewal workload kind")
        application.metadata(item, kind, namespace)
        spec = application.pod_spec(item)
        if not references(spec, names):
            continue
        if kind == "Deployment" and item["metadata"]["name"] in targets:
            continue
        owner = application.controller(item)
        if kind == "ReplicaSet" and owner and owner[0] == "Deployment" and owner[1] in targets:
            bootstrap.require(owner[2] == targets[owner[1]]["uid"], "Renewal ReplicaSet owner changed")
            consumer_bindings(spec, owner[1], images["keycloak" if owner[1] == "keycloak" else "services"], contract)
            continue
        if kind == "Pod" and owner and owner[0] == "ReplicaSet" and owner[2] in replica_sets:
            parent = application.controller(replica_sets[owner[2]])
            bootstrap.require(parent and parent[0] == "Deployment" and parent[1] in targets
                              and parent[2] == targets[parent[1]]["uid"], "Renewal Pod owner changed")
            consumer_bindings(spec, parent[1], images["keycloak" if parent[1] == "keycloak" else "services"], contract)
            continue
        raise bootstrap.BootstrapError("an unsupported workload consumes Renewal Secrets")
    return {"releaseName": release, "deployments": targets,
            "migrationUids": sorted(set(migrations) | set(configurators))}


def original_binding(state: Path) -> tuple[dict, dict, dict, bytes]:
    complete = staging.record(state / "bootstrap-complete.json")
    bootstrap.require(complete.get("status") == "openbao-and-application-credentials-ready",
                      "original Kubernetes bootstrap is incomplete")
    authority = complete.get("renewalAuthority")
    bootstrap.require(isinstance(authority, dict) and set(authority) == {
        "schema", "binding", "identityDirectory", "files", "bindingFile"}
        and authority["schema"] == "marty.kubernetes-renewal-authority/v1"
        and authority["identityDirectory"] == "renewal-identity"
        and authority["files"] == sorted(bootstrap.RENEWAL_IDENTITY_FILES)
        and authority["bindingFile"] == "renewal-binding.json",
        "original bootstrap has no supported Renewal authority")
    binding = bootstrap.application_binding(authority["binding"])
    lifecycle = complete["credentialLifecycle"]
    bootstrap.require(binding == {"namespace": complete["namespace"], "namespaceUid": lifecycle["namespaceUid"],
        "openbaoClusterId": complete["openbaoClusterId"], "workloadProject": lifecycle["workloadProject"]},
        "original Renewal binding differs")
    raw, _ = staging.private_bytes(state / "renewal-binding.json", 4096, {0o600})
    receipt = bootstrap.renewal_binding(application.json_bytes(raw, 4096), binding)
    bootstrap.require(receipt["producerNonce"] == lifecycle.get("producerNonce"),
                      "original Renewal producer identity differs")
    return complete, binding, receipt, raw


def authenticated_context(args: argparse.Namespace, work: Path, complete: dict, binding: dict,
                          receipt: dict, binding_raw: bytes) -> dict:
    retained = staging.record(args.state_dir / "marty-images.json")
    operator, operator_bytes, values, publication, _ = staging.admitted_runtime(args, complete, retained, work)
    contract = bootstrap.renewal_contract(operator)
    renewal.same_metadata(contract, complete.get("renewalContract"),
                          "retained Renewal capability differs; fresh bootstrap is required")
    activation = bootstrap.compiled_contract(operator, "kubernetes-renewal-activation-contract",
        activation_contract(publication), "Kubernetes Renewal activation")
    source = args.state_dir / "renewal-identity"
    staging.existing_private_directory(source)
    bootstrap.require({path.name for path in source.iterdir()} == bootstrap.RENEWAL_IDENTITY_FILES,
                      "Renewal identity inventory differs")
    authority = {name: staging.private_bytes(source / name, bound, {0o400, 0o600})
                 for name, bound in bootstrap.RENEWAL_IDENTITY_LIMITS.items()}
    bootstrap.private_directory(work / "renewal-identity")
    bootstrap.take_renewal_identity(staging.archive_snapshot(authority), work / "renewal-identity",
                                   modes={0o400, 0o600})
    bootstrap.write_new(work / "renewal-binding.json", binding_raw)
    kubeconfig, _ = staging.private_bytes(args.state_dir / "kubeconfig", 1024 * 1024, {0o600})
    scoped = application.json_bytes(kubeconfig, 1024 * 1024)
    bootstrap.require(isinstance(scoped.get("current-context"), str) and scoped["current-context"]
                      and len(scoped.get("contexts", [])) == 1
                      and scoped["contexts"][0].get("name") == scoped["current-context"],
                      "retained Kubernetes context is ambiguous")
    bootstrap.write_new(work / "kubeconfig", kubeconfig)
    kubectl = shutil.which("kubectl")
    bootstrap.require(kubectl is not None, "kubectl must be installed")
    pulls = complete.get("imagePullSecrets")
    bootstrap.require(isinstance(pulls, list) and all(isinstance(name, str) and re.fullmatch(
        r"[a-z0-9][a-z0-9.-]{0,251}[a-z0-9]|[a-z0-9]", name) for name in pulls),
        "retained pull Secret names differ")
    result = {"binding": binding, "bindingReceipt": receipt, "bindingBytes": binding_raw,
        "values": values, "operator": operator, "operatorBytes": operator_bytes, "authority": authority,
        "activation": activation, "pullSecrets": pulls, "state": args.state_dir, "work": work,
        "transport": application.BoundedTransport(work, work / "kubeconfig", binding["namespace"], kubectl),
        "activationAnnotation": ANNOTATION, "rolloutRequestSchema": "marty.kubernetes-renewal-rollout-request/v1"}
    result["deploymentSnapshot"] = lambda resource: deployment_snapshot(
        resource, binding["namespace"], values["images"], values["release"], activation)
    result["preflightResources"] = lambda resources: preflight_resources(
        resources, binding["namespace"], values["images"], values["release"], activation)
    return result


def custody(context: dict, current: dict, candidate: dict) -> None:
    bootstrap.require(staging.current_snapshot(context["currentDirectory"]) == current
                      and staging.current_snapshot(context["candidateDirectory"]) == candidate
                      and staging.current_snapshot(context["state"] / "renewal-identity") == context["authority"]
                      and staging.current_snapshot(context["work"] / "renewal-identity") == context["authority"]
                      and staging.private_bytes(context["state"] / "renewal-binding.json", 4096, {0o600})[0]
                          == context["bindingBytes"]
                      and staging.private_bytes(context["work"] / "renewal-binding.json", 4096, {0o600})[0]
                          == context["bindingBytes"], "Renewal credential custody changed")


def staged_candidate(stage: Path, context: dict, current: dict, destination: Path) -> None:
    staging.existing_private_directory(stage)
    expected = {"schema": "marty.kubernetes-renewal-stage-completion/v1", "binding": context["binding"],
        "runtime": context["values"]["release"], "producerNonce": context["bindingReceipt"]["producerNonce"],
        "currentDirectory": str(context["currentDirectory"]), "candidateDirectory": "candidate",
        "files": len(current), "changedFiles": 39, "scopedLeafTokens": 21, "transientRevoked": True,
        "status": "candidate-staged-not-activated", "activation": False, "caChanged": False}
    renewal.same_metadata(staging.record(stage / renewal.COMPLETE), expected, "staged Renewal receipt differs")
    captured = bootstrap.flat_archive(staging.private_bytes(stage / "current-snapshot.tar",
        staging.GENERATION_ARCHIVE_LIMIT, {0o600})[0], set(current),
        maximum=staging.GENERATION_ARCHIVE_LIMIT, modes=staging.FILE_MODES, allow_empty=True)
    bootstrap.require(captured == current, "staged Renewal belongs to another selected generation")
    application.copy_snapshot(destination, staging.current_snapshot(stage / "candidate"))


def validate_native_evidence(payload: bytes, *, complete: bool, context: dict, count: int) -> None:
    members = bootstrap.private_archive(payload, {"pending.json": 65536, "authority.token": 1025,
        "validated.json": 65536, "session-retired.json": 4096, "completed.json": 4096},
        maximum=EVIDENCE_LIMIT, modes={0o600}, directories={"."}, complete=complete, allow_empty=not complete)
    if complete:
        renewal.same_metadata(application.json_bytes(members["session-retired.json"][0], 4096), {
            "schema": "marty.kubernetes-renewal-session-retirement/v1", "transientRevoked": True},
            "native Renewal verifier retirement differs")
        renewal.same_metadata(application.json_bytes(members["completed.json"][0], 4096), {
            "schema": "marty.kubernetes-renewal-verification/v1", "binding": context["binding"],
            "producerNonce": context["bindingReceipt"]["producerNonce"], "files": count,
            "changedFiles": 39, "scopedLeafTokens": 21, "transientRevoked": True, "activated": False,
            "caChanged": False, "minimumTtlSeconds": MINIMUM_TTL}, "native Renewal verification completion differs")


def fresh_proof(context: dict, current: dict, candidate: dict) -> float:
    transport = context["transport"]
    deadline = time.monotonic() + ACTIVATION_SECONDS
    transport.deadline = deadline
    custody(context, current, candidate)
    bootstrap.check_application_binding(transport, context["binding"])
    pod = bootstrap.create_producer_pod(transport, image=context["values"]["images"]["services"],
        nonce=bootstrap.secrets.token_hex(6), pull_secrets=context["pullSecrets"], purpose="renewal-activation")
    remote_ready, uncertain, complete = False, False, False
    try:
        bootstrap.retain_producer_pointer(transport, pod)
        transport.kubectl("native Renewal verifier readiness", "wait", "--for=condition=Ready", "pod/" + pod,
                          "--timeout=300s", timeout=330)
        bootstrap.check_application_binding(transport, context["binding"])
        transport.execute(pod, ["/bin/sh", "-ec",
            'umask 077; for path in "$@"; do mkdir "$path"; chmod 700 "$path"; done', "--",
            REMOTE_CURRENT, REMOTE_CANDIDATE, REMOTE_IDENTITY, REMOTE_PROOF])
        remote_ready = True
        transport.upload(pod, REMOTE_OPERATOR, context["operatorBytes"], executable=True)
        copied = transport.execute(pod, ["sha256sum", REMOTE_OPERATOR]).decode().split()
        bootstrap.require(copied and copied[0] == hashlib.sha256(context["operatorBytes"]).hexdigest(),
                          "copied Renewal verifier differs")
        for path, snapshot in ((REMOTE_CURRENT, current), (REMOTE_CANDIDATE, candidate),
                               (REMOTE_IDENTITY, context["authority"])):
            transport.execute(pod, ["tar", "-xpf", "-", "-C", path], data=staging.archive_snapshot(snapshot))
        transport.upload(pod, REMOTE_BINDING, context["bindingBytes"])
        transport.upload(pod, "/tmp/ca.crt", current["openbao_tls_ca_cert"][0])
        custody(context, current, candidate)
        bootstrap.check_application_binding(transport, context["binding"])
        bootstrap.require(application.remaining(deadline) > VERIFICATION_SECONDS + 60,
                          "insufficient original budget for verification and evidence retention")
        uncertain = True
        raw = transport.execute(pod, [REMOTE_OPERATOR, "operator", "kubernetes-renewal-verify",
            "https://openbao:8200", "/tmp/ca.crt", REMOTE_IDENTITY],
            data=bootstrap.encoded({"current": REMOTE_CURRENT, "candidate": REMOTE_CANDIDATE,
                "output": REMOTE_PROOF, "binding_file": REMOTE_BINDING,
                "binding": context["binding"], "budget_seconds": VERIFICATION_SECONDS}),
            timeout=VERIFICATION_SECONDS)
        renewal.same_metadata(application.json_bytes(raw, 4096),
            {"ready": True, "count": 39, "minimumTtlSeconds": MINIMUM_TTL},
            "fresh native Renewal proof did not confirm readiness")
        uncertain, complete = False, True
    finally:
        retained, failures = not remote_ready, []
        if remote_ready:
            try:
                evidence = bootstrap.remote_archive(transport, pod, REMOTE_PROOF, EVIDENCE_LIMIT)
                validate_native_evidence(evidence, complete=complete, context=context, count=len(current))
                bootstrap.write_new(transport.state / "native-verification-evidence.tar", evidence)
                retained = True
            except Exception:
                failures.append("private native Renewal verification evidence export or confirmation failed")
        if uncertain:
            failures.append("native Renewal verification outcome is uncertain")
        if retained and not uncertain:
            try:
                transport.kubectl("native Renewal verifier cleanup", "delete", "pod", pod,
                                  "--wait=true", "--timeout=120s", timeout=150)
            except Exception:
                failures.append("native Renewal verifier cleanup failed")
        else:
            failures.append("native verifier retained within its remaining original 1200-second lifetime")
        if failures:
            raise bootstrap.BootstrapError("; ".join(failures) + "; preserve the private attempt")
    bootstrap.require(complete, "native Renewal verification was not completed")
    custody(context, current, candidate)
    application.remaining(deadline)
    return deadline


def native_publication(context: dict, command: dict) -> dict:
    raw = context["transport"].run("native Renewal Secret validation",
        [str(context["operator"]), "operator", "kubernetes-renewal-publication"],
        data=bootstrap.encoded(command), env={}, timeout=120)
    result = application.json_bytes(raw, 4096)
    count = sum(entry["secret"] == command["secret"] for entry in context["activation"]["inputs"])
    bootstrap.require(count in {1, 7}, "Renewal Secret destination differs")
    expected = {"ready": True, "secret": command["secret"], "count": count}
    if command["operation"] == "verify":
        expected["state"] = result.get("state")
        bootstrap.require(expected["state"] in {"candidate", "unchanged"}, "native Renewal publication state differs")
    renewal.same_metadata(result, expected, "native Renewal publication refused")
    return result


def observe_secret(context: dict, name: str, path: Path, deadline: float | None = None) -> dict:
    bootstrap.require(name in secret_names(context["activation"]), "unknown Renewal Secret")
    timeout = 60 if deadline is None else min(60, application.remaining(deadline))
    raw = context["transport"].kubectl("Renewal Secret observation", "get", "secret", name, "-o", "json", timeout=timeout)
    value = application.json_bytes(raw)
    application.metadata(value, "Secret", context["binding"]["namespace"])
    bootstrap.require(value["metadata"]["name"] == name, "Renewal Secret name changed")
    bootstrap.write_new(path, raw)
    return value


def before_path(operation: Path, name: str) -> Path:
    return operation / ("secret-" + name + "-before.json")


def patch_path(operation: Path, name: str) -> Path:
    return operation / ("secret-" + name + "-patch.json")


def publication_request(context: dict, operation: Path, request: dict, name: str) -> dict:
    return {"namespace": context["binding"]["namespace"], "secret": name,
            "current": request["previousDirectory"], "candidate": str(operation / "candidate"),
            "observed": str(before_path(operation, name)), "activationId": request["activationId"]}


def publication_state(context: dict, operation: Path, request: dict, name: str, result: Path) -> str:
    return native_publication(context, {**publication_request(context, operation, request, name),
                                       "operation": "verify", "result": str(result)})["state"]


def publish_secrets(context: dict, operation: Path, request: dict, current: dict, candidate: dict,
                    deadline: float) -> None:
    for name in sorted(secret_names(context["activation"])):
        custody(context, current, candidate)
        original = application.private_json(before_path(operation, name))
        receipt = {"schema": "marty.kubernetes-renewal-secret-request/v1",
            "activationId": request["activationId"], "secret": name,
            "uid": original["metadata"]["uid"], "resourceVersion": original["metadata"]["resourceVersion"]}
        dispatched = operation / ("secret-" + name + "-requested.json")
        observed = context["work"] / ("secret-" + name + "-before-dispatch.json")
        observe_secret(context, name, observed, deadline)
        state = publication_state(context, operation, request, name, observed)
        if dispatched.exists() or dispatched.is_symlink():
            renewal.same_metadata(staging.record(dispatched), receipt, "retained Renewal Secret request differs")
            bootstrap.require(state == "candidate",
                              "requested Renewal Secret is unchanged or uncertain; its patch will not be repeated")
            continue
        bootstrap.require(state == "unchanged", "untouched Renewal Secret changed before dispatch")
        # Rebuild only a private plan, not a Kubernetes request, so retained patch
        # bytes cannot silently change between the original preflight and resume.
        expected = context["work"] / ("secret-" + name + "-expected-patch.json")
        native_publication(context, {**publication_request(context, operation, request, name),
                                     "operation": "prepare", "output": str(expected)})
        bootstrap.require(staging.private_bytes(expected, application.API_LIMIT, {0o600})[0]
                          == staging.private_bytes(patch_path(operation, name), application.API_LIMIT, {0o600})[0],
                          "retained Renewal Secret patch changed")
        custody(context, current, candidate)
        bootstrap.write_new(dispatched, bootstrap.encoded(receipt))
        raw = context["transport"].kubectl("Renewal Secret activation", "patch", "secret", name,
            "--type=json", "--patch-file", str(patch_path(operation, name)), "-o", "json",
            timeout=min(60, application.remaining(deadline)))
        application.json_bytes(raw)
        bootstrap.write_new(operation / ("secret-" + name + "-response.json"), raw)
        after = context["work"] / ("secret-" + name + "-after-dispatch.json")
        observe_secret(context, name, after, deadline)
        bootstrap.require(publication_state(context, operation, request, name, after) == "candidate",
                          "Renewal Secret update did not confirm the candidate")


def verify_secrets(context: dict, operation: Path, request: dict, suffix: str, deadline: float) -> list[dict]:
    result = []
    for name in sorted(secret_names(context["activation"])):
        path = context["work"] / ("secret-" + name + "-" + suffix + ".json")
        value = observe_secret(context, name, path, deadline)
        bootstrap.require(publication_state(context, operation, request, name, path) == "candidate",
                          "Renewal Secret changed during activation")
        result.append({"name": name, "uid": value["metadata"]["uid"],
                       "resourceVersion": value["metadata"]["resourceVersion"]})
    return result


def delivery_script(name: str, entry: dict) -> str:
    variable = None
    for row in TLS_BINDINGS:
        if row[0] == name:
            if row[1] == entry["input"]:
                variable = row[2]
            elif row[3] == entry["input"]:
                variable = row[4]
    prefix = '[ "$' + variable + '" = "$1" ]; ' if variable else ""
    if name == "keycloak":
        if entry["input"] == "KEYCLOAK_SIGNING_KMS_TOKEN":
            prefix = '[ "$BAO_TOKEN_FILE" = "$1" ]; '
        elif entry["file"].endswith("_cert"):
            prefix = '[ "$MARTY_KEYCLOAK_RS256_CERT_DIR" = "/run/secrets" ]; '
        else:
            prefix = '[ "$MARTY_KEYCLOAK_JWE_TOKEN_DIR" = "/run/secrets" ]; '
    return prefix + DELIVERY_FILE


def delivered_credentials(context: dict, resources: dict, workloads: list[dict], candidate: dict,
                          deadline: float) -> None:
    pods = {item["metadata"]["uid"]: item for item in application.list_items(resources) if item.get("kind") == "Pod"}
    contract = context["activation"]
    for workload in workloads:
        name = workload["name"]
        for uid in workload["podUids"]:
            selected = pods[uid]
            pod_name = selected["metadata"]["name"]
            def observe_pod() -> dict:
                return application.json_bytes(context["transport"].kubectl("Renewal Pod delivery identity",
                    "get", "pod", pod_name, "-o", "json", timeout=min(60, application.remaining(deadline))))
            def require_identity(observed: dict) -> None:
                bootstrap.require(observed.get("metadata", {}).get("uid") == uid
                    and application.controller(observed) == application.controller(selected)
                    and observed.get("spec") == selected.get("spec")
                    and observed.get("metadata", {}).get("annotations") == selected.get("metadata", {}).get("annotations"),
                    "Renewal Pod changed during private delivery verification")
            require_identity(observe_pod())
            paths = projected_paths(application.pod_spec(selected), name, contract)
            for entry in contract["inputs"]:
                key = (entry["secret"], entry["key"])
                if key not in paths:
                    continue
                expected = candidate[entry["file"]][0].replace(b"\r", b"").rstrip(b"\n")
                bootstrap.require(0 < len(expected) <= 65536, "native-verified Renewal value size differs")
                actual = context["transport"].kubectl("private Renewal credential delivery", "exec", pod_name,
                    "--container", name, "--", "/bin/sh", "-ec", delivery_script(name, entry), "--", paths[key],
                    timeout=min(60, application.remaining(deadline)))
                bootstrap.require(actual == expected, "Renewal credential delivery differs")
            require_identity(observe_pod())


def validate_request(request: dict, context: dict, operation: Path, selected: object) -> None:
    bootstrap.require(set(request) == {"schema", "binding", "runtime", "activationId", "operationDirectory",
        "candidateDirectory", "previousDirectory", "stageDirectory", "currentFiles"}
        and request["schema"] == "marty.kubernetes-renewal-activation-request/v1"
        and request["binding"] == context["binding"] and request["runtime"] == context["values"]["release"]
        and isinstance(request["activationId"], str) and re.fullmatch(r"[0-9a-f]{32}", request["activationId"])
        and request["operationDirectory"] == str(operation)
        and request["candidateDirectory"] == str(operation / "candidate")
        and request["previousDirectory"] == str(selected.directory)
        and isinstance(request["stageDirectory"], str) and Path(request["stageDirectory"]).is_absolute()
        and type(request["currentFiles"]) is int and 0 < request["currentFiles"] <= staging.MAX_FILES,
        "retained Renewal activation request differs")


def activate(args: argparse.Namespace) -> None:
    bootstrap.require(os.name == "posix", "this development transport requires Linux")
    state, operation = args.state_dir, args.operation_dir
    staging.existing_private_directory(state)
    bootstrap.require(operation.is_absolute() and operation.resolve() == operation and operation != state
                      and all(not operation.is_relative_to(state / name)
                              for name in ("credentials", "application-identity", "renewal-identity")),
                      "Renewal activation overlaps retained private inputs")
    with selection.locked(state) as held:
        complete, binding, binding_receipt, binding_raw = original_binding(state)
        pending = held.pending(binding, domain="renewal") if args.reconcile else None
        selected = held.current(binding, pending_operation=operation if args.reconcile and pending is not None else None,
                                domain="renewal")
        if args.reconcile:
            staging.existing_private_directory(operation)
        else:
            bootstrap.require(args.stage_dir is not None, "completed Renewal staging is required")
            bootstrap.require(not operation.is_relative_to(selected.directory)
                              and not operation.is_relative_to(args.stage_dir),
                              "Renewal activation overlaps selected or staged inputs")
            bootstrap.private_directory(operation)
        work = operation / ("inspection-" + bootstrap.secrets.token_hex(6))
        bootstrap.private_directory(work)
        context = authenticated_context(args, work, complete, binding, binding_receipt, binding_raw)
        if args.reconcile and pending is None:
            proof, finished = staging.record(operation / VERIFIED), staging.record(operation / COMPLETE)
            bootstrap.require(selected.directory == operation / "candidate"
                              and selected.generation_activation_id == proof.get("activationId")
                              and selected.renewal_activation_id == proof.get("activationId")
                              and proof.get("binding") == binding
                              and proof.get("runtime") == context["values"]["release"],
                              "completed Renewal activation selection differs")
            renewal.same_metadata(finished, {**proof, "schema": "marty.kubernetes-renewal-activation-completion/v1",
                "status": "renewal-generation-selected"}, "completed Renewal activation receipt differs")
            print("Renewal activation was already recorded; no new cluster mutation was requested.")
            return
        context["currentDirectory"] = selected.directory
        context["candidateDirectory"] = operation / "candidate"
        current = staging.current_snapshot(selected.directory)
        bootstrap.require("openbao_tls_ca_cert" in current, "retained OpenBao trust is unavailable")
        if not args.reconcile:
            staged_candidate(args.stage_dir, context, current, operation / "candidate")
            bootstrap.write_new(operation / "current-snapshot.tar", staging.archive_snapshot(current))
        else:
            captured = bootstrap.flat_archive(staging.private_bytes(operation / "current-snapshot.tar",
                staging.GENERATION_ARCHIVE_LIMIT, {0o600})[0], set(current),
                maximum=staging.GENERATION_ARCHIVE_LIMIT, modes=staging.FILE_MODES, allow_empty=True)
            bootstrap.require(captured == current, "retained previous Renewal generation changed")
        candidate = staging.current_snapshot(operation / "candidate")
        staging.verify_result(staging.native_generation(context["transport"], str(context["operator"]), {
            "operation": "verify", "current": str(selected.directory), "candidate": str(operation / "candidate"),
            "ca_overlap": False, "ca_retire": False}), len(current), 39)
        bootstrap.check_application_binding(context["transport"], binding)
        if not args.reconcile:
            resources = application.observe(context, operation / "workloads-before.json", secret=False)
            graph = context["preflightResources"](resources)
            bootstrap.require(all(target["spec"]["template"].get("metadata", {}).get("annotations", {}).get(ANNOTATION)
                                  == selected.renewal_activation_id for target in graph["deployments"].values()),
                              "active Renewal Deployment marker differs from selected generation")
            activation_id = bootstrap.secrets.token_hex(16)
            request = {"schema": "marty.kubernetes-renewal-activation-request/v1", "binding": binding,
                "runtime": context["values"]["release"], "activationId": activation_id,
                "operationDirectory": str(operation), "candidateDirectory": str(operation / "candidate"),
                "previousDirectory": str(selected.directory), "stageDirectory": str(args.stage_dir),
                "currentFiles": len(current)}
            for name in sorted(secret_names(context["activation"])):
                secret = observe_secret(context, name, before_path(operation, name))
                bootstrap.require(secret["metadata"].get("annotations", {}).get(ANNOTATION) == selected.renewal_activation_id,
                                  "active Renewal Secret marker differs from selected generation")
                native_publication(context, {**publication_request(context, operation, request, name),
                    "operation": "prepare", "output": str(patch_path(operation, name))})
            bootstrap.write_new(operation / REQUEST, bootstrap.encoded(request))
            held.begin(binding, operation, operation / "candidate", activation_id, expected=selected, domain="renewal")
        else:
            request = staging.record(operation / REQUEST)
            validate_request(request, context, operation, selected)
            bootstrap.require(request["currentFiles"] == len(current), "retained Renewal generation count differs")
            graph = context["preflightResources"](application.private_json(operation / "workloads-before.json"))
            bootstrap.require(all(target["spec"]["template"].get("metadata", {}).get("annotations", {}).get(ANNOTATION)
                                  == selected.renewal_activation_id for target in graph["deployments"].values()),
                              "retained Renewal Deployment marker differs")
            for name in sorted(secret_names(context["activation"])):
                original = application.private_json(before_path(operation, name))
                bootstrap.require(original.get("metadata", {}).get("annotations", {}).get(ANNOTATION)
                                  == selected.renewal_activation_id, "retained Renewal Secret marker differs")
        deadline = fresh_proof(context, current, candidate)
        custody(context, current, candidate)
        bootstrap.check_application_binding(context["transport"], binding)
        publish_secrets(context, operation, request, current, candidate, deadline)
        verify_secrets(context, operation, request, "before-rollout", deadline)
        revisions = {target["name"]: application.rollout_one(context, operation, target, request["activationId"], deadline)
                     for target in graph["deployments"].values()}
        resources = application.observe(context, work / "workloads-final.json", secret=False,
                                        timeout=min(60, application.remaining(deadline)))
        workloads = application.verified_workloads(resources, context, graph, request["activationId"], revisions)
        delivered_credentials(context, resources, workloads, candidate, deadline)
        after = application.observe(context, work / "workloads-after-delivery.json", secret=False,
                                    timeout=min(60, application.remaining(deadline)))
        bootstrap.require(application.verified_workloads(after, context, graph, request["activationId"], revisions) == workloads,
                          "Renewal workload identity changed during private delivery verification")
        secrets = verify_secrets(context, operation, request, "final", deadline)
        bootstrap.check_application_binding(context["transport"], binding)
        custody(context, current, candidate)
        application.remaining(deadline)
        proof = {"schema": "marty.kubernetes-renewal-activation-verified/v1", "binding": binding,
            "activationId": request["activationId"], "operationDirectory": str(operation),
            "candidateDirectory": str(operation / "candidate"), "previousDirectory": str(selected.directory),
            "runtime": context["values"]["release"], "secrets": secrets, "deployments": workloads,
            "status": "secrets-and-rollouts-verified", "credentialDeliveryVerified": True,
            "credentialConsumptionVerified": False}
        if (operation / VERIFIED).exists() or (operation / VERIFIED).is_symlink():
            renewal.same_metadata(staging.record(operation / VERIFIED), proof,
                                  "retained Renewal proof no longer matches live observations")
        else:
            bootstrap.write_new(operation / VERIFIED, bootstrap.encoded(proof))
        application.remaining(deadline)
        held.publish(binding, operation, expected=selected, domain="renewal")
        application.remaining(deadline)
        held.complete(binding, operation, domain="renewal")
        application.remaining(deadline)
        held.finish(binding, operation, domain="renewal", check_deadline=lambda: application.remaining(deadline))
    print("Renewal Secrets and selected Deployment rollouts were verified; the candidate generation is current.")
    print("Keep the private attempt. Authenticated credential use, scheduling and expired-credential recovery remain separate.")


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
        parser.exit(1, f"Kubernetes Renewal activation stopped: {detail}. "
                    "Preserve the private attempt; the cluster may have changed. "
                    "Reconcile this operation; requested Secret updates are never repeated.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
