#!/usr/bin/env python3
"""Recover one retained legacy Kubernetes credential generation explicitly.

The signed native owner inspects, stages same-scope credentials and freshly
qualifies a closed existing-Secret plan. Private evidence is exported before
optional activation. Choose --stage-only or --activate-existing-secrets; the
latter can explicitly add --reload-owned-workloads. This command has no replay,
resume, rollback or enrollment mode.
The original retained state is read-only. Keep the private operation directory
on encrypted operator storage; it contains credentials and opaque API evidence.
"""
from __future__ import annotations

import argparse
import base64
from copy import deepcopy
import hashlib
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import time

import bootstrap_kubernetes_openbao as bootstrap
import inspect_kubernetes_legacy_credentials as inspection
import stage_kubernetes_application_credentials as private


STAGE_SCHEMA = "marty.kubernetes-legacy-recovery-stage/v1"
QUALIFICATION_SCHEMA = "marty.kubernetes-legacy-recovery-qualified-plan/v1"
TARGETS_SCHEMA = "marty.kubernetes-legacy-recovery-targets/v1"
PLAN_SCHEMA = "marty.kubernetes-legacy-recovery-activation-plan/v1"
REMOTE_STAGE = inspection.REMOTE_OPERATION + "/stage"
REMOTE_QUALIFICATION = inspection.REMOTE_OPERATION + "/qualification"
REMOTE_SECRETS = inspection.REMOTE_OPERATION + "/secrets.json"
SECRET_LIMIT = 2 * 1024 * 1024
REPORT_LIMIT = inspection.REPORT_LIMIT
EVIDENCE_LIMIT = private.NATIVE_EVIDENCE_LIMIT
PLAN_SECONDS = 300
CONTRACT = {
    "schema": STAGE_SCHEMA, "legacyRuntimeSourceSha": inspection.LEGACY_RUNTIME,
    "certificateReplacements": 18, "tokenReplacements": 33, "replacementFiles": 51,
    "existingSecretTargets": 34, "maximumReplacementTtlSeconds": 28800,
    "migrationTokenReplacement": False, "scopeMutation": False, "activationPerformed": False,
    "qualificationSchema": QUALIFICATION_SCHEMA, "planLifetimeSeconds": PLAN_SECONDS,
}


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def input_bindings(snapshot: dict) -> dict:
    return {name: {"sha256": sha256(value), "mode": mode}
            for name, (value, mode) in snapshot.items()}


def full_binding(complete: dict, binding: dict, chart: str) -> dict:
    return {"bootstrapId": complete["bootstrapId"], **binding,
            "producerNonce": complete["credentialLifecycle"]["producerNonce"],
            "runtimeSourceSha": inspection.LEGACY_RUNTIME, "chartSourceSha": chart}


def stage_contract(operator: Path) -> None:
    result = subprocess.run([str(operator), "operator", "kubernetes-legacy-recovery-stage-contract"],
                            stdin=subprocess.DEVNULL, capture_output=True, check=False, timeout=10, env={})
    bootstrap.require(result.returncode == 0, "selected signed recovery stage contract is unavailable")
    inspection.same(inspection.decode(result.stdout, 4096, "native stage contract"), CONTRACT,
                    "selected signed recovery stage contract differs")


def target_names(raw: bytes, namespace: str) -> list[str]:
    value = inspection.decode(raw, 16384, "native Secret targets")
    names = value.get("names")
    bootstrap.require(isinstance(names, list) and len(names) == 34
                      and all(isinstance(name, str) and re.fullmatch(
                          r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", name) for name in names)
                      and names == sorted(set(names)), "native Secret target inventory differs")
    inspection.same(value, {"schema": TARGETS_SCHEMA, "namespace": namespace,
                           "names": names, "replacementCount": 51}, "native Secret target contract differs")
    return names


def secret_identity(value: dict, namespace: str, name: str) -> None:
    metadata = value.get("metadata", {})
    bootstrap.require(value.get("apiVersion") == "v1" and value.get("kind") == "Secret"
                      and value.get("type") == "Opaque" and isinstance(metadata, dict)
                      and metadata.get("namespace") == namespace and metadata.get("name") == name
                      and inspection.valid_uuid(metadata.get("uid"))
                      and isinstance(metadata.get("resourceVersion"), str) and metadata["resourceVersion"]
                      and "deletionTimestamp" not in metadata
                      and ("immutable" not in value or value["immutable"] is False)
                      and "stringData" not in value and isinstance(value.get("data"), dict),
                      "existing Secret identity or mutable data differs")


def observe_secrets(transport, names: list[str], directory: Path) -> tuple[dict, bytes]:
    bootstrap.private_directory(directory)
    items = []
    for index, name in enumerate(names):
        raw = transport.kubectl("legacy Secret observation", "get", "secret", name, "-o", "json", timeout=30)
        bootstrap.require(0 < len(raw) <= SECRET_LIMIT, "Secret observation exceeds private transport bounds")
        bootstrap.write_new(directory / f"secret-{index:02}.json", raw)
        value = inspection.decode(raw, SECRET_LIMIT, "existing Secret observation")
        secret_identity(value, transport.namespace, name)
        items.append(value)
    # kubectl's generic multi-get List is not the native SecretList contract.
    observed = {"apiVersion": "v1", "kind": "SecretList", "items": items}
    raw = bootstrap.encoded(observed)
    bootstrap.require(len(raw) <= REPORT_LIMIT, "combined Secret observations exceed native bounds")
    bootstrap.write_new(directory / "all-secrets.json", raw)
    return observed, raw


def evidence_members(payload: bytes, snapshot: dict) -> dict:
    allowed = {"inspection.json": REPORT_LIMIT + 1, "secrets.json": REPORT_LIMIT,
               "stage/attempt.json": 65537, "stage/complete.json": REPORT_LIMIT + 1,
               "qualification/attempt.json": REPORT_LIMIT + 1,
               "qualification/plan.json": REPORT_LIMIT + 1}
    for phase, count in (("stage", 120), ("qualification", 51)):
        for index in range(count):
            allowed[f"{phase}/request-{index:03}.json"] = 65537
            allowed[f"{phase}/response-{index:03}.json"] = 128 * 1024 + 1
    for name in snapshot:
        allowed["stage/inputs/" + name] = 65536
        allowed["stage/candidate/" + name] = 65536
    members = bootstrap.private_archive(payload, allowed, maximum=EVIDENCE_LIMIT,
        modes=private.FILE_MODES, directories={".", "stage", "stage/inputs", "stage/candidate", "qualification"},
        complete=False, allow_empty=True)
    for name, (_, mode) in members.items():
        expected_mode = snapshot[name.removeprefix("stage/candidate/")][1] if name.startswith("stage/candidate/") else 0o600
        bootstrap.require(mode == expected_mode, "native evidence file mode differs")
    return members


def validate_inspection(members: dict, snapshot: dict, binding: dict) -> bytes:
    raw = members["inspection.json"][0]
    report = inspection.decode(raw, REPORT_LIMIT + 1, "private native inspection")
    bootstrap.require(report.get("schema") == inspection.SCHEMA and report.get("status") == "inspected-not-staged"
                      and report.get("mutationAvailable") is False, "native inspection is incomplete")
    inspection.same(report.get("binding"), binding, "native inspection installation binding differs")
    inspection.same(report.get("inputBindings"), input_bindings(snapshot), "native inspection input bindings differ")
    return raw


def validate_stage(members: dict, snapshot: dict, binding: dict, report: bytes, summary: dict) -> tuple[dict, bytes]:
    inspection.same(summary, {"schema": STAGE_SCHEMA, "status": "staged-not-activated",
        "candidate": REMOTE_STAGE + "/candidate", "replacementCount": 51, "activation": False,
        "stagingReceiptSha256": sha256(members["stage/complete.json"][0])}, "native stage summary or receipt hash differs")
    candidate = {name: members["stage/candidate/" + name] for name in snapshot}
    changed = {name for name in snapshot if candidate[name][0] != snapshot[name][0]}
    bootstrap.require(len(changed) == 51 and "openbao_bootstrap_token" not in changed,
                      "native staged replacement inventory differs")
    receipt_raw = members["stage/complete.json"][0]
    receipt = inspection.decode(receipt_raw, REPORT_LIMIT + 1, "native staging receipt")
    journal_names = sorted(f"{kind}-{index:03}.json" for kind in ("request", "response") for index in range(120))
    bootstrap.require(all("stage/" + name in members for name in journal_names),
                      "native completed staging journal is incomplete")
    journal_bindings = {name: sha256(members["stage/" + name][0]) for name in journal_names}
    inspection.same(receipt, {"schema": STAGE_SCHEMA, "binding": binding, "status": "staged-not-activated",
        "candidate": "candidate", "replacementCount": 51, "inputBindings": input_bindings(candidate),
        "completedRequests": 120, "journalBindings": journal_bindings, "activation": False},
        "native staging receipt binds different candidate inputs or journal records")
    attempt = inspection.decode(members["stage/attempt.json"][0], 65537, "native staging attempt")
    replacements = attempt.get("replacementFiles")
    bootstrap.require(isinstance(replacements, list) and len(replacements) == 51
                      and all(isinstance(name, str) for name in replacements)
                      and set(replacements) == changed, "native staging attempt replacement inventory differs")
    inspection.same(attempt, {"schema": STAGE_SCHEMA, "binding": binding, "inspectionSha256": sha256(report),
        "replacementFiles": replacements, "activation": False}, "native staging attempt binding differs")
    expected = {"inspection.json", "stage/attempt.json", "stage/complete.json"}
    expected.update("stage/candidate/" + name for name in snapshot)
    expected.update("stage/inputs/" + name for name in changed)
    expected.update(f"stage/{kind}-{index:03}.json" for kind in ("request", "response") for index in range(120))
    bootstrap.require(set(members) == expected, "native completed stage evidence inventory differs")
    for name in changed:
        bootstrap.require(members["stage/inputs/" + name] == (candidate[name][0], 0o600),
                          "native replacement input differs from its candidate")
    bootstrap.require(all(value for name, (value, _) in members.items() if not name.startswith("stage/candidate/")),
                      "native completed stage evidence is empty")
    return candidate, receipt_raw


class Freshness:
    """Bound plan use by both its native UTC deadline and local elapsed time."""
    def __init__(self, qualified: int, deadline: int, started_monotonic: float):
        now = time.time()
        monotonic = time.monotonic()
        bootstrap.require(type(qualified) is int and type(deadline) is int
                          and deadline - qualified == PLAN_SECONDS and qualified <= now < deadline
                          and 0 <= monotonic - started_monotonic < PLAN_SECONDS,
                          "native qualification is stale or its clock binding differs")
        self.qualified, self.deadline, self.last_wall = qualified, deadline, now
        self.monotonic_deadline = min(started_monotonic + PLAN_SECONDS, monotonic + deadline - now)

    def check(self) -> None:
        now = time.time()
        bootstrap.require(self.last_wall <= now < self.deadline and now >= self.qualified
                          and time.monotonic() < self.monotonic_deadline,
                          "native qualification expired or the operator clock moved backwards")
        self.last_wall = now

    def remaining(self) -> int:
        self.check()
        remaining = math.floor(min(self.deadline - time.time(), self.monotonic_deadline - time.monotonic()))
        bootstrap.require(remaining > 0, "native qualification has no request budget remaining")
        return remaining


def patch_key(path: object) -> str:
    bootstrap.require(isinstance(path, str) and path.startswith("/data/"), "native patch path differs")
    encoded = path[len("/data/"):]
    bootstrap.require("/" not in encoded and re.search(r"~(?![01])", encoded) is None,
                      "native patch pointer is malformed")
    key = encoded.replace("~1", "/").replace("~0", "~")
    bootstrap.require(re.fullmatch(r"[A-Za-z0-9_.-]{1,253}", key) is not None, "native Secret field differs")
    return key


def validate_plan(raw: bytes, summary: dict, binding: dict, current: dict, candidate: dict,
                  report: bytes, receipt: bytes, names: list[str], observed: dict,
                  qualification_started: float, qualified: dict) -> tuple[dict, dict, Freshness]:
    plan = inspection.decode(raw, REPORT_LIMIT + 1, "private qualified native plan")
    native = plan.get("nativePlan")
    bootstrap.require(isinstance(native, dict) and isinstance(native.get("secrets"), list), "native private plan is incomplete")
    inspection.same(summary, {"schema": QUALIFICATION_SCHEMA, "status": "qualified-not-activated",
        "credentialsQualified": True, "credentialsIssued": False, "activation": False, "secretCount": 34,
        "replacementCount": 51, "validBeforeUnixSeconds": plan.get("validBeforeUnixSeconds"),
        "privatePlanWritten": True, "privatePlanSha256": sha256(raw)}, "native qualification summary or plan hash differs")
    journal_bindings = {f"{kind}-{index:03}.json": sha256(qualified[f"qualification/{kind}-{index:03}.json"][0])
                        for kind in ("request", "response") for index in range(51)}
    inspection.same(plan, {"schema": QUALIFICATION_SCHEMA, "binding": binding, "status": "qualified-not-activated",
        "qualifiedAtUnixSeconds": plan.get("qualifiedAtUnixSeconds"), "validBeforeUnixSeconds": plan.get("validBeforeUnixSeconds"),
        "inspectionSha256": sha256(report), "stagingReceiptSha256": sha256(receipt),
        "qualificationJournalBindings": journal_bindings,
        "credentialsQualified": True, "credentialsIssued": False, "activation": False, "nativePlan": native},
        "native qualified plan binding differs")
    freshness = Freshness(plan["qualifiedAtUnixSeconds"], plan["validBeforeUnixSeconds"], qualification_started)
    inspection.same(native, {"schema": PLAN_SCHEMA, "status": "planned-not-qualified-or-activated", "private": True,
        "credentialsQualified": False, "activationPerformed": False, "atomicAcrossSecrets": False,
        "binding": binding, "currentInputs": input_bindings(current), "candidateInputs": input_bindings(candidate),
        "secrets": native["secrets"]}, "native existing-Secret plan binding differs")
    entries = native["secrets"]
    bootstrap.require(len(entries) == 34 and all(isinstance(entry, dict) for entry in entries)
                      and [entry.get("name") for entry in entries] == names, "native patch target inventory differs")
    originals = {item["metadata"]["name"]: item for item in observed["items"]}
    expected_after = {}
    changes = 0
    for entry in entries:
        old = originals[entry["name"]]
        patch = entry.get("patch")
        bootstrap.require(isinstance(patch, list) and 4 <= len(patch) <= 54, "native patch operation count differs")
        inspection.same(entry, {"name": old["metadata"]["name"], "namespace": binding["namespace"],
            "uid": old["metadata"]["uid"], "resourceVersion": old["metadata"]["resourceVersion"], "patch": patch},
            "native patch object binding differs")
        inspection.same(patch[:3], [
            {"op": "test", "path": "/metadata/uid", "value": old["metadata"]["uid"]},
            {"op": "test", "path": "/metadata/resourceVersion", "value": old["metadata"]["resourceVersion"]},
            {"op": "test", "path": "/data", "value": old["data"]}], "native patch preconditions differ")
        after = deepcopy(old)
        fields = set()
        for operation in patch[3:]:
            bootstrap.require(isinstance(operation, dict) and set(operation) == {"op", "path", "value"}
                              and operation["op"] == "replace", "native patch exceeds replacement scope")
            key = patch_key(operation["path"])
            value = operation["value"]
            bootstrap.require(key in old["data"] and key not in fields and isinstance(value, str)
                              and value != old["data"][key], "native patch replaces an absent, duplicate or unchanged field")
            decoded = base64.b64decode(value, validate=True)
            bootstrap.require(base64.b64encode(decoded).decode() == value, "native patch contains noncanonical data")
            fields.add(key)
            after["data"][key] = value
        changes += len(fields)
        expected_after[entry["name"]] = after
    bootstrap.require(changes == 51, "native patch replacement count differs")
    return plan, expected_after, freshness


def capture_patch(transport, name: str, patch: list, destination: Path, timeout: int) -> bytes:
    """Retain opaque success/failure/timeout bytes before interpreting a reply."""
    command = [*transport.base, "patch", "secret", name, "--type=json", "--patch-file=-", "-o", "json"]
    try:
        result = subprocess.run(command, input=bootstrap.encoded(patch), capture_output=True,
                                check=False, timeout=timeout)
        stdout, stderr = result.stdout, result.stderr
        status, completed = result.returncode, True
    except subprocess.TimeoutExpired as error:
        stdout, stderr = error.stdout or b"", error.stderr or b""
        status, completed = None, False
    except OSError:
        stdout, stderr, status, completed = b"", b"", None, False
    bounded = len(stdout) <= SECRET_LIMIT and len(stderr) <= 1024 * 1024
    bootstrap.write_new(destination, bootstrap.encoded({
        "completed": completed, "exitCode": status, "bounded": bounded,
        "stdoutBase64": base64.b64encode(stdout[:SECRET_LIMIT]).decode(),
        "stderrBase64": base64.b64encode(stderr[:1024 * 1024]).decode(),
    }))
    bootstrap.require(completed and status == 0 and bounded and stdout,
                      "Secret patch outcome is incomplete or failed; preserve private response evidence")
    return stdout


def verify_patch_reply(raw: bytes, expected: dict, original: dict) -> dict:
    value = inspection.decode(raw, SECRET_LIMIT, "private Secret patch response")
    name, namespace = original["metadata"]["name"], original["metadata"]["namespace"]
    secret_identity(value, namespace, name)
    bootstrap.require(value["metadata"]["uid"] == original["metadata"]["uid"]
                      and value["metadata"]["resourceVersion"] != original["metadata"]["resourceVersion"],
                      "Secret patch response identity or resource version differs")
    normalized = deepcopy(value)
    retained = deepcopy(expected)
    for item in (normalized, retained):
        item["metadata"].pop("resourceVersion", None)
        item["metadata"].pop("managedFields", None)
    inspection.same(normalized, retained, "Secret patch response changed data or metadata outside the plan")
    return value


def recover_locked(args: argparse.Namespace) -> None:
    state, operation = args.state_dir, args.operation_dir
    reload_requested = getattr(args, "reload_owned_workloads", False)
    records = inspection.retained_records(state, args.chart_source_sha)
    complete, initialize, metadata, binding, pull_secrets = records
    bound = full_binding(complete, binding, args.chart_source_sha)
    original, selected, operator_bytes = inspection.authenticate(args, complete)
    source_binding = inspection.sources.authenticate(args.recovery_assets, selected["release"])
    source_record = bootstrap.encoded({"schema": inspection.sources.SCHEMA,
        "recoveryRuntime": selected["release"], "files": source_binding})
    bootstrap.write_new(operation / "source-authenticated.json", source_record)
    stage_contract(operation / "marty-deploy")
    snapshot = private.current_snapshot(state / "credentials")
    bootstrap.require("openbao_tls_ca_cert" in snapshot, "retained OpenBao trust is unavailable")
    archive = private.archive_snapshot(snapshot)
    bootstrap.write_new(operation / "current-snapshot.tar", archive)
    config = inspection.kubeconfig_bytes(state)
    bootstrap.write_new(operation / "kubeconfig", config)
    initialization, _ = private.private_bytes(state / "openbao-initialization.json", 65536, {0o400})
    material = inspection.decode(initialization, 65536, "retained initialization")
    root = material.get("root_token")
    bootstrap.require(isinstance(root, str) and 20 <= len(root) <= 256
                      and all(33 <= ord(character) <= 126 for character in root)
                      and isinstance(material.get("recovery_keys_b64"), list) and len(material["recovery_keys_b64"]) == 1,
                      "retained initialization authority is invalid")
    root_bytes = root.encode()
    del root, material
    kubectl = shutil.which("kubectl")
    bootstrap.require(kubectl is not None, "kubectl must be installed")
    transport = bootstrap.Transport(operation, operation / "kubeconfig", binding["namespace"], kubectl)
    inspection.namespace_identity(transport, binding)
    openbao = inspection.openbao_identity(transport, original["images"]["openbao_didcomm"])
    expected = inspection.producer_document(binding["namespace"], selected["images"]["services"],
                                           bootstrap.secrets.token_hex(6), pull_secrets)
    pod = expected["metadata"]["name"]
    bootstrap.write_new(operation / "recovery-requested.json", bootstrap.encoded({
        "schema": "marty.kubernetes-legacy-recovery-request/v1", "binding": bound,
        "mode": "activate-existing-secrets" if args.activate_existing_secrets else "stage-only",
        "reloadOwnedWorkloads": reload_requested,
        "originalRuntime": original["release"], "recoveryRuntime": selected["release"],
        "openbao": openbao, "pod": expected, "automaticReplay": False,
    }))
    uid = None
    remote_ready = root_uploaded = operator_uploaded = native_inflight = exported = False
    phase_name = "producer-creation"
    progress = {"stageAttempted": False, "stageCompleted": False, "qualificationCompleted": False,
                "activationAttempted": False, "verifiedSecrets": []}
    producer_deadline = time.monotonic() + 1200
    completed = False
    retained_outputs = {operation / "kubeconfig": (config, 0o600), operation / "marty-deploy": (operator_bytes, 0o700),
                        operation / "current-snapshot.tar": (archive, 0o600),
                        operation / "source-authenticated.json": (source_record, 0o600)}
    retained_candidate = None
    verified_postimages = {}
    try:
        created = transport.kubectl("legacy producer creation", "create", "-f", "-", "-o", "json", data=bootstrap.encoded(expected))
        bootstrap.require(0 < len(created) <= 1024 * 1024, "created producer response exceeds private bounds")
        bootstrap.write_new(operation / "producer-created.json", created)
        observed = inspection.decode(created, 1024 * 1024, "created recovery producer")
        if inspection.valid_uuid(observed.get("metadata", {}).get("uid")) and observed["metadata"].get("name") == pod:
            uid = observed["metadata"]["uid"]
        uid = inspection.pod_identity(observed, expected)
        bootstrap.write_new(operation / "transport-pod.json", bootstrap.encoded({
            "schema": "marty.kubernetes-native-transport/v2", "namespace": binding["namespace"],
            "namespaceUid": binding["namespaceUid"], "pod": pod, "uid": uid,
            "activeDeadlineSeconds": 1200, "storage": "memory-backed-emptyDir", "durableRecovery": False,
        }))
        transport.kubectl("legacy producer readiness", "wait", "--for=condition=Ready", "pod/" + pod, "--timeout=300s", timeout=330)
        baseline = inspection.observed_pod(transport, expected, uid)["spec"]
        bootstrap.write_new(operation / "producer-admitted.json", bootstrap.encoded({"uid": uid, "spec": baseline}))

        def retained_consistency() -> None:
            inspection.sources.recheck(source_binding)
            bootstrap.require(private.current_snapshot(state / "credentials") == snapshot,
                              "retained original credentials changed during recovery")
            bootstrap.require(private.private_bytes(state / "openbao-initialization.json", 65536, {0o400})[0] == initialization,
                              "retained initialization changed during recovery")
            bootstrap.require(inspection.kubeconfig_bytes(state) == config, "retained Kubernetes configuration changed")
            inspection.same(inspection.retained_records(state, args.chart_source_sha), records,
                            "retained recovery records changed")
            for path, expected_output in retained_outputs.items():
                bootstrap.require(private.private_bytes(path, max(len(expected_output[0]), 1), {expected_output[1]}) == expected_output,
                                  "private recovery evidence or transport input changed")
            if retained_candidate is not None:
                bootstrap.require(private.current_snapshot(operation / "candidate") == retained_candidate,
                                  "private staged candidate changed")

        def phase() -> None:
            bootstrap.require(time.monotonic() < producer_deadline - 15, "bounded producer lifetime is exhausted")
            retained_consistency()
            inspection.namespace_identity(transport, binding)
            inspection.same(inspection.openbao_identity(transport, original["images"]["openbao_didcomm"], uid=openbao["uid"]),
                            openbao, "retained OpenBao pod changed during recovery")
            inspection.same(inspection.observed_pod(transport, expected, uid)["spec"], baseline,
                            "producer pod spec changed during recovery")
            if operator_uploaded:
                paths = [inspection.REMOTE_OPERATOR] + ([inspection.REMOTE_ROOT] if root_uploaded else [])
                observed_hashes = transport.execute(pod, ["sha256sum", *paths], timeout=15).decode().splitlines()
                hashes = [sha256(operator_bytes)] + ([sha256(root_bytes)] if root_uploaded else [])
                bootstrap.require(observed_hashes == [f"{digest}  {path}" for digest, path in zip(hashes, paths)],
                                  "remote native operator or retained root bytes changed")

        def export(label: str) -> dict:
            nonlocal exported
            inspection.same(inspection.observed_pod(transport, expected, uid)["spec"], baseline,
                            "producer changed before private evidence export")
            payload = bootstrap.remote_archive(transport, pod, inspection.REMOTE_OPERATION, EVIDENCE_LIMIT)
            # Retain the opaque archive before parsing it, including failed or
            # partial native writes. Never extract an unvalidated tar member.
            bootstrap.write_new(operation / label, payload)
            members = evidence_members(payload, snapshot)
            retained_outputs[operation / label] = (payload, 0o600)
            exported = True
            return members

        def native(label: str, command: str, request: dict, timeout: int, *arguments: str, maximum: int = 4096) -> dict:
            nonlocal native_inflight, exported, phase_name
            phase_name = label
            phase()
            budget = min(timeout, math.floor(producer_deadline - time.monotonic() - 90))
            bootstrap.require(budget > 0, "bounded producer has no native operation and export budget remaining")
            bootstrap.write_new(operation / ("native-" + label + "-request.json"), bootstrap.encoded(request))
            native_inflight, exported = True, False
            raw = transport.execute(pod, [inspection.REMOTE_OPERATOR, "operator", command, *arguments],
                                    data=bootstrap.encoded(request), timeout=budget)
            native_inflight = False
            bootstrap.write_new(operation / ("native-" + label + "-summary.json"), raw[:maximum + 1])
            result = inspection.decode(raw, maximum, "native recovery summary")
            phase()
            return result

        phase()
        transport.execute(pod, ["/bin/sh", "-ec",
            'umask 077; for path in "$@"; do mkdir "$path"; chmod 700 "$path"; done', "--",
            inspection.REMOTE_PUBLIC, inspection.REMOTE_CURRENT, inspection.REMOTE_IDENTITY,
            inspection.REMOTE_OPERATION, REMOTE_STAGE, REMOTE_QUALIFICATION])
        remote_ready = True
        phase()
        transport.upload(pod, inspection.REMOTE_OPERATOR, operator_bytes, executable=True)
        operator_uploaded = True
        phase()
        transport.upload(pod, inspection.REMOTE_CA, snapshot["openbao_tls_ca_cert"][0])
        target = inspection.decode(transport.execute(pod, [inspection.REMOTE_OPERATOR, "operator",
            "kubernetes-legacy-recovery-target", inspection.REMOTE_CA, binding["openbaoClusterId"]], timeout=30),
            4096, "native unauthenticated target")
        inspection.same(target, {"schema": inspection.TARGET_SCHEMA, "ready": True,
            "clusterId": binding["openbaoClusterId"], "authenticated": False}, "native target did not confirm the retained cluster")
        bootstrap.write_new(operation / "target-confirmed.json", bootstrap.encoded(target))
        phase()
        transport.execute(pod, ["tar", "-xpf", "-", "-C", inspection.REMOTE_CURRENT], data=archive)
        phase()
        transport.upload(pod, inspection.REMOTE_ROOT, root_bytes)
        root_uploaded = True
        phase()
        context = {"schema": inspection.SCHEMA, "bootstrap": complete, "initializeRequest": initialize,
            "tlsKeyMetadata": metadata, "namespaceObservation": {"name": binding["namespace"], "uid": binding["namespaceUid"]},
            "current": inspection.REMOTE_CURRENT, "rootTokenFile": inspection.REMOTE_ROOT,
            "retainedRootSha256": sha256(root_bytes)}
        summary = native("inspection", "kubernetes-legacy-recovery-inspect", context, 600, inspection.REMOTE_REPORT)
        inspection.same(summary, {"schema": inspection.SCHEMA, "status": "inspected-not-staged", "mutationAvailable": False,
            "namespace": binding["namespace"], "workloadIdentities": 16, "keycloakSigningCertificates": 2,
            "keycloakTokens": 5, "ordinaryRuntimeTokens": 12, "privateReportWritten": True}, "native inspection result differs")
        inspected = export("native-inspection-evidence.tar")
        bootstrap.require(set(inspected) == {"inspection.json"}, "native inspection exported unexpected files")
        report = validate_inspection(inspected, snapshot, bound)
        bootstrap.write_new(operation / "inspection.json", report)
        retained_outputs[operation / "inspection.json"] = (report, 0o600)
        targets = native("targets", "kubernetes-legacy-recovery-targets", context, 30, maximum=16384)
        names = target_names(bootstrap.encoded(targets), binding["namespace"])
        progress["stageAttempted"] = True
        stage_summary = native("stage", "kubernetes-legacy-recovery-stage", {"schema": STAGE_SCHEMA,
            "context": context, "inspection": inspection.REMOTE_REPORT, "output": REMOTE_STAGE}, 600)
        staged = export("native-stage-evidence.tar")
        bootstrap.require(staged["inspection.json"][0] == report, "native retained inspection changed before staging export")
        candidate, receipt = validate_stage(staged, snapshot, bound, report, stage_summary)
        bootstrap.private_directory(operation / "candidate")
        for name, (value, mode) in candidate.items():
            private.write_preserved(operation / "candidate" / name, value, mode)
        retained_candidate = candidate
        bootstrap.write_new(operation / "stage-complete.json", receipt)
        retained_outputs[operation / "stage-complete.json"] = (receipt, 0o600)
        progress["stageCompleted"] = True
        phase()
        observed_secrets, secret_bytes = observe_secrets(transport, names, operation / "secret-preimages")
        retained_outputs[operation / "secret-preimages" / "all-secrets.json"] = (secret_bytes, 0o600)
        phase()
        transport.upload(pod, REMOTE_SECRETS, secret_bytes)
        qualification_started = time.monotonic()
        qualification_summary = native("qualification", "kubernetes-legacy-recovery-qualify", {
            "schema": QUALIFICATION_SCHEMA, "context": context, "inspection": inspection.REMOTE_REPORT,
            "staged": REMOTE_STAGE, "secrets": REMOTE_SECRETS, "output": REMOTE_QUALIFICATION}, 300)
        qualified = export("native-qualified-evidence.tar")
        expected_files = set(staged) | {"secrets.json", "qualification/attempt.json", "qualification/plan.json"}
        expected_files.update(f"qualification/{kind}-{index:03}.json" for kind in ("request", "response") for index in range(51))
        bootstrap.require(set(qualified) == expected_files and all(qualified[name] == item for name, item in staged.items())
                          and qualified["secrets.json"] == (secret_bytes, 0o600),
                          "qualified export changed retained stage evidence or Secret observations")
        bootstrap.require(all(value for name, (value, _) in qualified.items() if name.startswith("qualification/")),
                          "native qualification evidence is incomplete")
        plan_bytes = qualified["qualification/plan.json"][0]
        bootstrap.write_new(operation / "qualified-plan.json", plan_bytes)
        retained_outputs[operation / "qualified-plan.json"] = (plan_bytes, 0o600)
        plan, expected_after, freshness = validate_plan(plan_bytes, qualification_summary, bound, snapshot, candidate,
            report, receipt, names, observed_secrets, qualification_started, qualified)
        attempt = inspection.decode(qualified["qualification/attempt.json"][0], REPORT_LIMIT + 1, "private qualification attempt")
        started_at = attempt.get("startedAtUnixSeconds")
        bootstrap.require(type(started_at) is int and 0 <= plan["qualifiedAtUnixSeconds"] - started_at <= PLAN_SECONDS,
                          "native qualification interval differs")
        inspection.same(attempt, {"schema": QUALIFICATION_SCHEMA, "binding": bound, "inspectionSha256": sha256(report),
            "startedAtUnixSeconds": started_at, "currentInputs": input_bindings(snapshot), "candidateInputs": input_bindings(candidate),
            "credentialsIssued": False, "activation": False}, "native qualification attempt binding differs")
        progress["qualificationCompleted"] = True
        phase_name = "qualified-evidence-retained"
        phase()
        freshness.check()
        if args.activate_existing_secrets:
            activation = operation / "activation"
            bootstrap.private_directory(activation)
            bootstrap.write_new(activation / "activation-requested.json", bootstrap.encoded({
                "schema": "marty.kubernetes-legacy-secret-activation/v1", "binding": bound,
                "privatePlanSha256": sha256(plan_bytes), "preimagesSha256": sha256(secret_bytes),
                "secretCount": 34, "replacementCount": 51, "atomicAcrossSecrets": False,
                "validBeforeUnixSeconds": plan["validBeforeUnixSeconds"],
            }))
            originals = {item["metadata"]["name"]: item for item in observed_secrets["items"]}
            for index, entry in enumerate(plan["nativePlan"]["secrets"]):
                phase_name = f"secret-patch-{index:02}"
                freshness.check()
                phase()
                freshness.remaining()
                intent = bootstrap.encoded({
                    "schema": "marty.kubernetes-legacy-secret-patch-intent/v1", "binding": bound,
                    "name": entry["name"], "uid": entry["uid"], "resourceVersion": entry["resourceVersion"],
                    "privatePlanSha256": sha256(plan_bytes), "patchSha256": sha256(bootstrap.encoded(entry["patch"])),
                    "validBeforeUnixSeconds": plan["validBeforeUnixSeconds"], "attemptedAtUnixSeconds": int(time.time()),
                })
                intent_path = activation / f"intent-{index:02}.json"
                bootstrap.write_new(intent_path, intent)
                retained_outputs[intent_path] = (intent, 0o600)
                timeout = min(30, freshness.remaining())
                progress["activationAttempted"] = True
                response_path = activation / f"response-{index:02}.json"
                raw = capture_patch(transport, entry["name"], entry["patch"], response_path, timeout)
                retained_outputs[response_path] = private.private_bytes(response_path, 5 * 1024 * 1024, {0o600})
                after = verify_patch_reply(raw, expected_after[entry["name"]], originals[entry["name"]])
                progress["verifiedSecrets"].append(entry["name"])
                verified_postimages[entry["name"]] = raw
                verified = bootstrap.encoded({
                    "name": entry["name"], "uid": after["metadata"]["uid"],
                    "resourceVersion": after["metadata"]["resourceVersion"], "responseSha256": sha256(raw),
                })
                verified_path = activation / f"verified-{index:02}.json"
                bootstrap.write_new(verified_path, verified)
                retained_outputs[verified_path] = (verified, 0o600)
                freshness.check()
            phase()
            freshness.check()
        completed = True
    except Exception:
        bootstrap.write_new(operation / "recovery-stopped.json", bootstrap.encoded({
            "schema": "marty.kubernetes-legacy-recovery-stopped/v1", "binding": bound, "phase": phase_name,
            **progress, "nativeMayStillRun": native_inflight, "automaticReplay": False,
            "status": "incomplete-preserve-private-evidence", "activationComplete": False,
        }))
        raise
    finally:
        failures = []
        if remote_ready and uid is not None and not exported:
            try:
                export("native-incomplete-evidence.tar")
            except Exception:
                failures.append("private native evidence could not be completely retained")
        if uid is not None and (not remote_ready or exported) and not native_inflight:
            try:
                inspection.delete_pod(transport, expected, uid)
            except Exception:
                failures.append("bounded producer cleanup did not confirm completion")
        elif uid is not None:
            failures.append("producer retained within its original 1200-second lifetime; preserve transport-pod.json")
        if failures:
            bootstrap.write_new(operation / "producer-retained.json", bootstrap.encoded({
                "pod": pod, "uid": uid, "activeDeadlineSeconds": 1200,
                "nativeMayStillRun": native_inflight, "privateEvidenceExported": exported,
                "completionRecorded": False,
            }))
            raise bootstrap.BootstrapError("; ".join(failures))
    bootstrap.require(completed, "recovery did not finish its explicit mode")
    retained_consistency()
    inspection.namespace_identity(transport, binding)
    inspection.same(inspection.openbao_identity(transport, original["images"]["openbao_didcomm"], uid=openbao["uid"]),
                    openbao, "retained OpenBao pod changed after recovery")
    credential_completion = bootstrap.encoded({
        "schema": "marty.kubernetes-legacy-recovery-completion/v1", "binding": bound,
        "originalRuntime": original["release"], "recoveryRuntime": selected["release"],
        "status": "existing-secrets-activated" if args.activate_existing_secrets else "staged-and-qualified-not-activated",
        "credentialsIssued": True, "activation": bool(args.activate_existing_secrets),
        "verifiedSecretCount": len(progress["verifiedSecrets"]), "workloadsRestarted": False,
        "privatePlanSha256": sha256(plan_bytes), "podRemoved": True,
    })
    bootstrap.write_new(operation / "recovery-complete.json", credential_completion)
    retained_outputs[operation / "recovery-complete.json"] = (credential_completion, 0o600)
    if reload_requested:
        # The producer was deleted after exporting its complete private evidence.
        # Reload uses only the original images and the verified Secret postimages.
        from reload_kubernetes_legacy_workloads import ReloadRequest, reload_workloads, verify_completed_evidence

        def reload_phase(_bounded_transport) -> None:
            # All local reads are bounded. The reload owner itself checks the
            # namespace and OpenBao through its capped cluster transport.
            retained_consistency()

        try:
            result = reload_workloads(ReloadRequest(operation / "reload", original, bound, openbao["uid"],
                plan_bytes, sha256(plan_bytes), verified_postimages), transport, freshness, reload_phase)
            verify_completed_evidence(operation / "reload", result, bound, sha256(plan_bytes))
            retained_consistency()
            verify_completed_evidence(operation / "reload", result, bound, sha256(plan_bytes))
            combined = bootstrap.encoded({
                "schema": "marty.kubernetes-legacy-recovery-reload-completion/v1", "binding": bound,
                "credentialCompletionSha256": sha256(credential_completion), "privatePlanSha256": sha256(plan_bytes),
                "reload": result, "fullEnvironmentHealthAssessed": False, "inMemoryProviderUseProved": False,
            })
            combined_path = operation / "recovery-reload-complete.json"
            bootstrap.write_new(combined_path, combined)
            retained_outputs[combined_path] = (combined, 0o600)
            retained_consistency()
            verify_completed_evidence(operation / "reload", result, bound, sha256(plan_bytes))
        except Exception:
            bootstrap.write_new(operation / "recovery-reload-stopped.json", bootstrap.encoded({
                "schema": "marty.kubernetes-legacy-recovery-reload-stopped/v1", "binding": bound,
                "credentialActivationComplete": True, "workloadReloadCompletionAccepted": False,
                "status": "incomplete-preserve-private-evidence", "automaticReplay": False,
            }))
            raise
        print("Verified 34 existing Secret updates and 16 new Ready Pods with matching credential projections. "
              "Full-environment health and end-to-end checks remain separate.")
    elif args.activate_existing_secrets:
        print("Verified 34 existing Secret updates. Private recovery evidence is retained; workload restart remains a separate step.")
    else:
        print("Staged and qualified 51 same-scope replacements. Private recovery evidence is retained; activation was not requested.")


def recover(args: argparse.Namespace) -> None:
    bootstrap.require(os.name == "posix", "this private recovery transport requires Linux")
    bootstrap.require(type(args.stage_only) is bool and type(args.activate_existing_secrets) is bool
                      and args.stage_only != args.activate_existing_secrets, "choose exactly one explicit recovery mode")
    reload_requested = getattr(args, "reload_owned_workloads", False)
    bootstrap.require(type(reload_requested) is bool and (not reload_requested or args.activate_existing_secrets),
                      "owned workload reload requires explicit existing-Secret activation")
    bootstrap.require(not args.operation_dir.is_relative_to(args.state_dir)
                      and not args.state_dir.is_relative_to(args.operation_dir),
                      "operation directory must be separate from retained state")
    with inspection.retained_lock(args.state_dir):
        bootstrap.private_directory(args.operation_dir)
        recover_locked(args)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("state-dir", "operation-dir", "original-assets", "recovery-assets", "gh", "cosign"):
        parser.add_argument("--" + name, required=True, type=Path)
    for name in ("chart-source-sha", "original-release-tag", "recovery-source-sha", "recovery-release-tag"):
        parser.add_argument("--" + name, required=True)
    for name in ("original-build-run-id", "original-build-run-attempt", "recovery-build-run-id", "recovery-build-run-attempt"):
        parser.add_argument("--" + name, required=True, type=int)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--stage-only", action="store_true")
    mode.add_argument("--activate-existing-secrets", action="store_true")
    parser.add_argument("--reload-owned-workloads", action="store_true",
                        help="after complete Secret activation, reload only the 16 original credential consumers")
    try:
        recover(parser.parse_args(argv))
    except (bootstrap.BootstrapError, ValueError, OSError, KeyError, TypeError,
            subprocess.TimeoutExpired, tarfile.TarError) as error:
        detail = str(error) if isinstance(error, bootstrap.BootstrapError) else type(error).__name__
        parser.exit(1, f"Legacy Kubernetes recovery stopped: {detail}. Preserve the private attempt; do not replay it.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
