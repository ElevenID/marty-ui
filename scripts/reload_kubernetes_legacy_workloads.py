"""Internal, existing-only reload of the 16 legacy credential consumers.

There is intentionally no CLI/main dispatch. The authenticated activation caller
must hold the retained-state lock and provide its private stability guard and
the original qualification Freshness object. This module issues no credentials,
changes no image/configuration, and does not assess full-environment health.
"""
from __future__ import annotations

import base64
from copy import deepcopy
from dataclasses import dataclass
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import time
from typing import Callable, Protocol

import bootstrap_kubernetes_openbao as bootstrap
import inspect_kubernetes_legacy_credentials as inspection
import recover_kubernetes_legacy_credentials as recovery


WORKLOADS = (
    "auth", "organization", "credential-template", "gateway", "verification", "notification",
    "compliance-profile", "presentation-policy", "deployment-profile", "flow", "revocation-profile",
    "event-stream", "issuance-native", "signing-keys", "canvas-sync-worker", "keycloak",
)
SCHEMA = "marty.kubernetes-legacy-workload-reload/v1"
EVIDENCE_SCHEMA = "marty.kubernetes-legacy-reload-evidence/v1"
OBJECT_LIMIT = 2 * 1024 * 1024
LIST_LIMIT = 8 * 1024 * 1024
EVIDENCE_LIMIT = 96 * 1024 * 1024
EVIDENCE_LIMITS = {"maximumRecords": 16600, "maximumBytes": EVIDENCE_LIMIT,
                   "maximumObservations": 8192, "maximumSeconds": 600}
REVISION = "deployment.kubernetes.io/revision"
PROBE_PROGRAM = (
    'set -eu; command -v sha256sum >/dev/null; command -v printenv >/dev/null; '
    'marty_count="$1"; shift; '
    'while [ "$marty_count" -gt 0 ]; do '
    'test -f "$1"; printf "file "; sha256sum -- "$1"; shift; marty_count=$((marty_count - 1)); done; '
    'for marty_variable do printenv "$marty_variable" >/dev/null; '
    'printf "env "; printenv "$marty_variable" | sha256sum; done'
)


@dataclass(frozen=True)
class ReloadRequest:
    output: Path
    original: dict
    binding: dict
    openbao_uid: str
    qualified_plan: bytes
    qualified_plan_sha256: str
    verified_secrets: dict[str, bytes]


class Freshness(Protocol):
    def check(self) -> None: ...
    def remaining(self) -> int: ...


class Budget:
    def __init__(self) -> None:
        self.deadline = time.monotonic() + EVIDENCE_LIMITS["maximumSeconds"]
        self.last_wall = time.time()

    def timeout(self, requested: int = 30) -> int:
        wall, remaining = time.time(), math.floor(self.deadline - time.monotonic())
        bootstrap.require(wall >= self.last_wall and remaining > 0,
                          "reload budget expired or operator wall clock moved backwards")
        self.last_wall = wall
        return min(requested, remaining)

    def pause(self) -> None:
        time.sleep(min(2, self.timeout(2)))
        self.timeout()


def file_identity(info: os.stat_result) -> dict:
    return {"device": info.st_dev, "inode": info.st_ino, "mode": info.st_mode,
            "uid": info.st_uid, "gid": info.st_gid, "links": info.st_nlink,
            "size": info.st_size, "mtimeNs": info.st_mtime_ns, "ctimeNs": info.st_ctime_ns}


def directory_identity(path: Path) -> dict:
    recovery.private.existing_private_directory(path)
    info = path.lstat()
    bootstrap.require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
                      and stat.S_IMODE(info.st_mode) == 0o700,
                      "reload evidence directory custody differs")
    # Entry creation legitimately changes directory timestamps/link counts.
    # The exact child inventory is checked separately, without following links.
    return {key: value for key, value in file_identity(info).items()
            if key in ("device", "inode", "mode", "uid", "gid")}


def private_record(path: Path, maximum: int) -> tuple[bytes, dict]:
    before = file_identity(path.lstat())
    raw, _ = recovery.private.private_bytes(path, maximum, {0o600})
    after = file_identity(path.lstat())
    bootstrap.require(before == after, "reload evidence changed while binding its bytes")
    return raw, {"sha256": recovery.sha256(raw), "bytes": len(raw), "identity": after}


def journal_recheck(output: Path, directories: dict, files: dict, *, full: bool, validated: bool = False,
                    budget: Budget | None = None) -> None:
    """Check immutable private records; full checkpoints also reread every hash."""
    try:
        if budget is not None:
            budget.timeout()
        bootstrap.require(set(directories) == {".", "observations"} and len(files) <= EVIDENCE_LIMITS["maximumRecords"],
                          "reload evidence inventory is invalid")
        if not validated:
            total = 0
            for name, record in files.items():
                bootstrap.require(isinstance(name, str) and re.fullmatch(
                    r"(?:[a-z][a-z0-9-]{0,127}\.json|observations/[0-9]{4}\.(?:meta\.)?json)", name)
                    and isinstance(record, dict) and set(record) == {"sha256", "bytes", "identity"}
                    and type(record["bytes"]) is int and 0 <= record["bytes"] <= LIST_LIMIT + 1
                    and isinstance(record["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", record["sha256"])
                    and isinstance(record["identity"], dict)
                    and all(type(value) is int for value in record["identity"].values())
                    and record["identity"].get("mode") == stat.S_IFREG | 0o600
                    and record["identity"].get("uid") == os.geteuid()
                    and record["identity"].get("links") == 1
                    and record["identity"].get("size") == record["bytes"],
                    "reload evidence record binding is invalid")
                total += record["bytes"]
            bootstrap.require(total <= EVIDENCE_LIMIT, "reload evidence exceeds its closed byte bound")
        for name, binding in directories.items():
            bootstrap.require(directory_identity(output / name) == binding, "reload evidence directory changed")
        names = set()
        for directory in (".", "observations"):
            with os.scandir(output / directory) as entries:
                for entry in entries:
                    if directory == "." and entry.name == "observations":
                        continue
                    name = entry.name if directory == "." else directory + "/" + entry.name
                    bootstrap.require(name in files and name not in names,
                                      "reload evidence has an unexpected record")
                    names.add(name)
                    record = files[name]
                    if budget is not None:
                        budget.timeout()
                    bootstrap.require(file_identity(entry.stat(follow_symlinks=False)) == record["identity"],
                                      "reload evidence record identity or custody changed")
                    if full:
                        _, current = private_record(output / directory / entry.name, max(record["bytes"], 1))
                        bootstrap.require(current == record, "reload evidence bytes or private custody changed")
        bootstrap.require(names == set(files), "reload evidence record is missing")
        for name, binding in directories.items():
            bootstrap.require(directory_identity(output / name) == binding, "reload evidence directory changed while checking")
        if budget is not None:
            budget.timeout()
    except OSError as error:
        raise bootstrap.BootstrapError("reload evidence private inventory is unavailable or changed") from error


def verify_completed_evidence(output: Path, result: dict, binding: dict, private_plan_sha256: str) -> None:
    """Revalidate the in-process completion binding before the caller commits it."""
    try:
        bootstrap.require(set(result) == {"schema", "status", "reloadCount", "privateEvidenceWritten", "privateEvidence",
                                           "fullEnvironmentHealthAssessed", "inMemoryProviderUseProved"}
                          and result["schema"] == SCHEMA
                          and result["status"] == "sixteen-ready-pods-with-matching-projections"
                          and result["reloadCount"] == 16 and result["privateEvidenceWritten"] is True
                          and result["fullEnvironmentHealthAssessed"] is False
                          and result["inMemoryProviderUseProved"] is False,
                          "reload returned completion summary differs")
        expected = result["privateEvidence"]
        bootstrap.require(set(expected) == {"schema", "completionSha256", "journalSha256", "recordCount",
                                           "totalBytes", "completionRecord"}
                          and expected["schema"] == EVIDENCE_SCHEMA,
                          "reload completion evidence binding is invalid")
        raw, completion_record = private_record(output / "reload-complete.json", LIST_LIMIT)
        inspection.same(completion_record, expected["completionRecord"], "reload completion record changed after return")
        bootstrap.require(recovery.sha256(raw) == expected["completionSha256"], "reload completion hash differs")
        completion = inspection.decode(raw, LIST_LIMIT, "private reload completion")
        inspection.same(completion.get("binding"), binding, "reload completion installation differs")
        bootstrap.require(completion.get("schema") == SCHEMA
                          and completion.get("status") == "new-ready-pods-with-matching-projected-credentials"
                          and completion.get("privatePlanSha256") == private_plan_sha256
                          and completion.get("reloadCount") == 16
                          and completion.get("inMemoryProviderUseProved") is False
                          and completion.get("fullEnvironmentHealthAssessed") is False,
                          "reload completion result differs")
        inspection.same(completion.get("evidenceLimits"), EVIDENCE_LIMITS, "reload evidence bounds differ")
        journal = completion["journalBindings"]
        bootstrap.require(set(journal) == {"schema", "directories", "files"}
                          and journal["schema"] == EVIDENCE_SCHEMA
                          and recovery.sha256(bootstrap.encoded(journal)) == expected["journalSha256"]
                          and "reload-complete.json" not in journal["files"]
                          and "reload-stopped.json" not in journal["files"],
                          "reload completion journal closure differs")
        files = {**journal["files"], "reload-complete.json": completion_record}
        bootstrap.require(expected["recordCount"] == len(files)
                          and expected["totalBytes"] == sum(record["bytes"] for record in files.values()),
                          "reload completion evidence totals differ")
        journal_recheck(output, journal["directories"], files, full=True)
    except (OSError, KeyError, TypeError, ValueError) as error:
        raise bootstrap.BootstrapError("reload completion evidence is unavailable or invalid") from error


class Evidence:
    def __init__(self, output: Path, budget: Budget | None = None):
        bootstrap.private_directory(output)
        bootstrap.private_directory(output / "observations")
        self.output, self.total, self.sequence = output, 0, 0
        self.budget = budget
        self.directories = {name: directory_identity(output / name) for name in (".", "observations")}
        self.files = {}

    def custody(self) -> None:
        for name, binding in self.directories.items():
            bootstrap.require(directory_identity(self.output / name) == binding, "reload evidence directory changed")

    def recheck(self, *, full: bool = False) -> None:
        # These bindings came directly from private_record(), not from disk or
        # an external manifest. Revalidate every filesystem identity/inventory;
        # the caller separately validates the serialized closure after return.
        journal_recheck(self.output, self.directories, self.files, full=full, validated=True, budget=self.budget)

    def write(self, name: str, raw: bytes, maximum: int = OBJECT_LIMIT) -> None:
        total = self.total + len(raw)
        ceiling = EVIDENCE_LIMIT if name == "reload-stopped.json" else EVIDENCE_LIMIT - 65536
        if name not in ("reload-complete.json", "reload-stopped.json"):
            ceiling -= LIST_LIMIT
        bootstrap.require(name not in self.files and len(raw) <= maximum and total <= ceiling,
                          "private reload evidence exceeds its bounded storage envelope")
        # A newly returned opaque reply is preserved before checking older
        # records, but never through a changed or nonprivate directory.
        self.custody()
        bootstrap.write_new(self.output / name, raw)
        observed, record = private_record(self.output / name, max(len(raw), 1))
        bootstrap.require(observed == raw, "new reload evidence bytes changed while writing")
        self.files[name] = record
        self.total = total
        self.custody()

    def observed(self, operation: str, raw: bytes) -> None:
        bootstrap.require(self.sequence < EVIDENCE_LIMITS["maximumObservations"], "reload observation count exceeds its bound")
        index = self.sequence
        self.sequence += 1
        self.write(f"observations/{index:04}.json", raw, LIST_LIMIT)
        self.write(f"observations/{index:04}.meta.json", bootstrap.encoded({"operation": operation,
            "sha256": recovery.sha256(raw), "bytes": len(raw)}), 4096)
        self.recheck()

    def complete(self, result: dict) -> dict:
        self.recheck(full=True)
        journal = {"schema": EVIDENCE_SCHEMA, "directories": deepcopy(self.directories), "files": deepcopy(self.files)}
        raw = bootstrap.encoded({**result, "evidenceLimits": EVIDENCE_LIMITS, "journalBindings": journal})
        self.write("reload-complete.json", raw, LIST_LIMIT)
        self.recheck(full=True)
        return {"schema": EVIDENCE_SCHEMA, "completionSha256": recovery.sha256(raw),
                "journalSha256": recovery.sha256(bootstrap.encoded(journal)), "recordCount": len(self.files),
                "totalBytes": self.total, "completionRecord": deepcopy(self.files["reload-complete.json"])}


class BudgetedTransport:
    """Only this capped interface is supplied to the caller's phase guard."""
    def __init__(self, transport, budget: Budget, evidence: Evidence):
        self._transport, self.budget, self.evidence = transport, budget, evidence
        self.namespace, self.base = transport.namespace, list(transport.base)

    def kubectl(self, operation: str, *args: str, data: bytes | None = None, timeout: int = 30) -> bytes:
        self.evidence.recheck()
        raw = self._transport.kubectl(operation, *args, data=data, timeout=self.budget.timeout(timeout))
        self.evidence.observed(operation, raw)
        self.budget.timeout()
        return raw

    def execute(self, pod: str, command: list[str], *, data: bytes | None = None,
                timeout: int = 30, container: str | None = None) -> bytes:
        args = ["exec"] + (["-i"] if data is not None else []) + [pod]
        if container is not None:
            args.extend(["-c", container])
        return self.kubectl("legacy reload private command", *args, "--", *command, data=data, timeout=timeout)


def identity(value: dict, kind: str, namespace: str, name: str | None = None) -> dict:
    metadata = value.get("metadata", {})
    bootstrap.require(value.get("apiVersion") == ("v1" if kind in ("Secret", "Pod") else "apps/v1")
                      and value.get("kind") == kind and isinstance(metadata, dict)
                      and metadata.get("namespace") == namespace
                      and isinstance(metadata.get("name"), str)
                      and re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", metadata["name"])
                      and (name is None or metadata["name"] == name)
                      and inspection.valid_uuid(metadata.get("uid"))
                      and isinstance(metadata.get("resourceVersion"), str) and metadata["resourceVersion"]
                      and "deletionTimestamp" not in metadata,
                      "reload object identity or live state differs")
    return metadata


def immutable_image(actual: object, expected: object) -> None:
    bootstrap.require(isinstance(expected, str) and re.fullmatch(r"[^@\s]+@sha256:[0-9a-f]{64}", expected),
                      "authenticated original image reference is invalid")
    repository, digest = expected.split("@", 1)
    bootstrap.require(isinstance(actual, str) and re.fullmatch(
        re.escape(repository) + r"(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?@" + re.escape(digest), actual),
        "workload image differs from the authenticated original release")


def admitted_inputs(request: ReloadRequest) -> tuple[dict, dict, dict[str, set[str]]]:
    bootstrap.require(recovery.sha256(request.qualified_plan) == request.qualified_plan_sha256
                      and inspection.valid_uuid(request.openbao_uid), "reload activation evidence binding differs")
    plan = inspection.decode(request.qualified_plan, recovery.REPORT_LIMIT + 1, "qualified reload plan")
    bootstrap.require(plan.get("schema") == recovery.QUALIFICATION_SCHEMA and plan.get("credentialsQualified") is True
                      and plan.get("credentialsIssued") is False and plan.get("activation") is False
                      and plan.get("status") == "qualified-not-activated", "reload requires a qualified native plan")
    inspection.same(plan.get("binding"), request.binding, "reload installation differs from qualification")
    release = request.original.get("release", {})
    bootstrap.require(release.get("runtimeSourceSha") == request.binding.get("runtimeSourceSha") == inspection.LEGACY_RUNTIME
                      and release.get("chartSourceSha") == request.binding.get("chartSourceSha"),
                      "reload original source identity differs")
    for role in ("services", "keycloak", "openbao_didcomm"):
        immutable_image(request.original["images"][role], request.original["images"][role])
    native = plan.get("nativePlan", {})
    inspection.same(native.get("binding"), request.binding, "reload native plan binding differs")
    entries = native.get("secrets")
    bootstrap.require(isinstance(entries, list) and len(entries) == 34 and len(request.verified_secrets) == 34,
                      "reload requires all 34 verified Secret responses")
    after, changed = {}, {}
    for entry in entries:
        name = entry["name"]
        bootstrap.require(name not in after and name in request.verified_secrets, "reload Secret inventory repeats or differs")
        secret = inspection.decode(request.verified_secrets[name], recovery.SECRET_LIMIT, "verified activation response")
        recovery.secret_identity(secret, request.binding["namespace"], name)
        patch = entry["patch"]
        bootstrap.require(isinstance(patch, list) and len(patch) >= 4, "reload native patch is incomplete")
        inspection.same(patch[:2], [{"op": "test", "path": "/metadata/uid", "value": entry["uid"]},
            {"op": "test", "path": "/metadata/resourceVersion", "value": entry["resourceVersion"]}],
            "reload native patch identity preconditions differ")
        bootstrap.require(patch[2].get("op") == "test" and patch[2].get("path") == "/data"
                          and isinstance(patch[2].get("value"), dict), "reload native preimage differs")
        expected, fields = deepcopy(patch[2]["value"]), set()
        for operation in patch[3:]:
            bootstrap.require(set(operation) == {"op", "path", "value"} and operation["op"] == "replace",
                              "reload native operation exceeds replacement scope")
            field = recovery.patch_key(operation["path"])
            bootstrap.require(field in expected and field not in fields, "reload Secret replacement repeats or is absent")
            value = operation["value"]
            bootstrap.require(isinstance(value, str) and base64.b64encode(base64.b64decode(value, validate=True)).decode() == value,
                              "reload native replacement encoding differs")
            expected[field] = value
            fields.add(field)
        bootstrap.require(secret["metadata"]["uid"] == entry["uid"]
                          and secret["metadata"]["resourceVersion"] != entry["resourceVersion"],
                          "reload Secret response is not the verified activation generation")
        inspection.same(secret["data"], expected, "reload Secret response differs from activated native data")
        after[name], changed[name] = secret, fields
    bootstrap.require(sum(map(len, changed.values())) == 51, "reload native replacement count differs")
    return plan, after, changed


def container_security(container: dict, *, init: bool = False) -> None:
    expected = {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}}
    if init:
        expected["readOnlyRootFilesystem"] = True
    observed = deepcopy(container.get("securityContext", {}))
    if observed.get("privileged") is False:
        observed.pop("privileged")
    inspection.same(observed, expected, "workload container privilege profile differs")


def workload_template(template: dict, name: str, original: dict) -> None:
    spec = template.get("spec", {})
    bootstrap.require(isinstance(spec, dict) and spec.get("automountServiceAccountToken") is False
                      and spec.get("serviceAccountName") == "marty-app"
                      and spec.get("serviceAccount", "marty-app") == "marty-app"
                      and all(spec.get(field, False) is False for field in ("hostNetwork", "hostPID", "hostIPC", "shareProcessNamespace"))
                      and not spec.get("ephemeralContainers")
                      and not any(field in spec for field in ("hostAliases", "runtimeClassName", "overhead", "resourceClaims")),
                      "workload Pod authority or execution profile differs")
    pod_security = {"runAsNonRoot": True, "runAsUser": 1000 if name == "keycloak" else 10001,
                    "fsGroup": 1000 if name == "keycloak" else 10001, "seccompProfile": {"type": "RuntimeDefault"}}
    if name != "keycloak":
        pod_security.update(runAsGroup=10001, fsGroupChangePolicy="OnRootMismatch")
    actual_security = deepcopy(spec.get("securityContext", {}))
    if actual_security.get("supplementalGroupsPolicy") == "Merge":
        actual_security.pop("supplementalGroupsPolicy")
    inspection.same(actual_security, pod_security, "workload Pod security context differs")
    containers = spec.get("containers")
    bootstrap.require(isinstance(containers, list) and len(containers) == 1 and containers[0].get("name") == name,
                      "workload has an unexpected main container or sidecar")
    main = containers[0]
    immutable_image(main.get("image"), original["images"]["keycloak" if name == "keycloak" else "services"])
    container_security(main)
    inspection.same(main.get("command"), ["/opt/keycloak/bin/kc.sh"] if name == "keycloak" else ["/app/services/entrypoint.sh"],
                    "workload entrypoint differs")
    inspection.same(main.get("args", []), ["start", "--import-realm", "--features=organization"] if name == "keycloak" else [],
                    "workload entrypoint arguments differ")
    init = spec.get("initContainers", [])
    if name == "keycloak":
        bootstrap.require(init == [], "Keycloak has an injected init container")
    else:
        bootstrap.require(isinstance(init, list) and len(init) == 1 and init[0].get("name") == "redis-trust",
                          "native workload init container differs")
        immutable_image(init[0].get("image"), original["images"]["services"])
        container_security(init[0], init=True)
        command = "cat /etc/ssl/certs/ca-certificates.crt /redis-ca/ca.crt"
        if name == "flow":
            command += " /signing-ca/ca.crt"
        inspection.same(init[0].get("command"), ["/bin/sh", "-ec", command + " > /trust/ca-certificates.crt"],
                        "native trust init execution differs")
        bootstrap.require(not init[0].get("env") and not init[0].get("envFrom") and not init[0].get("args"),
                          "native trust init has additional execution inputs")
    for volume in spec.get("volumes", []):
        bootstrap.require(isinstance(volume, dict) and len(set(volume) - {"name"}) == 1
                          and set(volume) - {"name"} <= {"secret", "configMap", "emptyDir"},
                          "workload has an unsupported volume projection")
    for container in containers + init:
        for mount in container.get("volumeMounts", []):
            bootstrap.require(not any(field in mount for field in ("subPath", "subPathExpr"))
                              and mount.get("mountPropagation", "None") == "None",
                              "workload has an unsupported subPath or mount propagation")
        for source in container.get("envFrom", []):
            bootstrap.require(set(source) <= {"configMapRef", "prefix"} and isinstance(source.get("configMapRef"), dict),
                              "workload has an unsupported Secret envFrom projection")


def release_annotation_matches(key: str, expected: object, actual: object) -> bool:
    if key not in ("buildRunId", "buildRunAttempt"):
        return actual == str(expected)
    # Preserve installer_release.positive's authenticated exact-integer bound.
    if (type(expected) is not int or not 0 < expected < 2**53
            or not isinstance(actual, str) or len(actual) > 21):
        return False
    digits = str(expected)
    if actual == digits:
        return True
    if len(digits) < 7:
        return False
    # Helm toString renders these JSON numbers in canonical scientific form.
    # Derive that spelling without parsing the observed text or rounding an ID.
    significant = digits.rstrip("0")
    coefficient = significant[0] + ("." + significant[1:] if len(significant) > 1 else "")
    return actual == f"{coefficient}e+{len(digits) - 1:02d}"


def deployment(value: dict, name: str, request: ReloadRequest, release_name: str | None = None) -> str:
    metadata = identity(value, "Deployment", request.binding["namespace"], name)
    labels, annotations, spec = metadata.get("labels", {}), metadata.get("annotations", {}), value.get("spec", {})
    selected_release = labels.get("app.kubernetes.io/instance")
    bootstrap.require(isinstance(selected_release, str) and re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,51}[a-z0-9])?", selected_release)
                      and (release_name is None or selected_release == release_name)
                      and labels.get("app.kubernetes.io/name") == "marty"
                      and labels.get("app.kubernetes.io/managed-by") == "Helm"
                      and labels.get("app.kubernetes.io/component", name) == name
                      and annotations.get("meta.helm.sh/release-name") == selected_release
                      and annotations.get("meta.helm.sh/release-namespace") == request.binding["namespace"]
                      and not metadata.get("ownerReferences") and not metadata.get("finalizers")
                      and type(metadata.get("generation")) is int and metadata["generation"] > 0
                      and type(spec.get("replicas")) is int and spec["replicas"] == 1
                      and spec.get("paused", False) is False
                      and spec.get("strategy") == {"type": "Recreate"},
                      "Deployment is not the original owned single-replica profile")
    selector = {"app.kubernetes.io/instance": selected_release, "app.kubernetes.io/component": name}
    inspection.same(spec.get("selector"), {"matchLabels": selector}, "Deployment selector differs")
    template = spec.get("template", {})
    bootstrap.require(all(template.get("metadata", {}).get("labels", {}).get(key) == item for key, item in selector.items()),
                      "Deployment template labels differ")
    for key, item in request.original["release"].items():
        bootstrap.require(release_annotation_matches(key, item,
                          template.get("metadata", {}).get("annotations", {}).get("marty.11id.dev/" + key)),
                          "Deployment original release annotations differ")
    workload_template(template, name, request.original)
    return selected_release


@dataclass(frozen=True)
class Probe:
    kind: str
    target: str
    secret: str
    field: str
    digest: str


def safe_path(value: object, *, absolute: bool) -> str:
    bootstrap.require(isinstance(value, str) and len(value) <= 512
                      and re.fullmatch(r"[A-Za-z0-9_./-]+", value)
                      and str(PurePosixPath(value)) == value and PurePosixPath(value).is_absolute() == absolute
                      and not any(part in (".", "..") for part in value.split("/"))
                      and value not in ("", "/"), "credential projection path is unsupported")
    return value


def projections(template: dict, changed: dict[str, set[str]], after: dict) -> list[Probe]:
    spec, probes = template["spec"], []
    main = spec["containers"][0]
    volumes = {volume["name"]: volume for volume in spec.get("volumes", [])}
    bootstrap.require(len(volumes) == len(spec.get("volumes", [])), "workload volume names repeat")
    mounts = main.get("volumeMounts", [])
    mounted_paths = [safe_path(mount.get("mountPath"), absolute=True) for mount in mounts]
    bootstrap.require(len(set(mounted_paths)) == len(mounted_paths), "workload mount paths repeat")
    for mount, root in zip(mounts, mounted_paths):
        volume = volumes.get(mount.get("name"), {})
        source = volume.get("secret", {})
        secret = source.get("secretName")
        if secret not in changed:
            continue
        bootstrap.require(mount.get("readOnly") is True and source.get("optional", False) is False,
                          "changed credential mount is not required and read-only")
        items = source.get("items")
        if items is None:
            items = [{"key": field, "path": field} for field in sorted(after[secret]["data"])]
        bootstrap.require(isinstance(items, list), "Secret item projection is invalid")
        paths = set()
        for item in items:
            bootstrap.require(isinstance(item, dict) and set(item) <= {"key", "path", "mode"}
                              and isinstance(item.get("key"), str), "Secret item projection differs")
            relative = safe_path(item.get("path"), absolute=False)
            target = root + "/" + relative
            bootstrap.require(target not in paths and not any(other.startswith(root + "/") and target.startswith(other + "/")
                              for other in mounted_paths), "credential path is duplicated or shadowed by another mount")
            paths.add(target)
            if item["key"] in changed[secret]:
                raw = base64.b64decode(after[secret]["data"][item["key"]], validate=True)
                probes.append(Probe("file", target, secret, item["key"], recovery.sha256(raw)))
    seen = set()
    for entry in main.get("env", []):
        name = entry.get("name")
        bootstrap.require(isinstance(name, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", name)
                          and name not in seen, "workload environment names are invalid or repeated")
        seen.add(name)
        source = entry.get("valueFrom", {}).get("secretKeyRef", {})
        secret, field = source.get("name"), source.get("key")
        if secret in changed and field in changed[secret]:
            bootstrap.require(set(entry) == {"name", "valueFrom"}
                              and set(entry["valueFrom"]) == {"secretKeyRef"}
                              and set(source) <= {"name", "key", "optional"} and source.get("optional", False) is False,
                              "changed credential environment projection differs")
            raw = base64.b64decode(after[secret]["data"][field], validate=True)
            bootstrap.require(b"\0" not in raw, "changed environment credential contains an unsupported NUL")
            probes.append(Probe("env", name, secret, field, recovery.sha256(raw + b"\n")))
    bootstrap.require(0 < len(probes) <= 128 and len({(probe.kind, probe.target) for probe in probes}) == len(probes),
                      "workload has no closed changed-credential projection or repeats a probe")
    return sorted(probes, key=lambda probe: (probe.kind != "file", probe.target))


def normalized_metadata(value: dict, *, controller: bool = False) -> dict:
    result = deepcopy(value)
    for field in ("resourceVersion", "generation", "managedFields"):
        result.pop(field, None)
    if controller:
        result.get("annotations", {}).pop(REVISION, None)
    return result


def same_deployment(observed: dict, expected: dict, namespace: str, *, controller: bool = False) -> None:
    identity(observed, "Deployment", namespace, expected["metadata"]["name"])
    inspection.same(observed["spec"], expected["spec"], "Deployment spec or patched template changed concurrently")
    inspection.same(normalized_metadata(observed["metadata"], controller=controller),
                    normalized_metadata(expected["metadata"], controller=controller),
                    "Deployment metadata changed outside the reload")
    bootstrap.require(observed["metadata"]["generation"] == expected["metadata"]["generation"],
                      "Deployment generation changed concurrently")


def ready(value: dict) -> bool:
    status = value.get("status", {})
    return (type(status.get("observedGeneration")) is int
            and status["observedGeneration"] >= value["metadata"]["generation"]
            and all(type(status.get(field)) is int and status[field] == 1
                    for field in ("replicas", "updatedReplicas", "readyReplicas", "availableReplicas"))
            and status.get("unavailableReplicas", 0) == 0 and status.get("terminatingReplicas", 0) == 0)


def owner(value: dict, kind: str, name: str, uid: str) -> None:
    owners = value.get("metadata", {}).get("ownerReferences")
    bootstrap.require(isinstance(owners, list) and len(owners) == 1 and owners[0].get("apiVersion") == "apps/v1"
                      and owners[0].get("kind") == kind and owners[0].get("name") == name
                      and owners[0].get("uid") == uid and owners[0].get("controller") is True,
                      "new workload object has different controller ownership")


def pod_spec_matches(actual: dict, expected: dict) -> None:
    observed, retained = deepcopy(actual), deepcopy(expected)
    if "nodeName" not in retained:
        bootstrap.require(isinstance(observed.get("nodeName"), str) and observed["nodeName"], "ready Pod has no assigned node")
        observed.pop("nodeName")
    for field, default in (("priority", 0), ("preemptionPolicy", "PreemptLowerPriority")):
        if field not in retained and observed.get(field) == default:
            observed.pop(field)
    defaults = {"dnsPolicy": "ClusterFirst", "restartPolicy": "Always", "schedulerName": "default-scheduler",
                "terminationGracePeriodSeconds": 30, "enableServiceLinks": True,
                "hostNetwork": False, "hostPID": False, "hostIPC": False, "shareProcessNamespace": False,
                "serviceAccount": "marty-app", "tolerations": []}
    for spec in (observed, retained):
        for field, default in defaults.items():
            spec.setdefault(field, deepcopy(default))
        for container in spec.get("containers", []) + spec.get("initContainers", []):
            container.setdefault("terminationMessagePath", "/dev/termination-log")
            container.setdefault("terminationMessagePolicy", "File")
        spec.setdefault("initContainers", [])
    standard = [{"key": "node.kubernetes.io/" + condition, "operator": "Exists", "effect": "NoExecute", "tolerationSeconds": 300}
                for condition in ("not-ready", "unreachable")]
    extras = [item for item in observed["tolerations"] if item not in retained["tolerations"]]
    bootstrap.require(all(item in standard for item in extras) and len(extras) == len({bootstrap.encoded(item) for item in extras}),
                      "new Pod has unexpected scheduling tolerations")
    observed["tolerations"] = [item for item in observed["tolerations"] if item not in extras]
    inspection.same(observed, retained, "new Pod execution, volumes or configuration differs from the frozen template")


def admitted_pod(pod: dict, replica_set: dict, deployment_value: dict, request: ReloadRequest) -> dict:
    name = deployment_value["metadata"]["name"]
    metadata = identity(pod, "Pod", request.binding["namespace"])
    owner(pod, "ReplicaSet", replica_set["metadata"]["name"], replica_set["metadata"]["uid"])
    inspection.same(metadata.get("labels"), replica_set["spec"]["template"]["metadata"]["labels"], "new Pod labels differ")
    inspection.same(metadata.get("annotations", {}), deployment_value["spec"]["template"]["metadata"]["annotations"],
                    "new Pod recovery or release annotations differ")
    workload_template({"spec": pod["spec"]}, name, request.original)
    pod_spec_matches(pod["spec"], deployment_value["spec"]["template"]["spec"])
    status, identities = pod.get("status", {}), {}
    bootstrap.require(status.get("phase") == "Running" and any(item.get("type") == "Ready" and item.get("status") == "True"
                      for item in status.get("conditions", [])) and not status.get("ephemeralContainerStatuses"),
                      "new Pod is not Ready")
    main = status.get("containerStatuses", [])
    bootstrap.require(isinstance(main, list) and len(main) == 1 and main[0].get("name") == name
                      and main[0].get("ready") is True and isinstance(main[0].get("state", {}).get("running"), dict),
                      "new main container is not the expected running process")
    init = status.get("initContainerStatuses", [])
    bootstrap.require(init == [] if name == "keycloak" else isinstance(init, list) and len(init) == 1
                      and init[0].get("name") == "redis-trust" and init[0].get("state", {}).get("terminated", {}).get("exitCode") == 0,
                      "new Pod init completion differs")
    for item in main + init:
        bootstrap.require(isinstance(item.get("imageID"), str) and item["imageID"]
                          and isinstance(item.get("containerID"), str) and item["containerID"]
                          and type(item.get("restartCount")) is int and item["restartCount"] >= 0,
                          "new container runtime identity is incomplete")
        identities[item["name"]] = {key: item[key] for key in ("imageID", "containerID", "restartCount")}
    return {"uid": metadata["uid"], "spec": pod["spec"], "runtimeIdentities": identities}


def captured_patch(transport: BudgetedTransport, name: str, patch: list, index: int,
                   remaining: Callable[[], int]) -> bytes:
    transport.evidence.recheck()
    command = [*transport.base, "patch", "deployment", name, "--type=json", "--patch-file=/dev/stdin", "-o", "json"]
    payload = bootstrap.encoded(patch)
    # Scanning and serialization consume both clocks. Check the original
    # qualification and native plan again after that work, at actual dispatch.
    timeout = transport.budget.timeout(min(30, remaining()))
    try:
        result = subprocess.run(command, input=payload, capture_output=True,
                                check=False, timeout=timeout)
        completed, code, stdout, stderr = True, result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired as error:
        completed, code, stdout, stderr = False, None, error.stdout or b"", error.stderr or b""
    except OSError:
        completed, code, stdout, stderr = False, None, b"", b""
    bounded = len(stdout) <= OBJECT_LIMIT and len(stderr) <= 1024 * 1024
    transport.evidence.write(f"patch-response-{index:02}.json", bootstrap.encoded({
        "completed": completed, "exitCode": code, "bounded": bounded,
        "stdoutBase64": base64.b64encode(stdout[:OBJECT_LIMIT]).decode(),
        "stderrBase64": base64.b64encode(stderr[:1024 * 1024]).decode()}), 5 * 1024 * 1024)
    transport.evidence.recheck()
    bootstrap.require(completed and code == 0 and bounded and stdout,
                      "Deployment restart outcome failed or is uncertain; preserve private evidence")
    transport.budget.timeout()
    return stdout


def active_objects(get: Callable, deployed: dict, request: ReloadRequest) -> tuple[dict, dict] | None:
    name = deployed["metadata"]["name"]
    selector = ",".join(key + "=" + value for key, value in sorted(deployed["spec"]["selector"]["matchLabels"].items()))
    sets = get("replicasets", "-l", selector, kind="ReplicaSetList", maximum=LIST_LIMIT)["items"]
    pods = get("pods", "-l", selector, kind="PodList", maximum=LIST_LIMIT)["items"]
    bootstrap.require(isinstance(sets, list) and isinstance(pods, list) and len(sets) <= 64 and len(pods) <= 64,
                      "reload controller observation inventory is invalid")
    selected, set_uids = [], set()
    for replica in sets:
        metadata = identity(replica, "ReplicaSet", request.binding["namespace"])
        owner(replica, "Deployment", name, deployed["metadata"]["uid"])
        bootstrap.require(metadata["uid"] not in set_uids, "ReplicaSet identities repeat")
        set_uids.add(metadata["uid"])
        template = deepcopy(replica["spec"]["template"])
        pod_hash = template["metadata"]["labels"].pop("pod-template-hash", None)
        if bootstrap.encoded(template) == bootstrap.encoded(deployed["spec"]["template"]):
            bootstrap.require(isinstance(pod_hash, str) and re.fullmatch(r"[a-z0-9]{1,63}", pod_hash)
                              and metadata.get("annotations", {}).get(REVISION) == deployed["metadata"].get("annotations", {}).get(REVISION)
                              and isinstance(metadata.get("annotations", {}).get(REVISION), str),
                              "new ReplicaSet revision or template hash differs")
            inspection.same(replica["spec"].get("selector"), {"matchLabels": {
                **deployed["spec"]["selector"]["matchLabels"], "pod-template-hash": pod_hash}},
                "new ReplicaSet selector differs")
            if replica["spec"].get("replicas") == 1 and replica.get("status", {}).get("replicas") == 1:
                selected.append(replica)
        elif replica["spec"].get("replicas", 0) != 0:
            raise bootstrap.BootstrapError("another ReplicaSet is active outside the requested rollout")
    for pod in pods:
        references = pod.get("metadata", {}).get("ownerReferences", [])
        bootstrap.require(len(references) == 1 and references[0].get("kind") == "ReplicaSet"
                          and references[0].get("uid") in set_uids and references[0].get("controller") is True,
                          "a selected Pod has foreign controller ownership")
    if len(selected) != 1 or len(pods) != 1:
        return None
    pod, replica = pods[0], selected[0]
    if (pod.get("metadata", {}).get("deletionTimestamp") or pod.get("status", {}).get("phase") != "Running"
            or not any(item.get("type") == "Ready" and item.get("status") == "True" for item in pod.get("status", {}).get("conditions", []))):
        return None
    admitted_pod(pod, replica, deployed, request)
    return replica, pod


def reload_workloads(request: ReloadRequest, transport, freshness: Freshness,
                     phase_guard: Callable[[BudgetedTransport], None]) -> dict:
    """Return a bounded observation summary after private completion is durable.

    The caller holds the retained-state lock. Its phase_guard must use the
    supplied capped transport for I/O and check original/current/candidate/root
    and private evidence stability; it must not require a deleted producer Pod.
    This module additionally binds namespace and original OpenBao Pod/image.
    Exec hashes prove projected bytes in a new Ready Pod, not provider memory
    or full-environment/end-to-end health. No public credential hash is returned.
    """
    request = ReloadRequest(request.output, deepcopy(request.original), deepcopy(request.binding),
        request.openbao_uid, request.qualified_plan, request.qualified_plan_sha256, dict(request.verified_secrets))
    budget = Budget()
    evidence = Evidence(request.output, budget)
    bounded = BudgetedTransport(transport, budget, evidence)
    bootstrap.require(bounded.namespace == request.binding["namespace"], "reload transport namespace differs")
    attempted, patched, proved = [], {}, {}
    phase_name = "activation-admission"
    try:
        plan, after, changed = admitted_inputs(request)
        evidence.write("qualified-plan.json", request.qualified_plan, recovery.REPORT_LIMIT + 1)
        for index, name in enumerate(sorted(after)):
            evidence.write(f"secret-after-{index:02}.json", request.verified_secrets[name], recovery.SECRET_LIMIT)
        annotation = "marty.11id.dev/legacy-reload-" + bootstrap.secrets.token_hex(6)
        evidence.write("reload-requested.json", bootstrap.encoded({"schema": SCHEMA,
            "binding": request.binding, "originalRuntime": request.original["release"], "openbaoUid": request.openbao_uid,
            "privatePlanSha256": request.qualified_plan_sha256, "annotation": annotation, "workloads": WORKLOADS,
            "maximumSeconds": EVIDENCE_LIMITS["maximumSeconds"], "automaticReplay": False}), 65536)

        def guard() -> None:
            budget.timeout()
            evidence.recheck()
            phase_guard(bounded)
            inspection.namespace_identity(bounded, request.binding)
            inspection.openbao_identity(bounded, request.original["images"]["openbao_didcomm"], uid=request.openbao_uid)
            budget.timeout()

        def get(resource: str, *arguments: str, kind: str | None = None, maximum: int = OBJECT_LIMIT) -> dict:
            raw = bounded.kubectl("legacy reload observation", "get", resource, *arguments, "-o", "json")
            value = inspection.decode(raw, maximum, "private reload observation")
            if kind is not None:
                bootstrap.require(value.get("kind") == kind and value.get("apiVersion") == (
                    "v1" if kind == "PodList" else "apps/v1"), "reload list type differs")
            return value

        def secrets_stable() -> None:
            for name, expected in sorted(after.items()):
                observed = get("secret", name)
                recovery.secret_identity(observed, request.binding["namespace"], name)
                inspection.same({"uid": observed["metadata"]["uid"], "resourceVersion": observed["metadata"]["resourceVersion"],
                    "data": observed["data"]}, {"uid": expected["metadata"]["uid"],
                    "resourceVersion": expected["metadata"]["resourceVersion"], "data": expected["data"]},
                    "activated Secret binding changed before or during reload")

        def fresh() -> int:
            freshness.check()
            remaining = math.floor(plan["validBeforeUnixSeconds"] - time.time())
            bootstrap.require(remaining > 0, "qualified credential plan expired before restart")
            return min(remaining, freshness.remaining())

        guard()
        fresh()
        secrets_stable()
        phase_name = "deployment-preimages"
        originals, probes, patches, release_name, seen_uids = {}, {}, {}, None, set()
        for index, name in enumerate(WORKLOADS):
            observed = get("deployment", name)
            release_name = deployment(observed, name, request, release_name)
            bootstrap.require(observed["metadata"]["uid"] not in seen_uids, "Deployment UIDs repeat")
            seen_uids.add(observed["metadata"]["uid"])
            template = observed["spec"]["template"]
            bootstrap.require(annotation not in template["metadata"]["annotations"], "recovery annotation already exists")
            originals[name], probes[name] = observed, projections(template, changed, after)
            evidence.write(f"deployment-before-{index:02}.json", bootstrap.encoded(observed))
            patches[name] = [
                {"op": "test", "path": "/metadata/uid", "value": observed["metadata"]["uid"]},
                {"op": "test", "path": "/metadata/resourceVersion", "value": observed["metadata"]["resourceVersion"]},
                {"op": "test", "path": "/spec/template", "value": template},
                {"op": "add", "path": "/spec/template/metadata/annotations/" + annotation.replace("~", "~0").replace("/", "~1"),
                 "value": request.qualified_plan_sha256},
            ]
        evidence.write("reload-plan.json", bootstrap.encoded({"schema": SCHEMA, "binding": request.binding,
            "privatePlanSha256": request.qualified_plan_sha256, "patches": patches}), LIST_LIMIT)
        for index, name in enumerate(WORKLOADS):
            phase_name = "restart-" + name
            fresh()
            guard()
            secrets_stable()
            fresh()
            evidence.write(f"patch-intent-{index:02}.json", bootstrap.encoded({"name": name,
                "uid": originals[name]["metadata"]["uid"], "patchSha256": recovery.sha256(bootstrap.encoded(patches[name])),
                "privatePlanSha256": request.qualified_plan_sha256, "validBeforeUnixSeconds": plan["validBeforeUnixSeconds"]}))
            evidence.recheck(full=True)
            attempted.append(name)
            raw = captured_patch(bounded, name, patches[name], index, fresh)
            observed = inspection.decode(raw, OBJECT_LIMIT, "private Deployment patch reply")
            expected = deepcopy(originals[name])
            expected["spec"]["template"]["metadata"]["annotations"][annotation] = request.qualified_plan_sha256
            expected["metadata"]["generation"] += 1
            same_deployment(observed, expected, request.binding["namespace"])
            bootstrap.require(observed["metadata"]["resourceVersion"] != originals[name]["metadata"]["resourceVersion"],
                              "Deployment patch response did not advance its resource version")
            evidence.write(f"deployment-patched-{index:02}.json", raw)
            patched[name] = observed

        def still_target(name: str, replica: dict, pod: dict, admitted: dict) -> None:
            observed = get("deployment", name)
            same_deployment(observed, patched[name], request.binding["namespace"], controller=True)
            bootstrap.require(ready(observed), "reloaded Deployment lost its one Ready replica")
            current_objects = active_objects(get, observed, request)
            bootstrap.require(current_objects is not None, "reloaded workload gained old or additional Pod replicas")
            current_replica, current_pod = current_objects
            bootstrap.require(current_replica["metadata"]["uid"] == replica["metadata"]["uid"]
                              and current_replica["metadata"].get("annotations", {}).get(REVISION)
                              == observed["metadata"].get("annotations", {}).get(REVISION), "new ReplicaSet identity changed")
            inspection.same(current_replica["spec"], replica["spec"], "new ReplicaSet spec changed")
            inspection.same(admitted_pod(current_pod, current_replica, observed, request), admitted,
                            "Pod UID, spec or runtime container identity changed across credential probe")

        pending, seen_pods, seen_sets = set(WORKLOADS), set(), set()
        while pending:
            phase_name = "bounded-readiness-and-projections"
            guard()
            for index, name in enumerate(WORKLOADS):
                if name not in pending:
                    continue
                current = get("deployment", name)
                same_deployment(current, patched[name], request.binding["namespace"], controller=True)
                if not ready(current):
                    continue
                selected = active_objects(get, current, request)
                if selected is None:
                    continue
                replica, pod = selected
                admitted = admitted_pod(pod, replica, current, request)
                bootstrap.require(admitted["uid"] not in seen_pods and replica["metadata"]["uid"] not in seen_sets,
                                  "reloaded Pod or ReplicaSet UID repeats across workloads")
                evidence.write(f"replicaset-{index:02}.json", bootstrap.encoded(replica))
                evidence.write(f"pod-before-{index:02}.json", bootstrap.encoded(pod))
                guard()
                secrets_stable()
                still_target(name, replica, pod, admitted)
                files = [probe.target for probe in probes[name] if probe.kind == "file"]
                variables = [probe.target for probe in probes[name] if probe.kind == "env"]
                raw = bounded.execute(pod["metadata"]["name"], ["/bin/sh", "-ec", PROBE_PROGRAM, "--", str(len(files)), *files, *variables],
                                      container=name, timeout=30)
                guard()
                still_target(name, replica, pod, admitted)
                secrets_stable()
                expected_output = b"".join((probe.kind + " " + probe.digest + "  "
                    + (probe.target if probe.kind == "file" else "-") + "\n").encode() for probe in probes[name])
                bootstrap.require(raw == expected_output, "new Pod mounted or environment credential hash differs, or probe capability is unavailable")
                evidence.recheck(full=True)
                evidence.write(f"projection-proof-{index:02}.json", bootstrap.encoded({"name": name,
                    "pod": pod["metadata"]["name"], "uid": admitted["uid"], "runtimeIdentities": admitted["runtimeIdentities"],
                    "probes": [vars(probe) for probe in probes[name]], "responseSha256": recovery.sha256(raw),
                    "scope": "projected mounted files and container environment; provider memory was not inspected"}))
                seen_pods.add(admitted["uid"])
                seen_sets.add(replica["metadata"]["uid"])
                proved[name] = {"replica": replica, "pod": pod, "admitted": admitted}
                pending.remove(name)
            if pending:
                budget.pause()
        phase_name = "final-observation"
        guard()
        secrets_stable()
        for name in WORKLOADS:
            result = proved[name]
            still_target(name, result["replica"], result["pod"], result["admitted"])
        budget.timeout()
        private_evidence = evidence.complete({"schema": SCHEMA, "binding": request.binding,
            "status": "new-ready-pods-with-matching-projected-credentials", "privatePlanSha256": request.qualified_plan_sha256,
            "workloads": {name: {"deploymentUid": patched[name]["metadata"]["uid"],
                "podUid": proved[name]["admitted"]["uid"], "replicaSetUid": proved[name]["replica"]["metadata"]["uid"]} for name in WORKLOADS},
            "reloadCount": 16, "inMemoryProviderUseProved": False, "fullEnvironmentHealthAssessed": False,
            "runtimeImageIdLimit": "observed runtime imageID is bound across probes; its platform/config digest representation is not equated to the published image digest"})
        budget.timeout()
        return {"schema": SCHEMA, "status": "sixteen-ready-pods-with-matching-projections", "reloadCount": 16,
                "privateEvidenceWritten": True, "privateEvidence": private_evidence,
                "fullEnvironmentHealthAssessed": False, "inMemoryProviderUseProved": False}
    except Exception:
        evidence.write("reload-stopped.json", bootstrap.encoded({"schema": SCHEMA, "binding": request.binding,
            "phase": phase_name, "attempted": attempted, "verifiedPatches": list(patched), "provedPods": list(proved),
            "status": "incomplete-preserve-private-evidence", "automaticReplay": False, "reloadComplete": False}))
        raise
