#!/usr/bin/env python3
"""Explicitly enroll a recovered legacy Kubernetes generation for routine renewal.

This creates a separate adoption receipt. It never edits historical bootstrap,
reissues runtime credentials, changes installed images, or replays an uncertain
enrollment. Reconciliation imports complete retained evidence and verifies live
authority; incomplete evidence remains a stopped private operator attempt.
"""
from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
from copy import copy
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import time

import bootstrap_kubernetes_openbao as bootstrap
import inspect_kubernetes_legacy_credentials as inspection
import kubernetes_application_state as selection
import kubernetes_renewal_adoption_state as adoption
import recover_kubernetes_legacy_credentials as recovery
import reload_kubernetes_legacy_workloads as reload
import stage_kubernetes_application_credentials as private

REMOTE_OPERATOR = "/tmp/marty-deploy"
REMOTE_CURRENT = "/tmp/adoption-current"
REMOTE_APPLICATION = "/tmp/adoption-application"
REMOTE_RENEWAL = "/tmp/adoption-renewal"
REMOTE_BINDING = "/tmp/adoption-binding.json"
REMOTE_OUTPUT = "/tmp/adoption-verification"


def write(path: Path, value: dict) -> None:
    bootstrap.write_new(path, bootstrap.encoded(value))
    descriptor = selection.directory_fd(path.parent)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def legacy_candidate(args, complete: dict, original: dict, binding: dict) -> tuple[dict, dict, bytes, dict]:
    source = args.recovery_dir
    selection.owned_directory(source)
    bootstrap.require(not source.is_relative_to(args.state_dir) and not args.state_dir.is_relative_to(source)
        and not args.operation_dir.is_relative_to(source) and not source.is_relative_to(args.operation_dir),
        "adoption, recovery and retained bootstrap directories must be separate")
    completion = adoption.record(source / "recovery-complete.json")
    bound = recovery.full_binding(complete, binding, args.chart_source_sha)
    value = completion.value
    bootstrap.require(value.get("schema") == "marty.kubernetes-legacy-recovery-completion/v1"
        and value.get("binding") == bound and value.get("originalRuntime") == original["release"]
        and value.get("status") == "existing-secrets-activated" and value.get("activation") is True
        and value.get("credentialsIssued") is True and value.get("verifiedSecretCount") == 34
        and value.get("podRemoved") is True, "adoption requires completed legacy Secret activation")
    snapshot = private.current_snapshot(source / "candidate")
    plan_raw = private.private_bytes(source / "qualified-plan.json", recovery.REPORT_LIMIT + 1, {0o600})[0]
    plan = inspection.decode(plan_raw, recovery.REPORT_LIMIT + 1, "retained recovery plan")
    bootstrap.require(adoption.digest(plan_raw) == value["privatePlanSha256"]
        and plan.get("binding") == bound
        and plan.get("nativePlan", {}).get("candidateInputs") == adoption.hashes(snapshot),
        "recovered candidate differs from completed native activation")
    responses = {}
    for index, entry in enumerate(plan["nativePlan"]["secrets"]):
        response = adoption.record(source / "activation" / f"response-{index:02}.json").value
        bootstrap.require(response.get("completed") is True and response.get("bounded") is True
            and response.get("exitCode") == 0, "legacy Secret activation response is incomplete")
        responses[entry["name"]] = base64.b64decode(response["stdoutBase64"], validate=True)
    # The original native plan remains provenance, never a fresh lifetime proof.
    requested = adoption.record(source / "recovery-requested.json").value
    bootstrap.require(requested.get("binding") == bound and requested.get("originalRuntime") == original["release"],
        "legacy recovery request names another installation")
    request = reload.ReloadRequest(args.operation_dir, original, bound,
        requested["openbao"]["uid"], plan_raw, adoption.digest(plan_raw), responses)
    _, after, changed = reload.admitted_inputs(request)
    return snapshot, {"completion": completion, "plan": plan_raw, "after": after, "changed": changed,
                      "bound": bound}, plan_raw, responses


def complete_domain(operation: Path, intent: dict, domain: str) -> None:
    bootstrap.require(adoption.record(operation / (domain + "-enrollment-intent.json")).value
        == domain_intent(intent, domain), "enrollment intent differs from adoption")
    values = private.current_snapshot(operation / (domain + "-identity"))
    names = bootstrap.APPLICATION_IDENTITY_FILES if domain == "application" else bootstrap.RENEWAL_IDENTITY_FILES
    bootstrap.require(set(values) == names, "renewal enrollment identity is partial")
    value = {"schema": "marty.kubernetes-renewal-adoption-domain/v1",
        "adoptionId": intent["adoptionId"], "binding": intent["binding"], "domain": domain,
        "identityInputs": adoption.hashes(values), "enrollmentReplayed": False}
    path = operation / (domain + "-enrolled.json")
    if path.exists():
        bootstrap.require(adoption.record(path).value == value, "retained enrollment completion changed")
    else:
        write(path, value)


def domain_intent(intent: dict, domain: str) -> dict:
    return {"schema": "marty.kubernetes-renewal-adoption-enrollment-intent/v1",
        "adoptionId": intent["adoptionId"], "binding": intent["binding"], "domain": domain,
        "operatorIdentity": intent["operatorBuildIdentity"], "candidateInputs": intent["candidateInputs"],
        "operation": "approle-bootstrap application" if domain == "application" else "kubernetes-renewal-enroll",
        "automaticReplay": False}


def import_uncertain(operation: Path, intent: dict, domain: str) -> None:
    """Recover only complete archived identities; never call either enrollment owner."""
    target = operation / (domain + "-identity")
    selection.owned_directory(target)
    names = bootstrap.APPLICATION_IDENTITY_FILES if domain == "application" else bootstrap.RENEWAL_IDENTITY_FILES
    if {path.name for path in target.iterdir()} != names:
        maximum = (bootstrap.APPLICATION_IDENTITY_ARCHIVE_LIMIT if domain == "application"
                   else bootstrap.RENEWAL_IDENTITY_ARCHIVE_LIMIT)
        raw = private.private_bytes(operation / (domain + "-authority-recovery.tar"), maximum, {0o600})[0]
        checked = operation / ("identity-reconciliation-" + bootstrap.secrets.token_hex(6))
        bootstrap.private_directory(checked)
        if domain == "application":
            bootstrap.take_application_identity(raw, checked, intent["binding"])
        else:
            bootstrap.take_renewal_identity(raw, checked)
        recovered = private.current_snapshot(checked)
        existing = private.current_snapshot(target) if any(target.iterdir()) else {}
        bootstrap.require(set(existing) <= names and all(recovered[name] == value for name, value in existing.items()),
            "partial enrollment identity conflicts with retained native evidence")
        write(checked / "reconciliation.json", {"schema": "marty.kubernetes-renewal-adoption-reconciliation/v1",
            "domain": domain, "adoptionId": intent["adoptionId"], "archiveSha256": adoption.digest(raw),
            "identityInputs": adoption.hashes(recovered), "enrollmentReplayed": False})
        for name, (value, mode) in recovered.items():
            if name not in existing:
                private.write_preserved(target / name, value, mode)
    if domain == "renewal" and not (operation / "renewal-binding.json").exists():
        raw = private.private_bytes(operation / "renewal-enrollment-recovery.tar",
            bootstrap.RENEWAL_ENROLLMENT_ARCHIVE_LIMIT, {0o600})[0]
        members = bootstrap.private_archive(raw, bootstrap.RENEWAL_ENROLLMENT_LIMITS,
            maximum=bootstrap.RENEWAL_ENROLLMENT_ARCHIVE_LIMIT, modes={0o600}, directories={"."},
            complete=True, allow_empty=False)
        binding = bootstrap.renewal_binding(inspection.decode(members["binding.json"][0], 4096,
            "reconciled renewal binding"), intent["binding"])
        expected = {"schema": "marty.kubernetes-renewal-enrollment/v1", "binding": intent["binding"],
            "producerNonce": binding["producerNonce"], "identityFiles": sorted(bootstrap.RENEWAL_IDENTITY_FILES),
            "scopedLeafTokens": 21, "enrolled": True, "activated": False}
        bootstrap.require(inspection.decode(members["completed.json"][0], 65536,
            "reconciled renewal enrollment") == expected, "renewal enrollment has no complete native receipt")
        write(operation / "renewal-binding.json", binding)
    complete_domain(operation, intent, domain)


def quiescent_attempts(operation: Path, transport) -> None:
    for path in sorted(operation.glob("transport-*/producer.json")):
        value = adoption.record(path).value
        raw = transport.kubectl("adoption prior producer reconciliation", "get", "pod",
            value["pod"]["metadata"]["name"], "--ignore-not-found", "-o", "json", timeout=30)
        if not raw.strip():
            continue
        observed = inspection.decode(raw, 1024 * 1024, "prior adoption producer")
        bootstrap.require(observed.get("metadata", {}).get("uid") == value["uid"]
            and observed.get("metadata", {}).get("namespace") == transport.namespace
            and observed.get("status", {}).get("phase") in {"Succeeded", "Failed"}
            and observed.get("status", {}).get("containerStatuses")
            and all("terminated" in entry.get("state", {}) for entry in observed["status"]["containerStatuses"]),
            "previous enrollment may still be running; preserve evidence and do not replay")


@contextmanager
def producer(args, intent: dict, operator: bytes, original: dict, selected: dict, guard):
    operation = args.operation_dir
    work = operation / ("transport-" + bootstrap.secrets.token_hex(6))
    bootstrap.private_directory(work)
    bootstrap.write_new(work / "kubeconfig", inspection.kubeconfig_bytes(args.state_dir))
    kubectl = shutil.which("kubectl")
    bootstrap.require(kubectl is not None, "kubectl must be installed")
    base = bootstrap.Transport(work, work / "kubeconfig", intent["binding"]["namespace"], kubectl)
    quiescent_attempts(operation, base)
    guard()
    inspection.namespace_identity(base, intent["binding"])
    openbao = inspection.openbao_identity(base, original["images"]["openbao_didcomm"])
    expected = inspection.producer_document(intent["binding"]["namespace"], selected["images"]["services"],
        bootstrap.secrets.token_hex(6), intent["pullSecrets"])
    write(work / "producer-requested.json", {"pod": expected, "adoptionId": intent["adoptionId"],
        "binding": intent["binding"], "automaticReplay": False})
    raw = base.kubectl("adoption producer creation", "create", "-f", "-", "-o", "json",
        data=bootstrap.encoded(expected), timeout=60)
    observed = inspection.decode(raw, 1024 * 1024, "adoption producer creation")
    uid = inspection.pod_identity(observed, expected)
    write(work / "producer.json", {"pod": expected, "uid": uid, "adoptionId": intent["adoptionId"]})
    pod = expected["metadata"]["name"]
    complete = False
    try:
        base.kubectl("adoption producer readiness", "wait", "--for=condition=Ready", "pod/" + pod,
            "--timeout=300s", timeout=330)
        baseline = inspection.observed_pod(base, expected, uid)["spec"]

        def phase():
            guard()
            inspection.namespace_identity(base, intent["binding"])
            inspection.same(inspection.openbao_identity(base, original["images"]["openbao_didcomm"], uid=openbao["uid"]),
                openbao, "adoption OpenBao owner changed")
            inspection.same(inspection.observed_pod(base, expected, uid)["spec"], baseline,
                "adoption producer owner changed")

        class Enroller:
            state, namespace = operation, base.namespace

            def execute(self, *arguments, **kwargs):
                phase()
                return base.execute(*arguments, **kwargs)

            def upload(self, *arguments, **kwargs):
                phase()
                return base.upload(*arguments, **kwargs)

            def kubectl(self, *arguments, **kwargs):
                phase()
                return base.kubectl(*arguments, **kwargs)

        transport = Enroller()
        transport.upload(pod, REMOTE_OPERATOR, operator, executable=True)
        copied = transport.execute(pod, ["sha256sum", REMOTE_OPERATOR]).decode().split()
        bootstrap.require(copied and copied[0] == adoption.digest(operator), "copied adoption operator differs")
        ca = private.current_snapshot(operation / "candidate")["openbao_tls_ca_cert"][0]
        transport.upload(pod, "/tmp/ca.crt", ca)
        yield transport, pod, base
        phase()
        complete = True
    finally:
        if complete:
            inspection.delete_pod(base, expected, uid)
            write(work / "retired.json", {"uid": uid, "removed": True})
        else:
            write(work / "uncertain.json", {"uid": uid, "nativeMayStillRun": True,
                "activeDeadlineSeconds": 1200, "automaticReplay": False})


def enroll_domains(args, intent: dict, operator: bytes, original: dict, selected: dict, guard) -> None:
    operation = args.operation_dir
    for domain in ("application", "renewal"):
        completed = operation / (domain + "-enrolled.json")
        requested = operation / (domain + "-enrollment-intent.json")
        if completed.exists():
            complete_domain(operation, intent, domain)
            continue
        if requested.exists():
            bootstrap.require(args.reconcile, "uncertain enrollment requires explicit reconciliation")
            import_uncertain(operation, intent, domain)
            continue
        # A domain with a durable native request is never sent here again.
        # The other domain may be enrolled once when it was never attempted.
        material = inspection.decode(private.private_bytes(args.state_dir / "openbao-initialization.json",
            65536, {0o400})[0], 65536, "retained initialization")
        root = material.get("root_token")
        bootstrap.require(isinstance(root, str) and 20 <= len(root) <= 256
            and all(33 <= ord(character) <= 126 for character in root), "retained root authority is invalid")
        with producer(args, intent, operator, original, selected, guard) as (transport, pod, _):
            write(requested, domain_intent(intent, domain))
            if domain == "application":
                files = {entry["input"]: operation / "candidate" / entry["file"]
                         for entry in intent["contracts"]["application"]["tokens"]}
                bootstrap.enroll_application_authority(transport, pod, root_token=root,
                    binding=intent["binding"], files=files)
            else:
                bootstrap.enroll_renewal_authority(transport, pod, root_token=root,
                    binding=intent["binding"], current=operation / "candidate")
            complete_domain(operation, intent, domain)


def verify_native(args, intent: dict, operator: bytes, original: dict, selected: dict, guard) -> Path:
    operation = args.operation_dir
    verification = operation / ("verification-" + bootstrap.secrets.token_hex(6))
    bootstrap.private_directory(verification)
    with producer(args, intent, operator, original, selected, guard) as (transport, pod, _):
        transport.execute(pod, ["/bin/sh", "-ec",
            'umask 077; for path in "$@"; do mkdir "$path"; chmod u=rwx,go=,a-s,a-t "$path"; done', "--",
            REMOTE_CURRENT, REMOTE_APPLICATION, REMOTE_RENEWAL, REMOTE_OUTPUT])
        for local, remote in ((operation / "candidate", REMOTE_CURRENT),
                              (operation / "application-identity", REMOTE_APPLICATION),
                              (operation / "renewal-identity", REMOTE_RENEWAL)):
            transport.execute(pod, ["tar", "-xpf", "-", "-C", remote],
                data=private.archive_snapshot(private.current_snapshot(local)))
        transport.upload(pod, REMOTE_BINDING,
            private.private_bytes(operation / "renewal-binding.json", 4096, {0o600})[0])
        write(verification / "requested.json", {"adoptionId": intent["adoptionId"], "binding": intent["binding"],
            "operation": "kubernetes-renewal-adoption-verify", "enrollmentReplayed": False})
        failed = None
        try:
            raw = transport.execute(pod, [REMOTE_OPERATOR, "operator", "kubernetes-renewal-adoption-verify",
                "https://openbao:8200", "/tmp/ca.crt", REMOTE_OUTPUT], data=bootstrap.encoded({
                "binding": intent["binding"], "bootstrap_id": intent["bootstrapId"],
                "adoption_id": intent["adoptionId"], "operator_identity": intent["operatorBuildIdentity"],
                "candidate": REMOTE_CURRENT, "application_identity": REMOTE_APPLICATION,
                "renewal_identity": REMOTE_RENEWAL, "renewal_binding": REMOTE_BINDING}), timeout=930)
            result = inspection.decode(raw, 4096, "native adoption verification")
            bootstrap.require(result.get("ready") is True and result.get("applicationRoles") == 11
                and result.get("scopedLeafTokens") == 21 and result.get("minimumTtlSeconds") == 3600,
                "native adoption verification did not complete")
        except Exception as error:
            failed = error
        # Preserve complete or partial verification/session evidence before producer retirement.
        archive = bootstrap.remote_archive(transport, pod, REMOTE_OUTPUT, 2 * 1024 * 1024)
        bootstrap.write_new(verification / "native-evidence.tar", archive)
        limits = {"attempt.json": 262144, "verified.json": 262144,
            "application/attempt.json": 4096, "application/login-response.json": 1024 * 1024,
            "application/complete.json": 4096, "renewal/pending.json": 65536,
            "renewal/authority.token": 1024, "renewal/complete.json": 4096}
        members = bootstrap.private_archive(archive, limits, maximum=2 * 1024 * 1024, modes={0o600},
            directories={".", "application", "renewal"}, complete=failed is None, allow_empty=failed is not None)
        for name, (value, mode) in members.items():
            path = verification / name
            if not path.parent.exists():
                bootstrap.private_directory(path.parent)
            private.write_preserved(path, value, mode)
        if failed is not None:
            raise failed
        adoption.native_evidence(operation, intent, verification, fresh=True)
    return verification


def delivery(verification: Path, intent: dict, original: dict, legacy: dict, transport, guard) -> None:
    """Observe existing controllers and projections using the existing reload owner."""
    output = verification / "delivery"
    bootstrap.private_directory(output)
    native = adoption.record(verification / "verified.json").value["verification"]
    started = time.monotonic()
    observation_hashes = {}

    def phase():
        guard()
        bootstrap.require(time.monotonic() - started < 900
            and time.time() < native["validBeforeUnixSeconds"], "adoption verification lifetime expired")
        inspection.namespace_identity(transport, intent["binding"])

    def get(resource, *arguments, kind=None, maximum=reload.OBJECT_LIMIT):
        phase()
        raw = transport.kubectl("adoption delivery readback", "get", resource, *arguments, "-o", "json", timeout=30)
        value = inspection.decode(raw, maximum, "adoption delivery readback")
        if kind is not None:
            bootstrap.require(value.get("kind") == kind, "adoption controller list kind differs")
        name = f"observation-{len(observation_hashes):03}.json"
        bootstrap.write_new(output / name, raw)
        observation_hashes[name] = adoption.digest(raw)
        return value

    def secrets_stable():
        for name, expected in sorted(legacy["after"].items()):
            observed = get("secret", name, maximum=recovery.SECRET_LIMIT)
            recovery.secret_identity(observed, intent["binding"]["namespace"], name)
            bootstrap.require(observed["metadata"]["uid"] == expected["metadata"]["uid"]
                and observed["data"] == expected["data"], "live Secret differs from the adopted generation")

    phase()
    openbao = inspection.openbao_identity(transport, original["images"]["openbao_didcomm"])
    request = reload.ReloadRequest(output, original, legacy["bound"], openbao["uid"], legacy["plan"],
        adoption.digest(legacy["plan"]), {})
    secrets_stable()
    observed_workloads, release_name, seen = {}, None, set()
    for name in reload.WORKLOADS:
        deployed = get("deployment", name)
        release_name = reload.deployment_profile(deployed, name, original, legacy["bound"], release_name)
        bootstrap.require(reload.ready(deployed), "adoption requires Ready owned workloads")
        active = reload.active_objects(get, deployed, request)
        bootstrap.require(active is not None, "adoption workload has no unambiguous Ready Pod")
        replica, pod = active
        admitted = reload.admitted_pod(pod, replica, deployed, request)
        bootstrap.require(admitted["uid"] not in seen, "adoption Pod owner is repeated")
        seen.add(admitted["uid"])
        probes = reload.projections(deployed["spec"]["template"], legacy["changed"], legacy["after"])
        files = [probe.target for probe in probes if probe.kind == "file"]
        variables = [probe.target for probe in probes if probe.kind == "env"]
        raw = transport.kubectl("adoption credential projection", "exec", pod["metadata"]["name"], "-c", name,
            "--", "/bin/sh", "-ec", reload.PROBE_PROGRAM, "--", str(len(files)), *files, *variables, timeout=30)
        phase()
        expected = b"".join((probe.kind + " " + probe.digest + "  "
            + (probe.target if probe.kind == "file" else "-") + "\n").encode() for probe in probes)
        bootstrap.require(raw == expected, "live Pod credential delivery differs from adopted candidate")
        after = get("deployment", name)
        reload.same_deployment(after, deployed, intent["binding"]["namespace"], controller=True)
        stable = reload.active_objects(get, after, request)
        bootstrap.require(stable is not None and stable[0]["metadata"]["uid"] == replica["metadata"]["uid"]
            and reload.admitted_pod(stable[1], stable[0], after, request) == admitted,
            "adoption workload identity changed across projection readback")
        observed_workloads[name] = {"deploymentUid": deployed["metadata"]["uid"], "podUid": admitted["uid"],
            "replicaSetUid": replica["metadata"]["uid"], "projectionResponseSha256": adoption.digest(raw)}
    secrets_stable()
    phase()
    inspection.openbao_identity(transport, original["images"]["openbao_didcomm"], uid=openbao["uid"])
    write(verification / "delivery.json", {"schema": adoption.DELIVERY_SCHEMA, "binding": intent["binding"],
        "adoptionId": intent["adoptionId"], "candidateInputs": intent["candidateInputs"],
        "secretCount": 34, "workloadCount": 16, "workloads": observed_workloads,
        "observationHashes": observation_hashes, "credentialDeliveryVerified": True,
        "credentialConsumptionVerified": False})


def adopt(args) -> None:
    bootstrap.require(os.name == "posix", "legacy renewal adoption requires Linux")
    with selection.locked(args.state_dir) as held:
        operation = args.operation_dir
        records = inspection.retained_records(args.state_dir, args.chart_source_sha)
        complete, _, _, binding, pulls = records
        if args.reconcile:
            selection.owned_directory(operation)
            retained, intent = adoption.request(operation, args.state_dir)
            pending = held.read(adoption.PENDING, missing=True)
            expected_pending = {"schema": adoption.REQUEST_SCHEMA,
                "operationDirectory": str(operation), "adoptionId": intent["adoptionId"],
                "requestSha256": adoption.digest(retained.raw)}
            if held.read(adoption.SELECTOR, missing=True) is not None:
                bootstrap.require(adoption.selected(args.state_dir, allow_pending=True) == intent,
                    "published adoption differs from pending attempt")
                if pending is None:
                    print("Renewal adoption selection was already complete; no enrollment or cluster change was requested.")
                    return
                # A pending final publication is not usable routine state. Prove
                # fresh authority and live delivery again before clearing it.
            bootstrap.require(pending is not None and pending.value == expected_pending,
                "adoption reconciliation names a different attempt")
            authentication = operation / ("authentication-" + bootstrap.secrets.token_hex(6))
            bootstrap.private_directory(authentication)
        else:
            bootstrap.require(held.read(selection.PENDING, missing=True) is None
                and held.read(selection.SELECTOR, missing=True) is None
                and held.read(adoption.PENDING, missing=True) is None
                and held.read(adoption.SELECTOR, missing=True) is None, "another generation or adoption is already selected or pending")
            bootstrap.private_directory(operation)
            authentication = operation
        authenticated_args = copy(args)
        authenticated_args.operation_dir = authentication
        original, selected_operator, operator = inspection.authenticate(authenticated_args, complete)
        sources = inspection.sources.authenticate(args.recovery_assets, selected_operator["release"])
        snapshot, legacy, _, _ = legacy_candidate(args, complete, original, binding)
        if not args.reconcile:
            candidate = operation / "candidate"
            bootstrap.private_directory(candidate)
            for name, (value, mode) in snapshot.items():
                private.write_preserved(candidate / name, value, mode)
            intent = {"schema": adoption.REQUEST_SCHEMA, "binding": binding, "bootstrapId": complete["bootstrapId"],
                "adoptionId": bootstrap.secrets.token_hex(16), "operationDirectory": str(operation),
                "operationIdentity": list(selection.owned_directory(operation)), "candidateDirectory": str(candidate),
                "candidateIdentity": list(selection.owned_directory(candidate)), "candidateInputs": adoption.hashes(snapshot),
                "originalRuntime": original["release"], "operatorRuntime": selected_operator["release"],
                "operatorBuildIdentity": args.recovery_source_sha + ":" + args.recovery_release_tag,
                "operatorSha256": adoption.digest(operator), "sourceRecoveryDirectory": str(args.recovery_dir),
                "recoveryCompletionSha256": adoption.digest(legacy["completion"].raw),
                "bootstrapSha256": adoption.digest(adoption.record(args.state_dir / "bootstrap-complete.json").raw),
                "originalImagesSha256": adoption.digest(adoption.record(args.state_dir / "marty-images.json").raw),
                "contracts": {"publication": bootstrap.publication_contract(operation / "marty-deploy"),
                    "application": bootstrap.application_token_contract(operation / "marty-deploy"),
                    "renewal": bootstrap.renewal_contract(operation / "marty-deploy")},
                "pullSecrets": pulls, "sources": sources, "automaticEnrollmentReplay": False}
            write(operation / "adoption-requested.json", intent)
            retained, intent = adoption.request(operation, args.state_dir)
            held.write_new(adoption.PENDING, {"schema": adoption.REQUEST_SCHEMA, "operationDirectory": str(operation),
                "adoptionId": intent["adoptionId"], "requestSha256": adoption.digest(retained.raw)})
        bootstrap.require(intent["operatorRuntime"] == selected_operator["release"] and intent["sources"] == sources
            and intent["operatorSha256"] == adoption.digest(operator) and intent["sourceRecoveryDirectory"] == str(args.recovery_dir)
            and intent["recoveryCompletionSha256"] == adoption.digest(legacy["completion"].raw)
            and intent["candidateInputs"] == adoption.hashes(snapshot), "adoption authenticated lineage changed")

        pending_record = held.read(adoption.PENDING)

        def guard():
            held.bound()
            bootstrap.require(held.read(adoption.PENDING) == pending_record
                and held.read(selection.PENDING, missing=True) is None
                and held.read(selection.SELECTOR, missing=True) is None
                and adoption.request(operation, args.state_dir)[0] == retained
                and inspection.retained_records(args.state_dir, args.chart_source_sha) == records,
                "adoption retained evidence changed")
            inspection.sources.recheck(sources)

        if args.reconcile:
            inspection_work = operation / ("reconciliation-" + bootstrap.secrets.token_hex(6))
            bootstrap.private_directory(inspection_work)
            bootstrap.write_new(inspection_work / "kubeconfig", inspection.kubeconfig_bytes(args.state_dir))
            kubectl = shutil.which("kubectl")
            bootstrap.require(kubectl is not None, "kubectl must be installed")
            check = bootstrap.Transport(inspection_work, inspection_work / "kubeconfig", binding["namespace"], kubectl)
            inspection.namespace_identity(check, binding)
            quiescent_attempts(operation, check)
        enroll_domains(args, intent, operator, original, selected_operator, guard)
        verification = verify_native(args, intent, operator, original, selected_operator, guard)
        work = operation / ("readback-" + bootstrap.secrets.token_hex(6))
        bootstrap.private_directory(work)
        bootstrap.write_new(work / "kubeconfig", inspection.kubeconfig_bytes(args.state_dir))
        transport = bootstrap.Transport(work, work / "kubeconfig", binding["namespace"], shutil.which("kubectl"))
        delivery(verification, intent, original, legacy, transport, guard)
        guard()
        write(verification / "adoption-complete.json", {"schema": adoption.COMPLETE_SCHEMA,
            "adoptionId": intent["adoptionId"], "binding": binding, "requestSha256": adoption.digest(retained.raw),
            "verificationDirectory": str(verification),
            "verificationSha256": adoption.digest(adoption.record(verification / "verified.json").raw),
            "deliverySha256": adoption.digest(adoption.record(verification / "delivery.json").raw),
            "selectedAtUnixSeconds": int(time.time()), "status": "both-enrollments-and-live-delivery-verified"})
        adoption.publish(held, operation, verification)
        print("Adopted both routine renewal authorities after native verification and live credential delivery readback.")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("state-dir", "operation-dir", "recovery-dir", "original-assets", "recovery-assets", "gh", "cosign"):
        parser.add_argument("--" + name, required=True, type=Path)
    for name in ("chart-source-sha", "original-release-tag", "recovery-source-sha", "recovery-release-tag"):
        parser.add_argument("--" + name, required=True)
    for name in ("original-build-run-id", "original-build-run-attempt", "recovery-build-run-id", "recovery-build-run-attempt"):
        parser.add_argument("--" + name, required=True, type=int)
    parser.add_argument("--reconcile", action="store_true")
    try:
        adopt(parser.parse_args(argv))
    except (bootstrap.BootstrapError, ValueError, OSError, KeyError, TypeError,
            subprocess.TimeoutExpired, tarfile.TarError) as error:
        detail = str(error) if isinstance(error, bootstrap.BootstrapError) else type(error).__name__
        parser.exit(1, "Legacy renewal adoption stopped: " + detail + ". Preserve the private attempt.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
