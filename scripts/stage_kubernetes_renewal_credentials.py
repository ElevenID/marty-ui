#!/usr/bin/env python3
"""Stage a private TLS/Keycloak renewal candidate for a retained Kubernetes bootstrap.

The signed native Renewal owner performs scoped login, existing TLS and Keycloak
production, live validation and transient-session retirement. This adapter uses
the existing Kubernetes transport and current-generation lock. It requires fresh
bootstrap enrollment; routine staging never opens retained root or seal material.

Keep the entire private attempt on encrypted operator storage. An uncertain
attempt cannot be replayed. Successful staging preserves the active generation
and does not publish Secrets, roll Deployments, rotate CAs or configure Keycloak.
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
import kubernetes_renewal_adoption_state as adoption
import stage_kubernetes_application_credentials as application


REMOTE_CURRENT = "/tmp/renewal-current"
REMOTE_IDENTITY = "/tmp/renewal-identity"
REMOTE_BINDING = "/tmp/renewal-binding.json"
REMOTE_OPERATION = "/tmp/renewal-operation"
REMOTE_CANDIDATE = "/tmp/renewal-candidate"
REMOTE_OPERATOR = "/tmp/marty-deploy"
REQUEST = "renewal-stage-requested.json"
COMPLETE = "renewal-stage-complete.json"
NATIVE_EVIDENCE_LIMIT = 4 * 1024 * 1024
OPERATION_SECONDS = 900
RETENTION_SECONDS = 60


class BoundedTransport(bootstrap.Transport):
    """Keep cluster observation, production, export and cleanup on one deadline."""

    deadline: float | None = None

    def remaining(self) -> int:
        bootstrap.require(self.deadline is not None, "renewal transport deadline is unavailable")
        seconds = math.floor(self.deadline - time.monotonic())
        bootstrap.require(seconds > 0, "Kubernetes renewal total deadline expired")
        return seconds

    def run(self, operation: str, command: list[str], *, data: bytes | None = None,
            timeout: int = 300, env: dict[str, str] | None = None) -> bytes:
        if self.deadline is not None:
            timeout = min(timeout, self.remaining())
        return super().run(operation, command, data=data, timeout=timeout, env=env)


def json_object(raw: bytes, maximum: int, description: str) -> dict:
    bootstrap.require(0 < len(raw) <= maximum, description + " size differs")
    try:
        value = json.loads(raw, object_pairs_hook=bootstrap.unique_json_members)
    except (ValueError, UnicodeError, RecursionError):
        raise bootstrap.BootstrapError(description + " is malformed") from None
    bootstrap.require(isinstance(value, dict), description + " is invalid")
    return value


def same_metadata(observed: dict, expected: dict, description: str) -> None:
    # Canonical bytes preserve JSON types, including true versus 1.
    bootstrap.require(bootstrap.encoded(observed) == bootstrap.encoded(expected), description)


def validate_native_evidence(payload: bytes, *, complete: bool, binding: dict,
                             nonce: str, count: int) -> None:
    """Keep credentials opaque; check the closed envelope and cleanup receipts."""
    allowed = {"pending.json": 65536, "authority.token": 1025, "validated.json": 65536,
               "session-retired.json": 4096, "completed.json": 4096}
    allowed.update({"tls/" + name: 65536 for name in bootstrap.SELFHOST_TLS_FILES})
    allowed["tls/selfhost-tls-kms-roles.json"] = 8192
    allowed.update({"keycloak/" + name: 1025 if name.endswith("_token") else 65536
                    for name in bootstrap.KEYCLOAK_FILES})
    members = bootstrap.private_archive(payload, allowed, maximum=NATIVE_EVIDENCE_LIMIT,
        modes={0o600}, directories={".", "tls", "keycloak"}, complete=complete,
        allow_empty=not complete)
    if complete:
        same_metadata(json_object(members["session-retired.json"][0], 4096,
                                  "native Renewal retirement receipt"), {
            "schema": "marty.kubernetes-renewal-session-retirement/v1", "transientRevoked": True,
        }, "native Renewal session retirement differs")
        same_metadata(json_object(members["completed.json"][0], 4096,
                                  "native Renewal completion receipt"), {
            "schema": "marty.kubernetes-renewal-staging/v1", "binding": binding,
            "producerNonce": nonce, "files": count, "changedFiles": 39,
            "scopedLeafTokens": 21, "transientRevoked": True, "activated": False, "caChanged": False,
        }, "native Renewal completion or binding differs")


def complete_attempt(operation: Path, value: dict) -> None:
    """A failed local completion write never leaves a success-named receipt."""
    path = operation / COMPLETE
    bootstrap.require(not path.exists() and not path.is_symlink(),
                      "renewal completion already exists; preserve the private attempt")
    try:
        bootstrap.write_new(path, bootstrap.encoded(value))
        same_metadata(application.record(path), value, "retained Renewal completion differs")
    except BaseException:
        # This fresh attempt owns the new path. Preserve every input and recovery
        # capture; only remove this unconfirmed terminal receipt.
        try:
            path.unlink(missing_ok=True)
            descriptor = os.open(operation, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        except OSError:
            pass
        raise


def stage(args: argparse.Namespace) -> None:
    bootstrap.require(os.name == "posix", "this development transport requires Linux")
    with application_state.locked(args.state_dir) as held:
        _stage_locked(args, held)


def _stage_locked(args: argparse.Namespace, held: application_state.LockedState) -> None:
    state, operation = args.state_dir, args.operation_dir
    application.existing_private_directory(state)
    complete = application.record(state / "bootstrap-complete.json")
    retained_images = application.record(state / "marty-images.json")
    bootstrap.require(complete.get("status") == "openbao-and-application-credentials-ready",
                      "original Kubernetes bootstrap is not complete")
    binding, identity_path = adoption.authority(state, complete, "renewal")
    adoption.operation_allowed(state, operation)
    lifecycle = complete["credentialLifecycle"]
    binding_raw, _ = application.private_bytes(adoption.binding_path(state), 4096, {0o600})
    receipt = bootstrap.renewal_binding(
        json_object(binding_raw, 4096, "retained Renewal binding"), binding)
    bootstrap.require(lifecycle.get("producerNonce") == receipt["producerNonce"],
                      "retained bootstrap Renewal producer nonce differs")
    selected = held.current(binding)
    current = selected.directory
    bootstrap.require(all(not operation.is_relative_to(path) for path in (
        current, state / "credentials", state / "application-identity", state / "renewal-identity")),
        "operation directory overlaps retained credential inputs")
    bootstrap.private_directory(operation)
    pull_secrets = adoption.pull_secrets(state, complete)
    bootstrap.require(isinstance(pull_secrets, list) and all(
        isinstance(name, str) and re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,251}[a-z0-9]|[a-z0-9]", name)
        for name in pull_secrets), "retained image pull Secret names are invalid")
    operator, operator_bytes, values, _publication, _application = application.admitted_runtime(
        args, complete, retained_images, operation)
    contract = bootstrap.renewal_contract(operator)
    same_metadata(adoption.contract(state, complete, "renewal"), contract,
                  "retained bootstrap Renewal capability differs; fresh bootstrap enrollment is required")
    snapshot = application.current_snapshot(current)
    bootstrap.require("openbao_tls_ca_cert" in snapshot, "original OpenBao trust is unavailable")
    application.existing_private_directory(identity_path)
    bootstrap.require({path.name for path in identity_path.iterdir()} == bootstrap.RENEWAL_IDENTITY_FILES,
                      "retained Renewal identity inventory differs")
    identity_snapshot = {name: application.private_bytes(identity_path / name, maximum, {0o400, 0o600})
                         for name, maximum in bootstrap.RENEWAL_IDENTITY_LIMITS.items()}
    identity_archive = application.archive_snapshot(identity_snapshot)
    identity_copy = operation / "renewal-identity"
    bootstrap.private_directory(identity_copy)
    bootstrap.take_renewal_identity(identity_archive, identity_copy, modes={0o400, 0o600})
    bootstrap.write_new(operation / "renewal-binding.json", binding_raw)
    current_archive = application.archive_snapshot(snapshot)
    bootstrap.write_new(operation / "current-snapshot.tar", current_archive)
    kubeconfig, _ = application.private_bytes(state / "kubeconfig", 1024 * 1024, {0o600})
    scoped = json_object(kubeconfig, 1024 * 1024, "retained Kubernetes context")
    bootstrap.require(isinstance(scoped.get("current-context"), str) and scoped["current-context"]
                      and len(scoped.get("contexts", [])) == 1
                      and scoped["contexts"][0].get("name") == scoped["current-context"],
                      "retained Kubernetes context is ambiguous")
    bootstrap.write_new(operation / "kubeconfig", kubeconfig)
    kubectl = shutil.which("kubectl")
    bootstrap.require(kubectl is not None, "kubectl must be installed")
    transport = BoundedTransport(operation, operation / "kubeconfig", binding["namespace"], kubectl)
    application.count_result(application.native_generation(transport, str(operator), {
        "operation": "application-check", "current": str(current),
    }), len(snapshot))
    nonce = bootstrap.secrets.token_hex(6)
    bootstrap.write_new(operation / REQUEST, bootstrap.encoded({
        "schema": "marty.kubernetes-renewal-stage-request/v1", "binding": binding,
        "runtime": values["release"], "transportNonce": nonce,
        "producerNonce": receipt["producerNonce"], "currentDirectory": str(current),
        "currentFiles": len(snapshot), "changedFiles": 39, "activation": False,
    }))
    transport.deadline = time.monotonic() + OPERATION_SECONDS
    # Recheck retained namespace/cluster identity before authority upload and
    # immediately before login. The transport nonce never changes TLS identity.
    bootstrap.check_application_binding(transport, binding)
    pod = bootstrap.create_producer_pod(transport, image=adoption.producer_image(args, values),
        nonce=nonce, pull_secrets=pull_secrets, purpose="renewal-stage")
    remote_ready = False
    native_outcome_uncertain = False
    native_batch_complete = False
    candidate = operation / "candidate"
    try:
        bootstrap.retain_producer_pointer(transport, pod)
        transport.kubectl("native producer readiness", "wait", "--for=condition=Ready",
                          "pod/" + pod, "--timeout=300s", timeout=330)
        bootstrap.check_application_binding(transport, binding)
        transport.execute(pod, ["/bin/sh", "-ec",
            'umask 077; for path in "$@"; do mkdir "$path"; chmod u=rwx,go=,a-s,a-t "$path"; done', "--",
            REMOTE_CURRENT, REMOTE_IDENTITY, REMOTE_OPERATION, REMOTE_CANDIDATE])
        remote_ready = True
        transport.upload(pod, REMOTE_OPERATOR, operator_bytes, executable=True)
        copied = transport.execute(pod, ["sha256sum", REMOTE_OPERATOR]).decode().split()
        bootstrap.require(copied and copied[0] == hashlib.sha256(operator_bytes).hexdigest(),
                          "copied native operator digest differs")
        for destination, payload in ((REMOTE_CURRENT, current_archive), (REMOTE_IDENTITY, identity_archive)):
            transport.execute(pod, ["tar", "-xpf", "-", "-C", destination], data=payload)
        transport.upload(pod, REMOTE_BINDING, binding_raw)
        transport.upload(pod, "/tmp/ca.crt", snapshot["openbao_tls_ca_cert"][0])
        application.count_result(application.native_generation(transport, REMOTE_OPERATOR, {
            "operation": "application-check", "current": REMOTE_CURRENT,
        }, pod=pod), len(snapshot))
        bootstrap.check_application_binding(transport, binding)
        held.require_current(binding, expected=selected)
        bootstrap.require(application.current_snapshot(current) == snapshot
                          and application.private_bytes(adoption.binding_path(state), 4096, {0o600})[0]
                          == binding_raw
                          and application.current_snapshot(identity_path) == identity_snapshot,
                          "retained Renewal inputs changed before issuance")
        budget = transport.remaining() - RETENTION_SECONDS
        bootstrap.require(60 <= budget <= contract["operationBudgetSeconds"],
                          "insufficient original Renewal budget for native work and evidence retention")
        native_outcome_uncertain = True
        raw = transport.execute(pod, [REMOTE_OPERATOR, "operator", "kubernetes-renewal-stage",
            "https://openbao:8200", "/tmp/ca.crt", REMOTE_IDENTITY], data=bootstrap.encoded({
                "current": REMOTE_CURRENT, "candidate": REMOTE_CANDIDATE, "output": REMOTE_OPERATION,
                "binding_file": REMOTE_BINDING, "binding": binding, "budget_seconds": budget,
            }), timeout=transport.remaining())
        ready = json_object(raw, 4096, "native Renewal staging response")
        same_metadata(ready, {
            "ready": True, "candidate": REMOTE_CANDIDATE, "count": len(snapshot),
            "changed": 39, "transientRevoked": True,
        }, "native Renewal batch did not confirm exact completion and session retirement")
        native_outcome_uncertain = False
        native_batch_complete = True
        bootstrap.check_application_binding(transport, binding)
        exported = bootstrap.flat_archive(bootstrap.remote_archive(transport, pod,
            REMOTE_CANDIDATE, application.GENERATION_ARCHIVE_LIMIT), set(snapshot),
            maximum=application.GENERATION_ARCHIVE_LIMIT, modes=application.FILE_MODES, allow_empty=True)
        bootstrap.private_directory(candidate)
        for name, (value, mode) in exported.items():
            application.write_preserved(candidate / name, value, mode)
        bootstrap.require(application.current_snapshot(current) == snapshot,
                          "selected credentials changed during Renewal staging")
        application.verify_result(application.native_generation(transport, str(operator), {
            "operation": "verify", "current": str(current), "candidate": str(candidate),
            "ca_overlap": False, "ca_retire": False,
        }), len(snapshot), 39)
        bootstrap.require(application.current_snapshot(candidate) == exported,
                          "Renewal candidate changed during local verification")
    finally:
        failures = []
        evidence_retained = not remote_ready
        if remote_ready:
            try:
                evidence = bootstrap.remote_archive(transport, pod, REMOTE_OPERATION, NATIVE_EVIDENCE_LIMIT)
                validate_native_evidence(evidence, complete=native_batch_complete, binding=binding,
                                         nonce=receipt["producerNonce"], count=len(snapshot))
                bootstrap.write_new(operation / "native-operation-evidence.tar", evidence)
                evidence_retained = True
            except Exception:
                failures.append("private native Renewal evidence export or confirmation failed")
        if native_outcome_uncertain:
            failures.append("native Renewal outcome is uncertain; private evidence is only a snapshot")
        if evidence_retained and not native_outcome_uncertain:
            try:
                transport.kubectl("native producer cleanup", "delete", "pod", pod,
                                  "--wait=true", "--timeout=120s", timeout=150)
            except Exception:
                failures.append("native Renewal transport cleanup failed")
        else:
            failures.append("native pod retained only within its remaining 1200-second total lifetime; "
                            "work may still be running; inspect transport-pod.json")
        if failures:
            raise bootstrap.BootstrapError("; ".join(failures)
                + "; authority may exist; preserve the private attempt and do not replay")
    transport.remaining()
    held.require_current(binding, expected=selected)
    bootstrap.require(application.current_snapshot(current) == snapshot
                      and application.current_snapshot(candidate) == exported
                      and application.current_snapshot(identity_path) == identity_snapshot
                      and application.current_snapshot(identity_copy) == identity_snapshot
                      and application.private_bytes(adoption.binding_path(state), 4096, {0o600})[0]
                      == binding_raw
                      and application.private_bytes(operation / "renewal-binding.json", 4096, {0o600})[0]
                      == binding_raw,
                      "retained Renewal inputs or candidate changed before completion")
    complete_attempt(operation, {
        "schema": "marty.kubernetes-renewal-stage-completion/v1", "binding": binding,
        "runtime": values["release"], "producerNonce": receipt["producerNonce"],
        "currentDirectory": str(current), "candidateDirectory": "candidate", "files": len(snapshot),
        "changedFiles": 39, "scopedLeafTokens": 21, "transientRevoked": True,
        "status": "candidate-staged-not-activated", "activation": False, "caChanged": False,
    })
    print("TLS and Keycloak credential candidate staged and verified; the transient Renewal session was retired.")
    print("Keep the entire private operation directory for review. The current generation is unchanged.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("state-dir", "operation-dir", "assets", "gh", "cosign"):
        parser.add_argument("--" + name, required=True, type=Path)
    for name in ("runtime-source-sha", "chart-source-sha", "release-tag"):
        parser.add_argument("--" + name, required=True)
    for name in ("build-run-id", "build-run-attempt"):
        parser.add_argument("--" + name, required=True, type=int)
    adoption.add_operator_arguments(parser)
    try:
        stage(parser.parse_args(argv))
    except (bootstrap.BootstrapError, ValueError, OSError, subprocess.TimeoutExpired,
            KeyError, TypeError, tarfile.TarError) as error:
        detail = str(error) if isinstance(error, bootstrap.BootstrapError) else type(error).__name__
        parser.exit(1, f"Kubernetes Renewal staging stopped: {detail}. "
                    "Preserve private state; authority may exist. Do not replay this operation.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
