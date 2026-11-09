#!/usr/bin/env python3
"""Stage ordinary application credentials for one retained Kubernetes bootstrap.

This is a private transport for the existing signed native authority and immutable
generation commands. It reauthenticates the original artifact closure, observes
the retained namespace/OpenBao binding, and uses a bounded memory-backed pod.
It creates no application Secret, activates no candidate and never reads the
retained root token. A fresh operation directory is mandatory; an uncertain
attempt is preserved for recovery and is never replayed.

The original state and operation directory must remain on private encrypted
operator storage with no concurrent writer. Candidate files, authority identity,
native response captures and opaque recovery archives are private credentials.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tarfile

import bootstrap_kubernetes_openbao as bootstrap


FILE_MODES = {0o400, 0o440, 0o444, 0o600, 0o640, 0o644}
MAX_FILES = 256
MAX_CURRENT_BYTES = 8 * 1024 * 1024
GENERATION_ARCHIVE_LIMIT = 9 * 1024 * 1024
NATIVE_EVIDENCE_LIMIT = 26 * 1024 * 1024
OPERATOR_LIMIT = 64 * 1024 * 1024
REMOTE_CURRENT = "/tmp/application-current"
REMOTE_IDENTITY = "/tmp/application-identity"
REMOTE_OPERATION = "/tmp/application-operation"
REMOTE_CANDIDATE = "/tmp/application-candidate"
REMOTE_OPERATOR = "/tmp/marty-deploy"
REMOTE_INPUTS = REMOTE_OPERATION + "/inputs"


def existing_private_directory(path: Path) -> None:
    bootstrap.require(path.is_absolute() and path.resolve() == path and not path.is_symlink(),
                      "retained private directory path is invalid")
    info = path.stat()
    bootstrap.require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
                      and stat.S_IMODE(info.st_mode) == 0o700,
                      "retained directory is not private and caller-owned")


def private_bytes(path: Path, maximum: int, modes: set[int]) -> tuple[bytes, int]:
    existing_private_directory(path.parent)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        mode = stat.S_IMODE(before.st_mode)
        bootstrap.require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                          and before.st_uid == os.geteuid() and mode in modes
                          and before.st_size <= maximum, "retained private file custody differs")
        value = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
        linked = path.lstat()
    identity = lambda info: (info.st_dev, info.st_ino, info.st_mode, info.st_uid,
                             info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    bootstrap.require(len(value) <= maximum and len(value) == before.st_size
                      and identity(before) == identity(after) == identity(linked),
                      "retained private file changed")
    return value, mode


def record(path: Path) -> dict:
    raw, _ = private_bytes(path, 65536, {0o600})
    value = json.loads(raw, object_pairs_hook=bootstrap.unique_json_members)
    bootstrap.require(isinstance(value, dict), "retained metadata is invalid")
    return value


def current_snapshot(path: Path) -> dict[str, tuple[bytes, int]]:
    existing_private_directory(path)
    entries = sorted(path.iterdir())
    bootstrap.require(0 < len(entries) <= MAX_FILES, "current credential inventory is oversized or empty")
    snapshot = {}
    total = 0
    for entry in entries:
        bootstrap.require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", entry.name) is not None,
                          "current credential filename is invalid")
        value, mode = private_bytes(entry, 65536, FILE_MODES)
        total += len(value)
        bootstrap.require(total <= MAX_CURRENT_BYTES, "current credential payload is oversized")
        snapshot[entry.name] = value, mode
    return snapshot


def archive_snapshot(snapshot: dict[str, tuple[bytes, int]]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for name, (value, mode) in sorted(snapshot.items()):
            entry = tarfile.TarInfo(name)
            entry.mode, entry.size = mode, len(value)
            archive.addfile(entry, io.BytesIO(value))
    payload = output.getvalue()
    bootstrap.require(len(payload) <= GENERATION_ARCHIVE_LIMIT, "current transport archive is oversized")
    return payload


def write_preserved(path: Path, value: bytes, mode: int) -> None:
    bootstrap.require(mode in FILE_MODES, "candidate file mode is unsupported")
    bootstrap.write_new(path, value)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
        bootstrap.require(stat.S_IMODE(os.fstat(descriptor).st_mode) == mode,
                          "candidate file mode was not preserved")
    finally:
        os.close(descriptor)


def native_generation(transport: bootstrap.Transport, operator: str, context: dict,
                      *, pod: str | None = None):
    command = [operator, "operator", "generation"]
    if pod is None:
        raw = transport.run("native application generation validation", command,
                            data=bootstrap.encoded(context), env={}, timeout=120)
    else:
        raw = transport.execute(pod, command, data=bootstrap.encoded(context), timeout=120)
    bootstrap.require(0 < len(raw) <= 4096, "native application generation response is invalid")
    response = json.loads(raw, object_pairs_hook=bootstrap.unique_json_members)
    bootstrap.require(isinstance(response, dict) and set(response) == {"value"},
                      "native application generation refused; preserve the private attempt")
    return response["value"]


def count_result(observed: object, expected: int) -> None:
    bootstrap.require(type(observed) is int and observed == expected,
                      "native application generation inventory differs")


def verify_result(observed: object, expected: int, changed: int) -> None:
    bootstrap.require(isinstance(observed, list) and len(observed) == 2
                      and all(type(value) is int for value in observed)
                      and observed == [expected, changed],
                      "native application generation proof differs")


def validate_native_evidence(payload: bytes, runtime_files: set[str], *, complete: bool) -> None:
    # Response bodies may contain issued credentials or incomplete writes. Keep
    # them opaque and private while validating their fixed transport envelope.
    allowed = {"attempt.json": 8193, "complete.json": 4097,
               "login-response.json": 2 * 1024 * 1024 + 1}
    allowed.update({f"mint-response-{index:02d}.json": 2 * 1024 * 1024 + 1
                    for index in range(len(runtime_files))})
    allowed.update({"inputs/" + name: 1025 for name in runtime_files})
    bootstrap.private_archive(payload, allowed, maximum=NATIVE_EVIDENCE_LIMIT,
        modes={0o600}, directories={".", "inputs"}, complete=complete, allow_empty=not complete)


def stage(args: argparse.Namespace) -> None:
    bootstrap.require(os.name == "posix", "this development transport requires Linux")
    existing_private_directory(args.state_dir)
    bootstrap.require(not args.operation_dir.is_relative_to(args.state_dir / "credentials")
                      and not args.operation_dir.is_relative_to(args.state_dir / "application-identity"),
                      "operation directory overlaps retained credential inputs")
    bootstrap.private_directory(args.operation_dir)
    state, operation = args.state_dir, args.operation_dir
    complete = record(state / "bootstrap-complete.json")
    retained_images = record(state / "marty-images.json")
    bootstrap.require(complete.get("status") == "openbao-and-application-credentials-ready",
                      "original Kubernetes bootstrap is not complete")
    authority = complete.get("applicationAuthority")
    bootstrap.require(isinstance(authority, dict) and set(authority) == {
        "schema", "binding", "identityDirectory", "files",
    } and authority["schema"] == "marty.kubernetes-application-authority/v1"
       and authority["identityDirectory"] == "application-identity"
       and authority["files"] == sorted(bootstrap.APPLICATION_IDENTITY_FILES),
       "original bootstrap has no supported application authority")
    binding = bootstrap.application_binding(authority["binding"])
    lifecycle = complete["credentialLifecycle"]
    bootstrap.require(binding == {
        "namespace": complete["namespace"], "namespaceUid": lifecycle["namespaceUid"],
        "openbaoClusterId": complete["openbaoClusterId"], "workloadProject": lifecycle["workloadProject"],
    }, "retained bootstrap application binding differs")
    bootstrap.require(complete["runtimeSourceSha"] == args.runtime_source_sha
                      and complete["chartSourceSha"] == args.chart_source_sha,
                      "explicit runtime or chart identity differs from original bootstrap")
    pull_secrets = complete.get("imagePullSecrets")
    bootstrap.require(isinstance(pull_secrets, list) and all(
        isinstance(name, str) and re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,251}[a-z0-9]|[a-z0-9]", name)
        for name in pull_secrets), "retained image pull Secret names are invalid")
    values, _ = bootstrap.prepare(assets=args.assets,
        runtime_source_sha=args.runtime_source_sha, release_tag=args.release_tag,
        build_run_id=args.build_run_id, build_run_attempt=args.build_run_attempt,
        chart_source_sha=args.chart_source_sha, gh=args.gh, cosign=args.cosign,
        output=operation / "marty-images.json", openbao_output=operation / "openbao-images.json")
    bootstrap.require(bootstrap.encoded(values) == bootstrap.encoded(retained_images),
                      "authenticated original runtime images or provenance differ")
    operator_bytes, _ = bootstrap.authenticated_bootstrap_inputs(args.assets, values["release"])
    retained_operator, _ = private_bytes(state / "marty-deploy", OPERATOR_LIMIT, {0o700})
    bootstrap.require(retained_operator == operator_bytes and len(operator_bytes) <= OPERATOR_LIMIT,
                      "retained signed operator differs or exceeds transport bounds")
    operator = operation / "marty-deploy"
    bootstrap.write_new(operator, operator_bytes, 0o700)
    identity = subprocess.run([str(operator), "--build-identity"], stdin=subprocess.DEVNULL,
                             capture_output=True, check=False, timeout=10, env={})
    bootstrap.require(identity.returncode == 0 and identity.stdout.strip().decode()
                      == args.runtime_source_sha + ":" + args.release_tag,
                      "signed operator build identity differs")
    publication = bootstrap.publication_contract(operator)
    application = bootstrap.application_token_contract(operator)
    bootstrap.require(bootstrap.encoded(complete["credentialPublication"]) == bootstrap.encoded(publication)
                      and bootstrap.encoded(complete["applicationTokenContract"]) == bootstrap.encoded(application),
                      "original bootstrap compiled contracts differ")
    current = state / "credentials"
    snapshot = current_snapshot(current)
    bootstrap.require("openbao_tls_ca_cert" in snapshot, "original OpenBao trust is unavailable")
    identity_path = state / "application-identity"
    existing_private_directory(identity_path)
    bootstrap.require({path.name for path in identity_path.iterdir()} == bootstrap.APPLICATION_IDENTITY_FILES,
                      "retained application identity inventory differs")
    identity_snapshot = {name: private_bytes(identity_path / name, maximum, {0o400, 0o600})
                         for name, maximum in bootstrap.APPLICATION_IDENTITY_LIMITS.items()}
    identity_copy = operation / "application-identity"
    bootstrap.private_directory(identity_copy)
    identity_archive = archive_snapshot(identity_snapshot)
    bootstrap.take_application_identity(identity_archive, identity_copy, binding, modes={0o400, 0o600})
    current_archive = archive_snapshot(snapshot)
    bootstrap.write_new(operation / "current-snapshot.tar", current_archive)
    kubeconfig, _ = private_bytes(state / "kubeconfig", 1024 * 1024, {0o600})
    scoped = json.loads(kubeconfig, object_pairs_hook=bootstrap.unique_json_members)
    bootstrap.require(isinstance(scoped, dict) and isinstance(scoped.get("current-context"), str)
                      and scoped["current-context"] and len(scoped.get("contexts", [])) == 1
                      and scoped["contexts"][0].get("name") == scoped["current-context"],
                      "retained Kubernetes context is ambiguous")
    bootstrap.write_new(operation / "kubeconfig", kubeconfig)
    kubectl = shutil.which("kubectl")
    bootstrap.require(kubectl is not None, "kubectl must be installed")
    transport = bootstrap.Transport(operation, operation / "kubeconfig", binding["namespace"], kubectl)
    count_result(native_generation(transport, str(operator), {
        "operation": "application-check", "current": str(current),
    }), len(snapshot))
    runtime_files = {entry["file"] for entry in application["tokens"] if entry["replacementRole"] is not None}
    nonce = bootstrap.secrets.token_hex(6)
    bootstrap.write_new(operation / "application-stage-requested.json", bootstrap.encoded({
        "schema": "marty.kubernetes-application-stage-request/v1", "binding": binding,
        "runtime": values["release"], "transportNonce": nonce,
        "currentFiles": len(snapshot), "replacementInputs": sorted(runtime_files), "activation": False,
    }))
    # Observe the retained binding before uploading any authority or current
    # credential material, and again immediately before the native login.
    bootstrap.check_application_binding(transport, binding)
    pod = bootstrap.create_producer_pod(transport, image=values["images"]["services"],
        nonce=nonce, pull_secrets=pull_secrets, purpose="application-stage")
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
            'umask 077; for path in "$@"; do mkdir "$path"; chmod 700 "$path"; done', "--",
            REMOTE_CURRENT, REMOTE_IDENTITY, REMOTE_OPERATION, REMOTE_CANDIDATE])
        remote_ready = True
        transport.upload(pod, REMOTE_OPERATOR, operator_bytes, executable=True)
        copied = transport.execute(pod, ["sha256sum", REMOTE_OPERATOR]).decode().split()
        bootstrap.require(copied and copied[0] == hashlib.sha256(operator_bytes).hexdigest(),
                          "copied native operator digest differs")
        for destination, payload in ((REMOTE_CURRENT, current_archive), (REMOTE_IDENTITY, identity_archive)):
            transport.execute(pod, ["tar", "-xpf", "-", "-C", destination], data=payload)
        transport.upload(pod, "/tmp/ca.crt", snapshot["openbao_tls_ca_cert"][0])
        count_result(native_generation(transport, REMOTE_OPERATOR, {
            "operation": "application-check", "current": REMOTE_CURRENT,
        }, pod=pod), len(snapshot))
        bootstrap.check_application_binding(transport, binding)
        native_outcome_uncertain = True
        raw = transport.execute(pod, [REMOTE_OPERATOR, "operator", "application-token-stage",
            "https://openbao:8200", "/tmp/ca.crt", REMOTE_IDENTITY], data=bootstrap.encoded({
                "current": REMOTE_CURRENT, "output": REMOTE_OPERATION, "binding": binding,
            }), timeout=600)
        native_outcome_uncertain = False
        bootstrap.require(0 < len(raw) <= 4096, "native application input response is invalid")
        ready = json.loads(raw, object_pairs_hook=bootstrap.unique_json_members)
        bootstrap.require(isinstance(ready, dict) and set(ready) == {"ready", "inputs", "count"}
                          and ready["ready"] is True and ready["inputs"] == REMOTE_INPUTS
                          and type(ready["count"]) is int and ready["count"] == len(runtime_files),
                          "native application input batch did not confirm exact readiness")
        native_batch_complete = True
        inputs = bootstrap.flat_archive(bootstrap.remote_archive(transport, pod, REMOTE_INPUTS, 65536),
            runtime_files, maximum=65536, modes={0o600})
        retained_inputs = operation / "inputs"
        bootstrap.private_directory(retained_inputs)
        for name, (value, mode) in inputs.items():
            bootstrap.require(len(value) <= 1025, "native application input exceeds transport bounds")
            bootstrap.write_new(retained_inputs / name, value, mode)
        count_result(native_generation(transport, REMOTE_OPERATOR, {
            "operation": "application-stage", "current": REMOTE_CURRENT,
            "replacements": REMOTE_INPUTS, "output": REMOTE_CANDIDATE,
        }, pod=pod), len(snapshot))
        verify_result(native_generation(transport, REMOTE_OPERATOR, {
            "operation": "application-verify", "current": REMOTE_CURRENT, "candidate": REMOTE_CANDIDATE,
        }, pod=pod), len(snapshot), len(runtime_files))
        bootstrap.check_application_binding(transport, binding)
        exported = bootstrap.flat_archive(bootstrap.remote_archive(transport, pod,
            REMOTE_CANDIDATE, GENERATION_ARCHIVE_LIMIT), set(snapshot),
            maximum=GENERATION_ARCHIVE_LIMIT, modes=FILE_MODES, allow_empty=True)
        bootstrap.private_directory(candidate)
        for name, (value, mode) in exported.items():
            write_preserved(candidate / name, value, mode)
        bootstrap.require(current_snapshot(current) == snapshot, "original credentials changed during staging")
        verify_result(native_generation(transport, str(operator), {
            "operation": "application-verify", "current": str(current), "candidate": str(candidate),
        }), len(snapshot), len(runtime_files))
    finally:
        failures = []
        evidence_retained = not remote_ready
        if remote_ready:
            try:
                # These opaque captures can contain minted credentials. Preserve
                # success and uncertainty privately before removing the pod.
                evidence = bootstrap.remote_archive(transport, pod, REMOTE_OPERATION, NATIVE_EVIDENCE_LIMIT)
                validate_native_evidence(evidence, runtime_files, complete=native_batch_complete)
                bootstrap.write_new(operation / "native-operation-evidence.tar", evidence)
                evidence_retained = True
            except Exception:
                failures.append("private native evidence export failed")
        if native_outcome_uncertain:
            failures.append("native authority command outcome is uncertain; private evidence is only a snapshot")
        if evidence_retained and not native_outcome_uncertain:
            try:
                transport.kubectl("native producer cleanup", "delete", "pod", pod,
                                  "--wait=true", "--timeout=120s", timeout=150)
            except Exception:
                failures.append("native transport cleanup failed")
        else:
            failures.append("native pod retained only within its remaining 1200-second total lifetime; "
                            "work may still be running; inspect transport-pod.json")
        if failures:
            raise bootstrap.BootstrapError("; ".join(failures)
                + "; authority may exist; preserve the private attempt and do not replay")
    bootstrap.write_new(operation / "application-stage-complete.json", bootstrap.encoded({
        "schema": "marty.kubernetes-application-stage-completion/v1", "binding": binding,
        "runtime": values["release"], "candidateDirectory": "candidate",
        "files": len(snapshot), "replacedInputs": sorted(runtime_files),
        "status": "candidate-staged-not-activated", "activation": False,
    }))
    print("Application credential candidate staged; no application Secret or active generation was changed.")
    print("Keep the entire private operation directory for review; this command does not activate the candidate.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("state-dir", "operation-dir", "assets", "gh", "cosign"):
        parser.add_argument("--" + name, required=True, type=Path)
    for name in ("runtime-source-sha", "chart-source-sha", "release-tag"):
        parser.add_argument("--" + name, required=True)
    for name in ("build-run-id", "build-run-attempt"):
        parser.add_argument("--" + name, required=True, type=int)
    try:
        stage(parser.parse_args(argv))
    except (bootstrap.BootstrapError, ValueError, OSError, subprocess.TimeoutExpired,
            KeyError, TypeError, tarfile.TarError) as error:
        detail = str(error) if isinstance(error, bootstrap.BootstrapError) else type(error).__name__
        parser.exit(1, f"Kubernetes application staging stopped: {detail}. "
                    "Preserve private state; authority may exist. Do not replay this operation.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
