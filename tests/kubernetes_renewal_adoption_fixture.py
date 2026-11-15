"""Synthetic private state for adoption/ordinary-generation transition tests."""
from __future__ import annotations

import json
import time
from pathlib import Path
from types import SimpleNamespace

import bootstrap_kubernetes_openbao as bootstrap
import kubernetes_application_state as selection
import kubernetes_renewal_adoption_state as adoption
import stage_kubernetes_application_credentials as staging


def write(path, value, mode=0o600):
    path.write_bytes(value if isinstance(value, bytes) else bootstrap.encoded(value))
    path.chmod(mode)


def private(path):
    path.mkdir(mode=0o700)
    return path


def retained(state: Path, current: Path, binding: dict, runtime: dict, *, operator=b"synthetic-selected-operator"):
    operation = private(state.parent / "adoption")
    candidate = private(operation / "candidate")
    for name, (raw, mode) in staging.current_snapshot(current).items():
        write(candidate / name, raw, mode)
    path = state / "bootstrap-complete.json"
    complete = json.loads(path.read_bytes()) if path.exists() else {}
    publication = complete.get("credentialPublication", {"schema": bootstrap.PUBLICATION_SCHEMA,
        "catalog": json.loads((bootstrap.ROOT / "deploy-config/catalog/kubernetes-secrets.json").read_bytes())})
    renewal = complete.get("renewalContract", {"schema": "marty.kubernetes-renewal/v1"})
    complete.update(status="openbao-and-application-credentials-ready",
        bootstrapId="8a8c5b50-46c2-4347-ab36-377c662c61eb", namespace=binding["namespace"],
        openbaoClusterId=binding["openbaoClusterId"], runtimeSourceSha=runtime["runtimeSourceSha"],
        chartSourceSha=runtime["chartSourceSha"], credentialLifecycle={"namespaceUid": binding["namespaceUid"],
        "workloadProject": binding["workloadProject"], "producerNonce": binding["workloadProject"].split("-")[-1]})
    for key in ("applicationAuthority", "renewalAuthority", "credentialPublication", "applicationTokenContract",
                "renewalContract", "imagePullSecrets"):
        complete.pop(key, None)
    write(path, complete)
    if (state / "renewal-binding.json").exists():
        (state / "renewal-binding.json").rename(operation / "historical-fixture-renewal-binding.json")
    for domain in ("application", "renewal"):
        previous = state / (domain + "-identity")
        if previous.exists():
            previous.rename(operation / (domain + "-identity"))
        else:
            private(operation / (domain + "-identity"))
    for name in ("application-role-id", "application-secret-id"):
        write(operation / "application-identity" / name, ("synthetic-retained-" + name).encode())
    write(operation / "application-identity/application-binding.json", binding)
    for name in ("renewal-role-id", "renewal-secret-id"):
        write(operation / "renewal-identity" / name, ("synthetic-retained-" + name).encode())
    write(operation / "renewal-identity/renewal-leaf-policies.json", [f"synthetic-scoped-{index:02}" for index in range(21)])
    write(operation / "renewal-binding.json", {"schema": "marty.kubernetes-renewal-binding/v1",
        "binding": binding, "producerNonce": complete["credentialLifecycle"]["producerNonce"]})
    write(operation / "marty-deploy", operator, 0o700)
    selected_runtime = {**runtime, "runtimeSourceSha": "3" * 40, "operatorSha256": adoption.digest(operator)}
    intent = {"schema": adoption.REQUEST_SCHEMA, "binding": binding, "bootstrapId": complete["bootstrapId"],
        "adoptionId": "d" * 32, "operationDirectory": str(operation),
        "operationIdentity": list(selection.owned_directory(operation)), "candidateDirectory": str(candidate),
        "candidateIdentity": list(selection.owned_directory(candidate)),
        "candidateInputs": adoption.hashes(staging.current_snapshot(candidate)),
        "originalRuntime": runtime, "operatorRuntime": selected_runtime,
        "operatorBuildIdentity": selected_runtime["runtimeSourceSha"] + ":" + selected_runtime["tag"],
        "operatorSha256": adoption.digest(operator), "sourceRecoveryDirectory": str(state.parent / "recovery"),
        "recoveryCompletionSha256": "4" * 64, "bootstrapSha256": adoption.digest(path.read_bytes()),
        "originalImagesSha256": adoption.digest((state / "marty-images.json").read_bytes()),
        "contracts": {"publication": publication, "application": bootstrap.APPLICATION_TOKEN_SPEC,
            "renewal": renewal},
        "pullSecrets": [], "sources": {"scripts/adopt_kubernetes_renewal.py": "5" * 64},
        "automaticEnrollmentReplay": False}
    write(operation / "adoption-requested.json", intent)
    verification = private(operation / "verification-012345abcdef")
    now = int(time.time())
    native = {"schema": adoption.NATIVE_SCHEMA, "binding": binding, "bootstrapId": complete["bootstrapId"],
        "adoptionId": intent["adoptionId"], "operatorIdentity": intent["operatorBuildIdentity"],
        "candidateInputs": intent["candidateInputs"],
        "applicationIdentity": adoption.hashes(staging.current_snapshot(operation / "application-identity")),
        "renewalIdentity": adoption.hashes(staging.current_snapshot(operation / "renewal-identity")),
        "renewalBindingSha256": adoption.digest((operation / "renewal-binding.json").read_bytes()),
        "verificationStartedAtUnixSeconds": now, "validBeforeUnixSeconds": now + 900,
        "minimumTtlSeconds": 3600, "applicationRoles": 11, "scopedLeafTokens": 21,
        "enrollmentReplayed": False, "credentialsIssued": False, "activated": False}
    write(verification / "verified.json", {"verification": native, "ready": True, "transientSessionsRevoked": True})
    for domain in ("application", "renewal"):
        import adopt_kubernetes_renewal as coordinator
        write(operation / (domain + "-enrollment-intent.json"), coordinator.domain_intent(intent, domain))
        write(operation / (domain + "-enrolled.json"), {"schema": "marty.kubernetes-renewal-adoption-domain/v1",
            "adoptionId": intent["adoptionId"], "binding": binding, "domain": domain,
            "identityInputs": native[domain + "Identity"], "enrollmentReplayed": False})
    observations = private(verification / "delivery")
    write(observations / "observation-000.json", {"synthetic": "readback"})
    write(verification / "delivery.json", {"schema": adoption.DELIVERY_SCHEMA, "binding": binding,
        "adoptionId": intent["adoptionId"], "candidateInputs": intent["candidateInputs"], "secretCount": 34,
        "workloadCount": 16, "credentialDeliveryVerified": True, "credentialConsumptionVerified": False,
        "observationHashes": {"observation-000.json": adoption.digest((observations / "observation-000.json").read_bytes())}})
    write(verification / "adoption-complete.json", {"schema": adoption.COMPLETE_SCHEMA,
        "adoptionId": intent["adoptionId"], "binding": binding,
        "requestSha256": adoption.digest((operation / "adoption-requested.json").read_bytes()),
        "verificationDirectory": str(verification),
        "verificationSha256": adoption.digest((verification / "verified.json").read_bytes()),
        "deliverySha256": adoption.digest((verification / "delivery.json").read_bytes()),
        "selectedAtUnixSeconds": now, "status": "both-enrollments-and-live-delivery-verified"})
    with selection.locked(state) as held:
        held.write_new(adoption.PENDING, {"schema": adoption.REQUEST_SCHEMA, "operationDirectory": str(operation),
            "adoptionId": intent["adoptionId"], "requestSha256": adoption.digest((operation / "adoption-requested.json").read_bytes())})
    return SimpleNamespace(operation=operation, candidate=candidate, verification=verification, intent=intent, native=native)


def publish(state, fixture):
    with selection.locked(state) as held:
        adoption.publish(held, fixture.operation, fixture.verification)


def staging_flow(flow, monkeypatch):
    """Select distinct recovered bytes while preserving installed runtime identity."""
    from copy import deepcopy
    import kubernetes_legacy_recovery_sources as sources
    root = flow.args.state_dir
    recovered = private(root.parent / "recovered-live")
    live = {}
    replaced = {entry["file"] for entry in bootstrap.APPLICATION_TOKEN_SPEC["tokens"]
                if entry["replacementRole"] is not None} | set(bootstrap.SELFHOST_TLS_FILES) | bootstrap.KEYCLOAK_FILES
    replaced.discard("workload_identity_ca_cert")
    for name, (raw, mode) in flow.snapshot.items():
        value = ("synthetic-recovered-live-" + name).encode() if name in replaced else raw
        live[name] = (value, mode)
        write(recovered / name, value, mode)
    fixture = retained(root, recovered, flow.binding, flow.values["release"], operator=flow.operator)
    flow.snapshot, flow.candidate = live, {**live, **flow.minted}
    values = deepcopy(flow.values)
    values["release"] = fixture.intent["operatorRuntime"]
    values["images"]["services"] = "ghcr.io/elevenid/marty-ui-oss/services@sha256:" + "6" * 64
    args = flow.args
    args.operator_assets = root.parent / "operator-assets"
    args.operator_source_sha = values["release"]["runtimeSourceSha"]
    args.operator_release_tag = values["release"]["tag"]
    args.operator_build_run_id = values["release"]["buildRunId"]
    args.operator_build_run_attempt = values["release"]["buildRunAttempt"]
    original_prepare, original_process = bootstrap.prepare, bootstrap.subprocess.run
    def prepare(**kwargs):
        if kwargs["assets"] != args.operator_assets:
            return original_prepare(**kwargs)
        assert kwargs["runtime_source_sha"] == args.operator_source_sha
        bootstrap.write_new(kwargs["output"], bootstrap.encoded(values))
        bootstrap.write_new(kwargs["openbao_output"], b"{}")
        return values, {}
    def process(command, **kwargs):
        if command[-1] == "--build-identity":
            return SimpleNamespace(returncode=0, stdout=fixture.intent["operatorBuildIdentity"].encode(), stderr=b"")
        return original_process(command, **kwargs)
    monkeypatch.setattr(bootstrap, "prepare", prepare)
    monkeypatch.setattr(bootstrap.subprocess, "run", process)
    monkeypatch.setattr(sources, "authenticate", lambda *args, **kwargs: fixture.intent["sources"])
    publish(root, fixture)
    return fixture, values
