"""Explicit legacy renewal adoption evidence and routine authority resolution.

Historical bootstrap records remain historical. The separate selector refers to
one complete pair of newly verified enrollments and a live delivered generation.
All callers hold kubernetes_application_state.LockedState while selecting it.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import secrets
import time

import bootstrap_kubernetes_openbao as bootstrap

SELECTOR = "renewal-adoption.json"
PENDING = "renewal-adoption-pending.json"
SCHEMA = "marty.kubernetes-renewal-adoption/v1"
REQUEST_SCHEMA = "marty.kubernetes-renewal-adoption-request/v1"
COMPLETE_SCHEMA = "marty.kubernetes-renewal-adoption-completion/v1"
NATIVE_SCHEMA = "marty.kubernetes-renewal-adoption-verification/v1"
DELIVERY_SCHEMA = "marty.kubernetes-renewal-adoption-delivery/v1"
REFUSAL = "legacy renewal adoption evidence differs or is incomplete; preserve the private attempt"


def require(value: bool) -> None:
    bootstrap.require(value, REFUSAL)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def hashes(snapshot: dict) -> dict:
    return {name: {"sha256": digest(raw), "mode": mode} for name, (raw, mode) in snapshot.items()}


def state_owner():
    import kubernetes_application_state
    return kubernetes_application_state


def private_owner():
    import stage_kubernetes_application_credentials
    return stage_kubernetes_application_credentials


def original_binding(complete: dict) -> dict:
    require(complete.get("status") == "openbao-and-application-credentials-ready")
    lifecycle = complete["credentialLifecycle"]
    return bootstrap.application_binding({"namespace": complete["namespace"],
        "namespaceUid": lifecycle["namespaceUid"], "openbaoClusterId": complete["openbaoClusterId"],
        "workloadProject": lifecycle["workloadProject"]})


def record(path: Path):
    return state_owner().private_record(path)


def request(operation: Path, state: Path) -> tuple[object, dict]:
    owner, private = state_owner(), private_owner()
    owner.owned_directory(operation)
    require(operation.is_absolute() and operation.resolve() == operation
            and not operation.is_relative_to(state) and not state.is_relative_to(operation))
    retained = record(operation / "adoption-requested.json")
    value = retained.value
    require(set(value) == {"schema", "binding", "bootstrapId", "adoptionId", "operationDirectory",
        "operationIdentity", "candidateDirectory", "candidateIdentity", "candidateInputs", "originalRuntime",
        "operatorRuntime", "operatorBuildIdentity", "operatorSha256", "sourceRecoveryDirectory",
        "recoveryCompletionSha256", "bootstrapSha256", "originalImagesSha256", "contracts", "pullSecrets",
        "sources", "automaticEnrollmentReplay"}
        and value["schema"] == REQUEST_SCHEMA and value["operationDirectory"] == str(operation)
        and value["operationIdentity"] == list(owner.owned_directory(operation))
        and re.fullmatch(r"[0-9a-f]{32}", value["adoptionId"]) is not None
        and value["automaticEnrollmentReplay"] is False)
    complete = record(state / "bootstrap-complete.json")
    for name in ("application-identity", "renewal-identity", "renewal-binding.json"):
        require(not (state / name).exists() and not (state / name).is_symlink())
    require(value["binding"] == original_binding(complete.value)
        and value["bootstrapId"] == complete.value["bootstrapId"]
        and "applicationAuthority" not in complete.value and "renewalAuthority" not in complete.value
        and value["bootstrapSha256"] == digest(complete.raw)
        and value["originalImagesSha256"] == digest(record(state / "marty-images.json").raw)
        and value["originalRuntime"] == record(state / "marty-images.json").value["release"])
    candidate = operation / "candidate"
    require(value["candidateDirectory"] == str(candidate)
        and value["candidateIdentity"] == list(owner.owned_directory(candidate))
        and value["candidateInputs"] == hashes(private.current_snapshot(candidate)))
    operator = value["operatorRuntime"]
    require(value["operatorBuildIdentity"] == operator["runtimeSourceSha"] + ":" + operator["tag"]
        and value["operatorSha256"] == operator["operatorSha256"]
        and value["operatorSha256"] == digest(private.private_bytes(operation / "marty-deploy",
                                                                  private.OPERATOR_LIMIT, {0o700})[0]))
    require(set(value["contracts"]) == {"publication", "application", "renewal"}
        and isinstance(value["pullSecrets"], list) and isinstance(value["sources"], dict))
    return retained, value


def native_evidence(operation: Path, intent: dict, verification: Path, *, fresh: bool) -> tuple[object, dict]:
    owner, private = state_owner(), private_owner()
    require(verification.parent == operation and re.fullmatch(r"verification-[0-9a-f]{12}", verification.name) is not None)
    owner.owned_directory(verification)
    native = record(verification / "verified.json")
    require(set(native.value) == {"verification", "ready", "transientSessionsRevoked"}
        and native.value["ready"] is True and native.value["transientSessionsRevoked"] is True)
    value = native.value["verification"]
    require(set(value) == {"schema", "binding", "bootstrapId", "adoptionId", "operatorIdentity",
        "candidateInputs", "applicationIdentity", "renewalIdentity", "renewalBindingSha256",
        "verificationStartedAtUnixSeconds", "validBeforeUnixSeconds", "minimumTtlSeconds",
        "applicationRoles", "scopedLeafTokens", "enrollmentReplayed", "credentialsIssued", "activated"}
        and value["schema"] == NATIVE_SCHEMA and value["binding"] == intent["binding"]
        and value["bootstrapId"] == intent["bootstrapId"] and value["adoptionId"] == intent["adoptionId"]
        and value["operatorIdentity"] == intent["operatorBuildIdentity"]
        and value["candidateInputs"] == intent["candidateInputs"]
        and value["minimumTtlSeconds"] == 3600 and value["applicationRoles"] == 11
        and value["scopedLeafTokens"] == 21 and value["enrollmentReplayed"] is False
        and value["credentialsIssued"] is False and value["activated"] is False
        and type(value["verificationStartedAtUnixSeconds"]) is int
        and type(value["validBeforeUnixSeconds"]) is int
        and value["validBeforeUnixSeconds"] - value["verificationStartedAtUnixSeconds"] == 900)
    if fresh:
        require(value["verificationStartedAtUnixSeconds"] <= time.time() < value["validBeforeUnixSeconds"])
    for domain, key, names in (("application", "applicationIdentity", bootstrap.APPLICATION_IDENTITY_FILES),
                               ("renewal", "renewalIdentity", bootstrap.RENEWAL_IDENTITY_FILES)):
        import adopt_kubernetes_renewal as coordinator
        require(record(operation / (domain + "-enrollment-intent.json")).value == coordinator.domain_intent(intent, domain))
        values = private.current_snapshot(operation / (domain + "-identity"))
        require(set(values) == names and all(mode in {0o400, 0o600} for _, mode in values.values())
            and hashes(values) == value[key])
        completed = record(operation / (domain + "-enrolled.json")).value
        require(completed == {"schema": "marty.kubernetes-renewal-adoption-domain/v1",
            "adoptionId": intent["adoptionId"], "binding": intent["binding"], "domain": domain,
            "identityInputs": value[key], "enrollmentReplayed": False})
    raw = private.private_bytes(operation / "renewal-binding.json", 4096, {0o600})[0]
    require(value["renewalBindingSha256"] == digest(raw))
    bootstrap.renewal_binding(bootstrap.json.loads(raw, object_pairs_hook=bootstrap.unique_json_members), intent["binding"])
    require(record(operation / "application-identity/application-binding.json").value == intent["binding"])
    return native, value


def validate(operation: Path, state: Path, verification: Path, *, fresh: bool = False) -> tuple[object, dict, object]:
    retained, intent = request(operation, state)
    completed = record(verification / "adoption-complete.json")
    value = completed.value
    require(set(value) == {"schema", "adoptionId", "binding", "requestSha256", "verificationDirectory",
        "verificationSha256", "deliverySha256", "selectedAtUnixSeconds", "status"}
        and value["schema"] == COMPLETE_SCHEMA and value["adoptionId"] == intent["adoptionId"]
        and value["binding"] == intent["binding"] and value["requestSha256"] == digest(retained.raw)
        and value["status"] == "both-enrollments-and-live-delivery-verified")
    require(value["verificationDirectory"] == str(verification))
    native, evidence = native_evidence(operation, intent, verification, fresh=fresh)
    delivery = record(verification / "delivery.json")
    require(value["verificationSha256"] == digest(native.raw) and value["deliverySha256"] == digest(delivery.raw)
        and type(value["selectedAtUnixSeconds"]) is int
        and evidence["verificationStartedAtUnixSeconds"] <= value["selectedAtUnixSeconds"] < evidence["validBeforeUnixSeconds"]
        and delivery.value.get("schema") == DELIVERY_SCHEMA
        and delivery.value.get("adoptionId") == intent["adoptionId"]
        and delivery.value.get("binding") == intent["binding"]
        and delivery.value.get("candidateInputs") == intent["candidateInputs"]
        and delivery.value.get("secretCount") == 34 and delivery.value.get("workloadCount") == 16
        and delivery.value.get("credentialDeliveryVerified") is True
        and delivery.value.get("credentialConsumptionVerified") is False)
    observations = delivery.value.get("observationHashes")
    require(isinstance(observations, dict) and 1 <= len(observations) <= 512)
    directory = verification / "delivery"
    state_owner().owned_directory(directory)
    require({path.name for path in directory.iterdir()} == set(observations))
    for name, expected in observations.items():
        require(re.fullmatch(r"observation-[0-9]{3}\.json", name) is not None
            and digest(private_owner().private_bytes(directory / name, 16 * 1024 * 1024, {0o600})[0]) == expected)
    return retained, intent, completed


def selected(state: Path, *, allow_pending: bool = False) -> dict | None:
    owner = state_owner()
    descriptor = owner.directory_fd(state)
    try:
        pending = owner.read_at(descriptor, PENDING, missing=True)
        selector = owner.read_at(descriptor, SELECTOR, missing=True)
    finally:
        os.close(descriptor)
    require(allow_pending or pending is None)
    if selector is None:
        return None
    value = selector.value
    require(set(value) == {"schema", "operationDirectory", "requestIdentity", "requestSha256",
                          "completionDirectory", "completionIdentity", "completionSha256"} and value["schema"] == SCHEMA)
    operation = owner.path_value(value["operationDirectory"])
    verification = owner.path_value(value["completionDirectory"])
    retained, intent, complete = validate(operation, state, verification)
    require(value == selector_value(operation, retained, complete))
    return intent


def selector_value(operation: Path, retained, complete) -> dict:
    return {"schema": SCHEMA, "operationDirectory": str(operation),
        "requestIdentity": list(retained.identity), "requestSha256": digest(retained.raw),
        "completionDirectory": complete.value["verificationDirectory"],
        "completionIdentity": list(complete.identity), "completionSha256": digest(complete.raw)}


def publish(held, operation: Path, verification: Path) -> None:
    owner = state_owner()
    held.bound()
    retained, intent, completed = validate(operation, held.path, verification, fresh=True)
    pending = held.read(PENDING)
    require(pending.value == {"schema": REQUEST_SCHEMA, "operationDirectory": str(operation),
        "adoptionId": intent["adoptionId"], "requestSha256": digest(retained.raw)})
    require(held.read(owner.PENDING, missing=True) is None and held.read(owner.SELECTOR, missing=True) is None)
    value = selector_value(operation, retained, completed)
    previous = held.read(SELECTOR, missing=True)
    if previous is not None:
        # A selector whose final journal cleanup was interrupted remains blocked
        # by PENDING. Only this same attempt may replace it with fresh evidence.
        require(selected(held.path, allow_pending=True) == intent)
    if previous is None or previous.value != value:
        temporary = "renewal-adoption-" + secrets.token_hex(12) + ".tmp"
        held.write_new(temporary, value)
        validate(operation, held.path, verification, fresh=True)
        held.bound()
        require(held.read(SELECTOR, missing=True) == previous)
        # The same checked single-writer lock as the ordinary generation owner
        # protects this atomic replacement. A link/unlink pair would leave an
        # unreadable two-link selector if interrupted between the operations.
        os.replace(temporary, SELECTOR, src_dir_fd=held.descriptor, dst_dir_fd=held.descriptor)
        os.fsync(held.descriptor)
    require(selected(held.path, allow_pending=True) == intent and held.read(PENDING) == pending)
    validate(operation, held.path, verification, fresh=True)
    os.unlink(PENDING, dir_fd=held.descriptor)
    try:
        os.fsync(held.descriptor)
        held.bound()
        require(held.read(PENDING, missing=True) is None and selected(held.path) == intent)
        validate(operation, held.path, verification, fresh=True)
    except BaseException:
        # Preserve the blocked state after any interrupted durability or final
        # lifetime check, just as the ordinary generation owner does.
        held.bound()
        observed = held.read(PENDING, missing=True)
        if observed is None:
            owner.write_file_at(held.descriptor, PENDING, pending.raw)
        else:
            require(observed.raw == pending.raw)
            owner.sync_file_at(held.descriptor, PENDING, observed)
        require(held.read(PENDING).raw == pending.raw)
        raise


def authority(state: Path, complete: dict, domain: str) -> tuple[dict, Path]:
    require(domain in {"application", "renewal"})
    adopted = selected(state)
    binding = original_binding(complete)
    if adopted is not None:
        require(adopted["binding"] == binding)
        return binding, Path(adopted["operationDirectory"]) / (domain + "-identity")
    value = complete.get(domain + "Authority")
    fields = {"schema", "binding", "identityDirectory", "files"}
    names = bootstrap.APPLICATION_IDENTITY_FILES if domain == "application" else bootstrap.RENEWAL_IDENTITY_FILES
    if domain == "renewal":
        fields.add("bindingFile")
    require(isinstance(value, dict) and set(value) == fields
        and value["schema"] == "marty.kubernetes-" + domain + "-authority/v1"
        and value["binding"] == binding and value["identityDirectory"] == domain + "-identity"
        and value["files"] == sorted(names)
        and (domain != "renewal" or value["bindingFile"] == "renewal-binding.json"))
    return binding, state / (domain + "-identity")


def binding_path(state: Path) -> Path:
    adopted = selected(state)
    return (state if adopted is None else Path(adopted["operationDirectory"])) / "renewal-binding.json"


def contract(state: Path, complete: dict, name: str) -> dict:
    adopted = selected(state)
    if adopted is not None:
        return adopted["contracts"][name]
    return complete[{"publication": "credentialPublication", "application": "applicationTokenContract",
                     "renewal": "renewalContract"}[name]]


def pull_secrets(state: Path, complete: dict) -> list:
    adopted = selected(state)
    return complete.get("imagePullSecrets") if adopted is None else adopted["pullSecrets"]


def add_operator_arguments(parser) -> None:
    parser.add_argument("--operator-assets", type=Path)
    for name in ("operator-source-sha", "operator-release-tag"):
        parser.add_argument("--" + name)
    for name in ("operator-build-run-id", "operator-build-run-attempt"):
        parser.add_argument("--" + name, type=int)


def producer_image(args, original: dict) -> str:
    selected_operator = getattr(args, "_authenticated_adoption_operator", None)
    return original["images"]["services"] if selected_operator is None else selected_operator["images"]["services"]


def operation_allowed(state: Path, operation: Path) -> None:
    adopted = selected(state)
    if adopted is not None:
        retained = Path(adopted["operationDirectory"])
        require(not operation.is_relative_to(retained) and not retained.is_relative_to(operation))


def authenticated_operator(args, complete: dict, operation: Path, original: dict,
                           original_bytes: bytes) -> tuple[bytes, str]:
    adopted = selected(args.state_dir)
    names = ("operator_assets", "operator_source_sha", "operator_release_tag",
             "operator_build_run_id", "operator_build_run_attempt")
    if adopted is None:
        require(all(getattr(args, name, None) is None for name in names))
        return original_bytes, args.runtime_source_sha + ":" + args.release_tag
    require(all(getattr(args, name, None) is not None for name in names))
    expected = adopted["operatorRuntime"]
    require(args.operator_source_sha == expected["runtimeSourceSha"]
        and args.operator_release_tag == expected["tag"]
        and args.operator_build_run_id == expected["buildRunId"]
        and args.operator_build_run_attempt == expected["buildRunAttempt"])
    values, _ = bootstrap.prepare(assets=args.operator_assets,
        runtime_source_sha=args.operator_source_sha, release_tag=args.operator_release_tag,
        build_run_id=args.operator_build_run_id, build_run_attempt=args.operator_build_run_attempt,
        chart_source_sha=args.chart_source_sha, gh=args.gh, cosign=args.cosign,
        output=operation / "operator-images.json", openbao_output=operation / "operator-openbao-images.json")
    require(values["release"] == expected and original["release"] == adopted["originalRuntime"])
    selected_bytes, initializer = bootstrap.authenticated_bootstrap_inputs(args.operator_assets, values["release"])
    _, original_initializer = bootstrap.authenticated_bootstrap_inputs(args.assets, original["release"])
    require(initializer == original_initializer and digest(selected_bytes) == adopted["operatorSha256"])
    import kubernetes_legacy_recovery_sources as sources
    require(sources.authenticate(args.operator_assets, values["release"]) == adopted["sources"])
    args._authenticated_adoption_operator = values
    return selected_bytes, adopted["operatorBuildIdentity"]
