"""Closed current-source D12 native cutover using existing journal, SQL and Rust CLIs.

The caller is the reviewed beta host and supplies its existing operation lock,
actual22 reader and frozen Compose model. Import and construction make no effects.
An uncertain command leaves a durable pending state for explicit reconciliation.
"""
from __future__ import annotations

import json,time
from pathlib import Path

from scoped_native_runtime import D12_CURRENT_RUNTIME_ROLES, daemon_source, durable_barrier, read_ref, require, selected_sources, sha, started_later
from scoped_native_profiles import D12_PASSPORT_CURRENT
from scoped_passport_successor import CURRENT_PROFILE, select_current_binaries
from scoped_native_database import D12CurrentDatabasePhase
import scoped_beta_binary_overlay as overlay
import scoped_passport_maintenance as maintenance

MIGRATION_SHA256 = {
    "rust/services/flow/migrations/0003_physical_start_intents.sql":
        "fd86a211a4b799b53827456ac1d5b8887ae3264c26ae889fb7714a1fa62e4edd",
    "rust/services/issuance/migrations/0010_passport_start_idempotency.sql":
        "05b3aafe03b9aa258c8061db2d9ac1adb35f17f0d513b9995d48ee2ef2305801",
    "rust/services/issuance/migrations/0011_passport_administrative_cancellation.sql":
        "9842f5ea39aab254d41cf7bc936411b813b853352a1e2de668594926dd08f682",
}
D05_MIGRATION_SHA256 = {**MIGRATION_SHA256,
    'rust/services/credential-template/migrations/0003_membership_achievement_criteria.sql': '8d4a006db83610c3253bf00504f779939e43069b9e45dde2074694891d9a0987',
    'rust/services/issuance/migrations/0012_membership_achievement_criteria.sql': '2becfb8d83bfe775f75a95d6b1aa17b317cdcec825f1350e181e93347d67bb7e',
}



def exact_exported_sql(prepared, inputs, profile=CURRENT_PROFILE):
    from scoped_native_profiles import current_rollout_build
    build = current_rollout_build(profile)
    """Use LF Git-exported source bytes, never a Windows checkout conversion."""
    from scoped_native_maintenance import operational_sql_sources
    from scoped_native_runtime import migration_names
    source = prepared["sources"]["ui"]
    require(source["revision"] == build.ui_revision,
            "D12_EXACT_SQL_SOURCE_REVISION_REQUIRED")
    root = Path(source["directory"]).resolve()
    expected = operational_sql_sources()
    require(set(inputs["sqlSources"]) == set(expected), "D12_EXACT_OPERATIONAL_SQL_SET_REQUIRED")
    for name, digest in expected.items():
        bound = inputs["sqlSources"][name]
        require(bound["sha256"] == digest
                and read_ref(bound).resolve() == root / "scripts" / "sql" / name,
                "D12_EXACT_GIT_EXPORTED_SQL_REQUIRED:" + name)
    from scoped_native_maintenance import migration_requirements
    required = migration_requirements()["catalogSqlSha256"]
    require(inputs["catalogSql"]["sha256"] == required
            and read_ref(inputs["catalogSql"]).resolve()
                == root / "scripts" / "sql" / "passport-beta-maintenance-catalog.sql",
            "D12_EXACT_GIT_EXPORTED_CATALOG_REQUIRED")
    required_migrations = D05_MIGRATION_SHA256 if profile == "d05-membership-current-functional" else MIGRATION_SHA256
    migration_paths = {"rust/services/" + item.replace("/", "/migrations/", 1) + ".sql"
                       for item in migration_names(profile)}
    require(set(inputs["migrationSources"]) == migration_paths == set(required_migrations),
            "D12_EXACT_RUST_MIGRATION_SET_REQUIRED")
    for name, bound in inputs["migrationSources"].items():
        require(bound["sha256"] == required_migrations[name]
                and read_ref(bound).resolve() == root / name,
                "D12_EXACT_GIT_EXPORTED_MIGRATION_REQUIRED")


def created_recovery_checkpoint(inputs, state, intent, recovery, *, operation_backend):
    """Bind a Root-reconciled acknowledged create, never repeat its commands."""
    from scoped_native_database import RECOVERY_SOURCE_FIELDS, RECOVERY_TRUST_FIELDS, _recovery_trust_models
    from scoped_native_runtime import validate_journal_readback
    def load(ref):
        return json.loads(read_ref(ref).read_bytes())
    def closed_job(ref, expected):
        job = load(ref)
        require(job.get("state") == expected and type(job.get("exitCode")) is int
                and job["exitCode"] == (0 if expected == "COMPLETE" else 1)
                and job.get("jobClosed") is True and job.get("terminalActiveProcesses") == 0
                and all(job.get(k) is False for k in ("forcedTermination", "timedOut", "cancelled", "hostMarginBreached")),
                "D12_CREATED_RECOVERY_NORMAL_JOB_REQUIRED")
    ob3_acknowledged = recovery.get("schema") == "marty.d12-ob3-acknowledged-replacement-recovery/v1"
    ob3_second_replacement = (ob3_acknowledged and recovery.get("operation") ==
        "REPLACE_OB3_AFTER_ACKNOWLEDGED_CREDENTIAL_REPLACEMENT_AND_RESUME")
    require((ob3_acknowledged and recovery.get("operation") in (
                "RESUME_OB3_AFTER_ACKNOWLEDGED_CREDENTIAL_REPLACEMENT",
                "REPLACE_OB3_AFTER_ACKNOWLEDGED_CREDENTIAL_REPLACEMENT_AND_RESUME")
            or recovery.get("schema") == "marty.d12-created-recovery/v1"
            and recovery.get("operation") in ("RESUME_AFTER_ACKNOWLEDGED_CREATE_SELECTED", "REPLACE_CREATED_CREDENTIAL_GENERATION_AND_RESUME",
                "RESUME_AFTER_ACKNOWLEDGED_CREDENTIAL_REPLACEMENT", "REPLACE_ACKNOWLEDGED_CREDENTIAL_GENERATION_AND_RESUME"))
            and recovery.get("draftOnly") is False and recovery.get("dispatchAuthorized") is True
            and recovery.get("runId") == inputs["runId"], "D12_CREATED_RECOVERY_AUTHORITY_REQUIRED")
    resuming_replacement=recovery["operation"] in ("RESUME_AFTER_ACKNOWLEDGED_CREDENTIAL_REPLACEMENT",
        "REPLACE_ACKNOWLEDGED_CREDENTIAL_GENERATION_AND_RESUME", "RESUME_OB3_AFTER_ACKNOWLEDGED_CREDENTIAL_REPLACEMENT",
        "REPLACE_OB3_AFTER_ACKNOWLEDGED_CREDENTIAL_REPLACEMENT_AND_RESUME")
    original, original_state = load(recovery["originalInputs"]), load(recovery["originalOperationState"])
    previous = load(recovery["previousRecoveryAuthority"])
    if resuming_replacement:
        if ob3_acknowledged:
            require(previous.get("schema")=="marty.d12-ob3-quiescent-recovery/v1"
                    and previous.get("operation")=="REPLACE_OB3_QUIESCENT_CREDENTIALS_AND_RESUME"
                    and recovery.get("scope")==previous.get("scope")=="OB3_FUNCTIONAL_ONLY"
                    and recovery.get("deferredRoles")==previous.get("deferredRoles")==[OB3_DEFERRED_ROLE]
                    and recovery.get("allowedScenarios")==previous.get("allowedScenarios")==list(OB3_ALLOWED_SCENARIOS)
                    and recovery.get("startupPrerequisites")==previous.get("startupPrerequisites")
                    and recovery.get("replaceCredentialGeneration") is ob3_second_replacement,
                    "D12_OB3_ACKNOWLEDGED_PRIOR_AUTHORITY_REQUIRED")
            ob3_startup_prerequisites(recovery["startupPrerequisites"])
            _ob3_acknowledged_failed_job_lineage(inputs,state,recovery,load)
            database_original, _, _=ob3_quiescent_checkpoint(original,
                load(previous["originalOperationState"]),intent,previous,operation_backend=operation_backend)
        else:
            require(previous.get("schema")=="marty.d12-created-recovery/v1"
                    and previous.get("operation") in ("REPLACE_CREATED_CREDENTIAL_GENERATION_AND_RESUME",
                        "REPLACE_ACKNOWLEDGED_CREDENTIAL_GENERATION_AND_RESUME")
                    and previous.get("dispatchAuthorized") is True and previous.get("draftOnly") is False,
                    "D12_CREATED_REPLACEMENT_PRIOR_AUTHORITY_REQUIRED")
            database_original, _, _=created_recovery_checkpoint(original,
                load(previous["originalOperationState"]),intent,previous,operation_backend=operation_backend)
    else:
        require(previous.get("schema") == "marty.d12-fence-install-recovery/v1"
                and previous.get("dispatchAuthorized") is True and previous.get("draftOnly") is False,
                "D12_CREATED_RECOVERY_PRIOR_AUTHORITY_CHANGED")
        database_original=original
    require(previous.get("runId")==inputs["runId"]
            and previous["originalApplyIntent"]==recovery["originalApplyIntent"]
            and load(recovery["originalApplyIntent"])==intent,
            "D12_CREATED_RECOVERY_PRIOR_AUTHORITY_CHANGED")
    require(state == original_state and state.get("schema") == "marty.d12-current-native-operation/v1"
            and state.get("phase") == "EFFECT_ACKNOWLEDGED" and state.get("acknowledgedStep") == ("REPLACE_CREATED_CREDENTIAL_GENERATION" if resuming_replacement else "CREATE_SELECTED")
            and state.get("pendingStep") is None and state.get("pendingArgv") is None and state.get("pendingRequest") is None
            and state.get("runId") == inputs["runId"] and state.get("sourceRevision") == inputs["uiRevision"]
            and state.get("coreRevision") == inputs["coreRevision"] and state.get("scope") == "FUNCTIONAL_ONLY"
            and state.get("releaseQualified") is False and state.get("recordingQualified") is False
            and state.get("recoveryAuthority") == recovery["previousRecoveryAuthority"]
            and state.get("databaseProof") == recovery["databaseProof"]
            and state.get("verifiedDatabase") == recovery["verifiedDatabase"]
            and state.get("steps") == [], "D12_ONLY_ACKNOWLEDGED_CREATE_RECOVERABLE")
    if resuming_replacement:
        prior_inputs=load(previous["originalInputs"])
        require(state.get("replacementAuthority")==recovery["previousRecoveryAuthority"]
                and state.get("originalOperationState")==previous["originalOperationState"]
                and state.get("priorCreatedSnapshot")==previous["selected22"]
                and state.get("priorCredentialGeneration")==prior_inputs["runScopedTrustLeaseProof"]
                and state.get("nextCredentialGeneration")==original["runScopedTrustLeaseProof"]
                and isinstance(state.get("replacementPreimage"),dict),
                "D12_CREATED_REPLACEMENT_LINEAGE_CHANGED")
        read_ref(state["replacementPreimage"])
        require(recovery["operation"] not in ("RESUME_AFTER_ACKNOWLEDGED_CREDENTIAL_REPLACEMENT",
                    "RESUME_OB3_AFTER_ACKNOWLEDGED_CREDENTIAL_REPLACEMENT")
                or all(inputs.get(key)==original.get(key) for key in RECOVERY_TRUST_FIELDS
                    - {"composeEffectReadOnlyProof","composeEffectReadOnlyJob"}),
                "D12_CREATED_RESUME_TARGET_CHANGED")
    require(intent.get("runId") == inputs["runId"] and intent.get("selectionSha256") == inputs["selection"]["sha256"]
            and intent.get("runtimeBefore") == inputs["runtimeBefore"]
            and intent.get("databaseBefore") == inputs["databaseBefore"], "D12_CREATED_RECOVERY_INTENT_CHANGED")
    require(recovery.get("sourceMap") == {key:{"original":original[key],"recovery":inputs[key]} for key in RECOVERY_SOURCE_FIELDS}
            and all(previous["sourceMap"][key]["recovery"] == original[key] for key in RECOVERY_SOURCE_FIELDS),
            "D12_CREATED_RECOVERY_SOURCE_MAP_CHANGED")
    require(recovery.get("trustDataMap") == {key:{"original":original.get(key),"recovery":inputs.get(key)} for key in RECOVERY_TRUST_FIELDS},
            "D12_CREATED_RECOVERY_TRUST_MAP_CHANGED")
    ignored = RECOVERY_SOURCE_FIELDS | RECOVERY_TRUST_FIELDS | {"d12Authority", "quiescence"}
    require({k:v for k,v in original.items() if k not in ignored} == {k:v for k,v in inputs.items() if k not in ignored},
            "D12_CREATED_RECOVERY_INPUT_DRIFT")
    _recovery_trust_models(original, inputs)
    old_lease,new_lease=load(original["runScopedTrustLeaseProof"]),load(inputs["runScopedTrustLeaseProof"])
    replacing=recovery["operation"] in ("REPLACE_CREATED_CREDENTIAL_GENERATION_AND_RESUME",
        "REPLACE_ACKNOWLEDGED_CREDENTIAL_GENERATION_AND_RESUME",
        "REPLACE_OB3_AFTER_ACKNOWLEDGED_CREDENTIAL_REPLACEMENT_AND_RESUME")
    require(recovery.get("replaceCredentialGeneration",False) is replacing,
            "D12_CREATED_REPLACEMENT_AUTHORITY_REQUIRED")
    require((old_lease["generationDirectory"]!=new_lease["generationDirectory"]) if replacing
            else (old_lease["generationDirectory"]==new_lease["generationDirectory"]),
            "D12_CREATED_CREDENTIAL_GENERATION_CHANGED")
    closed_job(recovery["reconciliationJob"], "COMPLETE")
    closed_job(recovery["selected22Job"], "COMPLETE")
    closed_job(recovery["failedCutoverJob"], "FAILED")
    observed = load(recovery["journalRead"])
    require(isinstance(observed,list) and len(observed)==1 and observed[0].get("state")=="EXACT_ROOT_DURABLE_METADATA_READ_COMPLETE"
            and observed[0].get("mountReadOnly") is True, "D12_CREATED_AUTHORITATIVE_JOURNAL_REQUIRED")
    files=observed[0]["files"]
    for name,ref,value in (("build-state.json",recovery["originalOperationState"],state),
                           ("build-apply-intent.json",recovery["originalApplyIntent"],intent)):
        exact=validate_journal_readback({"storedBytesBase64":files[name].get("storedBytesBase64"),
            "sha256":files[name].get("sha256"),"value":files[name].get("document")})
        require(exact==read_ref(ref).read_bytes(),"D12_CREATED_CHECKPOINT_STORED_BYTES_CHANGED")
        require(files[name].get("present") is True and files[name].get("document")==value
                and files[name].get("sha256")==ref["sha256"] and files[name].get("bytes")==ref["bytes"],
                "D12_CREATED_CHECKPOINT_READ_CHANGED")
    require(all(files[name].get("present") is False for name in ("build-receipt.json","configuration-receipt.json")),
            "D12_CREATED_CHECKPOINT_ALREADY_CONSUMED")
    require(isinstance(operation_backend, dict) and isinstance(operation_backend.get("rootProof"), dict),
            "D12_CREATED_JOURNAL_BACKEND_REQUIRED")
    backend=operation_backend
    require(all(observed[0]["root"][key]==backend["rootProof"][key] for key in ("device","inode","uid","mode")),
            "D12_CREATED_JOURNAL_ROOT_CHANGED")
    proof, verified = load(recovery["databaseProof"]), load(recovery["verifiedDatabase"])
    dbstate=load(proof["operationState"])
    require(dbstate.get("phase")=="DATABASE_MAINTENANCE_COMPLETED" and dbstate.get("runId")==inputs["runId"]
            and dbstate.get("executorSource")==database_original["executorSource"]
            and verified.get("operationState")==dbstate and verified.get("databaseIdentity")==dbstate["databaseIdentity"]
            and dbstate.get("quiescenceSha256")==recovery["quiescence"]["sha256"]
            and previous["quiescence"]==recovery["quiescence"], "D12_COMPLETED_DATABASE_CHECKPOINT_CHANGED")
    return database_original, proof, verified


def _ob3_acknowledged_failed_job_lineage(inputs,state,recovery,load):
    """Join the failed owned Job and its create acknowledgement to one invocation."""
    invocation_ref=recovery["failedCutoverInvocation"]
    invocation_path=Path(invocation_ref["path"])
    require(invocation_path.name=="invocation.armed.json", "D12_OB3_FAILED_INVOCATION_REQUIRED")
    invocation=load(invocation_ref);root=invocation_path.parent
    read_ref(invocation["actor"]);read_ref(invocation["executables"]["python"])
    require(invocation.get("schema")=="marty.current10-effect-invocation/v1"
            and invocation.get("executionMode")=="REPLACE_OB3_QUIESCENT_CREDENTIALS_AND_RESUME"
            and invocation.get("executeAuthorized") is True
            and invocation.get("effectInputs")==recovery["originalInputs"]
            and invocation.get("recoveryAuthority")==recovery["previousRecoveryAuthority"]
            and Path(invocation.get("outputRoot",""))==root/"outputs"
            and all(Path(recovery[key]["path"])==root/name for key,name in (
                ("failedCutoverRequest","current10-effect-request.private.json"),
                ("failedCutoverJob","current10-effect-job.json"),
                ("failedCutoverController","current10-effect-controller.safe.json"),
                ("acknowledgedReplacement","outputs/d12-created-replacement-target-ack.private.json"),
                ("ownedCreatedCids","outputs/d12-credential-replacement-cids-after-ack.private.json"))),
            "D12_OB3_FAILED_INVOCATION_LINEAGE_CHANGED")
    request=load(recovery["failedCutoverRequest"])
    require(request.get("schema")=="marty.windows-job-request/v1"
            and request.get("command")==[invocation["executables"]["python"]["path"],"-B",
                invocation["actor"]["path"],"--run",str(invocation_path),invocation_ref["sha256"]]
            and Path(request.get("cwd",""))==root
            and Path(request.get("receiptFile",""))==Path(recovery["failedCutoverJob"]["path"])
            and request.get("executableSha256")==invocation["executables"]["python"]["sha256"],
            "D12_OB3_FAILED_JOB_REQUEST_CHANGED")
    controller=load(recovery["failedCutoverController"])
    require(controller.get("state")=="CURRENT10_EFFECT_FAILED_OR_UNKNOWN_NO_RETRY"
            and controller.get("jobState")=="FAILED" and controller.get("jobClosed") is True
            and controller.get("terminalActiveProcesses")==0 and controller.get("resultPresent") is False
            and controller.get("failurePresent") is True and controller.get("automaticCleanupOrRetry") is False,
            "D12_OB3_FAILED_JOB_CONTROLLER_CHANGED")
    require(load(recovery["acknowledgedReplacement"])==state,
            "D12_OB3_FAILED_ACKNOWLEDGEMENT_CHANGED")
    cids=load(recovery["ownedCreatedCids"])
    selected=load(recovery["selected22"])
    require(cids.get("schema")=="marty.d12-owned-created-cids/v1"
            and cids.get("runId")==inputs["runId"] and cids.get("runtimeWrites") is True
            and cids.get("durableCreateAck")=={"phase":"EFFECT_ACKNOWLEDGED",
                "acknowledgedStep":"REPLACE_CREATED_CREDENTIAL_GENERATION"}
            and cids.get("selection")==inputs["selection"]
            and isinstance(cids.get("selectedContainerIds"),dict)
            and set(cids["selectedContainerIds"])==set(inputs["roleBinaries"])
            and all(selected[role]["Id"]==cid for role,cid in cids["selectedContainerIds"].items()),
            "D12_OB3_CREATED_CIDS_LINEAGE_CHANGED")


OB3_DEFERRED_ROLE="passport-beta-bureau"
OB3_ALLOWED_SCENARIOS=("D01_ORGANIZATION_OB3","D05_MEMBERSHIP_OB3","D05_MEMBERSHIP_EXPIRED_NEGATIVE",
    "D05_MEMBERSHIP_UNTRUSTED_NEGATIVE","D07_CANVAS_OB3")


def _closed_ob3_scope(recovery,inputs,operations):
    require(recovery.get("schema")=="marty.d12-ob3-partial-start-recovery/v1"
            and recovery.get("operation") in operations and recovery.get("scope")=="OB3_FUNCTIONAL_ONLY"
            and recovery.get("draftOnly") is False and recovery.get("dispatchAuthorized") is True
            and recovery.get("runId")==inputs["runId"] and recovery.get("deferredRoles")==[OB3_DEFERRED_ROLE]
            and recovery.get("allowedScenarios")==list(OB3_ALLOWED_SCENARIOS),"D12_CLOSED_OB3_AUTHORITY_REQUIRED")


def partial_start_ob3_checkpoint(inputs,state,intent,recovery,*,operation_backend):
    """Bind only the known Bureau failed-start checkpoint, not a successful start."""
    from scoped_native_database import RECOVERY_SOURCE_FIELDS,RECOVERY_TRUST_FIELDS
    from scoped_native_runtime import validate_journal_readback
    def load(reference):return json.loads(read_ref(reference).read_bytes())
    _closed_ob3_scope(recovery,inputs,("RESUME_OB3_AFTER_RECONCILED_PARTIAL_STARTS","QUIESCE_OB3_PARTIAL_STARTS"))
    original=load(recovery["originalInputs"]);previous=load(recovery["previousRecoveryAuthority"])
    require(previous.get("operation")=="REPLACE_ACKNOWLEDGED_CREDENTIAL_GENERATION_AND_RESUME"
            and state.get("recoveryAuthority")==recovery["previousRecoveryAuthority"]
            and state.get("replacementAuthority")==recovery["previousRecoveryAuthority"],"D12_OB3_PARTIAL_PRIOR_AUTHORITY_CHANGED")
    deepest,proof,verified=created_recovery_checkpoint(original,load(previous["originalOperationState"]),intent,
        previous,operation_backend=operation_backend)
    require(state==load(recovery["originalOperationState"]) and state.get("schema")=="marty.d12-current-native-operation/v1"
            and state.get("phase")=="START_INSPECTION_PENDING" and state.get("scope")=="FUNCTIONAL_ONLY"
            and state.get("pendingStep")=="INSPECT_START_"+OB3_DEFERRED_ROLE
            and state.get("acknowledgedStep")=="START_"+OB3_DEFERRED_ROLE and state.get("pendingArgv") is None
            and state.get("pendingRequest") is None
            and state.get("runId")==inputs["runId"] and state.get("sourceRevision")==inputs["uiRevision"]
            and state.get("coreRevision")==inputs["coreRevision"] and state.get("databaseProof")==previous["databaseProof"]
            and state.get("verifiedDatabase")==previous["verifiedDatabase"],"D12_EXACT_OB3_PARTIAL_CHECKPOINT_REQUIRED")
    created=load(state["created"]);rows=maintenance.exact_roles(created,inputs["rolloutProfile"])
    require(recovery.get("runtimeBefore")==inputs["runtimeBefore"] and recovery.get("selection")==inputs["selection"]
            and recovery.get("created")==state["created"],"D12_OB3_CONTAINMENT_INPUT_REFS_CHANGED")
    target_request=load(recovery["createdTargetRequest"]);target=load(recovery["createdTargetVerification"])
    target_terminal=load(recovery["createdTargetTerminal"])
    require(target_request.get("runId")==inputs["runId"] and target_request.get("selection")==inputs["selection"]
            and target_request.get("runtimeBefore")==inputs["runtimeBefore"] and target_request.get("plannedModels")==inputs["plannedModels"]
            and target_request.get("composeArguments")==inputs["composeArguments"]
            and target_request.get("engineId")==recovery.get("engineId"),"D12_OB3_INSTALLED_TARGET_BINDING_CHANGED")
    require(target_terminal.get("exitCode")==0 and type(target_terminal.get("exitCode")) is int
            and target_terminal.get("observation",{}).get("timedOut") is False
            and target_terminal.get("observation",{}).get("failures")==[],"D12_OB3_TARGET_READ_NOT_ACKNOWLEDGED")
    target_ack=load(target_request["acknowledgedState"]);cid_proof=load(target_request["createdCids"])
    require(target.get("state")=="ACTUAL_CREATED_TARGET_MODEL_BOUND_BY_CURRENT_OWNER"
            and target.get("runId")==inputs["runId"] and target.get("acknowledgedStep")=="REPLACE_CREATED_CREDENTIAL_GENERATION"
            and target.get("currentJobNormalClosureNotYetQualified") is True
            and target_ack.get("phase")=="EFFECT_ACKNOWLEDGED" and target_ack.get("acknowledgedStep")==target["acknowledgedStep"]
            and target_ack.get("replacementAuthority")==recovery["previousRecoveryAuthority"]
            and cid_proof.get("selection")==inputs["selection"],"D12_OB3_TARGET_ACK_LINEAGE_CHANGED")
    expected={role:row["containerId"] for role,row in rows.items()}
    require({row["role"]:row["containerId"] for row in target.get("roles",[])}==expected
            and cid_proof.get("selectedContainerIds")=={role:expected[role] for role in inputs["roleBinaries"]},
            "D12_OB3_TARGET_CURRENT22_CHANGED")
    parent=read_ref(state["created"]).parent
    require(all(read_ref(recovery[key]).parent==parent for key in
            ("createdTargetRequest","createdTargetVerification","createdTargetTerminal")),"D12_OB3_TARGET_CAPTURE_NAMESPACE_CHANGED")
    lease=load(inputs["runScopedTrustLeaseProof"]);sdk_metadata=load(lease["validationRequest"])
    require(recovery.get("ancillaryResourceBinding")==sdk_metadata["recoveryPrerequisites"]["resourceObservation"],
            "D12_OB3_ANCILLARY_BASELINE_CHANGED")
    require(recovery["deferredFailureJob"]==recovery["reconciliationJob"]
            and read_ref(recovery["currentOwned22"]).parent==read_ref(recovery["currentAncillary6"]).parent==read_ref(recovery["deferredFailure"]).parent,
            "D12_OB3_PARTIAL_CAPTURE_NAMESPACE_CHANGED")
    require(state.get("pendingContainerId")==rows[OB3_DEFERRED_ROLE]["containerId"],"D12_OB3_PENDING_CID_CHANGED")
    plan=load(inputs["maintenancePlan"]);before=load(inputs["runtimeBefore"])
    models={project:load(ref) for project,ref in plan["composeModels"].items()}
    order=maintenance.preview(plan,before,models)["restoreOrder"];prefix=order[:order.index(OB3_DEFERRED_ROLE)]
    require(state.get("steps")==["START_"+role for role in prefix] and set(state.get("startAcks",{}))==set(prefix),
            "D12_OB3_OBSERVED_START_PREFIX_CHANGED")
    for role,ack in state["startAcks"].items():
        require(set(ack)=={"containerId","startedAt","hostPid","imageId"} and ack["containerId"]==rows[role]["containerId"]
                and ack["imageId"]==rows[role]["imageId"] and type(ack["hostPid"]) is int and ack["hostPid"]>0,
                "D12_OB3_START_ACK_CHANGED:"+role)
    require(recovery.get("sourceMap")=={key:{"original":original[key],"recovery":inputs[key]} for key in RECOVERY_SOURCE_FIELDS}
            and all(previous["sourceMap"][key]["recovery"]==original[key] for key in RECOVERY_SOURCE_FIELDS),
            "D12_OB3_PARTIAL_SOURCE_MAP_CHANGED")
    require(all(original.get(key)==inputs.get(key) for key in RECOVERY_TRUST_FIELDS)
            and {k:v for k,v in original.items() if k not in RECOVERY_SOURCE_FIELDS|{"d12Authority"}}
                =={k:v for k,v in inputs.items() if k not in RECOVERY_SOURCE_FIELDS|{"d12Authority"}},
            "D12_OB3_PARTIAL_INPUTS_CHANGED")
    observed=load(recovery["journalRead"]);require(isinstance(observed,list) and len(observed)==1
        and observed[0].get("state")=="EXACT_ROOT_DURABLE_METADATA_READ_COMPLETE" and observed[0].get("mountReadOnly") is True,
        "D12_OB3_AUTHORITATIVE_JOURNAL_REQUIRED")
    for name,ref,value in (("build-state.json",recovery["originalOperationState"],state),
                           ("build-apply-intent.json",recovery["originalApplyIntent"],intent)):
        file=observed[0]["files"][name]
        exact=validate_journal_readback({"storedBytesBase64":file.get("storedBytesBase64"),"sha256":file.get("sha256"),"value":file.get("document")})
        require(file.get("present") is True and exact==read_ref(ref).read_bytes() and file.get("document")==value
                and file.get("sha256")==ref["sha256"] and file.get("bytes")==ref["bytes"],"D12_OB3_PARTIAL_READBACK_CHANGED")
    require(all(observed[0]["files"][name].get("present") is False for name in ("build-receipt.json","configuration-receipt.json"))
            and all(observed[0]["root"][k]==operation_backend["rootProof"][k] for k in ("device","inode","uid","mode")),
            "D12_OB3_PARTIAL_ROOT_OR_RECEIPT_CHANGED")
    require(recovery["originalApplyIntent"]==previous["originalApplyIntent"],"D12_OB3_ORIGINAL_INTENT_CHANGED")
    for key in ("reconciliationJob","deferredFailureJob","failedCutoverJob"):
        expected="FAILED" if key=="failedCutoverJob" else "COMPLETE"
        job=load(recovery[key]);require(job.get("state")==expected and type(job.get("exitCode")) is int and job.get("exitCode")== (1 if expected=="FAILED" else 0)
            and job.get("jobClosed") is True and job.get("terminalActiveProcesses")==0
            and all(job.get(k) is False for k in ("timedOut","forcedTermination","cancelled","hostMarginBreached")),
            "D12_OB3_PARTIAL_CLOSED_READ_REQUIRED")
    failure=load(recovery["deferredFailure"])
    require(failure.get("containerId")==rows[OB3_DEFERRED_ROLE]["containerId"] and failure.get("qualification") is False
            and all(failure.get(k) is True for k in
            ("sqlstate42501Observed","permissionDeniedForSchemaObserved","issuanceServiceSchemaObserved")),
            "D12_OB3_EXACT_DEFERRED_FAILURE_REQUIRED")
    baseline_ref=recovery.get("currentProcessBaseline")
    if baseline_ref is not None:
        baseline=load(baseline_ref)
        require(set(baseline)=={"schema","originalOperationState","journalRead","job","rootReview","owned22","ancillary6","restartedRoles"}
                and baseline.get("schema")=="marty.d12-ob3-current-process-baseline/v1"
                and baseline["originalOperationState"]==recovery["originalOperationState"]
                and baseline["restartedRoles"]==["canvas-sync-worker","compliance-profile","deployment-profile","device-registration"],
                "D12_OB3_CURRENT_PROCESS_BASELINE_REQUIRED")
        current=load(baseline["owned22"]);ancillary=load(baseline["ancillary6"]);old=load(recovery["currentOwned22"]);old_ancillary=load(recovery["currentAncillary6"])
        require(set(current)==set(old)==set(rows) and set(ancillary)==set(old_ancillary)
                and read_ref(baseline["owned22"]).parent==read_ref(baseline["ancillary6"]).parent==read_ref(baseline["journalRead"]).parent,
                "D12_OB3_CURRENT_PROCESS_CAPTURE_CHANGED")
        job=load(baseline["job"]);require(job.get("schema")=="marty.windows-job-result/v1" and job.get("state")=="COMPLETE"
                and type(job.get("exitCode")) is int and job["exitCode"]==0 and job.get("jobClosed") is True and job.get("terminalActiveProcesses")==0
                and all(job.get(k) is False for k in ("timedOut","forcedTermination","cancelled","hostMarginBreached")),"D12_OB3_CURRENT_PROCESS_JOB_REQUIRED")
        review=load(baseline["rootReview"])
        require(review.get("state")=="ROOT_QUIESCENCE_FAILURE_RECONCILED_READONLY" and review.get("journalStateSha256")==recovery["originalOperationState"]["sha256"]
                and review.get("journalUnchanged") is True and review.get("created22CidsUnchanged") is True
                and review.get("closedJobSha256")==baseline["job"]["sha256"] and review.get("workerResultSha256")==baseline["journalRead"]["sha256"]
                and review.get("quiescenceQualified") is False and review.get("fullStackQualified") is False,"D12_OB3_CURRENT_PROCESS_ROOT_REVIEW_REQUIRED")
        fresh_read=load(baseline["journalRead"]);require(isinstance(fresh_read,list) and len(fresh_read)==1
                and fresh_read[0].get("state")=="EXACT_ROOT_DURABLE_METADATA_READ_COMPLETE" and fresh_read[0].get("mountReadOnly") is True
                and all(fresh_read[0]["root"][k]==operation_backend["rootProof"][k] for k in ("device","inode","uid","mode")),"D12_OB3_CURRENT_PROCESS_JOURNAL_REQUIRED")
        for name,reference,value in (("build-state.json",recovery["originalOperationState"],state),("build-apply-intent.json",recovery["originalApplyIntent"],intent)):
            file=fresh_read[0]["files"][name]
            exact=validate_journal_readback({"storedBytesBase64":file.get("storedBytesBase64"),"sha256":file.get("sha256"),"value":file.get("document")})
            require(file.get("present") is True and exact==read_ref(reference).read_bytes() and file.get("bytes")==reference["bytes"] and file.get("document")==value,
                    "D12_OB3_CURRENT_PROCESS_JOURNAL_CHANGED")
        require(all(fresh_read[0]["files"][name].get("present") is False for name in ("build-receipt.json","configuration-receipt.json")),"D12_OB3_CURRENT_PROCESS_RECEIPTS_CHANGED")
        reviewed=review.get("restartDrift",[]);require([item.get("role") for item in reviewed]==baseline["restartedRoles"],"D12_OB3_EXACT_RESTARTED_ROLES_REQUIRED")
        by_role={item["role"]:item for item in reviewed}
        for role,now in current.items():
            prior=old[role]
            require({k:v for k,v in now.items() if k not in ("State","RestartCount")}=={k:v for k,v in prior.items() if k not in ("State","RestartCount")}
                    and now["Id"]==rows[role]["containerId"] and now["Image"]==rows[role]["imageId"],"D12_OB3_CURRENT_PROCESS_IDENTITY_CHANGED:"+role)
            if role in by_role:
                item=by_role[role];ack=state["startAcks"][role]
                require(now["State"]["Status"]=="running" and now["State"]["Running"] is True and type(now["State"]["Pid"]) is int and now["State"]["Pid"]>0
                        and now["State"]["Paused"] is False and now["State"]["OOMKilled"] is False
                        and now["State"]["StartedAt"]!=ack["startedAt"] and now["State"]["Pid"]!=ack["hostPid"]
                        and item=={"role":role,"ackStartedAt":ack["startedAt"],"ackHostPid":ack["hostPid"],"observedStartedAt":now["State"]["StartedAt"],"observedHostPid":now["State"]["Pid"],"restartCount":now["RestartCount"],"status":"running"},
                        "D12_OB3_REVIEWED_PROCESS_GENERATION_CHANGED:"+role)
            elif role in state["startAcks"]:
                ack=state["startAcks"][role];require(now["State"]["StartedAt"]==ack["startedAt"] and now["State"]["Pid"]==ack["hostPid"]
                    and now["State"]["Status"]=="running" and now["State"]["Running"] is True,"D12_OB3_UNREVIEWED_PROCESS_GENERATION_CHANGED:"+role)
            elif role!="passport-beta-bureau":
                require(now["State"]==prior["State"] and now["RestartCount"]==prior["RestartCount"],"D12_OB3_UNSTARTED_PROCESS_CHANGED:"+role)
        require(ancillary==old_ancillary,"D12_OB3_ANCILLARY_GENERATION_CHANGED")
    return deepest,proof,verified


def ob3_startup_prerequisites(reference):
    """One source-owned datafile; an operational graph, never an installed-model claim."""
    source=Path(__file__).resolve().with_name("ob3-startup-prerequisites.json")
    require(read_ref(reference,65536).resolve()==source,"D12_OB3_STARTUP_SOURCE_PATH_REQUIRED")
    proof=json.loads(source.read_bytes())
    require(proof.get("schema")=="marty.ob3-startup-prerequisites/v1" and proof.get("composeSourcePath")=="docker-compose.beta.yml"
            and isinstance(proof.get("composeSha256"),str) and len(proof["composeSha256"])==64
            and all(c in "0123456789abcdef" for c in proof["composeSha256"]) and proof.get("installedModelChanged") is False,
            "D12_OB3_STARTUP_SOURCE_PROOF_REQUIRED")
    requirements=proof.get("requirements")
    require(isinstance(requirements,list) and len(requirements)==4 and all(set(row)=={"dependentRole","prerequisiteRole","readiness"}
            and row["readiness"]=="DOCKER_HEALTHY" and row["prerequisiteRole"] in {"organization","signing-keys"} for row in requirements)
            and {row["dependentRole"] for row in requirements}=={"compliance-profile","deployment-profile","device-registration","canvas-sync-worker"},
            "D12_OB3_CLOSED_STARTUP_REQUIREMENTS_REQUIRED")
    return proof


def ob3_quiescent_checkpoint(inputs,state,intent,recovery,*,operation_backend):
    """Validate an actual OB3 quiescence; authorize only a new credential generation."""
    from scoped_native_database import RECOVERY_SOURCE_FIELDS,RECOVERY_TRUST_FIELDS,_recovery_trust_models
    from scoped_native_runtime import validate_journal_readback
    def load(reference):return json.loads(read_ref(reference).read_bytes())
    require(recovery.get("schema")=="marty.d12-ob3-quiescent-recovery/v1"
            and recovery.get("operation")=="REPLACE_OB3_QUIESCENT_CREDENTIALS_AND_RESUME"
            and recovery.get("replaceCredentialGeneration") is True
            and recovery.get("dispatchAuthorized") is True and recovery.get("draftOnly") is False
            and recovery.get("runId")==inputs["runId"] and recovery.get("scope")=="OB3_FUNCTIONAL_ONLY"
            and recovery.get("deferredRoles")==[OB3_DEFERRED_ROLE]
            and recovery.get("allowedScenarios")==list(OB3_ALLOWED_SCENARIOS),"D12_CLOSED_OB3_QUIESCENT_AUTHORITY_REQUIRED")
    ob3_startup_prerequisites(recovery["startupPrerequisites"])
    original=load(recovery["originalInputs"]);previous=load(recovery["previousRecoveryAuthority"])
    require(previous.get("operation")=="QUIESCE_OB3_PARTIAL_STARTS","D12_OB3_QUIESCENCE_PRIOR_AUTHORITY_REQUIRED")
    partial=load(previous["originalOperationState"])
    deepest,proof,verified=partial_start_ob3_checkpoint(original,partial,intent,previous,operation_backend=operation_backend)
    require(state==load(recovery["originalOperationState"]) and state.get("phase")=="OB3_PARTIAL_QUIESCENT"
            and state.get("schema")=="marty.d12-current-native-operation/v1" and state.get("runId")==inputs["runId"]
            and state.get("pendingStep") is None and state.get("pendingArgv") is None and state.get("pendingContainerId") is None
            and state.get("pendingRequest") is None and state.get("readinessScope")=="OB3_FUNCTIONAL_ONLY"
            and state.get("fullStackQualified") is False and state.get("scope")=="FUNCTIONAL_ONLY" and state.get("releaseQualified") is False and state.get("recordingQualified") is False
            and state.get("sourceRevision")==inputs["uiRevision"] and state.get("coreRevision")==inputs["coreRevision"] and state.get("deferredRoles")==[OB3_DEFERRED_ROLE]
            and state.get("allowedScenarios")==list(OB3_ALLOWED_SCENARIOS)
            and state.get("recoveryAuthority")==recovery["previousRecoveryAuthority"]
            and state.get("priorPartialStartState")==previous["originalOperationState"]
            and state.get("originalOperationState")==previous["originalOperationState"]
            and state.get("priorStartAcks")==partial["startAcks"] and state.get("startAcks")=={},
            "D12_OB3_ACTUAL_QUIESCENT_CHECKPOINT_REQUIRED")
    require(all(state.get(key)==partial.get(key) for key in
            ("created","databaseProof","verifiedDatabase","tenantPreflight","sourceRevision","coreRevision"))
            and recovery["databaseProof"]==state["databaseProof"] and recovery["verifiedDatabase"]==state["verifiedDatabase"]
            and recovery["deferredFailure"]==state["deferredFailure"]==previous["deferredFailure"],
            "D12_OB3_PRESERVED_DATABASE_AND_FAILURE_REQUIRED")
    observation=load(state["ob3Quiescence"])
    require(observation.get("schema")=="marty.ob3-containment-observation/v1"
            and observation.get("phase")=="OB3_PARTIAL_QUIESCENT" and observation.get("runId")==inputs["runId"]
            and observation.get("fullStackQualified") is False and observation.get("functionalRuntimeQualified") is False
            and observation.get("runningProcessQualified") is False and observation.get("currentJobNormalClosureNotYetQualified") is True
            and observation.get("readinessScope")=="OB3_FUNCTIONAL_ONLY" and len(observation.get("roles",[]))==22
            and len(observation.get("resources",[]))==28 and observation.get("deferredFailure")==state["deferredFailure"],
            "D12_OB3_ACTUAL_QUIESCENCE_OBSERVATION_REQUIRED")
    rows={row["role"]:row for row in observation["roles"]};current=load(recovery["selected22"])
    resources={row["role"]:row for row in observation["resources"]};ancillary=load(previous["currentAncillary6"])
    require(set(ancillary)=={"docs","nginx-proxy","openbao","postgres","redis","keycloak"}
            and set(resources)==set(rows)|set(ancillary) and len({row["containerId"] for row in resources.values()})==28
            and all(resources[role]["containerId"]==row["containerId"] for role,row in rows.items())
            and all(resources[role]["containerId"]==row["Id"] for role,row in ancillary.items()),"D12_OB3_EXACT_CURRENT28_REQUIRED")
    original_created={row["role"]:row for row in load(partial["created"])["roles"]}
    require(set(rows)==D12_CURRENT_RUNTIME_ROLES and set(current)==set(rows)
            and len({row["containerId"] for row in rows.values()})==22,"D12_OB3_QUIESCENT22_REQUIRED")
    outcomes=state["ob3StopOutcomes"];contract=load(previous["deferredStopContract"])
    require(set(outcomes)==set(partial["startAcks"])|{OB3_DEFERRED_ROLE}
            and contract.get("role")==OB3_DEFERRED_ROLE and contract.get("containerId")==partial["pendingContainerId"]
            and contract.get("schema")=="marty.reviewed-deferred-startup-stop/v1" and contract.get("signal")=="SIGTERM"
            and contract.get("gracefulShutdownVerified") is False and contract.get("allowedExitCodes")==[0,1,143] and contract.get("noAutomaticSigkill") is True
            and all(value.get("deferred") is (role==OB3_DEFERRED_ROLE) and value.get("observedExitCode")==0 for role,value in outcomes.items() if role!=OB3_DEFERRED_ROLE)
            and outcomes[OB3_DEFERRED_ROLE].get("deferred") is True,
            "D12_OB3_REVIEWED_STOP_OUTCOMES_REQUIRED")
    for role,row in rows.items():
        expected_exit=outcomes[role]["observedExitCode"] if role==OB3_DEFERRED_ROLE else 0
        snap=current[role]
        require(row.get("status")==("exited" if role in partial["startAcks"] or role==OB3_DEFERRED_ROLE else original_created[role]["state"]) and row.get("running") is False and row.get("hostPid")==0
                and row.get("containerExitCode")==expected_exit
                and (expected_exit in contract["allowedExitCodes"] if role==OB3_DEFERRED_ROLE else True)
                and snap.get("Id")==row["containerId"] and snap.get("Image")==row["imageId"]
                and snap["State"]["Status"]==row["status"] and snap["State"]["StartedAt"]==row["startedAt"]
                and snap["State"]["Running"] is False and snap["State"]["Pid"]==0
                and snap["State"]["OOMKilled"] is False and snap["State"]["Paused"] is False
                and snap["State"]["ExitCode"]==expected_exit,"D12_OB3_CURRENT_QUIESCENT_ROLE_CHANGED:"+role)
    require(recovery.get("sourceMap")=={key:{"original":original[key],"recovery":inputs[key]} for key in RECOVERY_SOURCE_FIELDS}
            and recovery.get("trustDataMap")=={key:{"original":original.get(key),"recovery":inputs.get(key)} for key in RECOVERY_TRUST_FIELDS},
            "D12_OB3_EXACT_SOURCE_AND_TRUST_MAP_REQUIRED")
    ignored=RECOVERY_SOURCE_FIELDS|RECOVERY_TRUST_FIELDS|{"d12Authority","quiescence"}
    require({key:value for key,value in original.items() if key not in ignored}=={key:value for key,value in inputs.items() if key not in ignored},
            "D12_OB3_RECOVERY_INPUT_DRIFT")
    _recovery_trust_models(original,inputs)
    require(load(original["runScopedTrustLeaseProof"])["generationDirectory"]!=load(inputs["runScopedTrustLeaseProof"])["generationDirectory"],
            "D12_OB3_FRESH_CREDENTIAL_GENERATION_REQUIRED")
    require(load(proof["operationState"])["quiescenceSha256"]==recovery["quiescence"]["sha256"] and read_ref(recovery["quiescence"]).is_file() and recovery["originalApplyIntent"]==previous["originalApplyIntent"]
            and load(recovery["originalApplyIntent"])==intent,"D12_OB3_ORIGINAL_DATABASE_LINEAGE_REQUIRED")
    for key in ("quiescenceJob","reconciliationJob","selected22Job"):
        job=load(recovery[key]);require(job.get("state")=="COMPLETE" and type(job.get("exitCode")) is int and job["exitCode"]==0
            and job.get("jobClosed") is True and job.get("terminalActiveProcesses")==0
            and all(job.get(name) is False for name in ("forcedTermination","timedOut","cancelled","hostMarginBreached")),
            "D12_OB3_NORMAL_CLOSED_QUIESCENCE_JOB_REQUIRED")
    read=load(recovery["journalRead"]);require(isinstance(read,list) and len(read)==1
            and read[0].get("state")=="EXACT_ROOT_DURABLE_METADATA_READ_COMPLETE" and read[0].get("mountReadOnly") is True,
            "D12_OB3_AUTHORITATIVE_QUIESCENT_JOURNAL_REQUIRED")
    require(all(read[0]["root"][key]==operation_backend["rootProof"][key] for key in ("device","inode","uid","mode")),
            "D12_OB3_JOURNAL_ROOT_CHANGED")
    for name,reference,value in (("build-state.json",recovery["originalOperationState"],state),("build-apply-intent.json",recovery["originalApplyIntent"],intent)):
        record=read[0]["files"][name]
        raw=validate_journal_readback({"storedBytesBase64":record.get("storedBytesBase64"),"sha256":record.get("sha256"),"value":record.get("document")})
        require(record.get("present") is True and raw==read_ref(reference).read_bytes() and record.get("sha256")==reference["sha256"]
                and record.get("bytes")==reference["bytes"] and record.get("document")==value,"D12_OB3_RAW_QUIESCENT_JOURNAL_CHANGED")
    require(all(read[0]["files"][name].get("present") is False for name in ("build-receipt.json","configuration-receipt.json")),
            "D12_OB3_QUIESCENCE_ALREADY_CONSUMED")
    resource=load(recovery["maintenanceResourceRecovery"])
    require(resource.get("ob3Quiescent")=={"authority":recovery["previousRecoveryAuthority"],"quiescence":state["ob3Quiescence"],
            "quiescenceJob":recovery["quiescenceJob"],"current22":recovery["selected22"],"current22Job":recovery["selected22Job"]}
            and "postCreate" not in resource,"D12_OB3_EXACT_QUIESCENT_RESOURCE_DTO_REQUIRED")
    return deepest,proof,verified


class D12CurrentExecution:
    def __init__(self, context, inputs, journal, *, read_only_preflight=False):
        self.g, self.i, self.store = context, inputs, journal
        require(type(read_only_preflight) is bool, "D12_PREFLIGHT_MODE_REQUIRED")
        self.read_only_preflight = read_only_preflight
        require(not read_only_preflight or getattr(journal, "read_only", False) is True,
                "D12_READ_ONLY_OPERATION_JOURNAL_REQUIRED")
        from scoped_native_profiles import current_rollout_build
        self.profile = inputs.get("rolloutProfile", CURRENT_PROFILE)
        self.build_profile = current_rollout_build(self.profile)
        self.roles = dict(self.build_profile.roles)
        self.native_preimage = None
        self.state = {"schema": "marty.d12-current-native-operation/v1", "phase": "NOT_STARTED",
                      "runId": inputs["runId"], "scope": "FUNCTIONAL_ONLY",
                      "sourceRevision": self.build_profile.ui_revision,
                      "coreRevision": self.build_profile.core_revision,
                      "releaseQualified": False, "recordingQualified": False, "steps": []}

    def record(self, phase, **fields):
        require(not self.read_only_preflight, "D12_READ_ONLY_PREFLIGHT_NO_INTENT")
        self.state.update(phase=phase, **fields)
        require(durable_barrier(self.store.state(self.state)), "D12_DURABLE_STATE_REQUIRED")

    def command(self, database, step, args):
        # The shared database transport inserts its pinned Desktop context.
        # Stop contracts already spell that context explicitly.
        if args[:3] == ["docker", "--context", "desktop-linux"]:
            args = ["docker", *args[3:]]
        require(args and args[0] == "docker", "D12_EXACT_DOCKER_TRANSPORT_REQUIRED")
        self.record("PENDING_EFFECT", pendingStep=step,
                    pendingArgv=["docker", "--context", "desktop-linux", *args[1:]])
        result = database.command(args)
        self.record("EFFECT_ACKNOWLEDGED", pendingStep=None, pendingArgv=None, acknowledgedStep=step)
        if "effect_acknowledged" in self.g:
            self.g["effect_acknowledged"](step, self.state)
        return result

    def inspect_all22(self):
        # The functional Docker observer requires running PID 1. During a
        # maintenance stop/create window use a fresh exact-22 batch when the
        # reviewed host provides one. The historical individual reader stays
        # available for existing callers and tests.
        if "inspect_all22" in self.g:
            snapshot = self.g["inspect_all22"]()
        else:
            snapshot = {"roles": [self.g["inspect_role"](role) for role in sorted(D12_CURRENT_RUNTIME_ROLES)]}
        maintenance.exact_roles(snapshot, self.profile)
        return snapshot

    def preflight(self):
        return self._preflight()

    def recovery_preflight(self, recovery_ref):
        return self._preflight(recovery_ref)

    def _preflight(self, recovery_ref=None):
        i, g = self.i, self.g
        require(g["dispatch_enabled"] is True and g["operation_lock_held"]() is True
                and g["recording_lock_held"]() is True,
                "D12_EXCLUSIVE_AUTHORITY_REQUIRED")
        selected_sources(i, self.profile)
        require(i["roleBinaries"] == self.roles and i["scope"] == "FUNCTIONAL_ONLY"
                and i["releaseQualified"] is False and i["recordingQualified"] is False,
                "D12_CURRENT_FUNCTIONAL_SCOPE_REQUIRED")
        require("quiescence" not in i, "D12_PREEXISTING_QUIESCENCE_FORBIDDEN")
        authority = json.loads(read_ref(i["d12Authority"], 65536).read_bytes())
        require((g["authorization_verified"](i["d12Authority"]) if recovery_ref is None
                 else g["recovery_authorization_verified"](i["d12Authority"], recovery_ref)) is True
                and authority.get("dispatchAuthorized") is True
                and authority.get("runId") == i["runId"]
                and read_ref(i["executionSource"]).resolve() == Path(__file__).resolve()
                and authority.get("approvedExecutionSourceSha256") == i["executionSource"]["sha256"]
                and sha(Path(__file__)) == i["executionSource"]["sha256"]
                and authority.get("approvedMetadataModuleSha256") == i["metadataModule"]["sha256"]
                and read_ref(i["metadataModule"]).name == "native-maintenance-metadata.js"
                and authority.get("approvedFunctionalRuntimeSha256") == i["functionalRuntimeModule"]["sha256"]
                and read_ref(i["functionalRuntimeModule"]).name == "functional-debug-runtime.js"
                and read_ref(i["functionalRuntimeModule"]).parent
                    == read_ref(i["metadataModule"]).parent
                and authority.get("approvedRuntimeReaderSha256") == i["d12RuntimeModule"]["sha256"]
                and read_ref(i["d12RuntimeModule"]).name == "d12-current-native-runtime.js"
                and authority.get("approvedProfileSourceSha256")
                    == sha(Path(__file__).with_name("scoped_native_profiles.py")),
                "D12_REVIEWED_AUTHORIZATION_REQUIRED")
        selection = (select_current_binaries(i["preparedSource"], i["canonicalBuildReceipt"], g["build_journal"])
                     if self.profile == CURRENT_PROFILE else select_current_binaries(i["preparedSource"], i["canonicalBuildReceipt"], g["build_journal"], self.profile))
        exact_exported_sql(json.loads(read_ref(i["preparedSource"]).read_bytes()), i, self.profile)
        require(selection == json.loads(read_ref(i["selection"]).read_bytes())
                and authority.get("approvedSelectionSha256") == i["selection"]["sha256"],
                "D12_EXACT_SELECTED_BUILD_REQUIRED")
        if self.profile == "d05-membership-current-functional":
            abi_plan=json.loads(read_ref(i["compatibility"]["plan"]).read_bytes())
            require(abi_plan["beforeBinding"]["sha256"]==i["runtimeBefore"]["sha256"],"CURRENT10_IMAGE_PREIMAGE_BINDING_CHANGED")
            self.native_preimage={"binding":i["runtimeBefore"],"inspections":abi_plan["nativeInspections"]}
        if recovery_ref is None:
            before = g["observe22"]()
            require(maintenance.same_full_role_snapshot(
                        before, json.loads(read_ref(i["runtimeBefore"]).read_bytes()), self.profile),
                    "D12_FRESH_ACTUAL22_PREIMAGE_REQUIRED")
        else:
            require(g["verify_recovery_quiescent"](recovery_ref) is True,
                    "D12_FRESH_RECOVERY_QUIESCENCE_REQUIRED")
            # The original running preimage is historical input to the same
            # plan/overlay validators; the fresh state is explicitly stopped.
            before = json.loads(read_ref(i["runtimeBefore"]).read_bytes())
        require(authority.get("approvedRuntimeBeforeSha256") == i["runtimeBefore"]["sha256"],
                "D12_FRESH_ACTUAL22_PREIMAGE_REQUIRED")
        require(g["database_snapshot"]() == json.loads(read_ref(i["databaseBefore"]).read_bytes())
                and authority.get("approvedDatabaseBeforeSha256") == i["databaseBefore"]["sha256"],
                "D12_FRESH_DATABASE_PREIMAGE_REQUIRED")
        plan = json.loads(read_ref(i["maintenancePlan"]).read_bytes())
        models = {name: json.loads(read_ref(bound).read_bytes())
                  for name, bound in plan["composeModels"].items()}
        preview = maintenance.preview(plan, before, models)
        require(preview["noApplyAuthority"] is True and preview["allStopRoles"]
                and set(preview["allStopRoles"]) == D12_CURRENT_RUNTIME_ROLES,
                "D12_ALL22_MAINTENANCE_REQUIRED")
        base = models["elevenid-beta"]
        if self.profile == "d05-membership-current-functional":
            from scoped_native_database import current_tenant
            tenant = current_tenant(i, authority)
            mixed_ref=i["composeProductBinding"]
            mixed=json.loads(read_ref(mixed_ref,65536).read_bytes())
            require(authority.get("approvedComposeProductBindingSha256")==mixed_ref["sha256"]
                    and set(mixed)=={"binaryUiRevision","binaryCoreRevision","composeRevision","composeSource","modelSources"}
                    and mixed["binaryUiRevision"]==self.build_profile.ui_revision
                    and mixed["binaryCoreRevision"]==self.build_profile.core_revision
                    and mixed["composeRevision"]=="82862f78876f2885a32353ba99a34ccba284faac"
                    and mixed["composeSource"]["sha256"]=="8a5d929fc657dc0f80582ad140d10fbcc05eb90cc6a39e68fe85a4d4962231ab"
                    and read_ref(mixed["composeSource"]).name=="docker-compose.beta.yml"
                    and mixed["modelSources"]==i["composeSources"],
                    "CURRENT_TEN_EXPLICIT_MIXED_COMPOSE_BINDING_REQUIRED")
            for role,key in (("flow","MARTY_ORG_ID"),("issuance-native","MARTY_ORG_ID"),("organization","MARTY_ORG_ID"),("auth","CREDENTIAL_LOGIN_ORGANIZATION_ID")):
                require(base["services"][role].get("environment",{}).get(key)==tenant,"CURRENT_TEN_COMPOSE_TENANT_CHANGED:"+role)
        require(g["compose_model"](i["composeArguments"], None) == base,
                "D12_FRESH_COMPOSE_MODEL_REQUIRED")
        replacement = overlay.binary_overlay(selection["binaries"], self.profile, before=base,native_preimage=self.native_preimage)
        overlay_ref = g["save"]("d12-current-overlay.private.json", replacement)
        after_model = g["compose_model"](i["composeArguments"], overlay_ref)
        overlay.validate_delta(base, after_model, selection["binaries"], self.profile,native_preimage=self.native_preimage)
        overlay.compose_recreate_arguments(i["composeArguments"], overlay_ref["path"],
                                           self.profile, list(self.roles), no_start=True)
        database = (D12CurrentDatabasePhase(g, i, self.store, read_only_preflight=True)
                    if self.read_only_preflight else D12CurrentDatabasePhase(g, i, self.store)
                    if recovery_ref is None else D12CurrentDatabasePhase(g, i, self.store, recovery_ref=recovery_ref))
        database._check_current_compatibility(selection, i["compatibility"]["plan"],
                                               i["compatibility"]["result"])
        if self.profile == "d05-membership-current-functional":
            from scoped_native_database import current_ten_tenant_observation
            tenant_observation = g["save"]("current-ten-tenant-preflight.json",current_ten_tenant_observation(database))
            self.state["tenantPreflight"] = tenant_observation
        return database, before, preview, overlay_ref

    def quiesce_ob3_partial_starts(self,recovery_ref):
        require(not self.read_only_preflight and self.profile=="d05-membership-current-functional",
                "D12_OB3_QUIESCE_CURRENT10_REQUIRED")
        selected_sources(self.i,self.profile)
        recovery=json.loads(read_ref(recovery_ref).read_bytes())
        require(recovery.get("operation")=="QUIESCE_OB3_PARTIAL_STARTS","D12_OB3_QUIESCE_AUTHORITY_REQUIRED")
        original_state=self.store.read("build-state.json")
        partial_start_ob3_checkpoint(self.i,original_state,self.store.read("build-apply-intent.json"),recovery,
            operation_backend=self.store.specification)
        g=self.g
        require(g["operation_lock_held"]() is True and g["recording_lock_held"]() is True
                and g["ob3_quiesce_authorization_verified"](self.i["d12Authority"],recovery_ref) is True,
                "D12_OB3_QUIESCE_FULL_OWNERSHIP_REQUIRED")
        # The callback returns source-policy checked exact stop steps for only
        # the actual observed running prefix and the failed Bureau restart loop.
        steps=g["ob3_quiesce_steps"](recovery_ref)
        expected=set(original_state["startAcks"])|{OB3_DEFERRED_ROLE}
        require(len(steps)==len(expected) and {row["role"] for row in steps}==expected,
                "D12_OB3_EXACT_QUIESCE_STOP_SET_REQUIRED")
        self.state=json.loads(read_ref(recovery["originalOperationState"]).read_bytes())
        self.record("OB3_QUIESCE_AUTHORIZED",recoveryAuthority=recovery_ref,originalOperationState=recovery["originalOperationState"],
            priorPartialStartState=recovery["originalOperationState"],readinessScope="OB3_FUNCTIONAL_ONLY",fullStackQualified=False)
        deferred_stop=json.loads(read_ref(recovery["deferredStopContract"]).read_bytes())
        require(deferred_stop.get("schema")=="marty.reviewed-deferred-startup-stop/v1"
                and deferred_stop.get("role")==OB3_DEFERRED_ROLE
                and deferred_stop.get("containerId")==original_state["pendingContainerId"]
                and deferred_stop.get("allowedExitCodes")==[0,1,143]
                and deferred_stop.get("signal")=="SIGTERM" and deferred_stop.get("noAutomaticSigkill") is True
                and deferred_stop.get("gracefulShutdownVerified") is False,
                "D12_OB3_EXACT_FAILED_ROLE_STOP_CONTRACT_REQUIRED")
        outcomes={}
        for step in steps:
            role=step["role"];self.record("OB3_STOP_PENDING",pendingStep="OB3_STOP_"+role,pendingArgv=step["argv"])
            observed=g["ob3_stop_owned_role"](recovery_ref,step)
            require(observed["containerId"]==step["containerId"] and observed["state"]=="exited"
                    and observed["running"] is False and observed["hostPid"]==0 and observed["oomKilled"] is False
                    and observed["containerExitCode"] in (deferred_stop["allowedExitCodes"] if role==OB3_DEFERRED_ROLE else [0]),
                    "D12_OB3_STOP_NOT_RECONCILED:"+role)
            outcomes[role]={"observedExitCode":observed["containerExitCode"],"deferred":role==OB3_DEFERRED_ROLE}
            self.record("OB3_STOP_TERMINAL",pendingStep=None,pendingArgv=None,ob3StopOutcomes=dict(outcomes))
        quiescence=g["observe_ob3_quiescence"](recovery_ref,outcomes)
        require(read_ref(quiescence).is_file(),"D12_OB3_ACTUAL_QUIESCENCE_REQUIRED")
        self.record("OB3_PARTIAL_QUIESCENT",pendingStep=None,pendingArgv=None,pendingContainerId=None,
            ob3Quiescence=quiescence,priorStartAcks=original_state["startAcks"],startAcks={},
            deferredRoles=[OB3_DEFERRED_ROLE],deferredFailure=recovery["deferredFailure"],fullStackQualified=False,
            readinessScope="OB3_FUNCTIONAL_ONLY",allowedScenarios=list(OB3_ALLOWED_SCENARIOS))
        return {"schema":"marty.d12-ob3-quiescence/v1","runId":self.i["runId"],"quiescence":quiescence,
            "readinessScope":"OB3_FUNCTIONAL_ONLY","fullStackQualified":False,"runningProcessQualified":False,
            "priorStartAcksAreHistorical":True,"deferredFailure":recovery["deferredFailure"]}

    def run(self):
        require(not self.read_only_preflight, "D12_READ_ONLY_PREFLIGHT_NO_APPLY")
        database, before, preview, overlay_ref = self.preflight()
        i, g = self.i, self.g
        intent = {"schema": "marty.d12-current-apply-intent/v1", "runId": i["runId"],
                  "selectionSha256": i["selection"]["sha256"], "executorSource": i["executorSource"],
                  "runtimeBefore": i["runtimeBefore"], "databaseBefore": i["databaseBefore"],
                  "authority": i["d12Authority"], "automaticRetry": False}
        require(durable_barrier(self.store.exclusive("build-apply-intent.json", intent)),
                "D12_DURABLE_ONE_SHOT_INTENT_REQUIRED")
        self.record("APPLY_INTENT_DURABLE")
        outcomes = {}
        for step in preview["stopSteps"]:
            role = step["role"]
            self.command(database, "STOP_" + role, step["argv"])
            row = g["inspect_role"](role)
            require(row["containerId"] == step["containerId"] and row["state"] == "exited"
                    and row["hostPid"] == 0 and row["containerExitCode"] == 0
                    and row["oomKilled"] is False, "D12_STOP_NOT_TERMINAL:" + role)
            outcomes[role] = {"terminal": True, "exitCode": 0, "stopAcknowledged": True}
            self.state["steps"].append("STOP_" + role)
            self.record("STOP_TERMINAL")
        stopped = self.inspect_all22()
        maintenance.validate_quiescent(before, stopped, outcomes, self.profile)
        quiescence = g["save"]("d12-all22-quiescent.private.json", stopped)
        # This actual receipt cannot exist before the 22 stop outcomes. Keep
        # the frozen caller input immutable and pass a derived phase input to
        # the existing database executor only after durable observation.
        require(read_ref(quiescence).is_file(), "D12_FRESH_QUIESCENCE_REQUIRED")
        require(durable_barrier(self.store.state({"phase": "ALL22_QUIESCENT", "runId": i["runId"],
                "quiescenceSha256": quiescence["sha256"]})), "D12_DURABLE_QUIESCENCE_REQUIRED")
        database.i = {**i, "quiescence": quiescence}
        database_proof = database.run()
        return self._finish_after_database(database, before, preview, overlay_ref, database_proof)

    def resume_after_fence_install(self, recovery_ref):
        require(not self.read_only_preflight, "D12_READ_ONLY_PREFLIGHT_NO_APPLY")
        database, before, preview, overlay_ref = self.recovery_preflight(recovery_ref)
        recovery = json.loads(read_ref(recovery_ref).read_bytes())
        database.i = {**self.i, "quiescence": recovery["quiescence"]}
        database_proof = database.resume_after_fence_install(recovery_ref)
        self.state["recoveryAuthority"] = recovery_ref
        return self._finish_after_database(database, before, preview, overlay_ref, database_proof)

    def resume_after_create_selected(self, recovery_ref):
        return self._resume_created(recovery_ref, replace_credentials=False)

    def replace_created_credentials_and_resume(self, recovery_ref):
        return self._resume_created(recovery_ref, replace_credentials=True)

    def resume_after_created_credential_replacement(self, recovery_ref):
        return self._resume_created(recovery_ref, replace_credentials=False, resume_replacement=True)

    def replace_acknowledged_created_credentials_and_resume(self, recovery_ref):
        return self._resume_created(recovery_ref, replace_credentials=True, resume_replacement=True)

    def replace_ob3_quiescent_credentials_and_resume(self,recovery_ref):
        return self._resume_created(recovery_ref,replace_credentials=True,ob3=True)

    def resume_ob3_acknowledged_credential_replacement(self,recovery_ref):
        return self._resume_created(recovery_ref,replace_credentials=False,resume_replacement=True,ob3=True)

    def replace_ob3_acknowledged_credential_replacement_and_resume(self,recovery_ref):
        return self._resume_created(recovery_ref,replace_credentials=True,resume_replacement=True,ob3=True)

    def _resume_created(self, recovery_ref, *, replace_credentials, resume_replacement=False,ob3=False):
        require(type(replace_credentials) is bool and type(resume_replacement) is bool and type(ob3) is bool
                and (not ob3 or replace_credentials or resume_replacement),"D12_CREATED_REPLACEMENT_MODE_REQUIRED")
        require(not self.read_only_preflight, "D12_READ_ONLY_PREFLIGHT_NO_APPLY")
        require(self.profile=="d05-membership-current-functional","D12_CREATED_RECOVERY_CURRENT10_ONLY")
        recovery=json.loads(read_ref(recovery_ref).read_bytes())
        require(recovery.get("operation")==("REPLACE_OB3_AFTER_ACKNOWLEDGED_CREDENTIAL_REPLACEMENT_AND_RESUME" if ob3 and resume_replacement and replace_credentials
                else "RESUME_OB3_AFTER_ACKNOWLEDGED_CREDENTIAL_REPLACEMENT" if ob3 and resume_replacement
                else "REPLACE_OB3_QUIESCENT_CREDENTIALS_AND_RESUME" if ob3 else "REPLACE_ACKNOWLEDGED_CREDENTIAL_GENERATION_AND_RESUME" if resume_replacement and replace_credentials
                else "RESUME_AFTER_ACKNOWLEDGED_CREDENTIAL_REPLACEMENT" if resume_replacement
                else "REPLACE_CREATED_CREDENTIAL_GENERATION_AND_RESUME" if replace_credentials
                else "RESUME_AFTER_ACKNOWLEDGED_CREATE_SELECTED"),"D12_CREATED_RECOVERY_OPERATION_CHANGED")
        checkpoint=ob3_quiescent_checkpoint if ob3 and not resume_replacement else created_recovery_checkpoint
        original, proof, verified=checkpoint(self.i, self.store.read("build-state.json"),
            self.store.read("build-apply-intent.json"), recovery, operation_backend=self.store.specification)
        database, before, preview, overlay_ref = self.recovery_preflight(recovery_ref)
        if ob3:preview={**preview,"restoreOrder":self.g["ob3_startup_plan"](recovery_ref)["order"]}
        # Recheck after all fresh reads and before the first new durable write.
        checkpoint(self.i, self.store.read("build-state.json"),
            self.store.read("build-apply-intent.json"), recovery, operation_backend=self.store.specification)
        database.i={**self.i,"quiescence":recovery["quiescence"]}
        dbstate=json.loads(read_ref(proof["operationState"]).read_bytes())
        from scoped_native_database import schema_steps
        command_steps={step for command in ("migrate","verify-owned-schema")
            for step,_role in schema_steps(self.profile=="d05-membership-current-functional",command)}
        database.commands=[json.loads(read_ref(op["receipt"]).read_bytes()) for op in dbstate["operations"]
            if op["stepId"] in command_steps]
        require({op["stepId"] for op in dbstate["operations"] if op["stepId"] in command_steps}==command_steps,
                "D12_COMPLETED_SCHEMA_COMMAND_SET_CHANGED")
        checked=database.node("verify",proof=proof,commands=database.commands,context={
            "runId":self.i["runId"],"selectionSha256":self.i["selection"]["sha256"],
            "executorSource":original["executorSource"],"rolloutProfile":self.profile,
            "sourceRevision":self.build_profile.ui_revision,"coreRevision":self.build_profile.core_revision,
            "baseline":database.baseline_refs,"approvedDatabaseBeforeSha256":self.i["databaseBefore"]["sha256"],
            "approvedEngineId":database.engine_id,"tenantId":database.tenant_id})
        require(checked==verified,"D12_COMPLETED_DATABASE_PROOF_REVERIFY_CHANGED")
        replacement_preimage=(self.g["prepare_created_credential_replacement"](recovery_ref)
            if replace_credentials else None)
        self.state=json.loads(read_ref(recovery["originalOperationState"]).read_bytes())
        self.record("POST_CREATE_RECOVERY_VERIFIED",recoveryAuthority=recovery_ref,
                    originalOperationState=recovery["originalOperationState"],**({"steps":[],"startAcks":{}} if ob3 else {}))
        if replace_credentials:
            # A new authorized effect, with its own durable pending/ack state;
            # neither the original SQL nor the original create is replayed.
            self.record("CREATED_CREDENTIAL_REPLACEMENT_AUTHORIZED",replacementAuthority=recovery_ref,
                priorCreatedSnapshot=recovery["selected22"],replacementPreimage=replacement_preimage,priorCredentialGeneration=json.loads(read_ref(recovery["originalInputs"]).read_bytes())["runScopedTrustLeaseProof"],
                nextCredentialGeneration=self.i["runScopedTrustLeaseProof"])
            arguments=overlay.compose_recreate_arguments(self.i["composeArguments"],overlay_ref["path"],
                self.profile,list(self.roles),no_start=True)
            self.command(database,"REPLACE_CREATED_CREDENTIAL_GENERATION",arguments)
        return self._finish_after_create(database,before,preview,proof,ob3_recovery=recovery_ref if ob3 else None)

    def _finish_after_database(self, database, before, preview, overlay_ref, database_proof):
        i, g = self.i, self.g
        # Preserve the original pre-create integrity check across the split.
        read_ref(database.i["quiescence"])
        verified_database = database.node("verify", proof=database_proof,
            commands=database.commands, context={"runId": i["runId"],
                "selectionSha256": i["selection"]["sha256"],
                "executorSource": i["executorSource"], "rolloutProfile": self.profile,
                "sourceRevision": self.build_profile.ui_revision,
                "coreRevision": self.build_profile.core_revision,
                "baseline": database.baseline_refs,
                "approvedDatabaseBeforeSha256": i["databaseBefore"]["sha256"],
                "approvedEngineId": database.engine_id,
                **({"tenantId":database.tenant_id} if self.profile == "d05-membership-current-functional" else {})})
        require(verified_database["sourceCommit"] == self.build_profile.ui_revision
                and verified_database["databaseIdentity"] == database.identity,
                "D12_ACTUAL_DATABASE_PROOF_REQUIRED")
        self.record("DATABASE_MAINTENANCE_TERMINAL", databaseProof=g["save"]("d12-database-proof.private.json", database_proof),
                    verifiedDatabase=g["save"]("d12-database-verified.private.json", verified_database))
        recreate = overlay.compose_recreate_arguments(i["composeArguments"], overlay_ref["path"],
                    self.profile, list(self.roles), no_start=True)
        self.command(database, "CREATE_SELECTED", recreate)
        return self._finish_after_create(database, before, preview, database_proof)

    def _finish_after_create(self, database, before, preview, database_proof,*,ob3_recovery=None):
        i, g = self.i, self.g
        ob3_runtime_authority=ob3_recovery
        if ob3_recovery is not None:
            recovery=json.loads(read_ref(ob3_recovery).read_bytes())
            if recovery.get("schema")=="marty.d12-ob3-acknowledged-replacement-recovery/v1":
                ob3_runtime_authority=recovery["previousRecoveryAuthority"]
        stopped_rows = maintenance.exact_roles(json.loads(read_ref(self.state["replacementPreimage"] if ob3_recovery is not None else database.i["quiescence"]).read_bytes()), self.profile)
        self.record("CREATE_INSPECTION_PENDING", pendingStep="INSPECT_CREATED")
        created = self.inspect_all22()
        old_rows = maintenance.exact_roles(before, self.profile)
        new_rows = maintenance.exact_roles(created, self.profile)
        for role in self.roles:
            old, new = old_rows[role], new_rows[role]
            require(new["containerId"] != old["containerId"] and new["state"] == "created"
                    and new["hostPid"] == 0 and new["imageId"] == old["imageId"]
                    and new["oomKilled"] is False, "D12_SELECTED_CREATE_NOT_PROVEN:" + role)
            target = "/usr/local/bin/" + self.roles[role]
            prior_mounts = {row["destination"]: row for row in old["binaryMounts"]}
            mounts = {row["destination"]: row for row in new["binaryMounts"]}
            image_owned=self.profile=="d05-membership-current-functional" and target not in prior_mounts
            if image_owned:
                overlay.image_owned_baseline(role,self.roles[role],self.native_preimage,old)
            require(len(prior_mounts) == len(old["binaryMounts"])
                    and len(mounts) == len(new["binaryMounts"])
                    and set(mounts) == (set(prior_mounts)|{target} if image_owned else set(prior_mounts)) and target in mounts
                    and all(mounts[key] == prior_mounts[key] for key in mounts if key != target)
                    and mounts[target]["type"] == "bind" and mounts[target]["writable"] is False
                    and daemon_source(mounts[target]["source"])
                    == daemon_source(database.selection["binaries"][role]["path"]),
                    "D12_CREATED_EXECUTABLE_BIND_CHANGED:" + role)
        for role in D12_CURRENT_RUNTIME_ROLES - set(self.roles):
            require(new_rows[role] == stopped_rows[role],
                    "D12_UNSELECTED_CREATE_CHANGED:" + role)
        created_ref = g["save"]("d12-created.private.json", {"runId": i["runId"], "roles": created["roles"]})
        self.record("SELECTED_CREATED", pendingStep=None, created=created_ref)
        start_acks = {}
        remaining_wait_budget=120.0 if ob3_recovery is not None else None
        requirements=(g["ob3_startup_plan"](ob3_recovery)["requirements"] if ob3_recovery is not None else [])
        for role in preview["restoreOrder"]:
            if ob3_recovery is not None and role==OB3_DEFERRED_ROLE:continue
            for requirement in requirements:
                if requirement["dependentRole"]!=role:continue
                prerequisite=requirement["prerequisiteRole"]
                require(prerequisite in start_acks,"D12_OB3_PREREQUISITE_NOT_STARTED:"+prerequisite)
                remaining=int(remaining_wait_budget);require(remaining>0,"D12_OB3_START_READINESS_DEADLINE")
                self.record("OB3_START_PREREQUISITE_PENDING",pendingStep="WAIT_READY_"+prerequisite,pendingContainerId=start_acks[prerequisite]["containerId"],startupDependentRole=role)
                wait_started=time.monotonic()
                readiness=g["wait_ob3_prerequisite_ready"](remaining,ob3_recovery,prerequisite,role,start_acks[prerequisite])
                remaining_wait_budget-=time.monotonic()-wait_started
                require(remaining_wait_budget>=0,"D12_OB3_START_READINESS_DEADLINE")
                actual=json.loads(read_ref(readiness).read_bytes())
                require(actual.get("readiness")=="DOCKER_HEALTHY" and actual.get("health")=="healthy" and actual.get("role")==prerequisite
                        and actual.get("dependentRole")==role and all(actual.get(key)==start_acks[prerequisite][key] for key in ("containerId","imageId","startedAt","hostPid")),
                        "D12_OB3_PREREQUISITE_NOT_READY:"+prerequisite)
                self.record("OB3_START_PREREQUISITE_OBSERVED",pendingStep=None,pendingContainerId=None,startupReadiness=readiness)
            cid = new_rows[role]["containerId"]
            self.command(database, "START_" + role, ["docker", "start", cid])
            self.record("START_INSPECTION_PENDING", pendingStep="INSPECT_START_" + role,
                        pendingContainerId=cid)
            observed = json.loads(database.command(["docker", "inspect", cid]))[0]
            state = observed["State"]
            labels = observed["Config"]["Labels"]
            require(observed["Id"] == cid and observed["Image"] == old_rows[role]["imageId"]
                    and labels.get("com.docker.compose.project") == old_rows[role]["project"]
                    and labels.get("com.docker.compose.service") == role
                    and state["Status"] == "running" and state["Running"] is True
                    and state["OOMKilled"] is False
                    and type(state["Pid"]) is int and state["Pid"] > 0
                    and started_later(state["StartedAt"], old_rows[role]["startedAt"]),
                    "D12_START_GENERATION_NOT_OWNED:" + role)
            start_acks[role] = {"containerId": cid, "startedAt": state["StartedAt"],
                                "hostPid": state["Pid"], "imageId": observed["Image"]}
            self.state["steps"].append("START_" + role)
            self.record("START_OBSERVED", pendingStep=None, pendingContainerId=None,
                        startAcks=dict(start_acks))
        require(set(start_acks) == (D12_CURRENT_RUNTIME_ROLES-{OB3_DEFERRED_ROLE} if ob3_recovery is not None else D12_CURRENT_RUNTIME_ROLES), "D12_EXACT_START_ACKS_REQUIRED" if ob3_recovery is not None else "D12_ALL22_START_ACKS_REQUIRED")
        acks_ref = g["save"]("d12-start-acks.private.json", {"runId": i["runId"], "acks": start_acks})
        self.record("OB3_21_STARTS_OBSERVED" if ob3_recovery is not None else "ALL22_STARTS_OBSERVED", startAcksRef=acks_ref)
        if ob3_recovery is not None:
            remaining=int(remaining_wait_budget)
            require(remaining>0,"D12_OB3_START_READINESS_DEADLINE")
            wait_started=time.monotonic()
            healthy=g["wait_ob3_required_healthy"](remaining,ob3_runtime_authority)
            remaining_wait_budget-=time.monotonic()-wait_started
            require(remaining_wait_budget>=0,"D12_OB3_START_READINESS_DEADLINE")
            require(healthy is True,"D12_OB3_21_HEALTH_DEADLINE_REQUIRED")
        else:
            require(g["wait_all22_healthy"](120) is True,"D12_ALL22_HEALTH_DEADLINE_REQUIRED")
        after = database.node("runtime", module=i["d12RuntimeModule"],
            inputs={"before": i["runtimeBefore"], "selection": i["selection"],
                    "created": created_ref, "startAcks": acks_ref,
                    "runId": i["runId"], "engineId": database.engine_id,**({"ob3Authority":ob3_runtime_authority} if ob3_runtime_authority is not None else {})})
        proof = overlay.validate_runtime_after(before, after, database.selection["binaries"],
                   D12_CURRENT_RUNTIME_ROLES - set(self.roles)-({OB3_DEFERRED_ROLE} if ob3_recovery is not None else set()), self.profile,native_preimage=self.native_preimage,ob3_authority=ob3_runtime_authority)
        require(g["database_snapshot"]()["databaseIdentity"] == database.identity,
                "D12_DATABASE_POSTFLIGHT_REQUIRED")
        startup_schema = None
        runtime_ref = None
        if self.profile == "d05-membership-current-functional":
            from scoped_native_database import current_ten_startup_schema_observation
            self.record("NATIVE_STARTUP_SCHEMA_INSPECTION_PENDING")
            runtime_ref = g["save"]("d12-runtime-after.private.json",proof)
            observed_schema=current_ten_startup_schema_observation(database)
            auth=next(row for row in proof["roles"] if row["role"]=="auth")
            fresh_auth=g["inspect_role"]("auth")
            require(all(fresh_auth[key]==auth[key] for key in ("containerId","startedAt","hostPid","imageId"))
                    and fresh_auth.get("running") is True and fresh_auth.get("health")=="healthy",
                    "CURRENT_TEN_AUTH_STARTUP_GENERATION_CHANGED")
            observed_schema.update(nativeRuntime=runtime_ref,startupOwner={"role":"auth","containerId":auth["containerId"],"startedAt":auth["startedAt"],"sourceRevision":auth["source"],"elfSha256":auth["sha256"]})
            startup_schema = g["save"]("current-ten-startup-schema-observation.json",observed_schema)
            self.record("NATIVE_STARTUP_SCHEMA_OBSERVED",startupSchema=startup_schema)
        result = {"schema": "marty.d12-current-native-functional/v1", "runId": i["runId"],
                  "sourceRevision": self.build_profile.ui_revision,
                  "coreRevision": self.build_profile.core_revision,
                  "selection": i["selection"], "database": database_proof,
                  "runtime": runtime_ref if runtime_ref is not None else g["save"]("d12-runtime-after.private.json", proof),
                  "nativeRuntimeReady": ob3_recovery is None, "functionalReady": False,
                  "passportScenarioVerified": False, "physicalBookletVerified": False,
                  "releaseQualified": False, "recordingQualified": False}
        if startup_schema is not None:
            result["startupSchema"] = startup_schema
            result["tenantId"] = database.tenant_id
        if ob3_recovery is not None:
            for key in ("readinessScope","fullStackQualified","ob3RuntimeReady","nativeRuntimeReady","deferredRoles","deferredFailure","allowedScenarios"):result[key]=after[key]
        self.record("OB3_NATIVE_TERMINAL" if ob3_recovery is not None else "FUNCTIONAL_NATIVE_TERMINAL", result=g["save"]("d12-native-result.private.json", result))
        return result
