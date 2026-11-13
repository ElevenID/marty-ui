"""Fourth OB3 checkpoint binds the captured third Flow failure before effects."""
from copy import deepcopy
import json
import pathlib
import sys

import pytest

sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/"scripts"))
import scoped_d12_native_execution as execution
import scoped_passport_maintenance as maintenance
from scoped_native_database import RECOVERY_SOURCE_FIELDS
from scoped_native_runtime import D12_CURRENT_RUNTIME_ROLES,journal_readback,ref


def case(tmp_path,monkeypatch):
    def save(name,value):
        path=tmp_path/name
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_text(json.dumps(value),encoding="utf-8")
        return ref(path)
    roles=sorted(D12_CURRENT_RUNTIME_ROLES)
    prefix=[role for role in roles if role not in ("flow","auth","gateway","verification","passport-beta-bureau")]
    order=[*prefix[:11],"passport-beta-bureau",*prefix[11:],"flow","auth","gateway","verification"]
    rows={role:{"containerId":f"{n+1:064x}","imageId":"sha256:"+"a"*64,
                "source":"synthetic-source","sha256":"b"*64}
          for n,role in enumerate(roles)}
    old_lease=save("old-lease.json",{"schema":"marty.current10-run-scoped-trust-lease/v1",
        "project":"synthetic","generationDirectory":"old","minimumRemainingSeconds":1200,
        "actualNativeGrantExpiryUnixSeconds":1})
    before=save("before.json",{"roles":[]})
    model=save("model.json",{})
    plan=save("plan.json",{"composeModels":{"elevenid-beta":model}})
    selected_sha="c"*64
    selection=save("selection.json",{"sourceRevision":"selected-ui",
        "binaries":{"flow":{"sha256":selected_sha}}})
    original={"runId":"SYNTHETIC","uiRevision":"old-ui","coreRevision":"old-core",
              "rolloutProfile":"d05-membership-current-functional","runtimeBefore":before,
              "maintenancePlan":plan,"selection":selection,
              "plannedModels":{"elevenid-beta":model},"composeArguments":["docker","compose"],
              "runScopedTrustLeaseProof":old_lease}
    for key in RECOVERY_SOURCE_FIELDS:original[key]=save("old-"+key+".json",{})
    original_ref=save("original-inputs.json",original)
    inputs=deepcopy(original)
    for key in RECOVERY_SOURCE_FIELDS:inputs[key]=save("new-"+key+".json",{})
    intent={"runId":"SYNTHETIC"};intent_ref=save("intent.json",intent)
    proof=save("db-proof.json",{});verified=save("verified-db.json",{})
    previous={"schema":"marty.d12-ob3-acknowledged-replacement-recovery/v1",
              "operation":"REPLACE_OB3_AFTER_SECOND_ACKNOWLEDGED_CREDENTIAL_REPLACEMENT_AND_RESUME",
              "originalOperationState":save("ancestor.json",{}),"originalApplyIntent":intent_ref,
              "databaseProof":proof,"verifiedDatabase":verified,"quiescence":save("historical-quiescence.json",{}),
              "startupPrerequisites":save("startup-prerequisites.json",{})}
    previous_ref=save("previous.json",previous)
    created=save("created.json",{"roles":[]})
    state={"schema":"marty.d12-current-native-operation/v1","phase":"START_INSPECTION_PENDING",
           "scope":"FUNCTIONAL_ONLY","pendingStep":"INSPECT_START_flow","acknowledgedStep":"START_flow",
           "pendingArgv":None,"pendingRequest":None,"runId":"SYNTHETIC","sourceRevision":"old-ui",
           "coreRevision":"old-core","databaseProof":proof,"verifiedDatabase":verified,
           "recoveryAuthority":previous_ref,"replacementAuthority":previous_ref,
           "created":created,"pendingContainerId":rows["flow"]["containerId"],
           "steps":["START_"+role for role in prefix],
           "startAcks":{role:{"containerId":rows[role]["containerId"],"imageId":rows[role]["imageId"],
                              "startedAt":"2026-01-01T00:00:00Z","hostPid":n+1}
                        for n,role in enumerate(prefix)}}
    state_ref=save("state.json",state)
    root={"device":1,"inode":2,"uid":0,"mode":448}
    files={}
    for name,reference,value in (("build-state.json",state_ref,state),
                                 ("build-apply-intent.json",intent_ref,intent)):
        files[name]={"present":True,"document":value,"bytes":reference["bytes"],
                     **journal_readback(pathlib.Path(reference["path"]).read_bytes())}
    files["build-receipt.json"]={"present":False}
    files["configuration-receipt.json"]={"present":False}
    journal=save("capture/journal.json",[{"state":"EXACT_ROOT_DURABLE_METADATA_READ_COMPLETE",
                                         "mountReadOnly":True,"root":root,"files":files}])
    current={role:{"Id":row["containerId"],"Image":row["imageId"],
                   "State":{"Status":"restarting" if role=="flow" else "running",
                            "Running":True,
                            "Pid":0 if role=="flow" else 101,"ExitCode":1 if role=="flow" else 0}}
             for role,row in rows.items()}
    current_ref=save("capture/current22.json",current)
    ancillary_ref=save("capture/ancillary6.json",{str(n):{} for n in range(6)})
    closed={"jobClosed":True,"terminalActiveProcesses":0,
            **{key:False for key in ("timedOut","forcedTermination","cancelled","hostMarginBreached")}}
    failed=save("failed/current10-effect-job.json",{**closed,"state":"FAILED","exitCode":1})
    read_job=save("read-job.json",{**closed,"state":"COMPLETE","exitCode":0})
    actor=save("failed/actor.py",{})
    python=save("failed/python.exe",{})
    invocation=save("failed/invocation.armed.json",{
        "schema":"marty.current10-effect-invocation/v1",
        "executionMode":"REPLACE_OB3_AFTER_SECOND_ACKNOWLEDGED_CREDENTIAL_REPLACEMENT_AND_RESUME",
        "executeAuthorized":True,"effectInputs":original_ref,
        "recoveryAuthority":previous_ref,"outputRoot":str(tmp_path/"failed"/"outputs"),
        "actor":actor,"executables":{"python":python}})
    request=save("failed/current10-effect-request.private.json",{
        "schema":"marty.windows-job-request/v1",
        "command":[python["path"],"-B",actor["path"],"--run",invocation["path"],invocation["sha256"]],
        "cwd":str(tmp_path/"failed"),"receiptFile":failed["path"],
        "executableSha256":python["sha256"]})
    controller=save("failed/current10-effect-controller.safe.json",{
        "state":"CURRENT10_EFFECT_FAILED_OR_UNKNOWN_NO_RETRY","jobState":"FAILED",
        "jobClosed":True,"terminalActiveProcesses":0,"resultPresent":False,
        "failurePresent":True,"automaticCleanupOrRetry":False})
    capture=save("capture/result.json",{"state":"OB3_THIRD_FLOW_PENDING_JOURNAL_AND_CURRENT28_CAPTURE_COMPLETE",
        "failedCutoverJob":failed,"serviceWrites":False,"sqlWrites":False,"journalContentRead":True,
        "identity28StableDuringRead":True,"selectedGenerationsBound":10,"retainedOriginalGenerations":12})
    contracts={role:save("contracts/"+role+".json",{
        "schema":"marty.reviewed-flow-crash-stop/v1" if role=="flow" else "marty.reviewed-graceful-stop/v1",
        "role":role,"containerId":rows[role]["containerId"],"imageId":rows[role]["imageId"],
        "sourceRevision":"selected-ui" if role=="flow" else rows[role]["source"],
        "elfSha256":selected_sha if role=="flow" else rows[role]["sha256"],
        "signal":"SIGTERM","allowedExitCodes":[0,1,143] if role=="flow" else [0],
        "noAutomaticSigkill":True,"gracefulShutdownVerified":False,
        "observedExitCode":1,"failedStart":state_ref,
        "sourceProof":save("proofs/"+role+".json",{
            "schema":"marty.graceful-shutdown-source-proof/v1","role":role,
            "sourceRevision":"selected-ui" if role=="flow" else rows[role]["source"],
            "elfSha256":selected_sha if role=="flow" else rows[role]["sha256"],
            "supportedSignals":["SIGTERM"]})}) for role in [*prefix,"flow"]}
    recovery={"schema":"marty.d12-ob3-flow-pending-recovery/v1",
        "operation":"QUIESCE_OB3_FLOW_PENDING_STARTS","scope":"OB3_FUNCTIONAL_ONLY",
        "draftOnly":False,"dispatchAuthorized":True,"runId":"SYNTHETIC",
        "deferredRoles":[execution.OB3_DEFERRED_ROLE],"allowedScenarios":list(execution.OB3_ALLOWED_SCENARIOS),
        "originalInputs":original_ref,"previousRecoveryAuthority":previous_ref,
        "originalOperationState":state_ref,"originalApplyIntent":intent_ref,"created":created,
        "selection":inputs["selection"],"currentOwned22":current_ref,"currentAncillary6":ancillary_ref,
        "stopContracts":contracts,"journalRead":journal,"failedCutoverJob":failed,
        "failedCutoverInvocation":invocation,"failedCutoverRequest":request,
        "failedCutoverController":controller,
        "reconciliationJob":read_job,"reconciliationResult":capture,"quiescence":previous["quiescence"],
        "sourceMap":{key:{"original":original[key],"recovery":inputs[key]}
                     for key in RECOVERY_SOURCE_FIELDS}}
    monkeypatch.setattr(execution,"created_recovery_checkpoint",
                        lambda *args,**kwargs:(original,proof,verified))
    monkeypatch.setattr(execution.maintenance,"exact_roles",lambda *args:rows)
    monkeypatch.setattr(execution,"ob3_startup_prerequisites",lambda *args,**kwargs:{"requirements":[]})
    monkeypatch.setattr(maintenance,"_reviewed_cross_edges",lambda *args:set())
    monkeypatch.setattr(maintenance,"_restore_order",lambda *args:order)
    return inputs,state,intent,recovery,save,{"rootProof":root}


@pytest.mark.parametrize("fault",[None,"operation","cid","prefix","journal","job","trust-drift","stop-contract","flow-source","flow-elf","failed-mode","failed-request"])
def test_exact_flow_checkpoint_and_refusals(tmp_path,monkeypatch,fault):
    inputs,state,intent,recovery,save,backend=case(tmp_path,monkeypatch)
    if fault=="operation":recovery["operation"]="RESUME_OB3_AFTER_SECOND_ACKNOWLEDGED_CREDENTIAL_REPLACEMENT"
    elif fault=="cid":
        current=json.loads(pathlib.Path(recovery["currentOwned22"]["path"]).read_bytes())
        current["flow"]["Id"]="f"*64
        recovery["currentOwned22"]=save("capture/foreign-current.json",current)
    elif fault=="prefix":state["steps"].pop()
    elif fault=="journal":
        journal=json.loads(pathlib.Path(recovery["journalRead"]["path"]).read_bytes())
        journal[0]["files"]["build-state.json"]["sha256"]="f"*64
        recovery["journalRead"]=save("capture/foreign-journal.json",journal)
    elif fault=="job":recovery["reconciliationJob"]=save("open-job.json",{"state":"COMPLETE","exitCode":0})
    elif fault=="trust-drift":inputs["runScopedTrustLeaseProof"]=save("foreign-lease.json",{})
    elif fault=="stop-contract":recovery["stopContracts"].pop("flow")
    elif fault in ("flow-source","flow-elf"):
        contract=json.loads(pathlib.Path(recovery["stopContracts"]["flow"]["path"]).read_bytes())
        contract["sourceRevision" if fault=="flow-source" else "elfSha256"]="foreign"
        recovery["stopContracts"]["flow"]=save("contracts/foreign-flow.json",contract)
    elif fault=="failed-mode":
        invocation=json.loads(pathlib.Path(recovery["failedCutoverInvocation"]["path"]).read_bytes())
        invocation["executionMode"]="REPLACE_OB3_QUIESCENT_CREDENTIALS_AND_RESUME"
        recovery["failedCutoverInvocation"]=save("failed/foreign-invocation.json",invocation)
    elif fault=="failed-request":
        request=json.loads(pathlib.Path(recovery["failedCutoverRequest"]["path"]).read_bytes())
        request["receiptFile"]="foreign-job.json"
        recovery["failedCutoverRequest"]=save("failed/foreign-request.json",request)
    if fault:
        with pytest.raises((ValueError,KeyError,AssertionError)):
            execution.flow_pending_ob3_checkpoint(inputs,state,intent,recovery,operation_backend=backend)
    else:
        result=execution.flow_pending_ob3_checkpoint(inputs,state,intent,recovery,operation_backend=backend)
        assert len(result[3])==17
