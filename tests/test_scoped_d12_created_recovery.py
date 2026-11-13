"""Typed created-checkpoint source controls; all records synthetic, no runtime."""
from copy import deepcopy
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
import scoped_d12_native_execution as execution
import scoped_native_database as database
from scoped_native_runtime import ref, journal_readback
from test_scoped_native_database import recovery_fixture


def created_fixture(tmp_path,quiescence=None):
    original,_old_state,intent,previous,saved=recovery_fixture(tmp_path)
    if quiescence is not None:previous["quiescence"]=quiescence
    original.pop("quiescence")
    previous_ref=saved("previous-authority.json",previous)
    root={"device":1,"inode":2,"uid":1000,"mode":448}
    saved("created-backend.json",{"rootProof":root})
    original["operationJournal"]=None
    dbstate={"phase":"DATABASE_MAINTENANCE_COMPLETED","runId":original["runId"],"executorSource":original["executorSource"],
             "databaseIdentity":{"containerId":"SYNTHETIC_DATABASE"},"quiescenceSha256":previous["quiescence"]["sha256"],"operations":[{"stepId":step,"receipt":saved("command-"+step+".json",{"role":role,"command":command})}
                 for command in ("migrate","verify-owned-schema") for step,role in database.schema_steps(True,command)]}
    proof={"operationState":saved("completed-db.json",dbstate)}
    verified={"operationState":dbstate,"databaseIdentity":dbstate["databaseIdentity"]}
    state={"schema":"marty.d12-current-native-operation/v1","phase":"EFFECT_ACKNOWLEDGED","acknowledgedStep":"CREATE_SELECTED",
           "pendingStep":None,"pendingArgv":None,"runId":original["runId"],"sourceRevision":original["uiRevision"],"coreRevision":original["coreRevision"],
           "scope":"FUNCTIONAL_ONLY","releaseQualified":False,"recordingQualified":False,"recoveryAuthority":previous_ref,
           "databaseProof":saved("completed-proof.json",proof),"verifiedDatabase":saved("verified-db.json",verified),"steps":[]}
    inputs=deepcopy(original)
    for key in database.RECOVERY_SOURCE_FIELDS:inputs[key]={"sha256":"next-"+key}
    inputs["d12Authority"]={"sha256":"new-created-authority"}
    state_ref=saved("created-state.json",state)
    files={}
    for name,bound,value in (("build-state.json",state_ref,state),("build-apply-intent.json",previous["originalApplyIntent"],intent)):
        files[name]={"present":True,"document":value,"bytes":bound["bytes"],**journal_readback(Path(bound["path"]).read_bytes())}
    for name in ("build-receipt.json","configuration-receipt.json"):files[name]={"present":False}
    observed=[{"state":"EXACT_ROOT_DURABLE_METADATA_READ_COMPLETE","mountReadOnly":True,"root":root,"files":files}]
    def job(state):return {"state":state,"exitCode":0 if state=="COMPLETE" else 1,"jobClosed":True,"terminalActiveProcesses":0,
        **{k:False for k in ("forcedTermination","timedOut","cancelled","hostMarginBreached")}}
    recovery={"schema":"marty.d12-created-recovery/v1","operation":"RESUME_AFTER_ACKNOWLEDGED_CREATE_SELECTED","draftOnly":False,"dispatchAuthorized":True,
        "runId":inputs["runId"],"originalInputs":saved("executed-inputs.json",original),"originalOperationState":state_ref,
        "previousRecoveryAuthority":previous_ref,"originalApplyIntent":previous["originalApplyIntent"],"databaseProof":state["databaseProof"],
        "verifiedDatabase":state["verifiedDatabase"],"quiescence":previous["quiescence"],"journalRead":saved("created-journal.json",observed),
        "reconciliationJob":saved("read-job.json",job("COMPLETE")),"selected22":saved("selected22.json",{}),"selected22Job":saved("selected-job.json",job("COMPLETE")),
        "failedCutoverJob":saved("failed-job.json",job("FAILED")),
        "sourceMap":{k:{"original":original[k],"recovery":inputs[k]} for k in database.RECOVERY_SOURCE_FIELDS},
        "trustDataMap":{k:{"original":original.get(k),"recovery":inputs.get(k)} for k in database.RECOVERY_TRUST_FIELDS}}
    return inputs,state,intent,recovery,saved,observed


def replacement_checkpoint_fixture(tmp_path,quiescence=None,expired_prior=False):
    inputs,old_state,intent,prior,saved,_=created_fixture(tmp_path,quiescence)
    prior.update(operation="REPLACE_CREATED_CREDENTIAL_GENERATION_AND_RESUME",replaceCredentialGeneration=True)
    generation=tmp_path/"executed-replacement-generation"
    model=json.loads(Path(inputs["plannedModels"]["elevenid-beta"]["path"]).read_bytes())
    for secret,name in (("trust_profile_workload_server_cert","trust_profile_workload_server_cert"),
                        ("trust_profile_tls_kms_token","trust_profile_workload_server_kms_token")):
        model["secrets"][secret]["file"]=str(generation/name)
    inputs["plannedModels"]={**inputs["plannedModels"],"elevenid-beta":saved("executed-replacement-model.json",model)}
    inputs["runScopedTrustLeaseProof"]=saved("executed-replacement-lease.json",{"generationDirectory":str(generation),
        "actualNativeGrantExpiryUnixSeconds":1 if expired_prior else 4000000000})
    for key in ("plannedModels","runScopedTrustLeaseProof"):prior["trustDataMap"][key]["recovery"]=inputs[key]
    prior_ref=saved("executed-replacement-authority.json",prior)
    original=deepcopy(inputs)
    state=deepcopy(old_state);state.update(acknowledgedStep="REPLACE_CREATED_CREDENTIAL_GENERATION",
        recoveryAuthority=prior_ref,replacementAuthority=prior_ref,originalOperationState=prior["originalOperationState"],
        priorCreatedSnapshot=prior["selected22"],replacementPreimage=saved("replacement-preimage.json",{}),
        priorCredentialGeneration=json.loads(Path(prior["originalInputs"]["path"]).read_bytes())["runScopedTrustLeaseProof"],
        nextCredentialGeneration=original["runScopedTrustLeaseProof"])
    state_ref=saved("replacement-ack-state.json",state)
    for key in database.RECOVERY_SOURCE_FIELDS:inputs[key]={"sha256":"resume-"+key}
    recovery=deepcopy(prior);recovery.update(operation="RESUME_AFTER_ACKNOWLEDGED_CREDENTIAL_REPLACEMENT",replaceCredentialGeneration=False,
        originalInputs=saved("executed-replacement-inputs.json",original),originalOperationState=state_ref,previousRecoveryAuthority=prior_ref,
        sourceMap={k:{"original":original[k],"recovery":inputs[k]} for k in database.RECOVERY_SOURCE_FIELDS},
        trustDataMap={k:{"original":original.get(k),"recovery":inputs.get(k)} for k in database.RECOVERY_TRUST_FIELDS})
    observed=json.loads(Path(prior["journalRead"]["path"]).read_bytes())
    observed[0]["files"]["build-state.json"]={"present":True,"document":state,"bytes":state_ref["bytes"],
        **journal_readback(Path(state_ref["path"]).read_bytes())}
    recovery["journalRead"]=saved("replacement-journal.json",observed)
    return inputs,state,intent,recovery,saved,observed


def acknowledged_replacement_fixture(tmp_path,quiescence=None):
    inputs,state,intent,recovery,saved,observed=replacement_checkpoint_fixture(tmp_path,quiescence,expired_prior=True)
    installed=json.loads(Path(recovery["originalInputs"]["path"]).read_bytes())
    assert json.loads(Path(installed["runScopedTrustLeaseProof"]["path"]).read_bytes())["actualNativeGrantExpiryUnixSeconds"]==1
    generation=tmp_path/"fresh-next-credential-generation"
    model=json.loads(Path(installed["plannedModels"]["elevenid-beta"]["path"]).read_bytes())
    for secret,name in (("trust_profile_workload_server_cert","trust_profile_workload_server_cert"),
                        ("trust_profile_tls_kms_token","trust_profile_workload_server_kms_token")):
        model["secrets"][secret]["file"]=str(generation/name)
    inputs["plannedModels"]={**inputs["plannedModels"],"elevenid-beta":saved("fresh-next-model.json",model)}
    inputs["runScopedTrustLeaseProof"]=saved("fresh-next-lease.json",{"generationDirectory":str(generation),"actualNativeGrantExpiryUnixSeconds":4000000000})
    for key in ("plannedModels","runScopedTrustLeaseProof"):recovery["trustDataMap"][key]["recovery"]=inputs[key]
    recovery.update(operation="REPLACE_ACKNOWLEDGED_CREDENTIAL_GENERATION_AND_RESUME",replaceCredentialGeneration=True)
    return inputs,state,intent,recovery,saved,observed


@pytest.mark.parametrize("fault", [None, "wrong-prior", "new-generation", "changed-model", "changed-ack", "old-schema", "job-request", "current-cid"])
@pytest.mark.parametrize("mode", ["resume", "replace"])
def test_ob3_acknowledged_recovery_requires_explicit_generation_and_current_lineage(tmp_path,monkeypatch,fault,mode):
    inputs,state,intent,recovery,saved,observed=replacement_checkpoint_fixture(tmp_path)
    original=json.loads(Path(recovery["originalInputs"]["path"]).read_bytes())
    original["roleBinaries"]={"auth":"marty-auth"};inputs["roleBinaries"]=original["roleBinaries"]
    recovery["originalInputs"]=saved("ob3-executed-inputs.json",original)
    previous=json.loads(Path(recovery["previousRecoveryAuthority"]["path"]).read_bytes())
    previous.update(schema="marty.d12-ob3-quiescent-recovery/v1",
                    operation="REPLACE_OB3_QUIESCENT_CREDENTIALS_AND_RESUME",
                    scope="OB3_FUNCTIONAL_ONLY",deferredRoles=["passport-beta-bureau"],
                    allowedScenarios=list(execution.OB3_ALLOWED_SCENARIOS),
                    startupPrerequisites=saved("ob3-startup.json",{"schema":"marty.ob3-startup-prerequisites/v1"}))
    previous_ref=saved("ob3-prior-authority.json",previous)
    state.update(recoveryAuthority=previous_ref,replacementAuthority=previous_ref,
                 priorCreatedSnapshot=previous["selected22"])
    state_ref=saved("ob3-replacement-ack.json",state)
    observed[0]["files"]["build-state.json"]={"present":True,"document":state,"bytes":state_ref["bytes"],
        **journal_readback(Path(state_ref["path"]).read_bytes())}
    recovery.update(schema="marty.d12-ob3-acknowledged-replacement-recovery/v1",
                    operation=("RESUME_OB3_AFTER_ACKNOWLEDGED_CREDENTIAL_REPLACEMENT" if mode=="resume" else
                        "REPLACE_OB3_AFTER_ACKNOWLEDGED_CREDENTIAL_REPLACEMENT_AND_RESUME"),
                    scope="OB3_FUNCTIONAL_ONLY",deferredRoles=["passport-beta-bureau"],
                    allowedScenarios=list(execution.OB3_ALLOWED_SCENARIOS),
                    startupPrerequisites=previous["startupPrerequisites"],replaceCredentialGeneration=mode=="replace",
                    previousRecoveryAuthority=previous_ref,originalOperationState=state_ref,
                    journalRead=saved("ob3-replacement-journal.json",observed))
    if mode=="replace":
        next_generation=tmp_path/"next-ob3-generation"
        model=json.loads(Path(original["plannedModels"]["elevenid-beta"]["path"]).read_bytes())
        for secret,name in (("trust_profile_workload_server_cert","trust_profile_workload_server_cert"),
                            ("trust_profile_tls_kms_token","trust_profile_workload_server_kms_token")):
            model["secrets"][secret]["file"]=str(next_generation/name)
        inputs["plannedModels"]={**inputs["plannedModels"],"elevenid-beta":saved("next-ob3-model.json",model)}
        inputs["runScopedTrustLeaseProof"]=saved("next-ob3-lease.json",{"generationDirectory":str(next_generation),"actualNativeGrantExpiryUnixSeconds":4000000000})
        for key in ("plannedModels","runScopedTrustLeaseProof"):
            recovery["trustDataMap"][key]["recovery"]=inputs[key]
    recovery["selected22"]=saved("ob3-current-selected22.json",{"auth":{"Id":"a"*64}})
    failed=tmp_path/"failed"/"cutover";outputs=failed/"outputs";outputs.mkdir(parents=True)
    def failed_ref(name,value):
        p=failed/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(value));return ref(p)
    actor=failed_ref("actor.py",{"synthetic":"actor"});python=failed_ref("python.exe",{"synthetic":"python"})
    invocation=failed_ref("invocation.armed.json",{"schema":"marty.current10-effect-invocation/v1",
        "executionMode":"REPLACE_OB3_QUIESCENT_CREDENTIALS_AND_RESUME","executeAuthorized":True,
        "effectInputs":recovery["originalInputs"],"recoveryAuthority":previous_ref,
        "actor":actor,"executables":{"python":python},"outputRoot":str(outputs)})
    recovery["failedCutoverInvocation"]=invocation
    recovery["failedCutoverJob"]=failed_ref("current10-effect-job.json",{"state":"FAILED","exitCode":1,
        "jobClosed":True,"terminalActiveProcesses":0,**{k:False for k in ("forcedTermination","timedOut","cancelled","hostMarginBreached")}})
    recovery["failedCutoverController"]=failed_ref("current10-effect-controller.safe.json",{
        "state":"CURRENT10_EFFECT_FAILED_OR_UNKNOWN_NO_RETRY","jobState":"FAILED","jobClosed":True,
        "terminalActiveProcesses":0,"resultPresent":False,"failurePresent":True,"automaticCleanupOrRetry":False})
    recovery["failedCutoverRequest"]=failed_ref("current10-effect-request.private.json",{
        "schema":"marty.windows-job-request/v1","command":[python["path"],"-B",actor["path"],"--run",invocation["path"],invocation["sha256"]],
        "cwd":str(failed),"receiptFile":recovery["failedCutoverJob"]["path"],"executableSha256":python["sha256"]})
    recovery["acknowledgedReplacement"]=failed_ref("outputs/d12-created-replacement-target-ack.private.json",state)
    recovery["ownedCreatedCids"]=failed_ref("outputs/d12-credential-replacement-cids-after-ack.private.json",{
        "schema":"marty.d12-owned-created-cids/v1","runId":inputs["runId"],"runtimeWrites":True,
        "durableCreateAck":{"phase":"EFFECT_ACKNOWLEDGED","acknowledgedStep":"REPLACE_CREATED_CREDENTIAL_GENERATION"},
        "selection":inputs["selection"],"selectedContainerIds":{"auth":"a"*64}})
    called=[]
    def prior_checkpoint(original,prior_state,actual_intent,authority,*,operation_backend,historical_source=False):
        called.append((original,prior_state,actual_intent,authority))
        assert historical_source is True
        assert authority==previous and actual_intent==intent
        return json.loads(Path(previous["originalInputs"]["path"]).read_bytes()),{},{}
    monkeypatch.setattr(execution,"ob3_quiescent_checkpoint",prior_checkpoint)
    def startup(ref,*,historical_execution_source=None):
        called.append(ref)
        return {"same":True}
    monkeypatch.setattr(execution,"ob3_startup_prerequisites",startup)
    if fault=="wrong-prior":recovery["previousRecoveryAuthority"]=saved("foreign-ob3-authority.json",{**previous,"operation":"UNREVIEWED"})
    if fault=="new-generation":
        generation="C:/different" if mode=="resume" else json.loads(Path(original["runScopedTrustLeaseProof"]["path"]).read_bytes())["generationDirectory"]
        inputs["runScopedTrustLeaseProof"]=saved("unapproved-new-lease.json",{"generationDirectory":generation})
        recovery["trustDataMap"]["runScopedTrustLeaseProof"]["recovery"]=inputs["runScopedTrustLeaseProof"]
    if fault=="changed-model":
        model=json.loads(Path(inputs["plannedModels"]["elevenid-beta"]["path"]).read_bytes())
        model["name"]="foreign-project"
        inputs["plannedModels"]={**inputs["plannedModels"],"elevenid-beta":saved("foreign-ob3-model.json",model)}
        recovery["trustDataMap"]["plannedModels"]["recovery"]=inputs["plannedModels"]
    if fault=="changed-ack":state["replacementAuthority"]={"sha256":"foreign"}
    if fault=="old-schema":recovery["schema"]="marty.d12-created-recovery/v1"
    if fault=="job-request":
        request=json.loads(Path(recovery["failedCutoverRequest"]["path"]).read_bytes());request["command"][-1]="f"*64
        recovery["failedCutoverRequest"]=saved("foreign-job-request.json",request)
    if fault=="current-cid":recovery["selected22"]=saved("foreign-current-cid.json",{"auth":{"Id":"b"*64}})
    backend=json.loads((tmp_path/"created-backend.json").read_bytes())
    if fault:
        with pytest.raises(ValueError):execution.created_recovery_checkpoint(inputs,state,intent,recovery,operation_backend=backend)
    else:
        result=execution.created_recovery_checkpoint(inputs,state,intent,recovery,operation_backend=backend)
        assert result[0]["runId"]==inputs["runId"] and len(called)==3


@pytest.mark.parametrize("change",[None,"missing-flag","same-generation","other-model-field"])
def test_acknowledged_replacement_accepts_only_explicit_new_generation(tmp_path,change):
    inputs,state,intent,recovery,saved,_=acknowledged_replacement_fixture(tmp_path)
    if change=="missing-flag":recovery["replaceCredentialGeneration"]=False
    elif change=="same-generation":
        original=json.loads(Path(recovery["originalInputs"]["path"]).read_bytes())
        for key in ("plannedModels","runScopedTrustLeaseProof"):
            inputs[key]=original[key];recovery["trustDataMap"][key]["recovery"]=inputs[key]
    elif change=="other-model-field":
        model=json.loads(Path(inputs["plannedModels"]["elevenid-beta"]["path"]).read_bytes());model["name"]="foreign-project"
        inputs["plannedModels"]={**inputs["plannedModels"],"elevenid-beta":saved("wrong-fresh-model.json",model)}
        recovery["trustDataMap"]["plannedModels"]["recovery"]=inputs["plannedModels"]
    backend=json.loads((tmp_path/"created-backend.json").read_bytes())
    if change:
        with pytest.raises(ValueError):execution.created_recovery_checkpoint(inputs,state,intent,recovery,operation_backend=backend)
    else:
        deepest,proof,_=execution.created_recovery_checkpoint(inputs,state,intent,recovery,operation_backend=backend)
        assert deepest["executorSource"]==json.loads(Path(proof["operationState"]["path"]).read_bytes())["executorSource"]


@pytest.mark.parametrize("change",[None,"pending","wrong-ack","lease","authority","target","consumed"])
def test_replacement_checkpoint_requires_exact_chain_and_same_executed_target(tmp_path,change):
    inputs,state,intent,recovery,saved,observed=replacement_checkpoint_fixture(tmp_path)
    if change=="pending":state["pendingStep"]="START_auth"
    elif change=="wrong-ack":state["acknowledgedStep"]="CREATE_SELECTED"
    elif change=="lease":state["nextCredentialGeneration"]={"sha256":"foreign"}
    elif change=="authority":state["replacementAuthority"]={"sha256":"foreign"}
    elif change=="target":
        inputs["composeArguments"]=["foreign-target"]
        recovery["trustDataMap"]["composeArguments"]["recovery"]=inputs["composeArguments"]
    elif change=="consumed":
        observed[0]["files"]["configuration-receipt.json"]={"present":True}
        recovery["journalRead"]=saved("replacement-consumed.json",observed)
    backend=json.loads((tmp_path/"created-backend.json").read_bytes())
    if change:
        with pytest.raises(ValueError):execution.created_recovery_checkpoint(inputs,state,intent,recovery,operation_backend=backend)
    else:
        deepest,proof,verified=execution.created_recovery_checkpoint(inputs,state,intent,recovery,operation_backend=backend)
        dbstate=json.loads(Path(proof["operationState"]["path"]).read_bytes())
        assert deepest["executorSource"]==dbstate["executorSource"]
        assert deepest["executorSource"]!=json.loads(Path(recovery["originalInputs"]["path"]).read_bytes())["executorSource"]
        assert verified["operationState"]==dbstate


def test_created_checkpoint_accepts_exact_bytes_without_mutating_original(tmp_path):
    inputs,state,intent,recovery,_,_=created_fixture(tmp_path)
    before=deepcopy((state,intent,recovery))
    original,proof,verified=execution.created_recovery_checkpoint(inputs,state,intent,recovery,operation_backend=json.loads((tmp_path/"created-backend.json").read_bytes()))
    assert original["runId"]==inputs["runId"]
    assert json.loads(Path(proof["operationState"]["path"]).read_bytes())==verified["operationState"]
    assert (state,intent,recovery)==before


@pytest.mark.parametrize("change",["pending","wrong-ack","consumed","base64","source-map","db-proof","job","foreign-root"])
def test_created_checkpoint_refuses_drift_before_any_effect(tmp_path,change):
    inputs,state,intent,recovery,saved,observed=created_fixture(tmp_path)
    if change=="pending":state["pendingStep"]="START_auth"
    elif change=="wrong-ack":state["acknowledgedStep"]="STOP_auth"
    elif change=="consumed":observed[0]["files"]["build-receipt.json"]={"present":True};recovery["journalRead"]=saved("changed-read.json",observed)
    elif change=="base64":observed[0]["files"]["build-state.json"]["storedBytesBase64"]="e30=";recovery["journalRead"]=saved("changed-read.json",observed)
    elif change=="source-map":recovery["sourceMap"]["executorSource"]["original"]={}
    elif change=="db-proof":recovery["databaseProof"]=saved("foreign-proof.json",{})
    elif change=="job":recovery["selected22Job"]=saved("bad-job.json",{"state":"FAILED"})
    elif change=="foreign-root":observed[0]["root"]["inode"]=3;recovery["journalRead"]=saved("changed-read.json",observed)
    with pytest.raises(ValueError):execution.created_recovery_checkpoint(inputs,state,intent,recovery,operation_backend=json.loads((tmp_path/"created-backend.json").read_bytes()))


@pytest.mark.parametrize("mode",["create","replace","replacement-ack","replacement-ack-replace"])
def test_created_resume_enters_shared_finish_then_start_without_sql_stop_or_recreate(tmp_path,mode):
    replace=mode in ("replace","replacement-ack-replace")
    import hashlib
    from scoped_native_profiles import current_rollout_build
    from scoped_native_runtime import D12_CURRENT_RUNTIME_ROLES
    inputs,state,intent,recovery,saved,_observed=(acknowledged_replacement_fixture(tmp_path) if mode=="replacement-ack-replace"
        else replacement_checkpoint_fixture(tmp_path) if mode=="replacement-ack" else created_fixture(tmp_path))
    if mode=="replace":
        recovery.update(operation="REPLACE_CREATED_CREDENTIAL_GENERATION_AND_RESUME",replaceCredentialGeneration=True)
        generation=tmp_path/"new-synthetic-generation"
        model=json.loads(Path(inputs["plannedModels"]["elevenid-beta"]["path"]).read_bytes())
        for secret,name in (("trust_profile_workload_server_cert","trust_profile_workload_server_cert"),
                            ("trust_profile_tls_kms_token","trust_profile_workload_server_kms_token")):
            model["secrets"][secret]["file"]=str(generation/name)
        inputs["plannedModels"]={**inputs["plannedModels"],"elevenid-beta":saved("replacement-model.json",model)}
        inputs["runScopedTrustLeaseProof"]=saved("replacement-lease.json",{"generationDirectory":str(generation)})
        for key in ("plannedModels","runScopedTrustLeaseProof"):recovery["trustDataMap"][key]["recovery"]=inputs[key]
    profile="d05-membership-current-functional"
    selected=dict(current_rollout_build(profile).roles)
    before={"roles":[]};binaries={}
    for role in sorted(D12_CURRENT_RUNTIME_ROLES):
        row={"role":role,"containerId":hashlib.sha256(role.encode()).hexdigest(),"imageId":"sha256:"+"a"*64,
             "state":"running","running":True,"hostPid":1,"containerExitCode":0,"oomKilled":False,"binaryMounts":[]}
        if role in selected:
            path=tmp_path/selected[role];path.write_bytes(b"synthetic")
            binaries[role]={"path":str(path)}
            row["binaryMounts"]=[{"type":"bind","source":str(tmp_path/("old-"+selected[role])),"destination":"/usr/local/bin/"+selected[role],"writable":False}]
        before["roles"].append(row)
    stopped=deepcopy(before)
    for row in stopped["roles"]:row.update(state="exited",running=False,hostPid=0)
    q=saved("actual-test-quiescence.json",stopped)
    if mode in ("replacement-ack","replacement-ack-replace"):
        inputs,state,intent,recovery,saved,_observed=(acknowledged_replacement_fixture(tmp_path,quiescence=q) if mode=="replacement-ack-replace"
            else replacement_checkpoint_fixture(tmp_path,quiescence=q))
        proof=json.loads(Path(recovery["databaseProof"]["path"]).read_bytes())
        verified=json.loads(Path(recovery["verifiedDatabase"]["path"]).read_bytes())
    else:
        # Rebind the synthetic predecessor and completed proof consistently.
        previous=json.loads(Path(recovery["previousRecoveryAuthority"]["path"]).read_bytes());previous["quiescence"]=q
        recovery["previousRecoveryAuthority"]=saved("updated-previous.json",previous);recovery["quiescence"]=q
        state["recoveryAuthority"]=recovery["previousRecoveryAuthority"]
        proof=json.loads(Path(recovery["databaseProof"]["path"]).read_bytes());dbstate=json.loads(Path(proof["operationState"]["path"]).read_bytes());dbstate["quiescenceSha256"]=q["sha256"]
        proof["operationState"]=saved("updated-completed.json",dbstate);verified={"operationState":dbstate,"databaseIdentity":dbstate["databaseIdentity"]}
        state["databaseProof"]=recovery["databaseProof"]=saved("updated-proof.json",proof)
        state["verifiedDatabase"]=recovery["verifiedDatabase"]=saved("updated-verified.json",verified)
        recovery["originalOperationState"]=saved("updated-state.json",state)
        observed=json.loads(Path(recovery["journalRead"]["path"]).read_bytes());raw=Path(recovery["originalOperationState"]["path"]).read_bytes()
        observed[0]["files"]["build-state.json"]={"present":True,"document":state,"bytes":len(raw),**journal_readback(raw)}
        recovery["journalRead"]=saved("updated-journal.json",observed)
    created=deepcopy(stopped)
    for row in created["roles"]:
        if row["role"] in selected:
            row.update(containerId=hashlib.sha256(("new-"+row["role"]).encode()).hexdigest(),state="created")
            row["binaryMounts"][0]["source"]=str(tmp_path/selected[row["role"]])
    value=execution.D12CurrentExecution.__new__(execution.D12CurrentExecution)
    value.i=inputs;value.profile=profile;value.roles=selected;value.native_preimage=None;value.read_only_preflight=False
    value.build_profile=SimpleNamespace(ui_revision="source",core_revision="core")
    value.store=SimpleNamespace(specification=json.loads((tmp_path/"created-backend.json").read_bytes()),read=lambda name:state if name=="build-state.json" else intent,
        state=lambda data:{"fileFsync":True,"parentDirectory":{"supported":True,"synced":True}})
    calls=[]
    def node(mode,**kwargs):
        assert mode=="verify";assert len(kwargs["commands"])==len(database.schema_steps(True,"migrate"))+len(database.schema_steps(True,"verify-owned-schema"))
        assert kwargs["context"]["executorSource"]==json.loads(Path(proof["operationState"]["path"]).read_bytes())["executorSource"]
        calls.append("VERIFY_COMPLETED_DB");return verified
    db=SimpleNamespace(i={},commands=[],baseline_refs={},engine_id="synthetic",tenant_id="synthetic",node=node,selection={"binaries":binaries})
    value.recovery_preflight=lambda ref:(db,before,{"restoreOrder":sorted(D12_CURRENT_RUNTIME_ROLES)},None)
    value.g={"save":lambda name,data:{"path":name,"sha256":"synthetic"},
        "prepare_created_credential_replacement":lambda ref:calls.append("PREPARE_REPLACEMENT") or {"sha256":"preimage"}}
    value.inspect_all22=lambda:deepcopy(created)
    class ReachedFirstStart(Exception):pass
    def command(_db,step,argv):
        if step=="REPLACE_CREATED_CREDENTIAL_GENERATION":
            assert replace;calls.append(step);return b""
        assert step.startswith("START_");calls.append(step);raise ReachedFirstStart
    value.command=command
    if replace:
        value.recovery_preflight=lambda ref:(db,before,{"restoreOrder":sorted(D12_CURRENT_RUNTIME_ROLES)},{"path":"synthetic-overlay"})
        from unittest.mock import patch
        with patch.object(execution.overlay,"compose_recreate_arguments",return_value=["docker","compose","up","--no-start"]):
            with pytest.raises(ReachedFirstStart):
                (value.replace_acknowledged_created_credentials_and_resume if mode=="replacement-ack-replace"
                    else value.replace_created_credentials_and_resume)(saved("recovery.json",recovery))
        assert calls[:3]==["VERIFY_COMPLETED_DB","PREPARE_REPLACEMENT","REPLACE_CREATED_CREDENTIAL_GENERATION"] and len(calls)==4
    else:
        with pytest.raises(ReachedFirstStart):
            (value.resume_after_created_credential_replacement if mode=="replacement-ack" else value.resume_after_create_selected)(saved("recovery.json",recovery))
        assert calls[0]=="VERIFY_COMPLETED_DB" and len(calls)==2
    assert value.state["phase"]=="SELECTED_CREATED"
    if mode=="replacement-ack-replace":
        installed=json.loads(Path(recovery["originalInputs"]["path"]).read_bytes())
        assert value.state["priorCredentialGeneration"]==installed["runScopedTrustLeaseProof"]
        assert value.state["nextCredentialGeneration"]==inputs["runScopedTrustLeaseProof"]
    with pytest.raises(ValueError,match="D12_ONLY_ACKNOWLEDGED_CREATE_RECOVERABLE"):
        execution.created_recovery_checkpoint(inputs,value.state,intent,recovery,operation_backend=value.store.specification)


@pytest.mark.parametrize("reconciled",[False,"resume","replace-ack","ob3-resume"])
@pytest.mark.parametrize("change",[None,"reused-current-cid","missing-prepare"])
def test_replacement_observer_requires_new_cids_against_current_created_preimage(tmp_path,change,reconciled):
    from scoped_d12_native_effect_host import D12CurrentEffectObserver
    from scoped_d12_native_host import D12ReadOnlyHost
    from scoped_linux_journal import LinuxBuildJournal
    from scoped_native_profiles import current_rollout_build
    from scoped_native_runtime import D12_CURRENT_RUNTIME_ROLES,daemon_source
    profile="d05-membership-current-functional";build=current_rollout_build(profile);selected=dict(build.roles)
    before={};binaries={};old={role:f"{i+1:064x}" for i,role in enumerate(sorted(D12_CURRENT_RUNTIME_ROLES))}
    first={role:f"{i+100:064x}" for i,role in enumerate(sorted(selected))};second={role:f"{i+200:064x}" for i,role in enumerate(sorted(selected))}
    image="sha256:"+"a"*64
    for role in sorted(old):
        mounts=[]
        if role in selected:
            file=tmp_path/selected[role];file.write_bytes(b"SYNTHETIC_SOURCE_BYTES");binaries[role]=ref(file)
            mounts=[{"type":"bind","destination":"/usr/local/bin/"+selected[role],"source":"C:/old/"+selected[role],"writable":False}]
        before[role]={"role":role,"containerId":old[role],"imageId":image,"project":"elevenid-beta-ui" if role=="ui-prod" else "elevenid-beta","binaryMounts":mounts}
    def saved(name,value):
        file=tmp_path/name;file.write_text(json.dumps(value));return ref(file)
    selection=saved("observer-selection.json",{"sourceRevision":build.ui_revision,"coreRevision":build.core_revision,"binaries":binaries})
    state={"phase":"EFFECT_ACKNOWLEDGED","acknowledgedStep":"CREATE_SELECTED","runId":"SYNTHETIC_RUN"}
    journal=LinuxBuildJournal.__new__(LinuxBuildJournal);journal.read=lambda name:state
    host=D12ReadOnlyHost.__new__(D12ReadOnlyHost);host.before=before;host.engine_id="SYNTHETIC_ENGINE";host._recheck_source=lambda:None
    current=dict(first)
    def docker(argv):
        if argv[0]=="info":return host.engine_id
        if argv[0]=="ps":return current[argv[-1].split("=")[-1]]
        assert argv[0]=="inspect";rows=[]
        for cid in argv[1:]:
            role=next(role for role in old if cid in (old[role],first.get(role),second.get(role)))
            selected_now=role in selected and cid!=old[role]
            mounts=[{"Type":m["type"],"Source":daemon_source(binaries[role]["path"]) if selected_now else m["source"],"Destination":m["destination"],"RW":m["writable"]} for m in before[role]["binaryMounts"]]
            rows.append({"Id":cid,"Image":image,"Config":{"Labels":{"com.docker.compose.project":before[role]["project"],"com.docker.compose.service":role}},"Mounts":mounts,
                "State":{"StartedAt":"0001-01-01T00:00:00Z","Status":"created" if selected_now else "exited","Running":False,"Pid":0,"ExitCode":0,"Paused":False,"OOMKilled":False}})
        return json.dumps(rows)
    host._docker=docker
    observer=D12CurrentEffectObserver(host,selection,journal,saved,profile)
    observer.bind_created_after_ack("CREATE_SELECTED",state)
    recovery=saved("replacement-authority.json",{"schema":"marty.d12-created-recovery/v1","operation":"REPLACE_CREATED_CREDENTIAL_GENERATION_AND_RESUME",
        "replaceCredentialGeneration":True,"dispatchAuthorized":True,"draftOnly":False,"originalOperationState":saved("observer-state.json",state)})
    if change!="missing-prepare":observer.prepare_credential_replacement(recovery)
    current.update(second)
    if change=="reused-current-cid":current["auth"]=first["auth"]
    state.update(acknowledgedStep="REPLACE_CREATED_CREDENTIAL_GENERATION",replacementAuthority=recovery)
    options={}
    if reconciled:
        prior=saved("reconciled-prior-authority.json",{"operation":"REPLACE_OB3_QUIESCENT_CREDENTIALS_AND_RESUME" if reconciled=="ob3-resume"
            else "REPLACE_CREATED_CREDENTIAL_GENERATION_AND_RESUME",
            "selected22":saved("reconciled-prior22.json",{role:{"Id":first.get(role,old[role])} for role in old})})
        state["replacementAuthority"]=prior
        resume=saved("reconciled-resume-authority.json",{"schema":"marty.d12-ob3-acknowledged-replacement-recovery/v1" if reconciled=="ob3-resume"
            else "marty.d12-created-recovery/v1",
            "operation":"REPLACE_ACKNOWLEDGED_CREDENTIAL_GENERATION_AND_RESUME" if reconciled=="replace-ack"
                else "RESUME_OB3_AFTER_ACKNOWLEDGED_CREDENTIAL_REPLACEMENT" if reconciled=="ob3-resume"
                else "RESUME_AFTER_ACKNOWLEDGED_CREDENTIAL_REPLACEMENT","dispatchAuthorized":True,
            "draftOnly":change=="missing-prepare","previousRecoveryAuthority":prior,
            "originalOperationState":saved("reconciled-state.json",state),
            "selected22":saved("reconciled-selected22.json",{role:{"Id":second.get(role,old[role])} for role in old})})
        observer=D12CurrentEffectObserver(host,selection,journal,saved,profile)
        options={"reconciled_replacement":resume}
    if change:
        with pytest.raises(ValueError):observer.bind_created_after_ack("REPLACE_CREATED_CREDENTIAL_GENERATION",state,**options)
    else:
        observed_ref=observer.bind_created_after_ack("REPLACE_CREATED_CREDENTIAL_GENERATION",state,**options)
        assert {role:observer.current[role]["containerId"] for role in selected}==second
        assert all(observer.current[role]["containerId"]==old[role] for role in set(old)-set(selected))
        assert observer._replacement_ready_authority is None
        assert json.loads(Path(observed_ref["path"]).read_bytes())["runtimeWrites"] is (not reconciled)



@pytest.mark.parametrize("changed",[False,True])
def test_host_ack_verifies_new_target_model_without_borrowing_old_job(tmp_path,monkeypatch,changed):
    import scoped_d12_native_effect_host as host_module
    binding=host_module.D12CurrentHostBindings.__new__(host_module.D12CurrentHostBindings)
    binding.profile="d05-membership-current-functional";binding.root=tmp_path
    def saved(name,value):
        p=tmp_path/name;p.write_text(json.dumps(value));return ref(p)
    resource=saved("resource.json",{"resourceBefore":{"sha256":"held-before"}})
    recovery=saved("recovery.json",{"maintenanceResourceRecovery":resource})
    state={"phase":"EFFECT_ACKNOWLEDGED","acknowledgedStep":"REPLACE_CREATED_CREDENTIAL_GENERATION","replacementAuthority":recovery}
    binding.observer=SimpleNamespace(bind_created_after_ack=lambda *args:{"sha256":"actual-new-cids"})
    binding.store=SimpleNamespace(read=lambda name:{**state,"acknowledgedStep":"foreign"} if changed else state)
    calls=[];binding.assert_inputs=lambda:calls.append("INPUTS")
    binding.inputs={"composeArguments":["docker","compose","--env-file","C:/reviewed/current.env"],"runId":"SYNTHETIC","selection":{"sha256":"selection"},"plannedModels":{"elevenid-beta":{"sha256":"NEW_TARGET_MODEL"}},
                    "runtimeBefore":{"sha256":"old-native"},"functionalRuntimeModule":{"path":"source-runtime.js","sha256":"bound"}}
    binding.host=SimpleNamespace(engine_id="synthetic-engine");binding.node=Path("node.exe");binding.docker=Path("docker.exe");binding.environment={}
    def run(argv,**kwargs):
        assert "verifyCreatedTargetModel" in argv[2]
        request=json.loads(Path(argv[-3]).read_bytes())
        assert request["plannedModels"]==binding.inputs["plannedModels"]
        assert request["createdCids"]=={"sha256":"actual-new-cids"}
        calls.append("CURRENT_ACK_TARGET_MODEL")
        return SimpleNamespace(returncode=0,stdout=json.dumps({"state":"ACTUAL_CREATED_TARGET_MODEL_BOUND_BY_CURRENT_OWNER","runId":"SYNTHETIC",
            "acknowledgedStep":state["acknowledgedStep"],"currentJobNormalClosureNotYetQualified":True}).encode(),stderr=b"",
            observation={"timedOut":False,"failures":[]})
    monkeypatch.setattr(host_module,"bounded_run",run)
    if changed:
        with pytest.raises(ValueError,match="D12_CREATED_TARGET_ACK_CHANGED"):binding.effect_acknowledged(state["acknowledgedStep"],state)
        assert calls==["INPUTS"]
    else:
        binding.effect_acknowledged(state["acknowledgedStep"],state)
        assert calls==["INPUTS","CURRENT_ACK_TARGET_MODEL","INPUTS"]


@pytest.mark.parametrize("backend",[None,{}, {"rootProof":None}, {"rootProof":{"device":1,"inode":999,"uid":1000,"mode":448}}])
def test_created_checkpoint_requires_separately_bound_backend_root(tmp_path,backend):
    inputs,state,intent,recovery,_,_=created_fixture(tmp_path)
    assert inputs["operationJournal"] is None
    with pytest.raises(ValueError,match="D12_CREATED_JOURNAL_(BACKEND_REQUIRED|ROOT_CHANGED)"):
        execution.created_recovery_checkpoint(inputs,state,intent,recovery,operation_backend=backend)


def test_ob3_historical_startup_source_requires_exact_sibling_and_current_bytes(tmp_path):
    current=Path(execution.__file__).with_name("ob3-startup-prerequisites.json")
    historical=tmp_path/"historical";historical.mkdir()
    prior_execution=historical/"scoped_d12_native_execution.py"
    prior_execution.write_bytes(b"historical execution source")
    prior_startup=historical/current.name
    prior_startup.write_bytes(current.read_bytes().replace(b"\r\n",b"\n").replace(b"\n",b"\r\n"))
    assert execution.ob3_startup_prerequisites(ref(prior_startup),historical_execution_source=ref(prior_execution))
    foreign=tmp_path/current.name;foreign.write_bytes(current.read_bytes())
    with pytest.raises(ValueError,match="D12_OB3_STARTUP_SOURCE_PATH_REQUIRED"):
        execution.ob3_startup_prerequisites(ref(foreign),historical_execution_source=ref(prior_execution))
    foreign_execution=tmp_path/"foreign_execution.py";foreign_execution.write_bytes(prior_execution.read_bytes())
    with pytest.raises(ValueError,match="D12_OB3_STARTUP_SOURCE_PATH_REQUIRED"):
        execution.ob3_startup_prerequisites(ref(prior_startup),historical_execution_source=ref(foreign_execution))
    changed=prior_startup.read_bytes().replace(b"signing-keys",b"signing-kays")
    assert len(changed)==prior_startup.stat().st_size
    prior_startup.write_bytes(changed)
    with pytest.raises(ValueError,match="D12_OB3_HISTORICAL_STARTUP_CONTENT_CHANGED"):
        execution.ob3_startup_prerequisites(ref(prior_startup),historical_execution_source=ref(prior_execution))


@pytest.mark.parametrize("checkpoint",["create","replacement"])
@pytest.mark.parametrize("gate",["authorization","quiescence"])
@pytest.mark.parametrize("foreign_root",[False,True])
def test_created_host_gates_pass_actual_separate_backend(tmp_path,gate,foreign_root,checkpoint):
    from scoped_d12_native_effect_host import D12CurrentHostBindings
    inputs,state,intent,recovery,saved,_=(replacement_checkpoint_fixture(tmp_path) if checkpoint=="replacement" else created_fixture(tmp_path))
    assert inputs["operationJournal"] is None
    owner=D12CurrentHostBindings.__new__(D12CurrentHostBindings)
    owner.inputs=inputs;owner.assert_inputs=lambda:None
    backend=json.loads((tmp_path/"created-backend.json").read_bytes())
    if foreign_root:backend["rootProof"]["inode"]+=1
    owner.store=SimpleNamespace(specification=backend,read=lambda name:state if name=="build-state.json" else intent)
    class ReachedObserverAfterRealCheckpoint(Exception):pass
    class Observer:
        @property
        def created_ref(self):raise ReachedObserverAfterRealCheckpoint
    owner.observer=Observer()
    authority=saved("host-authority.json",{})
    inputs["d12Authority"]=authority
    if gate=="authorization":
        module=tmp_path/"tests/scripts/functional-debug-runtime.js"
        module.parent.mkdir(parents=True);module.write_text("// source-only fixture")
        inputs["functionalRuntimeModule"]=ref(module)
        recovery["sourceMap"]["functionalRuntimeModule"]["recovery"]=ref(module)
        owner.host=SimpleNamespace(_root=tmp_path,_source_files={"tests/scripts/functional-debug-runtime.js":ref(module)})
        owner.lock=SimpleNamespace(held=lambda:True)
        owner.dispatch_permit={"authority":authority,"resourceProfile":saved("host-profile.json",{
            "schema":"marty.functional-mixed-runtime/v2","scope":"FUNCTIONAL_ONLY",
            "releaseQualified":False,"recordingQualified":False,"resourceRestart":{}})}
        owner._probe_compose_discovery=lambda prefix:None
    recovery_ref=saved("host-recovery.json",recovery)
    def check():
        if gate=="authorization":owner._authorization_verified(authority,recovery_ref)
        else:owner.verify_recovery_quiescent(recovery_ref)
    if foreign_root:
        with pytest.raises(ValueError,match="D12_CREATED_JOURNAL_ROOT_CHANGED"):check()
    else:
        with pytest.raises(ReachedObserverAfterRealCheckpoint):check()


@pytest.mark.parametrize("phase",["before-replacement","after-replacement","wrong-operation"])
def test_acknowledged_replacement_target_request_uses_exact_phase_model(tmp_path,monkeypatch,phase):
    import scoped_d12_native_effect_host as host_module
    owner=host_module.D12CurrentHostBindings.__new__(host_module.D12CurrentHostBindings)
    owner.profile="d05-membership-current-functional";owner.root=tmp_path
    def saved(name,value):
        file=tmp_path/name;file.write_text(json.dumps(value));return ref(file)
    selection=saved("target-selection.json",{"fixture":"same-selected-build"})
    old_model=saved("installed-SDK4-model.json",{"fixture":"installed-SDK4-generation"})
    new_model=saved("target-SDK5-model.json",{"fixture":"fresh-SDK5-generation"})
    old_args=["docker","compose","--env-file",str(tmp_path/"installed-SDK4.env")]
    new_args=["docker","compose","--env-file",str(tmp_path/"target-SDK5.env")]
    owner.inputs={"runId":"SYNTHETIC","selection":selection,"plannedModels":{"elevenid-beta":new_model},
        "composeArguments":new_args,"runtimeBefore":{"sha256":"historical-running-preimage"},"functionalRuntimeModule":{"path":"reviewed-current-module","sha256":"source"}}
    installed={**owner.inputs,"plannedModels":{"elevenid-beta":old_model},"composeArguments":old_args}
    state={"runId":"SYNTHETIC","phase":"EFFECT_ACKNOWLEDGED","acknowledgedStep":"REPLACE_CREATED_CREDENTIAL_GENERATION"}
    recovery=saved("phase-authority.json",{"operation":"RESUME_AFTER_ACKNOWLEDGED_CREDENTIAL_REPLACEMENT" if phase=="wrong-operation"
        else "REPLACE_ACKNOWLEDGED_CREDENTIAL_GENERATION_AND_RESUME","dispatchAuthorized":True,"draftOnly":False,
        "originalInputs":saved("installed-inputs.json",installed),"originalOperationState":saved("prior-ack.json",state),
        "maintenanceResourceRecovery":saved("target-resource.json",{"resourceBefore":{"sha256":"actual-bound-baseline"}})})
    owner.store=SimpleNamespace(read=lambda name:state);owner.assert_inputs=lambda:None
    owner.host=SimpleNamespace(engine_id="SYNTHETIC_ENGINE");owner.node="node";owner.docker="docker";owner.environment={}
    owner.save=saved
    def save_bytes(name,raw):
        file=tmp_path/name;file.write_bytes(raw);return ref(file)
    owner.save_bytes=save_bytes
    calls=[]
    def run(argv,**kwargs):
        request=json.loads(Path(argv[-3]).read_bytes());calls.append(request)
        expected=installed if phase=="before-replacement" else owner.inputs
        assert request["plannedModels"]==expected["plannedModels"]
        assert request["composeArguments"]==expected["composeArguments"]
        assert request["selection"]==selection and request["runtimeBefore"]==owner.inputs["runtimeBefore"]
        return SimpleNamespace(returncode=0,stdout=json.dumps({"state":"ACTUAL_CREATED_TARGET_MODEL_BOUND_BY_CURRENT_OWNER",
            "runId":"SYNTHETIC","acknowledgedStep":state["acknowledgedStep"],"currentJobNormalClosureNotYetQualified":True}).encode(),
            stderr=b"",observation={"timedOut":False,"failures":[]})
    monkeypatch.setattr(host_module,"bounded_run",run)
    def check():return owner._verify_created_target(state["acknowledgedStep"],state,{"sha256":"exact-current-cids"},
        recovery_ref=recovery,prefix="phase-control",use_installed_model=phase!="after-replacement")
    if phase=="wrong-operation":
        with pytest.raises(ValueError,match="D12_CREATED_INSTALLED_MODEL_AUTHORITY_REQUIRED"):check()
        assert calls==[]
    else:
        check();assert len(calls)==1
