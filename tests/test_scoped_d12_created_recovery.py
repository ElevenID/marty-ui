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


def created_fixture(tmp_path):
    original,_old_state,intent,previous,saved=recovery_fixture(tmp_path)
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


@pytest.mark.parametrize("replace",[False,True])
def test_created_resume_enters_shared_finish_then_start_without_sql_stop_or_recreate(tmp_path,replace):
    import hashlib
    from scoped_native_profiles import current_rollout_build
    from scoped_native_runtime import D12_CURRENT_RUNTIME_ROLES
    inputs,state,intent,recovery,saved,_observed=created_fixture(tmp_path)
    if replace:
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
        assert kwargs["context"]["executorSource"]==json.loads(Path(recovery["originalInputs"]["path"]).read_bytes())["executorSource"]
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
            with pytest.raises(ReachedFirstStart):value.replace_created_credentials_and_resume(saved("recovery.json",recovery))
        assert calls[:3]==["VERIFY_COMPLETED_DB","PREPARE_REPLACEMENT","REPLACE_CREATED_CREDENTIAL_GENERATION"] and len(calls)==4
    else:
        with pytest.raises(ReachedFirstStart):value.resume_after_create_selected(saved("recovery.json",recovery))
        assert calls[0]=="VERIFY_COMPLETED_DB" and len(calls)==2
    assert value.state["phase"]=="SELECTED_CREATED"
    with pytest.raises(ValueError,match="D12_ONLY_ACKNOWLEDGED_CREATE_RECOVERABLE"):
        execution.created_recovery_checkpoint(inputs,value.state,intent,recovery,operation_backend=value.store.specification)


@pytest.mark.parametrize("change",[None,"reused-current-cid","missing-prepare"])
def test_replacement_observer_requires_new_cids_against_current_created_preimage(tmp_path,change):
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
    if change:
        with pytest.raises(ValueError):observer.bind_created_after_ack("REPLACE_CREATED_CREDENTIAL_GENERATION",state)
    else:
        observer.bind_created_after_ack("REPLACE_CREATED_CREDENTIAL_GENERATION",state)
        assert {role:observer.current[role]["containerId"] for role in selected}==second
        assert all(observer.current[role]["containerId"]==old[role] for role in set(old)-set(selected))
        assert observer._replacement_ready_authority is None


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
    binding.inputs={"runId":"SYNTHETIC","selection":{"sha256":"selection"},"plannedModels":{"elevenid-beta":{"sha256":"NEW_TARGET_MODEL"}},
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
