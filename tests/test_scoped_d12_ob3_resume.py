"""Synthetic source/API boundaries only; never observed quiescence or a live grant."""
from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace
import pytest,sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import scoped_d12_native_execution as execution
import scoped_native_database as database
from scoped_native_runtime import D12_CURRENT_RUNTIME_ROLES,journal_readback
from test_scoped_d12_ob3_quiesce import fixture as partial_fixture

def test_acknowledged_ob3_replacement_continues_without_recreate_or_sql(tmp_path,monkeypatch):
    from scoped_native_runtime import ref
    def save(name,value):
        p=tmp_path/name;p.write_text(json.dumps(value));return ref(p)
    inputs={"runId":"SYNTHETIC","rolloutProfile":"d05-membership-current-functional",
            "runScopedTrustLeaseProof":{"sha256":"same-generation"},"selection":{"sha256":"selected"},
            "databaseBefore":{"sha256":"database-before"},"executorSource":{"sha256":"reviewed-executor"}}
    original=deepcopy(inputs)
    commands=[{"stepId":step,"receipt":save("sql-"+step+".json",{"stepId":step})}
              for command in ("migrate","verify-owned-schema") for step,_role in database.schema_steps(True,command)]
    proof={"operationState":save("database-state.json",{"operations":commands})}
    verified={"state":"SYNTHETIC_VERIFIED_DATABASE"}
    recovery={"operation":"RESUME_OB3_AFTER_ACKNOWLEDGED_CREDENTIAL_REPLACEMENT",
              "quiescence":{"sha256":"quiescent"},"originalOperationState":save("ack.json",{"phase":"EFFECT_ACKNOWLEDGED"})}
    recovery_ref=save("recovery.json",recovery)
    value=execution.D12CurrentExecution.__new__(execution.D12CurrentExecution)
    value.i=inputs;value.profile="d05-membership-current-functional";value.read_only_preflight=False
    value.store=SimpleNamespace(specification={},read=lambda name:{"phase":"EFFECT_ACKNOWLEDGED"})
    value.build_profile=SimpleNamespace(ui_revision="source",core_revision="core")
    calls=[]
    def checkpoint(*args,**kwargs):calls.append("CHECKPOINT");return original,proof,verified
    monkeypatch.setattr(execution,"created_recovery_checkpoint",checkpoint)
    db=SimpleNamespace(i={},commands=[],baseline_refs={},engine_id="SYNTHETIC",tenant_id="SYNTHETIC",
                       node=lambda mode,**kwargs:verified)
    value.recovery_preflight=lambda ref:(db,{}, {"restoreOrder":[]},None)
    value.g={"ob3_startup_plan":lambda ref:{"order":[]}}
    value.record=lambda phase,**kwargs:calls.append(phase)
    value.command=lambda *args,**kwargs:pytest.fail("acknowledged recovery replayed a create or SQL command")
    value._finish_after_create=lambda *args,**kwargs:calls.append("CONTINUE_STARTS") or kwargs["ob3_recovery"]
    assert value.resume_ob3_acknowledged_credential_replacement(recovery_ref)==recovery_ref
    assert calls==["CHECKPOINT","CHECKPOINT","POST_CREATE_RECOVERY_VERIFIED","CONTINUE_STARTS"]


@pytest.mark.parametrize("generation",["second","third"])
def test_ob3_acknowledged_replacement_journals_only_new_credential_create(tmp_path,monkeypatch,generation):
    from scoped_native_runtime import ref
    def save(name,value):
        p=tmp_path/name;p.write_text(json.dumps(value));return ref(p)
    inputs={"runId":"SYNTHETIC","rolloutProfile":"d05-membership-current-functional",
            "runScopedTrustLeaseProof":{"sha256":"new-generation"},"selection":{"sha256":"selected"},
            "databaseBefore":{"sha256":"database-before"},"executorSource":{"sha256":"reviewed-executor"},
            "composeArguments":["reviewed-compose"]}
    original={**inputs,"runScopedTrustLeaseProof":{"sha256":"prior-generation"}}
    commands=[{"stepId":step,"receipt":save("sql-"+step+".json",{"stepId":step})}
              for command in ("migrate","verify-owned-schema") for step,_role in database.schema_steps(True,command)]
    proof={"operationState":save("database-state.json",{"operations":commands})}
    verified={"state":"SYNTHETIC_VERIFIED_DATABASE"}
    recovery={"operation":("REPLACE_OB3_AFTER_SECOND_ACKNOWLEDGED_CREDENTIAL_REPLACEMENT_AND_RESUME" if generation=="third" else
                           "REPLACE_OB3_AFTER_ACKNOWLEDGED_CREDENTIAL_REPLACEMENT_AND_RESUME"),
              "quiescence":{"sha256":"quiescent"},"originalInputs":save("prior-inputs.json",original),
              "originalOperationState":save("ack.json",{"phase":"EFFECT_ACKNOWLEDGED"}),
              "selected22":save("current-cids.json",{"synthetic":"preimage"})}
    recovery_ref=save("recovery.json",recovery)
    value=execution.D12CurrentExecution.__new__(execution.D12CurrentExecution)
    value.i=inputs;value.profile="d05-membership-current-functional";value.read_only_preflight=False
    value.store=SimpleNamespace(specification={},read=lambda name:{"phase":"EFFECT_ACKNOWLEDGED"})
    value.build_profile=SimpleNamespace(ui_revision="source",core_revision="core")
    value.roles={"auth":"marty-auth"}
    calls=[]
    monkeypatch.setattr(execution,"created_recovery_checkpoint",
        lambda *args,**kwargs:calls.append("CHECKPOINT") or (original,proof,verified))
    monkeypatch.setattr(execution.overlay,"compose_recreate_arguments",
        lambda *args,**kwargs:calls.append("COMPOSE_NEW_GENERATION") or ["compose","up","--no-start"])
    db=SimpleNamespace(i={},commands=[],baseline_refs={},engine_id="SYNTHETIC",tenant_id="SYNTHETIC",
                       node=lambda mode,**kwargs:verified if mode=="verify" else pytest.fail("SQL replay"))
    value.recovery_preflight=lambda ref:(db,{}, {"restoreOrder":[]}, {"path":"synthetic-overlay"})
    value.g={"ob3_startup_plan":lambda ref:{"order":[]},
             "prepare_created_credential_replacement":lambda ref:calls.append("PREPARE_CURRENT_CIDS") or recovery["selected22"]}
    value.record=lambda phase,**kwargs:calls.append(phase)
    value.command=lambda database,step,argv:calls.append(step) if step=="REPLACE_CREATED_CREDENTIAL_GENERATION" else pytest.fail("SQL or prior create replay")
    value._finish_after_create=lambda *args,**kwargs:calls.append("CONTINUE_STARTS") or kwargs["ob3_recovery"]
    method=(value.replace_ob3_second_acknowledged_credential_replacement_and_resume if generation=="third" else
            value.replace_ob3_acknowledged_credential_replacement_and_resume)
    assert method(recovery_ref)==recovery_ref
    assert calls==["CHECKPOINT","CHECKPOINT","PREPARE_CURRENT_CIDS","POST_CREATE_RECOVERY_VERIFIED",
                   "CREATED_CREDENTIAL_REPLACEMENT_AUTHORIZED","COMPOSE_NEW_GENERATION",
                   "REPLACE_CREATED_CREDENTIAL_GENERATION","CONTINUE_STARTS"]


@pytest.mark.parametrize("generation",["second","third"])
@pytest.mark.parametrize("fault",[None,"stale-cid","bureau-exit"])
def test_ob3_acknowledged_replacement_preimage_is_current_and_deferred(tmp_path,monkeypatch,fault,generation):
    import scoped_d12_native_effect_host as host
    from scoped_native_runtime import ref
    def save_file(name,value):
        p=tmp_path/name;p.write_text(json.dumps(value));return ref(p)
    state={"phase":"EFFECT_ACKNOWLEDGED","acknowledgedStep":"REPLACE_CREATED_CREDENTIAL_GENERATION",
           "ob3StopOutcomes":{"passport-beta-bureau":{"observedExitCode":1}}}
    prior=save_file("prior.json",{"operation":("REPLACE_OB3_AFTER_ACKNOWLEDGED_CREDENTIAL_REPLACEMENT_AND_RESUME" if generation=="third" else
                                               "REPLACE_OB3_QUIESCENT_CREDENTIALS_AND_RESUME")})
    state["replacementAuthority"]=prior
    if fault=="bureau-exit":state["ob3StopOutcomes"]["passport-beta-bureau"]["observedExitCode"]=0
    state_ref=save_file("ack.json",state)
    rows={"auth":{"containerId":"a"*64,"state":"created","running":False,"hostPid":0,
                  "paused":False,"oomKilled":False,"containerExitCode":0},
          "passport-beta-bureau":{"containerId":"b"*64,"state":"exited","running":False,"hostPid":0,
                                  "paused":False,"oomKilled":False,"containerExitCode":1}}
    saved={role:{"Id":row["containerId"],"State":{"ExitCode":row["containerExitCode"]}}
           for role,row in rows.items()}
    if fault=="stale-cid":saved["auth"]["Id"]="f"*64
    recovery={"schema":"marty.d12-ob3-acknowledged-replacement-recovery/v1",
              "operation":("REPLACE_OB3_AFTER_SECOND_ACKNOWLEDGED_CREDENTIAL_REPLACEMENT_AND_RESUME" if generation=="third" else
                           "REPLACE_OB3_AFTER_ACKNOWLEDGED_CREDENTIAL_REPLACEMENT_AND_RESUME"),
              "replaceCredentialGeneration":True,"dispatchAuthorized":True,"draftOnly":False,
              "originalOperationState":state_ref,"previousRecoveryAuthority":prior,
              "selected22":save_file("current22.json",saved)}
    recovery_ref=save_file("recovery.json",recovery)
    observer=host.D12CurrentEffectObserver.__new__(host.D12CurrentEffectObserver)
    observer.profile="d05-membership-current-functional";observer.created_ref={"sha256":"current-created"}
    observer.store=SimpleNamespace(read=lambda _:state)
    observer.build_profile=SimpleNamespace(roles={"auth":"marty-auth"})
    observer.inspect_all22=lambda:rows
    observer.save=lambda name,value:save_file(name,value)
    monkeypatch.setattr(host,"exact_roles",lambda snapshot,profile:snapshot)
    if fault:
        with pytest.raises(ValueError):observer.prepare_credential_replacement(recovery_ref)
    else:
        preimage=observer.prepare_credential_replacement(recovery_ref)
        assert json.loads(Path(preimage["path"]).read_bytes())==rows

def startup_fixture(tmp_path,monkeypatch):
    """Controlled source namespace; Git verification belongs to Host construction."""
    import scoped_d12_native_effect_host as host
    import scoped_passport_maintenance as maintenance
    from scoped_native_runtime import ref
    root=tmp_path/'controlled-source';(root/'scripts').mkdir(parents=True)
    monkeypatch.setattr(execution,'__file__',str(root/'scripts/scoped_d12_native_execution.py'))
    requirements=[{'dependentRole':role,'prerequisiteRole':dependency,'readiness':'DOCKER_HEALTHY'} for role,dependency in [('compliance-profile','organization'),('deployment-profile','organization'),('device-registration','organization'),('canvas-sync-worker','signing-keys')]]
    proof={'schema':'marty.ob3-startup-prerequisites/v1','composeSourcePath':'docker-compose.beta.yml','composeSha256':'a'*64,'requirements':requirements,'installedModelChanged':False}
    source=root/'scripts/ob3-startup-prerequisites.json';source.write_text(json.dumps(proof));source_ref=ref(source)
    def save(name,value):p=tmp_path/name;p.write_text(json.dumps(value));return ref(p)
    models={project:{'name':project,'services':{}} for project in ['elevenid-beta','elevenid-beta-ui']};rows=[]
    for role in sorted(D12_CURRENT_RUNTIME_ROLES):
        project=maintenance.ROLE_PROJECTS[role];models[project]['services'][role]={};rows.append({'role':role,'project':project,'containerId':f'{len(rows)+1:064x}'})
    plan={'composeModels':{project:save(project+'.json',model) for project,model in models.items()}}
    owner=host.D12CurrentHostBindings.__new__(host.D12CurrentHostBindings);owner.profile='d05-membership-current-functional';owner.host=SimpleNamespace(_root=root,_source_files={'scripts/ob3-startup-prerequisites.json':{'sha256':source_ref['sha256'],'bytes':source_ref['bytes'],'gitBlob':'b'*40}});owner.inputs={'maintenancePlan':save('plan.json',plan),'runtimeBefore':save('before.json',{'roles':rows})}
    authority=save('graph-authority.json',{'operation':'QUIESCE_OB3_PARTIAL_STARTS','dispatchAuthorized':True,'draftOnly':False,'startupPrerequisites':source_ref})
    return owner,authority,requirements,models,plan,save,source

def test_one_source_graph_orders_start_and_reverse_stop_without_changing_installed_models(tmp_path,monkeypatch):
    owner,authority,requirements,models,plan,save,source=startup_fixture(tmp_path,monkeypatch)
    before=deepcopy(models);result=owner.ob3_startup_plan(authority);order=result['order']
    assert len(order)==22 and set(order)==D12_CURRENT_RUNTIME_ROLES and models==before and result['installedModelChanged'] is False
    for requirement in requirements:
        assert order.index(requirement['prerequisiteRole'])<order.index(requirement['dependentRole'])
        reverse=list(reversed(order));assert reverse.index(requirement['dependentRole'])<reverse.index(requirement['prerequisiteRole'])

@pytest.mark.parametrize('fault',['wrong-source-hash','foreign-path','cycle'])
def test_startup_graph_refuses_unbound_source_or_a_new_cycle(tmp_path,monkeypatch,fault):
    owner,authority,requirements,models,plan,save,source=startup_fixture(tmp_path,monkeypatch)
    if fault=='wrong-source-hash':owner.host._source_files['scripts/ob3-startup-prerequisites.json']['sha256']='f'*64
    if fault=='foreign-path':
        doc=json.loads(Path(authority['path']).read_bytes());doc['startupPrerequisites']=save('foreign-proof.json',json.loads(source.read_bytes()));authority=save('foreign-authority.json',doc)
    if fault=='cycle':
        models['elevenid-beta']['services']['organization']['depends_on']={'compliance-profile':{'condition':'service_healthy'}};plan['composeModels']['elevenid-beta']=save('cycle-model.json',models['elevenid-beta']);owner.inputs['maintenancePlan']=save('cycle-plan.json',plan)
    with pytest.raises(ValueError):owner.ob3_startup_plan(authority)

def fixture(tmp_path,monkeypatch):
    _startup,_authority,_requirements,_models,_plan,_save,source=startup_fixture(tmp_path,monkeypatch)
    original,partial,intent,prior,save,backend,created,prefix,_=partial_fixture(tmp_path,monkeypatch)
    ancillary={role:{'Id':f'{n+101:064x}'} for n,role in enumerate(['docs','nginx-proxy','openbao','postgres','redis','keycloak'])};prior['currentAncillary6']=save('capture/ancillary28.json',ancillary)
    prior_ref=save('quiesce-authority.json',prior)
    db_quiescence=save('original-database-quiescence.json',{})
    proof={'operationState':save('deep-database-state.json',{'quiescenceSha256':db_quiescence['sha256'],'executorSource':{'sha256':'DEEP_ORIGINAL_DATABASE_OWNER'}})}
    verified={'databaseIdentity':{'containerId':'SYNTHETIC_DATABASE'}}
    calls=[]
    def shared(inputs,state,applied,authority,*,operation_backend):
        assert inputs==original and state==partial and applied==intent and authority==prior and operation_backend==backend
        calls.append('SHARED_PARTIAL_AND_DEEP_DATABASE_CHECKPOINT')
        return {'executorSource':{'sha256':'DEEP_ORIGINAL_DATABASE_OWNER'}},proof,verified
    monkeypatch.setattr(execution,'partial_start_ob3_checkpoint',shared)
    # The separately tested maintained trust-model owner remains the sole domain
    # comparator. This source-boundary control records its call, never replaces
    # that owner in production or purports to qualify its synthetic model bytes.
    def trust(old,new):assert old==original;calls.append('EXISTING_TWO_CREDENTIAL_PATH_COMPARATOR')
    monkeypatch.setattr(database,'_recovery_trust_models',trust)
    original['runScopedTrustLeaseProof']=save('old-installed-sdk5.json',{'generationDirectory':'SYNTHETIC_OLD'})
    outcomes={role:{'observedExitCode':0,'deferred':False} for role in prefix};outcomes['passport-beta-bureau']={'observedExitCode':1,'deferred':True}
    current={};rows=[]
    for role,row in created.items():
        status='exited' if role in prefix or role=='passport-beta-bureau' else 'created';exit_code=1 if role=='passport-beta-bureau' else 0
        current[role]={'Id':row['containerId'],'Image':row['imageId'],'State':{'Status':status,'Running':False,'Pid':0,'Paused':False,'OOMKilled':False,'StartedAt':row['startedAt'],'ExitCode':exit_code}}
        rows.append({'role':role,'containerId':row['containerId'],'imageId':row['imageId'],'status':status,'running':False,'hostPid':0,'containerExitCode':exit_code,'startedAt':row['startedAt']})
    observation=save('actual-control-quiescence.json',{'schema':'marty.ob3-containment-observation/v1','phase':'OB3_PARTIAL_QUIESCENT','runId':original['runId'],'readinessScope':'OB3_FUNCTIONAL_ONLY','fullStackQualified':False,'functionalRuntimeQualified':False,'runningProcessQualified':False,'currentJobNormalClosureNotYetQualified':True,'roles':rows,'resources':rows+[{'role':role,'containerId':row['Id']} for role,row in ancillary.items()],'deferredFailure':prior['deferredFailure']})
    state={**partial,'phase':'OB3_PARTIAL_QUIESCENT','pendingStep':None,'pendingArgv':None,'pendingContainerId':None,'pendingRequest':None,'readinessScope':'OB3_FUNCTIONAL_ONLY','fullStackQualified':False,'releaseQualified':False,'recordingQualified':False,'deferredRoles':['passport-beta-bureau'],'allowedScenarios':list(execution.OB3_ALLOWED_SCENARIOS),'recoveryAuthority':prior_ref,'priorPartialStartState':prior['originalOperationState'],'originalOperationState':prior['originalOperationState'],'priorStartAcks':partial['startAcks'],'startAcks':{},'ob3Quiescence':observation,'ob3StopOutcomes':outcomes,'deferredFailure':prior['deferredFailure']}
    state_ref=save('quiescent-raw-state.json',state)
    inputs=deepcopy(original)
    for key in database.RECOVERY_SOURCE_FIELDS:inputs[key]={'sha256':'next-'+key}
    inputs['d12Authority']={'sha256':'NEXT_ROOT_APPROVAL'};inputs['runScopedTrustLeaseProof']=save('new-sdk6.json',{'generationDirectory':'SYNTHETIC_NEW'})
    closed={'state':'COMPLETE','exitCode':0,'jobClosed':True,'terminalActiveProcesses':0,**{key:False for key in ['forcedTermination','timedOut','cancelled','hostMarginBreached']}}
    job=save('normal-closed-job.json',closed);selected=save('current22.json',current)
    files={name:{'present':True,'document':value,'bytes':reference['bytes'],**journal_readback(Path(reference['path']).read_bytes())} for name,reference,value in [('build-state.json',state_ref,state),('build-apply-intent.json',prior['originalApplyIntent'],intent)]}
    for name in ['build-receipt.json','configuration-receipt.json']:files[name]={'present':False}
    journal=[{'state':'EXACT_ROOT_DURABLE_METADATA_READ_COMPLETE','mountReadOnly':True,'root':backend['rootProof'],'files':files}]
    resource=save('new-maintenance-envelope.json',{'ob3Quiescent':{'authority':prior_ref,'quiescence':observation,'quiescenceJob':job,'current22':selected,'current22Job':job}})
    recovery={'startupPrerequisites':__import__('scoped_native_runtime').ref(source),'schema':'marty.d12-ob3-quiescent-recovery/v1','operation':'REPLACE_OB3_QUIESCENT_CREDENTIALS_AND_RESUME','replaceCredentialGeneration':True,'dispatchAuthorized':True,'draftOnly':False,'runId':inputs['runId'],'scope':'OB3_FUNCTIONAL_ONLY','deferredRoles':['passport-beta-bureau'],'allowedScenarios':list(execution.OB3_ALLOWED_SCENARIOS),'originalInputs':save('executed-quiesce-inputs.json',original),'previousRecoveryAuthority':prior_ref,'originalOperationState':state_ref,'originalApplyIntent':prior['originalApplyIntent'],'databaseProof':state['databaseProof'],'verifiedDatabase':state['verifiedDatabase'],'deferredFailure':prior['deferredFailure'],'selected22':selected,'selected22Job':job,'quiescenceJob':job,'reconciliationJob':job,'journalRead':save('new-journal.json',journal),'quiescence':db_quiescence,'maintenanceResourceRecovery':resource,'sourceMap':{key:{'original':original[key],'recovery':inputs[key]} for key in database.RECOVERY_SOURCE_FIELDS},'trustDataMap':{key:{'original':original.get(key),'recovery':inputs.get(key)} for key in database.RECOVERY_TRUST_FIELDS}}
    return inputs,state,intent,recovery,save,backend,calls,journal,created

@pytest.mark.parametrize('fault',[None,'old-phase','pending','wrong-scope','fullstack','foreign-role','changed-exit','same-generation','source-map','raw-bytes','unclosed-job','old-postcreate'])
def test_ob3_quiescent_checkpoint_is_new_mode_and_delegates_original_database_owner(tmp_path,monkeypatch,fault):
    i,s,intent,r,save,backend,calls,journal,created=fixture(tmp_path,monkeypatch)
    if fault=='old-phase':s['phase']='EFFECT_ACKNOWLEDGED'
    elif fault=='pending':s['pendingStep']='START_auth'
    elif fault=='wrong-scope':r['scope']='FUNCTIONAL_ONLY'
    elif fault=='fullstack':s['fullStackQualified']=True
    elif fault=='foreign-role':
        rows=json.loads(Path(r['selected22']['path']).read_bytes());rows['foreign']=rows.pop('auth');r['selected22']=save('foreign-current22.json',rows)
    elif fault=='changed-exit':
        rows=json.loads(Path(r['selected22']['path']).read_bytes());rows['auth']['State']['ExitCode']=1;r['selected22']=save('changed-current22.json',rows)
    elif fault=='same-generation':
        original=json.loads(Path(r['originalInputs']['path']).read_bytes());i['runScopedTrustLeaseProof']=original['runScopedTrustLeaseProof'];r['trustDataMap']['runScopedTrustLeaseProof']['recovery']=i['runScopedTrustLeaseProof']
    elif fault=='source-map':r['sourceMap']['executorSource']['recovery']={'sha256':'FOREIGN'}
    elif fault=='raw-bytes':journal[0]['files']['build-state.json']['storedBytesBase64']='e30=';r['journalRead']=save('changed-journal.json',journal)
    elif fault=='unclosed-job':r['quiescenceJob']=save('not-closed.json',{'state':'COMPLETE','exitCode':0,'jobClosed':False})
    elif fault=='old-postcreate':
        envelope=json.loads(Path(r['maintenanceResourceRecovery']['path']).read_bytes());envelope['postCreate']={};r['maintenanceResourceRecovery']=save('hybrid-envelope.json',envelope)
    if fault:
        with pytest.raises((ValueError,AssertionError)):execution.ob3_quiescent_checkpoint(i,s,intent,r,operation_backend=backend)
    else:
        deepest,proof,_=execution.ob3_quiescent_checkpoint(i,s,intent,r,operation_backend=backend)
        assert deepest['executorSource']==json.loads(Path(proof['operationState']['path']).read_bytes())['executorSource']
        assert calls==['SHARED_PARTIAL_AND_DEEP_DATABASE_CHECKPOINT','EXISTING_TWO_CREDENTIAL_PATH_COMPARATOR']

@pytest.mark.parametrize('timing',['normal','slow-orchestration','cumulative-exhaustion','final-exhaustion'])
@pytest.mark.parametrize('readiness_failure',[False,True])
def test_shared_start_loop_starts_exact21_and_never_the_deferred_role(tmp_path,monkeypatch,readiness_failure,timing):
    clock=[0.0];wait_budgets=[]
    monkeypatch.setattr(execution.time,'monotonic',lambda:clock[0])
    def save(name,value):p=tmp_path/name;p.write_text(json.dumps(value));return {'path':str(p),'sha256':__import__('hashlib').sha256(p.read_bytes()).hexdigest(),'bytes':p.stat().st_size}
    startup,authority,requirements,_models,_plan,_save,_source=startup_fixture(tmp_path,monkeypatch);startup_plan=startup.ob3_startup_plan(authority)
    from scoped_native_profiles import current_rollout_build
    selected=dict(current_rollout_build('d05-membership-current-functional').roles);before={'roles':[]};created={'roles':[]};binaries={}
    for n,role in enumerate(sorted(D12_CURRENT_RUNTIME_ROLES)):
        row={'role':role,'containerId':f'{n+1:064x}','imageId':'sha256:'+'a'*64,'project':'elevenid-beta','state':'running','running':True,'hostPid':1,'startedAt':'2026-01-01T00:00:00Z','containerExitCode':0,'oomKilled':False,'binaryMounts':[]}
        if role in selected:
            path=tmp_path/selected[role];path.write_bytes(b'SYNTHETIC');binaries[role]={'path':str(path)};row['binaryMounts']=[{'type':'bind','source':str(path),'destination':'/usr/local/bin/'+selected[role],'writable':False}]
        before['roles'].append(row);next_row=deepcopy(row);next_row.update(state='created' if role in selected else 'exited',running=False,hostPid=0,containerExitCode=1 if role=='passport-beta-bureau' else 0)
        if role in selected:next_row['containerId']=f'{n+101:064x}'
        created['roles'].append(next_row)
    stopped=deepcopy(created)
    for row in stopped['roles']:
        if row['role'] in selected:row['containerId']=next(x['containerId'] for x in before['roles'] if x['role']==row['role'])
    value=execution.D12CurrentExecution.__new__(execution.D12CurrentExecution);value.i={'runId':'SYNTHETIC','d12RuntimeModule':{},'runtimeBefore':{},'selection':{}};value.profile='d05-membership-current-functional';value.roles=selected;value.native_preimage=None;value.read_only_preflight=False;value.state={'replacementPreimage':save('stopped.json',stopped),'steps':[]};value.build_profile=SimpleNamespace(ui_revision='source',core_revision='core');value.store=SimpleNamespace(state=lambda state:{'fileFsync':True,'parentDirectory':{'supported':True,'synced':True}})
    readiness_calls=[]
    def ready(seconds,authority,role,dependent,observed):
        assert 0<seconds<=120 and {'dependentRole':dependent,'prerequisiteRole':role,'readiness':'DOCKER_HEALTHY'} in requirements;readiness_calls.append((role,dependent))
        wait_budgets.append(seconds)
        clock[0]+=40 if timing=='cumulative-exhaustion' else 5
        if readiness_failure:raise ValueError('D12_OB3_PREREQUISITE_READINESS_DEADLINE')
        return save('ready-'+role+'-'+dependent+'.json',{'role':role,'dependentRole':dependent,'readiness':'DOCKER_HEALTHY','health':'healthy',**observed})
    def final_ready(seconds,ref):
        wait_budgets.append(seconds);clock[0]+=101 if timing=='final-exhaustion' else 1;return True
    value.g={'save':save,'wait_ob3_required_healthy':final_ready,'wait_ob3_prerequisite_ready':ready,'ob3_startup_plan':lambda ref:startup_plan};value.inspect_all22=lambda:deepcopy(created);calls=[]
    def command(db,step,args):
        clock[0]+=90 if timing=='slow-orchestration' else 0
        calls.append(step);assert step.startswith('START_') and 'passport-beta-bureau' not in step
    value.command=command
    original_record=value.record
    def record(*args,**kwargs):
        clock[0]+=30 if timing=='slow-orchestration' else 0
        return original_record(*args,**kwargs)
    value.record=record
    class ReachedObserver(Exception):pass
    reviewed=save('reviewed-ob3-authority.json',{'schema':'marty.d12-ob3-quiescent-recovery/v1'})
    def node(mode,**kwargs):assert mode=='runtime' and kwargs['inputs']['ob3Authority']==reviewed;raise ReachedObserver
    def inspect(args):
        role=next(row['role'] for row in created['roles'] if row['containerId']==args[-1]);row=next(row for row in created['roles'] if row['role']==role)
        return json.dumps([{'Id':row['containerId'],'Image':row['imageId'],'Config':{'Labels':{'com.docker.compose.project':row['project'],'com.docker.compose.service':role}},'State':{'Status':'running','Running':True,'OOMKilled':False,'Pid':100,'StartedAt':'2026-01-02T00:00:00Z'}}]).encode()
    db=SimpleNamespace(i={},selection={'binaries':binaries},engine_id='SYNTHETIC',node=node,command=inspect)
    if readiness_failure:
        with pytest.raises(ValueError,match='D12_OB3_PREREQUISITE_READINESS_DEADLINE'):value._finish_after_create(db,before,{'restoreOrder':startup_plan['order']},{},ob3_recovery=reviewed)
        assert 0<len(calls)<21 and value.state['phase']=='OB3_START_PREREQUISITE_PENDING'
        assert 'START_'+value.state['startupDependentRole'] not in calls and len(readiness_calls)==1
        return
    if timing in ('cumulative-exhaustion','final-exhaustion'):
        with pytest.raises(ValueError,match='D12_OB3_START_READINESS_DEADLINE'):value._finish_after_create(db,before,{'restoreOrder':startup_plan['order']},{},ob3_recovery=reviewed)
        assert wait_budgets==([120,80,40] if timing=='cumulative-exhaustion' else [120,115,110,105,100])
        return
    with pytest.raises(ReachedObserver):value._finish_after_create(db,before,{'restoreOrder':startup_plan['order']},{},ob3_recovery=reviewed)
    assert len(calls)==21 and set(calls)=={'START_'+role for role in D12_CURRENT_RUNTIME_ROLES-{'passport-beta-bureau'}}
    assert value.state['phase']=='OB3_21_STARTS_OBSERVED' and len(readiness_calls)==4
    assert wait_budgets==[120,115,110,105,100]
    if timing=='slow-orchestration':assert clock[0]>1800
