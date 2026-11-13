"""OB3 containment source controls only; no Docker, SQL, credentials or runtime claims."""
from copy import deepcopy
import hashlib,json,pathlib,subprocess,sys,shutil
from types import SimpleNamespace
import pytest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'scripts'))
import scoped_d12_native_execution as execution
import scoped_d12_native_effect_host as host_module
from scoped_native_runtime import ref,journal_readback,D12_CURRENT_RUNTIME_ROLES
from scoped_native_database import RECOVERY_SOURCE_FIELDS

def fixture(tmp_path,monkeypatch):
 def save(name,value):
  p=tmp_path/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(value));return ref(p)
 roles=sorted(D12_CURRENT_RUNTIME_ROLES);prefix=['canvas-sync-worker','compliance-profile','deployment-profile','device-registration','event-stream','notification','organization','passport-callback-signer','signing-keys','trust-profile','ui-prod']
 order=prefix+['passport-beta-bureau']+[r for r in roles if r not in prefix and r!='passport-beta-bureau']
 rows={role:{'role':role,'containerId':f'{n+1:064x}','imageId':'sha256:'+'a'*64,'state':'created','hostPid':0,'startedAt':'2026-01-01T00:00:00Z'} for n,role in enumerate(roles)}
 created=save('attempt/outputs/created.json',{'roles':list(rows.values())})
 proof=save('proof.json',{});verified=save('verified.json',{})
 from scoped_native_profiles import current_rollout_build
 build=current_rollout_build('d05-membership-current-functional')
 original={'runId':'SYNTHETIC','scope':'FUNCTIONAL_ONLY','uiRevision':build.ui_revision,'coreRevision':build.core_revision,'rolloutProfile':'d05-membership-current-functional',
  'buildProfile':None,'releaseQualified':False,'recordingQualified':False,'dispatchEnabled':True,'applyAuthorized':True,
  'roleBinaries':dict(build.roles),'plannedModels':{},'composeArguments':['docker','compose','SYNTHETIC'],
  'runtimeBefore':save('before.json',{'roles':list(rows.values())}),'selection':save('selection.json',{}),
  'maintenancePlan':save('plan.json',{'composeModels':{'elevenid-beta':save('model.json',{})}}),'d12Authority':{'sha256':'old'}}
 for key in RECOVERY_SOURCE_FIELDS:original[key]={'sha256':'old-'+key}
 ancestor=save('ancestor.json',{});intent={'runId':'SYNTHETIC'};ir=save('intent.json',intent)
 previous={'operation':'REPLACE_ACKNOWLEDGED_CREDENTIAL_GENERATION_AND_RESUME','originalOperationState':ancestor,
  'originalApplyIntent':ir,'sourceMap':{key:{'recovery':original[key]} for key in RECOVERY_SOURCE_FIELDS},'databaseProof':proof,'verifiedDatabase':verified}
 previous_ref=save('previous.json',previous)
 state={'schema':'marty.d12-current-native-operation/v1','scope':'FUNCTIONAL_ONLY','phase':'START_INSPECTION_PENDING','runId':'SYNTHETIC','sourceRevision':build.ui_revision,'coreRevision':build.core_revision,
  'pendingStep':'INSPECT_START_passport-beta-bureau','acknowledgedStep':'START_passport-beta-bureau','pendingArgv':None,'pendingContainerId':rows['passport-beta-bureau']['containerId'],
  'databaseProof':proof,'verifiedDatabase':verified,'replacementAuthority':previous_ref,'recoveryAuthority':previous_ref,'created':created,
  'steps':['START_'+role for role in prefix],'startAcks':{role:{'containerId':rows[role]['containerId'],'imageId':rows[role]['imageId'],'startedAt':'2026-01-02T00:00:00Z','hostPid':n+10} for n,role in enumerate(prefix)}}
 selection=original['selection'];resource=save('baseline.json',{})
 original['runScopedTrustLeaseProof']=save('expired-lease.json',{'validationRequest':save('sdk-metadata.json',{'recoveryPrerequisites':{'resourceObservation':resource}}),'actualNativeGrantExpiryUnixSeconds':1})
 original_ref=save('original-inputs.json',original);inputs=deepcopy(original)
 for key in RECOVERY_SOURCE_FIELDS:inputs[key]={'sha256':'new-'+key}
 inputs['d12Authority']={'sha256':'new'}
 state_ref=save('partial-state.json',state)
 target_ack=save('attempt/outputs/target-ack.json',{'phase':'EFFECT_ACKNOWLEDGED','acknowledgedStep':'REPLACE_CREATED_CREDENTIAL_GENERATION','replacementAuthority':previous_ref})
 cids=save('attempt/outputs/cids.json',{'selection':selection,'selectedContainerIds':{r:rows[r]['containerId'] for r in inputs['roleBinaries']}})
 target_request=save('attempt/outputs/target-request.json',{'runId':'SYNTHETIC','selection':selection,'runtimeBefore':inputs['runtimeBefore'],'plannedModels':inputs['plannedModels'],'composeArguments':inputs['composeArguments'],'engineId':'SYNTHETIC_ENGINE','acknowledgedState':target_ack,'createdCids':cids})
 target=save('attempt/outputs/target.json',{'state':'ACTUAL_CREATED_TARGET_MODEL_BOUND_BY_CURRENT_OWNER','runId':'SYNTHETIC','acknowledgedStep':'REPLACE_CREATED_CREDENTIAL_GENERATION','currentJobNormalClosureNotYetQualified':True,'roles':[{'role':r,'containerId':rows[r]['containerId']} for r in roles]})
 terminal=save('attempt/outputs/terminal.json',{'exitCode':0,'observation':{'timedOut':False,'failures':[]}})
 closed={'state':'COMPLETE','exitCode':0,'jobClosed':True,'terminalActiveProcesses':0,**{k:False for k in ['timedOut','forcedTermination','cancelled','hostMarginBreached']}}
 job=save('read-job.json',closed)
 root={'device':1,'inode':2,'uid':1000,'mode':448}
 files={name:{'present':True,'document':value,'bytes':reference['bytes'],**journal_readback(pathlib.Path(reference['path']).read_bytes())} for name,reference,value in [('build-state.json',state_ref,state),('build-apply-intent.json',ir,intent)]}
 for name in ['build-receipt.json','configuration-receipt.json']:files[name]={'present':False}
 observed=[{'state':'EXACT_ROOT_DURABLE_METADATA_READ_COMPLETE','mountReadOnly':True,'root':root,'files':files}]
 failure=save('capture/failure.json',{'containerId':rows['passport-beta-bureau']['containerId'],'qualification':False,'rawLogsRetained':False,'sqlstate42501Observed':True,'permissionDeniedForSchemaObserved':True,'issuanceServiceSchemaObserved':True})
 recovery={'schema':'marty.d12-ob3-partial-start-recovery/v1','operation':'QUIESCE_OB3_PARTIAL_STARTS','scope':'OB3_FUNCTIONAL_ONLY','draftOnly':False,'dispatchAuthorized':True,'runId':'SYNTHETIC','deferredRoles':['passport-beta-bureau'],'allowedScenarios':list(execution.OB3_ALLOWED_SCENARIOS),
  'originalInputs':original_ref,'previousRecoveryAuthority':previous_ref,'originalOperationState':state_ref,'originalApplyIntent':ir,'runtimeBefore':inputs['runtimeBefore'],'selection':selection,'created':created,'engineId':'SYNTHETIC_ENGINE',
  'createdTargetRequest':target_request,'createdTargetVerification':target,'createdTargetTerminal':terminal,'ancillaryResourceBinding':resource,
  'currentOwned22':save('capture/owned.json',{}),'currentAncillary6':save('capture/ancillary.json',{}),'journalRead':save('journal.json',observed),'reconciliationJob':job,'deferredFailureJob':job,'deferredFailure':failure,
  'failedCutoverJob':save('failed-job.json',{**closed,'state':'FAILED','exitCode':1}),
  'deferredStopContract':save('deferred-stop.json',{'schema':'marty.reviewed-deferred-startup-stop/v1','role':'passport-beta-bureau','containerId':rows['passport-beta-bureau']['containerId'],'imageId':rows['passport-beta-bureau']['imageId'],'allowedExitCodes':[0,1,143],'signal':'SIGTERM','noAutomaticSigkill':True,'gracefulShutdownVerified':False}),
  'sourceMap':{key:{'original':original[key],'recovery':inputs[key]} for key in RECOVERY_SOURCE_FIELDS}}
 def prior(i,s,intent_value,r,*,operation_backend):
  assert i==original and s=={} and intent_value==intent and r==previous and operation_backend=={'rootProof':root}
  return original,proof,verified
 monkeypatch.setattr(execution,'created_recovery_checkpoint',prior)
 monkeypatch.setattr(execution.maintenance,'preview',lambda *args:{'restoreOrder':order,'stopSteps':[{'role':r} for r in reversed(order)]})
 return inputs,state,intent,recovery,save,{'rootProof':root},rows,prefix,observed

@pytest.mark.parametrize('fault',[None,'scope','pending','prefix','runtime-ref','selection-ref','target-model','failure','root','receipt'])
def test_partial_checkpoint_exact_recorded_shape_and_refusals(tmp_path,monkeypatch,fault):
 i,s,intent,r,save,backend,rows,prefix,observed=fixture(tmp_path,monkeypatch)
 if fault=='scope':r['scope']='FUNCTIONAL_ONLY'
 elif fault=='pending':s['pendingStep']='START_auth'
 elif fault=='prefix':s['steps'].pop()
 elif fault=='runtime-ref':r['runtimeBefore']=save('foreign-before.json',{})
 elif fault=='selection-ref':r['selection']=save('foreign-selection.json',{})
 elif fault=='target-model':
  q=json.loads(pathlib.Path(r['createdTargetRequest']['path']).read_bytes());q['plannedModels']={'foreign':{}};r['createdTargetRequest']=save('attempt/outputs/changed-target.json',q)
 elif fault=='failure':
  q=json.loads(pathlib.Path(r['deferredFailure']['path']).read_bytes());q['sqlstate42501Observed']=False;r['deferredFailure']=save('capture/changed-failure.json',q)
 elif fault=='root':backend['rootProof']['inode']=3
 elif fault=='receipt':observed[0]['files']['build-receipt.json']={'present':True};r['journalRead']=save('consumed.json',observed)
 if fault:
  with pytest.raises((ValueError,AssertionError)):execution.partial_start_ob3_checkpoint(i,s,intent,r,operation_backend=backend)
 else:
  original,_,_=execution.partial_start_ob3_checkpoint(i,s,intent,r,operation_backend=backend);assert original['runId']==i['runId']

@pytest.mark.parametrize('bureau_exit',[0,1,143])
def test_quiescence_durable_stops_only_current_prefix_preserves_history_no_lease(tmp_path,monkeypatch,bureau_exit):
 i,s,intent,r,save,backend,rows,prefix,_=fixture(tmp_path,monkeypatch)
 current={'state':deepcopy(s)};calls=[]
 def persist(value):current['state']=deepcopy(value);return {'fileFsync':True,'parentDirectory':{'supported':True,'synced':True}}
 value=execution.D12CurrentExecution.__new__(execution.D12CurrentExecution);value.i=i;value.profile=i['rolloutProfile'];value.read_only_preflight=False;value.state={}
 value.store=SimpleNamespace(specification=backend,read=lambda name:current['state'] if name=='build-state.json' else intent,state=persist)
 steps=[{'role':role,'containerId':rows[role]['containerId'],'argv':['docker','stop',rows[role]['containerId']]} for role in [*prefix,'passport-beta-bureau']]
 def stop(approval,step):
  assert current['state']['phase']=='OB3_STOP_PENDING' and current['state']['pendingArgv']==step['argv'];calls.append(step['role'])
  return {'containerId':step['containerId'],'state':'exited','running':False,'hostPid':0,'oomKilled':False,'containerExitCode':bureau_exit if step['role']=='passport-beta-bureau' else 0}
 q=save('quiescent.json',{'schema':'marty.ob3-containment-observation/v1'})
 value.g={'operation_lock_held':lambda:True,'recording_lock_held':lambda:True,'ob3_quiesce_authorization_verified':lambda *a:True,
  'ob3_quiesce_steps':lambda *a:steps,'ob3_stop_owned_role':stop,'observe_ob3_quiescence':lambda *a:q}
 result=value.quiesce_ob3_partial_starts(save('approved-ob3.json',r))
 assert calls==[*prefix,'passport-beta-bureau'] and current['state']['phase']=='OB3_PARTIAL_QUIESCENT'
 assert current['state']['startAcks']=={} and current['state']['priorStartAcks']==s['startAcks']
 assert result['fullStackQualified'] is False and result['runningProcessQualified'] is False


def test_containment_node_routes_real_script_arguments_6_8(tmp_path,monkeypatch):
 module=tmp_path/'tests/scripts/functional-debug-runtime.js';module.parent.mkdir(parents=True)
 module.write_text("const a=require('node:assert/strict');exports.verifyOb3ContainmentRuntime=(p,o)=>{a.equal(o.phase,'PARTIAL');a.deepEqual(o.outcomes,{});a.equal(o.recoveryRef.sha256,'44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a');return {schema:'marty.ob3-containment-observation/v1',runId:'SYNTHETIC',phase:'OB3_PARTIAL_STARTS_OWNED',fullStackQualified:false,resources:Array(28).fill({}),roles:Array(22).fill({})};};")
 profile=tmp_path/'profile.json';profile.write_text('{}')
 owner=host_module.D12CurrentHostBindings.__new__(host_module.D12CurrentHostBindings);owner.inputs={'runId':'SYNTHETIC','functionalRuntimeModule':ref(module),'resourceProfile':ref(profile)}
 owner.host=SimpleNamespace(_root=tmp_path,_source_files={'tests/scripts/functional-debug-runtime.js':ref(module)})
 owner.assert_inputs=lambda:None;owner.lock=SimpleNamespace(held=lambda:True);owner.node=shutil.which('node');owner.docker='READ_BARRIER';owner.environment={}
 record={};owner.save=lambda name,value:record.setdefault(name,value);owner.save_bytes=lambda name,value:record.setdefault(name,value)
 recovery=tmp_path/'recovery.json';recovery.write_text('{}')
 def run(argv,**kwargs):
  assert 'verifyOb3ContainmentRuntime' in argv[2] and 'verifyFunctionalRuntime(profile' not in argv[2]
  out=subprocess.run(argv,capture_output=True,check=False);return SimpleNamespace(returncode=out.returncode,stdout=out.stdout,stderr=out.stderr,observation={'timedOut':False,'failures':[]})
 monkeypatch.setattr(host_module,'bounded_run',run)
 result=owner._ob3_containment_read(ref(recovery),'PARTIAL',{})
 assert result['phase']=='OB3_PARTIAL_STARTS_OWNED'


def test_quiescence_unknown_stop_keeps_pending_and_never_retries(tmp_path,monkeypatch):
 i,s,intent,r,save,backend,rows,prefix,_=fixture(tmp_path,monkeypatch);current={'state':deepcopy(s)};calls=[]
 def persist(value):current['state']=deepcopy(value);return {'fileFsync':True,'parentDirectory':{'supported':True,'synced':True}}
 value=execution.D12CurrentExecution.__new__(execution.D12CurrentExecution);value.i=i;value.profile=i['rolloutProfile'];value.read_only_preflight=False;value.state={}
 value.store=SimpleNamespace(specification=backend,read=lambda name:current['state'] if name=='build-state.json' else intent,state=persist)
 steps=[{'role':role,'containerId':rows[role]['containerId'],'argv':['docker','stop',rows[role]['containerId']]} for role in [*prefix,'passport-beta-bureau']]
 def unknown(*args):calls.append('STOP_UNKNOWN');raise ValueError('OWNED_COMMAND_UNKNOWN')
 value.g={'operation_lock_held':lambda:True,'recording_lock_held':lambda:True,'ob3_quiesce_authorization_verified':lambda *a:True,
  'ob3_quiesce_steps':lambda *a:steps,'ob3_stop_owned_role':unknown,'observe_ob3_quiescence':lambda *a:pytest.fail('UNKNOWN_CANNOT_BECOME_QUIESCENT')}
 with pytest.raises(ValueError,match='OWNED_COMMAND_UNKNOWN'):value.quiesce_ob3_partial_starts(save('approved-ob3.json',r))
 assert calls==['STOP_UNKNOWN'] and current['state']['phase']=='OB3_STOP_PENDING'
 assert current['state']['pendingStep']=='OB3_STOP_'+prefix[0]

@pytest.mark.parametrize('wrong_cid',[False,True])
def test_host_quiesce_steps_use_real_source_contracts_exact_cids(tmp_path,monkeypatch,wrong_cid):
 i,s,intent,r,save,backend,rows,prefix,_=fixture(tmp_path,monkeypatch)
 current={role:{**rows[role],'binary':'marty-'+role,'sha256':'a'*64,'source':'source'} for role in rows}
 current['ui-prod'].update(binary=None,sha256=None,kind='SIGNED_NIGHTLY_IMAGE')
 contracts={}
 for role in prefix:
  row=current[role]
  if role=='ui-prod':
   obs=save('ui-observation.json',{'schema':'marty.ui-image-stop-observation/v1','role':role,'containerId':row['containerId'],'imageId':row['imageId'],'sourceRevision':'source','configuredStopSignal':'SIGQUIT','entrypoint':'/docker-entrypoint.sh','command':['nginx','-g','daemon off;'],'exitCode':0,'runtimeWrites':False,'stopExecuted':False})
   proof=save('ui-proof.json',{'schema':'marty.graceful-shutdown-image-source-proof/v1','role':role,'sourceRevision':'source','imageId':row['imageId'],'supportedSignals':['SIGQUIT'],'imageObservation':obs,'stopExecuted':False})
   policy={'schema':'marty.reviewed-graceful-image-stop/v1','role':role,'containerId':row['containerId'],'imageId':row['imageId'],'sourceRevision':'source','signal':'SIGQUIT','allowedExitCodes':[0],'noAutomaticSigkill':True,'sourceProof':proof,'imageObservation':obs}
  else:
   proof=save(role+'-proof.json',{'schema':'marty.graceful-shutdown-source-proof/v1','role':role,'sourceRevision':'source','elfSha256':'a'*64,'supportedSignals':['SIGTERM']})
   policy={'schema':'marty.reviewed-graceful-stop/v1','role':role,'containerId':row['containerId'],'sourceRevision':'source','elfSha256':'a'*64,'signal':'SIGTERM','allowedExitCodes':[0],'noAutomaticSigkill':True,'sourceProof':proof}
  if wrong_cid and role==prefix[0]:policy['containerId']='f'*64
  contracts[role]=save(role+'-stop.json',policy)
 r['stopContracts']=contracts;rr=save('source-approved.json',r)
 owner=host_module.D12CurrentHostBindings.__new__(host_module.D12CurrentHostBindings);owner.inputs=i;owner.profile=i['rolloutProfile'];owner._ob3_quiesce_approval=rr;owner.store=SimpleNamespace(read=lambda name:s)
 owner.observer=SimpleNamespace(current=current,inspect_role=lambda role:current[role])
 if wrong_cid:
  with pytest.raises(ValueError,match='EXACT_STOP_CONTRACT_REQUIRED'):owner.ob3_quiesce_steps(rr)
 else:
  steps=owner.ob3_quiesce_steps(rr);assert {v['role'] for v in steps}==set(prefix)|{'passport-beta-bureau'}
  for step in steps:
   assert step['argv']==['docker','stop','--signal','SIGQUIT' if step['role']=='ui-prod' else 'SIGTERM','--time','-1',current[step['role']]['containerId']]


@pytest.mark.parametrize('fault',[None,'disabled','old-execution-ref'])
def test_containment_authority_requires_enabled_actual_execution_source(tmp_path,monkeypatch,fault):
 i,state,intent,recovery,save,backend,rows,prefix,_=fixture(tmp_path,monkeypatch)
 root=pathlib.Path(execution.__file__).resolve().parents[1];actual=ref(pathlib.Path(execution.__file__).resolve())
 i['executionSource']=actual;recovery['sourceMap']['executionSource']['recovery']=actual
 owner=host_module.D12CurrentHostBindings.__new__(host_module.D12CurrentHostBindings)
 owner.profile=i['rolloutProfile'];owner.inputs=i;owner.assert_inputs=lambda:None
 owner.host=SimpleNamespace(_root=root,_source_files={'scripts/scoped_d12_native_execution.py':actual},engine_id='SYNTHETIC_ENGINE')
 owner.lock=SimpleNamespace(held=lambda:True)
 owner.store=SimpleNamespace(specification=backend,read=lambda name:state if name=='build-state.json' else intent)
 owner.observer=SimpleNamespace(bind_ob3_partial_created=lambda *a:None)
 called=[];owner._ob3_containment_read=lambda *a:called.append('ACTUAL_CURRENT28_BOUND') or {}
 if fault=='disabled':i['dispatchEnabled']=False
 if fault=='old-execution-ref':i['executionSource']=save('old-execution.py',{'oldCode':True})
 rr=save('held-ob3-authority.json',recovery)
 authority={'schema':'marty.d12-current-native-authority/v1','scope':'OB3_FUNCTIONAL_ONLY','dispatchAuthorized':True,'draftOnly':False,'runId':i['runId'],
  'approvedRecoveryAuthoritySha256':rr['sha256'],'approvedExecutionSourceSha256':i['executionSource']['sha256'],
  'approvedFunctionalRuntimeSha256':i['functionalRuntimeModule']['sha256'],'approvedRuntimeReaderSha256':i['d12RuntimeModule']['sha256'],
  'approvedProfileSourceSha256':hashlib.sha256((root/'scripts/scoped_native_profiles.py').read_bytes()).hexdigest(),
  'approvedSelectionSha256':i['selection']['sha256'],'allowedScenarios':list(execution.OB3_ALLOWED_SCENARIOS),'deferredRoles':['passport-beta-bureau']}
 ar=save('held-root-authority.json',authority);i['d12Authority']=ar;owner.dispatch_permit={'scope':'OB3_FUNCTIONAL_ONLY','authority':ar}
 if fault:
  with pytest.raises(ValueError,match='D12_OB3_CURRENT_EXECUTION_AND_ENABLED_INPUTS_REQUIRED'):owner.ob3_quiesce_authorization_verified(ar,rr)
  assert not called
 else:
  assert owner.ob3_quiesce_authorization_verified(ar,rr) is True
  assert called==['ACTUAL_CURRENT28_BOUND']
