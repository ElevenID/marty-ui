'use strict';
// Controlled metadata only. These fixtures are not an observed beta checkpoint.
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const {maintenanceOb3QuiescentContext,verifyOb3ContainmentRuntime}=require('./functional-debug-runtime');
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const scenarios=['D01_ORGANIZATION_OB3','D05_MEMBERSHIP_OB3','D05_MEMBERSHIP_EXPIRED_NEGATIVE','D05_MEMBERSHIP_UNTRUSTED_NEGATIVE','D07_CANVAS_OB3'];
function fixture(t){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'ob3-quiescent-control-'));t.after(()=>{assert.equal(path.dirname(root),fs.realpathSync(os.tmpdir()));assert(path.basename(root).startsWith('ob3-quiescent-control-'));assert.equal(fs.realpathSync(root),root);assert(!fs.lstatSync(root).isSymbolicLink());fs.rmSync(root,{recursive:true});});
 const file=(name,value)=>{const p=path.join(root,name),raw=Buffer.from(JSON.stringify(value));fs.writeFileSync(p,raw);return {path:p,bytes:raw.length,sha256:sha(raw)};};
 const runId='8b5f5d22-eb3a-4a7f-b9e7-2cdcb651c8e0',imageId='sha256:'+'b'.repeat(64),time='2026-01-01T00:00:00Z';
 const names=['gateway','organization','auth','issuance-native','flow','credential-template','signing-keys','trust-profile','presentation-policy','compliance-profile','passport-beta-bureau',...Array.from({length:11},(_,i)=>'retained-'+i)];
 const owned={},ancillary={},live={},created={roles:[]},prefix={},outcomes={},resources=[],roles=[],modelRoles=[];
 for(const [i,role]of names.entries()){
  const cid=(i+1).toString(16).padStart(64,'0'),status=i>=4&&i<10?'created':'exited',exit=role==='passport-beta-bureau'?1:0;
  const config={Env:['SYNTHETIC=1'],Labels:{'com.docker.compose.project':'elevenid-beta','com.docker.compose.service':role}},host={Memory:67108864};
  const snapshot={Id:cid,Image:imageId,State:{Status:status,Running:false,Pid:0,Paused:false,OOMKilled:false,ExitCode:exit,StartedAt:time},HostConfig:host,Mounts:[],Labels:config.Labels};owned[role]=snapshot;
  live[cid]={...structuredClone(snapshot),Config:config};
  created.roles.push({role,containerId:cid,imageId,state:status,startedAt:time});modelRoles.push({role,containerId:cid,configSha256:sha(JSON.stringify(config))});
  if(i<4||i>=11&&i<18){prefix[role]={containerId:cid,imageId,startedAt:time,hostPid:i+1};outcomes[role]={observedExitCode:0,deferred:false};}
  const row={role,containerId:cid,imageId,status,running:false,hostPid:0,startedAt:time,containerExitCode:exit,configSha256:sha(JSON.stringify(config)),hostConfigSha256:sha(JSON.stringify(host)),mountsSha256:sha('[]')};roles.push(row);resources.push(row);
 }
 outcomes['passport-beta-bureau']={observedExitCode:1,deferred:true};
 for(const [i,role]of ['docs','keycloak','nginx-proxy','openbao','postgres','redis'].entries()){
  const cid=(i+100).toString(16).padStart(64,'0'),config={Env:['SYNTHETIC=1'],Labels:{'com.docker.compose.project':'elevenid-beta','com.docker.compose.service':role}},host={Memory:67108864};
  ancillary[role]={Id:cid,Image:imageId,State:{Status:'running',Running:true,Pid:i+100,StartedAt:time},HostConfig:host,Mounts:[],Labels:config.Labels};live[cid]={...structuredClone(ancillary[role]),Config:config,State:{...ancillary[role].State,Paused:false,OOMKilled:false,ExitCode:0}};
  resources.push({role,containerId:cid,imageId,status:'running',running:true,hostPid:i+100,startedAt:time,containerExitCode:0,configSha256:sha(JSON.stringify(config)),hostConfigSha256:sha(JSON.stringify(host)),mountsSha256:sha('[]')});
 }
 const job={schema:'marty.windows-job-result/v1',state:'COMPLETE',exitCode:0,jobClosed:true,terminalActiveProcesses:0,forcedTermination:false,timedOut:false,cancelled:false,hostMarginBreached:false};
 const runtimeBefore=file('runtime-before.json',{roles:created.roles}),failure=file('failure.json',{code:'SYNTHETIC_REVIEWED_DEFERRED_FAILURE'});
 const partial={schema:'marty.d12-current-native-operation/v1',runId,phase:'START_INSPECTION_PENDING',pendingStep:'INSPECT_START_passport-beta-bureau',pendingContainerId:owned['passport-beta-bureau'].Id,startAcks:prefix,created:file('created.json',created),sourceRevision:'c'.repeat(40),coreRevision:'d'.repeat(40),databaseProof:file('database-proof.json',{}),verifiedDatabase:file('database-verified.json',{}),tenantPreflight:file('tenant.json',{})};
 const authority={schema:'marty.d12-ob3-partial-start-recovery/v1',operation:'QUIESCE_OB3_PARTIAL_STARTS',scope:'OB3_FUNCTIONAL_ONLY',runId,dispatchAuthorized:true,draftOnly:false,allowedScenarios:scenarios,deferredRoles:['passport-beta-bureau'],runtimeBefore,engineId:'SYNTHETIC_ENGINE',selection:file('selection.json',{binaries:Object.fromEntries(names.slice(0,10).map(role=>[role,{}]))}),originalOperationState:file('partial.json',partial),currentOwned22:file('partial22.json',owned),currentAncillary6:file('ancillary6.json',ancillary),createdTargetVerification:file('model-proof.json',{state:'ACTUAL_CREATED_TARGET_MODEL_BOUND_BY_CURRENT_OWNER',runId,currentJobNormalClosureNotYetQualified:true,roles:modelRoles}),ancillaryResourceBinding:file('resource-proof.json',{scope:'MAINTENANCE_RECOVERY_ONLY',resources}),deferredFailure:failure,deferredStopContract:file('stop-contract.json',{schema:'marty.reviewed-deferred-startup-stop/v1',role:'passport-beta-bureau',containerId:partial.pendingContainerId,signal:'SIGTERM',noAutomaticSigkill:true,gracefulShutdownVerified:false,allowedExitCodes:[0,1,143]})};
 const baseline=authority.ancillaryResourceBinding;
 const original={runId,runtimeBefore,selection:authority.selection,plannedModels:{'elevenid-beta':file('installed-model.json',{})},composeArguments:['SYNTHETIC_COMPOSE_ARGUMENTS'],roleBinaries:Object.fromEntries(names.slice(0,10).map(role=>[role,{}])),runScopedTrustLeaseProof:file('lease.json',{validationRequest:file('lease-validation.json',{recoveryPrerequisites:{resourceObservation:baseline}})})};
 authority.originalInputs=file('original-inputs.json',original);authority.created=partial.created;authority.previousRecoveryAuthority=file('previous-authority.json',{});authority.reconciliationJob=file('partial-read-job.json',job);authority.deferredFailureJob=authority.reconciliationJob;
 const targetAck=file('target-ack.json',{phase:'EFFECT_ACKNOWLEDGED',acknowledgedStep:'REPLACE_CREATED_CREDENTIAL_GENERATION',replacementAuthority:authority.previousRecoveryAuthority});
 authority.createdTargetRequest=file('target-request.json',{...original,engineId:authority.engineId,acknowledgedState:targetAck,createdCids:file('created-cids.json',{selection:original.selection,selectedContainerIds:Object.fromEntries(names.slice(0,10).map(role=>[role,owned[role].Id]))})});
 authority.createdTargetTerminal=file('target-terminal.json',{exitCode:0,observation:{timedOut:false,failures:[]}});
 authority.createdTargetVerification=file('model-proof.json',{state:'ACTUAL_CREATED_TARGET_MODEL_BOUND_BY_CURRENT_OWNER',acknowledgedStep:'REPLACE_CREATED_CREDENTIAL_GENERATION',runId,currentJobNormalClosureNotYetQualified:true,roles:modelRoles});
 const quiescence={schema:'marty.ob3-containment-observation/v1',phase:'OB3_PARTIAL_QUIESCENT',runId,readinessScope:'OB3_FUNCTIONAL_ONLY',fullStackQualified:false,functionalRuntimeQualified:false,runningProcessQualified:false,currentJobNormalClosureNotYetQualified:true,resources,roles,startedRoles:Object.keys(prefix),notStartedInCurrentAttempt:names.filter(role=>role!=='passport-beta-bureau'&&!Object.hasOwn(prefix,role)),deferredFailure:failure};
 const post={authority:file('authority.json',authority),quiescence:file('quiescence.json',quiescence),quiescenceJob:file('quiescence-job.json',job),current22:file('current22.json',owned),current22Job:file('current22-job.json',job)};
 const state={...partial,phase:'OB3_PARTIAL_QUIESCENT',pendingStep:null,pendingArgv:null,pendingContainerId:null,pendingRequest:null,readinessScope:'OB3_FUNCTIONAL_ONLY',fullStackQualified:false,allowedScenarios:scenarios,deferredRoles:['passport-beta-bureau'],recoveryAuthority:post.authority,ob3Quiescence:post.quiescence,priorPartialStartState:authority.originalOperationState,originalOperationState:authority.originalOperationState,priorStartAcks:prefix,startAcks:{},ob3StopOutcomes:outcomes,deferredFailure:failure};
 const recovery={runId,runtimeBefore,ob3Quiescent:post};
 const read=argv=>{if(JSON.stringify(argv)===JSON.stringify(['info','--format','{{json .}}']))return JSON.stringify({ID:authority.engineId});assert.equal(argv.length,2);assert.equal(argv[0],'inspect');assert(live[argv[1]],'SYNTHETIC_SCOPE_ONLY');return JSON.stringify([live[argv[1]]]);};
 return {file,job,post,state,recovery,quiescence,owned,live,outcomes,authority,original,invoke:()=>maintenanceOb3QuiescentContext(recovery,state),read};
}
test('controlled OB3 checkpoint preserves mixed created/exited states and deferred exit1 without postCreate',t=>{
 const f=fixture(t),context=f.invoke();assert.equal(context.current['passport-beta-bureau'].State.ExitCode,1);assert.equal(Object.values(context.current).filter(row=>row.State.Status==='created').length,6);assert.equal(context.quiescence.fullStackQualified,false);assert.equal(f.recovery.postCreate,undefined);
 const fresh=verifyOb3ContainmentRuntime({}, {recoveryRef:f.post.authority,readDocker:f.read,phase:'QUIESCENT',outcomes:f.outcomes});assert.deepEqual(fresh,f.quiescence);assert(!Object.hasOwn(fresh,'neverStartedRoles'));assert.equal(fresh.notStartedInCurrentAttempt.length,10);
});
for(const fault of ['old-phase','postCreate','pending','wrong-authority','wrong-raw-checkpoint-ref','unclosed-job','foreign-current-cid','bureau-healthy-exit','other-role-exit1','mount-drift','false-fullstack'])test('OB3 quiescent metadata refuses '+fault,t=>{
 const f=fixture(t);
 if(fault==='old-phase')f.state.phase='EFFECT_ACKNOWLEDGED';
 if(fault==='postCreate')f.recovery.postCreate={};
 if(fault==='pending')f.state.pendingStep='START_auth';
 if(fault==='wrong-authority')f.state.recoveryAuthority=f.file('wrong-authority.json',{});
 if(fault==='wrong-raw-checkpoint-ref')f.state.priorPartialStartState=f.file('wrong-partial.json',{});
 if(fault==='unclosed-job')f.post.current22Job=f.file('unclosed-job.json',{...f.job,jobClosed:false});
 if(fault==='foreign-current-cid')f.owned.gateway.Id='f'.repeat(64);
 if(fault==='bureau-healthy-exit')f.owned['passport-beta-bureau'].State.ExitCode=0;
 if(fault==='other-role-exit1')f.owned.auth.State.ExitCode=1;
 if(fault==='mount-drift')f.owned.auth.Mounts.push({Destination:'/foreign',Type:'bind',Source:'/foreign',RW:false});
 if(fault==='false-fullstack')f.state.fullStackQualified=true;
 f.post.current22=f.file('changed-current22.json',f.owned);assert.throws(f.invoke);
});
for(const fault of ['environment','full-hostconfig','image','generation','running','deferred-other-exit'])test('fresh controlled OB3 containment refuses '+fault,t=>{
 const f=fixture(t);f.invoke();const row=f.live[f.owned.auth.Id];
 if(fault==='environment')row.Config.Env.push('FOREIGN=1');
 if(fault==='full-hostconfig')row.HostConfig.Extra='changed';
 if(fault==='image')row.Image='sha256:'+'e'.repeat(64);
 if(fault==='generation')row.Id='f'.repeat(64);
 if(fault==='running'){row.State.Status='running';row.State.Running=true;row.State.Pid=17;}
 if(fault==='deferred-other-exit')row.State.ExitCode=1;
 assert.throws(()=>verifyOb3ContainmentRuntime({}, {recoveryRef:f.post.authority,readDocker:f.read,phase:'QUIESCENT',outcomes:f.outcomes}));
});

for(const fault of ['selection-ref','created-ref','model-arguments','target-terminal','selected-cids','ancillary-baseline'])test('containment source chain refuses '+fault+' before any Docker read',t=>{
 const f=fixture(t),authority=structuredClone(f.authority),load=ref=>JSON.parse(fs.readFileSync(ref.path));
 if(fault==='selection-ref')authority.selection=f.file('foreign-selection.json',{});
 if(fault==='created-ref')authority.created=f.file('foreign-created.json',{});
 if(fault==='model-arguments'){const request=load(authority.createdTargetRequest);request.composeArguments=['FOREIGN'];authority.createdTargetRequest=f.file('foreign-request.json',request);}
 if(fault==='target-terminal')authority.createdTargetTerminal=f.file('foreign-terminal.json',{exitCode:1,observation:{timedOut:false,failures:[]}});
 if(fault==='selected-cids'){const request=load(authority.createdTargetRequest),proof=load(request.createdCids);proof.selectedContainerIds.auth='f'.repeat(64);request.createdCids=f.file('foreign-cids.json',proof);authority.createdTargetRequest=f.file('foreign-request.json',request);}
 if(fault==='ancillary-baseline')authority.ancillaryResourceBinding=f.file('foreign-resource.json',{});
 let reads=0;assert.throws(()=>verifyOb3ContainmentRuntime({}, {recoveryRef:f.file('changed-authority.json',authority),phase:'QUIESCENT',outcomes:f.outcomes,readDocker:()=>{reads++;throw Error('NO_DOCKER_ALLOWED');}}));assert.equal(reads,0);
});
