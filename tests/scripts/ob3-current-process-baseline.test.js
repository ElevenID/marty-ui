'use strict';
// Controlled metadata only; no observed beta runtime qualification.
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const {maintenanceOb3QuiescentContext,verifyOb3ContainmentRuntime}=require('./functional-debug-runtime');
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const scenarios=['D01_ORGANIZATION_OB3','D05_MEMBERSHIP_OB3','D05_MEMBERSHIP_EXPIRED_NEGATIVE','D05_MEMBERSHIP_UNTRUSTED_NEGATIVE','D07_CANVAS_OB3'];
function fixture(t){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'ob3-quiescent-control-'));t.after(()=>{assert.equal(path.dirname(root),fs.realpathSync(os.tmpdir()));assert(path.basename(root).startsWith('ob3-quiescent-control-'));assert.equal(fs.realpathSync(root),root);assert(!fs.lstatSync(root).isSymbolicLink());fs.rmSync(root,{recursive:true});});
 const file=(name,value)=>{const p=path.join(root,name),raw=Buffer.from(JSON.stringify(value));fs.writeFileSync(p,raw);return {path:p,bytes:raw.length,sha256:sha(raw)};};
 const runId='8b5f5d22-eb3a-4a7f-b9e7-2cdcb651c8e0',imageId='sha256:'+'b'.repeat(64),time='2026-01-01T00:00:00Z';
 const names=['gateway','organization','auth','issuance-native','flow','credential-template','signing-keys','trust-profile','presentation-policy','compliance-profile','passport-beta-bureau','canvas-sync-worker','deployment-profile','device-registration','event-stream','notification','passport-callback-signer','ui-prod','applicant','issuance','verification','revocation-profile'];
 const owned={},ancillary={},live={},created={roles:[]},prefix={},outcomes={},resources=[],roles=[],modelRoles=[];
 for(const [i,role]of names.entries()){
  const cid=(i+1).toString(16).padStart(64,'0'),status=['gateway','auth','issuance-native','flow','credential-template','presentation-policy'].includes(role)?'created':'exited',exit=role==='passport-beta-bureau'?1:0;
  const config={Env:['SYNTHETIC=1'],Labels:{'com.docker.compose.project':'elevenid-beta','com.docker.compose.service':role}},host={Memory:67108864};
  const snapshot={Id:cid,Image:imageId,State:{Status:status,Running:false,Pid:0,Paused:false,OOMKilled:false,ExitCode:exit,StartedAt:time},HostConfig:host,Mounts:[],Labels:config.Labels};owned[role]=snapshot;
  live[cid]={...structuredClone(snapshot),Config:config};
  created.roles.push({role,containerId:cid,imageId,state:status,startedAt:time});modelRoles.push({role,containerId:cid,configSha256:sha(JSON.stringify(config))});
  if(['organization','signing-keys','trust-profile','compliance-profile','canvas-sync-worker','deployment-profile','device-registration','event-stream','notification','passport-callback-signer','ui-prod'].includes(role)){prefix[role]={containerId:cid,imageId,startedAt:time,hostPid:i+1};outcomes[role]={observedExitCode:0,deferred:false};}
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
function baseline(f){
 const restartedRoles=['canvas-sync-worker','compliance-profile','deployment-profile','device-registration'],partial=JSON.parse(fs.readFileSync(f.authority.originalOperationState.path)),old=structuredClone(f.owned),current=structuredClone(old),restartDrift=[];
 for(const [role,ack]of Object.entries(partial.startAcks)){
  old[role].State={...old[role].State,Status:'running',Running:true,Pid:ack.hostPid,StartedAt:ack.startedAt};current[role]=structuredClone(old[role]);
 }
 for(const role of restartedRoles){const ack=partial.startAcks[role],row=current[role];row.State.StartedAt='2026-01-02T00:00:00Z';row.State.Pid=ack.hostPid+100;row.RestartCount=3;restartDrift.push({role,ackStartedAt:ack.startedAt,ackHostPid:ack.hostPid,observedStartedAt:row.State.StartedAt,observedHostPid:row.State.Pid,restartCount:3,status:'running'});f.live[row.Id].State.StartedAt=row.State.StartedAt;f.live[row.Id].RestartCount=3;}
 f.authority.currentOwned22=f.file('partial22.json',old);
 const intent=f.file('intent.json',{runId:partial.runId});f.authority.originalApplyIntent=intent;
 const record=ref=>{const raw=fs.readFileSync(ref.path);return {present:true,storedBytesBase64:raw.toString('base64'),sha256:sha(raw),bytes:raw.length,document:JSON.parse(raw)};};
 const journal=[{root:{device:1,inode:2,uid:1000,gid:1000,mode:448},state:'EXACT_ROOT_DURABLE_METADATA_READ_COMPLETE',mountReadOnly:true,files:{'build-state.json':record(f.authority.originalOperationState),'build-apply-intent.json':record(intent),'build-receipt.json':{present:false},'configuration-receipt.json':{present:false}}}];
 f.authority.journalRead=f.file('original-journal.json',journal);
 const b={schema:'marty.d12-ob3-current-process-baseline/v1',originalOperationState:f.authority.originalOperationState,journalRead:f.file('fresh-journal.json',journal),job:f.file('fresh-job.json',f.job),rootReview:null,owned22:f.file('fresh-owned.json',current),ancillary6:f.authority.currentAncillary6,restartedRoles};
 b.rootReview=f.file('root-review.json',{state:'ROOT_QUIESCENCE_FAILURE_RECONCILED_READONLY',journalStateSha256:f.authority.originalOperationState.sha256,journalUnchanged:true,created22CidsUnchanged:true,closedJobSha256:b.job.sha256,workerResultSha256:b.journalRead.sha256,quiescenceQualified:false,fullStackQualified:false,restartDrift});
 f.authority.currentProcessBaseline=f.file('process-baseline.json',b);return {b,current,partial};
}
for(const fault of [null,'newer-live-generation','extra-role','unreviewed-drift','cid','host-config','mount','job','raw-state','foreign-root','review','ancillary'])test('explicit current process baseline '+(fault||'preserves history and passes'),t=>{
 const f=fixture(t),{b,current,partial}=baseline(f),history=structuredClone(partial.startAcks),role='canvas-sync-worker';
 if(fault==='newer-live-generation')f.live[current[role].Id].State.StartedAt='2026-01-03T00:00:00Z';
 else if(fault==='extra-role')b.restartedRoles.push('organization');
 else if(fault==='unreviewed-drift')current.organization.State.Pid++;
 else if(fault==='cid')current[role].Id='e'.repeat(64);
 else if(fault==='host-config')current[role].HostConfig.Memory++;
 else if(fault==='mount')f.live[current[role].Id].Mounts.push({Destination:'/unexpected',Source:'/tmp/a',Type:'bind',RW:false});
 else if(fault==='job')b.job=f.file('bad-job.json',{...f.job,jobClosed:false});
 else if(fault==='raw-state'){const j=JSON.parse(fs.readFileSync(b.journalRead.path));j[0].files['build-state.json'].storedBytesBase64='e30=';b.journalRead=f.file('bad-journal.json',j);}
 else if(fault==='foreign-root'){const j=JSON.parse(fs.readFileSync(b.journalRead.path));j[0].root.inode++;b.journalRead=f.file('foreign-root-journal.json',j);const review=JSON.parse(fs.readFileSync(b.rootReview.path));review.workerResultSha256=b.journalRead.sha256;b.rootReview=f.file('root-review.json',review);}
 else if(fault==='review'){const review=JSON.parse(fs.readFileSync(b.rootReview.path));review.journalUnchanged=false;b.rootReview=f.file('bad-review.json',review);}
 else if(fault==='ancillary'){const rows=JSON.parse(fs.readFileSync(b.ancillary6.path));rows.postgres.State.Pid++;b.ancillary6=f.file('bad-ancillary.json',rows);}
 b.owned22=f.file('fresh-owned.json',current);f.authority.currentProcessBaseline=f.file('process-baseline.json',b);const ref=f.file('authority.json',f.authority);
 const invoke=()=>verifyOb3ContainmentRuntime({}, {recoveryRef:ref,readDocker:f.read,phase:'QUIESCENT',outcomes:f.outcomes});
 if(fault)assert.throws(invoke,fault==='foreign-root'?/OB3_CURRENT_PROCESS_JOURNAL_ROOT_CHANGED:inode/:undefined);else {const result=invoke();assert.equal(result.fullStackQualified,false);assert.equal(result.roles.length,22);}
 assert.deepEqual(partial.startAcks,history);
});
