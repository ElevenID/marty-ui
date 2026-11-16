'use strict';
// Controlled metadata only. These fixtures are not an observed beta checkpoint.
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const {maintenanceOb3QuiescentContext,verifyOb3ContainmentRuntime}=require('./functional-debug-runtime');
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const scenarios=['D01_ORGANIZATION_OB3','D05_MEMBERSHIP_OB3','D05_MEMBERSHIP_EXPIRED_NEGATIVE','D05_MEMBERSHIP_UNTRUSTED_NEGATIVE','D07_CANVAS_OB3'];
function fixture(t,{proxyEvidence=false}={}){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'ob3-quiescent-control-'));t.after(()=>{assert.equal(path.dirname(root),fs.realpathSync(os.tmpdir()));assert(path.basename(root).startsWith('ob3-quiescent-control-'));assert.equal(fs.realpathSync(root),root);assert(!fs.lstatSync(root).isSymbolicLink());fs.rmSync(root,{recursive:true});});
 const file=(name,value)=>{const p=path.join(root,name),raw=Buffer.from(JSON.stringify(value));fs.writeFileSync(p,raw);return {path:p,bytes:raw.length,sha256:sha(raw)};};
 const runId='8b5f5d22-eb3a-4a7f-b9e7-2cdcb651c8e0',imageId='sha256:'+'b'.repeat(64),time='2026-01-01T00:00:00Z';
 const names=['gateway','organization','auth','issuance-native','flow','credential-template','signing-keys','trust-profile','presentation-policy','compliance-profile','passport-beta-bureau',...Array.from({length:11},(_,i)=>'retained-'+i)];
 const owned={},ancillary={},live={},created={roles:[]},prefix={},outcomes={},resources=[],roles=[],modelRoles=[];
 const publicFile=(name,text)=>{const p=path.join(root,name);fs.writeFileSync(p,text);return {path:p,bytes:Buffer.byteLength(text),sha256:sha(text)};};
 const route=proxyEvidence?publicFile('route.template','location = /ready { set $backend_api ${GATEWAY_UPSTREAM}; proxy_pass http://$backend_api/ready; }'):null;
 const entry=proxyEvidence?publicFile('entry.sh',"GATEWAY_UPSTREAM=${GATEWAY_UPSTREAM:-gateway:8000}\nenvsubst '${PUBLIC_DOMAIN} ${UI_DEV_PORT} ${DOCS_DOMAIN} ${GATEWAY_UPSTREAM}' < /etc/nginx/conf.d/default.conf.template"):null;
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
  const mounts=proxyEvidence&&role==='nginx-proxy'?[{Destination:'/etc/nginx/conf.d/default.conf.template',Type:'bind',RW:false,Source:route.path},{Destination:'/docker-entrypoint.d/40-substitute-env.sh',Type:'bind',RW:false,Source:entry.path}]:[];
  if(proxyEvidence&&role==='nginx-proxy'){config.Env=['GATEWAY_UPSTREAM=gateway:8000'];config.Healthcheck={Test:['CMD-SHELL','wget --quiet --tries=1 --spider http://127.0.0.1/ready || exit 1']};}
  ancillary[role]={Id:cid,Image:imageId,State:{Status:'running',Running:true,Pid:i+100,StartedAt:time},HostConfig:host,Mounts:mounts,Labels:config.Labels};live[cid]={...structuredClone(ancillary[role]),Config:config,State:{...ancillary[role].State,Paused:false,OOMKilled:false,ExitCode:0}};
  if(proxyEvidence&&role==='nginx-proxy')live[cid].State.Health={Status:'unhealthy',Log:Array.from({length:5},()=>({ExitCode:1,Output:'wget: server returned error: HTTP/1.1 502 Bad Gateway',End:new Date().toISOString()}))};
  resources.push({role,containerId:cid,imageId,status:'running',running:true,hostPid:i+100,startedAt:time,containerExitCode:0,configSha256:sha(JSON.stringify(config)),hostConfigSha256:sha(JSON.stringify(host)),mountsSha256:sha(JSON.stringify([...mounts].sort((a,b)=>a.Destination.localeCompare(b.Destination))))});
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
 if(proxyEvidence){const proxy=Object.values(live).find(row=>row.Config.Labels['com.docker.compose.service']==='nginx-proxy');recovery.proxyDependencyHealth=file('proxy-evidence.json',{schema:'marty.maintenance-proxy-dependency/v1',proxyObservation:file('proxy-observation.json',{Id:proxy.Id,Image:proxy.Image,Health:proxy.State.Health,Healthcheck:proxy.Config.Healthcheck}),selectedUpstream:file('selected-upstream.json',{containerId:proxy.Id,selectedVariable:'GATEWAY_UPSTREAM',present:true,otherEnvironmentValuesReported:false,value:'gateway:8000'}),routeTemplate:route,entrypoint:entry});}
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

function observerFixture(t){
 const f=fixture(t),observer=require('./d12-current-native-runtime'),read=reference=>JSON.parse(fs.readFileSync(reference.path));
 const before=read(f.recovery.runtimeBefore),oldCreated=read(f.state.created),names=before.roles.map(row=>row.role),native=observer.CURRENT10.roles;
 const binaries={};for(const [role,binary]of Object.entries(native))binaries[role]=f.file(binary,'SYNTHETIC_ELF_SOURCE_BYTES');
 const selection={profile:observer.CURRENT10.profile,state:'SELECTED_NOT_DEPLOYED',sourceRevision:observer.CURRENT10.source,coreRevision:observer.CURRENT10.core,roleBinaries:native,binaries,scope:'FUNCTIONAL_ONLY',releaseQualified:false,recordingQualified:false},selectionRef=f.file('observer-selection.json',selection);
 for(const [i,row]of before.roles.entries()){
  const role=row.role,binary=native[role]||'marty-'+role,source=Object.hasOwn(native,role)?'e'.repeat(40):'f'.repeat(40),hash=Object.hasOwn(native,role)?binaries[role].sha256:'d'.repeat(64);
  Object.assign(row,{project:'elevenid-beta',binary,source,kind:'RETAINED_SOURCE_BOUND_BINARY',sha256:hash,processExecutableSha256:hash,executablePath:'/usr/local/bin/'+binary,effectiveUid:10001,configuredRuntimeUid:10001,effectiveGid:10001,configuredRuntimeGid:10001,running:true,paused:false,oomKilled:false,state:'running',health:'healthy',hostPid:1,startedAt:'2026-01-01T00:00:00Z',binaryMounts:[{type:'bind',source:require('node:path').join(require('node:path').dirname(binaries.auth.path),'original-'+binary),destination:'/usr/local/bin/'+binary,writable:false}]});
  if(Object.hasOwn(native,role))row.containerId=(i+5001).toString(16).padStart(64,'0');
 }
 before.roles.find(row=>row.role==='passport-beta-bureau').binaryMounts=[];
 const beforeRef=f.file('observer-before.json',before),partial=read(f.authority.originalOperationState);partial.sourceRevision=observer.CURRENT10.source;partial.coreRevision=observer.CURRENT10.core;
 const authority={...f.authority,runtimeBefore:beforeRef,selection:selectionRef,originalOperationState:f.file('observer-partial.json',partial)},original={...f.original,runtimeBefore:beforeRef,selection:selectionRef};authority.originalInputs=f.file('observer-original.json',original);
 const bureauBefore=before.roles.find(row=>row.role==='passport-beta-bureau'),bureauLive=f.live[f.owned['passport-beta-bureau'].Id];bureauLive.Config.User='10001:10001';const bureauHash=sha(JSON.stringify(bureauLive.Config));
 const quiescence=structuredClone(f.quiescence);quiescence.roles.find(row=>row.role==='passport-beta-bureau').configSha256=bureauHash;quiescence.resources.find(row=>row.role==='passport-beta-bureau').configSha256=bureauHash;
 const post={...f.post,authority:f.file('observer-quiesce-authority.json',authority),quiescence:f.file('observer-quiescence.json',quiescence)};
 const state={...f.state,sourceRevision:partial.sourceRevision,coreRevision:partial.coreRevision,recoveryAuthority:post.authority,ob3Quiescence:post.quiescence,priorPartialStartState:authority.originalOperationState,originalOperationState:authority.originalOperationState};
 const recovery={...f.recovery,runtimeBefore:beforeRef,ob3Quiescent:post};
 const nextAuthority={schema:'marty.d12-ob3-quiescent-recovery/v1',operation:'REPLACE_OB3_QUIESCENT_CREDENTIALS_AND_RESUME',dispatchAuthorized:true,draftOnly:false,replaceCredentialGeneration:true,scope:'OB3_FUNCTIONAL_ONLY',runId:state.runId,engineId:authority.engineId,allowedScenarios:scenarios,deferredRoles:['passport-beta-bureau'],deferredFailure:authority.deferredFailure,originalInputs:authority.originalInputs,originalOperationState:f.file('observer-quiescent-state.json',state),previousRecoveryAuthority:post.authority,selected22:post.current22,selected22Job:post.current22Job,quiescenceJob:post.quiescenceJob,maintenanceResourceRecovery:f.file('observer-maintenance.json',recovery)};
 const created={runId:state.runId,roles:[]},acks={runId:state.runId,acks:{}},live={},hashById={};
 for(const [i,prior]of before.roles.entries()){
  const chosen=Object.hasOwn(native,prior.role),cid=chosen?(i+1001).toString(16).padStart(64,'0'):prior.containerId;
  const row={...prior,containerId:cid,state:chosen?'created':'exited',hostPid:0,running:false,containerExitCode:prior.role==='passport-beta-bureau'?1:0};created.roles.push(row);
  if(prior.role==='passport-beta-bureau'){live[cid]=structuredClone(bureauLive);continue;}
  const mounts=chosen?[{type:'bind',source:binaries[prior.role].path,destination:'/usr/local/bin/'+prior.binary,writable:false}]:prior.binaryMounts;
  live[cid]={Id:cid,Image:prior.imageId,Config:{User:'10001:10001',Labels:{'com.docker.compose.project':prior.project,'com.docker.compose.service':prior.role}},Mounts:mounts.map(m=>({Type:m.type,Source:m.source,Destination:m.destination,RW:m.writable})),State:{Status:'running',Running:true,Pid:i+100,Paused:false,OOMKilled:false,StartedAt:'2026-02-01T00:00:00Z',Health:{Status:'healthy'}}};
  hashById[cid]=chosen?binaries[prior.role].sha256:prior.sha256;acks.acks[prior.role]={containerId:cid,imageId:prior.imageId,hostPid:i+100,startedAt:live[cid].State.StartedAt};
 }
 const inputs={before:beforeRef,selection:selectionRef,created:f.file('observer-created.json',created),startAcks:f.file('observer-start-acks.json',acks),runId:state.runId,engineId:authority.engineId,ob3Authority:f.file('next-root-authority.json',nextAuthority)};
 let execs=0;const transport=argv=>{
  if(JSON.stringify(argv)===JSON.stringify(['info','--format','{{json .}}']))return JSON.stringify({ID:inputs.engineId});
  if(argv[0]==='ps'){const role=argv.at(-1).split('=').at(-1);const row=Object.values(live).find(row=>row.Config.Labels['com.docker.compose.service']===role&&row.State.Running);return row?.Id||'';}
  if(argv[0]==='inspect'){assert(live[argv[1]]);return JSON.stringify([live[argv[1]]]);}
  assert.equal(argv[0],'exec');assert.notEqual(argv[1],bureauBefore.containerId,'DEFERRED_ROLE_MUST_NOT_EXEC');execs++;
  if(argv[2]==='readlink')return '/usr/local/bin/'+before.roles.find(row=>row.role===live[argv[1]].Config.Labels['com.docker.compose.service']).binary;
  if(argv[2]==='sha256sum')return hashById[argv[1]]+'  '+argv[3];
  assert.deepEqual(argv.slice(2),['cat','/proc/1/status']);return 'Uid:\t10001\t10001\t10001\t10001\nGid:\t10001\t10001\t10001\t10001\n';
 };
 return {observer,inputs,transport,live,file:f.file,read,post,nextAuthority,execs:()=>execs,invoke:()=>observer.observeOb3(inputs,{readDocker:transport})};
}
test('controlled OB3 transport requests process facts for21 roles and validates both cached shapes',t=>{
 const f=observerFixture(t),out=f.invoke();assert.equal(out.roles.length,22);assert(f.execs()>0);assert.equal(out.fullStackQualified,false);assert.equal(out.nativeRuntimeReady,false);assert.equal(out.ob3RuntimeReady,true);
 const bureau=out.roles.find(row=>row.role==='passport-beta-bureau');assert.equal(bureau.hostPid,0);assert.equal(bureau.sourceFactsInherited,true);assert.equal(bureau.processExecutableSha256,null);
 f.observer.validateOb3Observation(out);f.observer.validateOb3Observation({...out,schema:'marty.functional-mixed-runtime-binding/v2',mixedSourceStack:true,receiptDigests:{syntheticOnly:true}});
 assert.deepEqual(f.observer.observe(f.inputs,{readDocker:f.transport}),out);
});
for(const fault of ['missing-role','foreign-image','wrong-native-source','uid','elf','healthy-bureau','bureau-pid','fake-bureau-elf','unknown-schema','fullstack','retained-kind','gid'])test('cached OB3 facts refuse '+fault,t=>{
 const f=observerFixture(t),out=f.invoke(),first=out.roles.find(row=>row.role==='auth'),bureau=out.roles.find(row=>row.role==='passport-beta-bureau');
 if(fault==='retained-kind')out.roles.find(row=>row.role==='retained-0').kind='FOREIGN_KIND';if(fault==='gid')first.effectiveGid=0;if(fault==='missing-role')out.roles.pop();if(fault==='foreign-image')first.imageId='sha256:'+'f'.repeat(64);if(fault==='wrong-native-source')first.source='f'.repeat(40);if(fault==='uid')first.effectiveUid=0;if(fault==='elf')first.processExecutableSha256='f'.repeat(64);if(fault==='healthy-bureau')bureau.health='healthy';if(fault==='bureau-pid')bureau.hostPid=123;if(fault==='fake-bureau-elf')bureau.processExecutableSha256=bureau.sha256;if(fault==='unknown-schema')out.schema='marty.other/v1';if(fault==='fullstack')out.fullStackQualified=true;assert.throws(()=>f.observer.validateOb3Observation(out));
});

function recursivelySorted(value){
 if(Array.isArray(value))return value.map(recursivelySorted);
 if(value&&typeof value==='object')return Object.fromEntries(Object.keys(value).sort().map(key=>[key,recursivelySorted(value[key])]));
 return value;
}
for(const drift of ['none','host-value','host-extra','mount-value','mount-extra'])test('bound quiescent full objects survive sorted capture and refuse '+drift,t=>{
 const f=fixture(t),load=ref=>JSON.parse(fs.readFileSync(ref.path)),prior=load(f.authority.currentOwned22);
 prior.auth.HostConfig={Z:{Nested:1,Earlier:false},A:67108864};
 prior.auth.Mounts=[{Type:'bind',Source:'/source',Destination:'/bound',RW:false,Propagation:'rprivate'}];
 const hostSha=sha(JSON.stringify(prior.auth.HostConfig)),mountSha=sha(JSON.stringify(prior.auth.Mounts));
 for(const rows of [f.quiescence.roles,f.quiescence.resources])Object.assign(rows.find(row=>row.role==='auth'),{hostConfigSha256:hostSha,mountsSha256:mountSha});
 const authority={...f.authority,currentOwned22:f.file('ordered-prestop.json',prior)};
 f.post.authority=f.file('ordered-authority.json',authority);f.state.recoveryAuthority=f.post.authority;
 f.post.quiescence=f.file('original-raw-hash-proof.json',f.quiescence);f.state.ob3Quiescence=f.post.quiescence;
 const sorted=recursivelySorted(prior);assert.notEqual(sha(JSON.stringify(sorted.auth.HostConfig)),hostSha);assert.notEqual(sha(JSON.stringify(sorted.auth.Mounts)),mountSha);
 if(drift==='host-value')sorted.auth.HostConfig.Z.Nested=2;
 if(drift==='host-extra')sorted.auth.HostConfig.Extra=true;
 if(drift==='mount-value')sorted.auth.Mounts[0].RW=true;
 if(drift==='mount-extra')sorted.auth.Mounts[0].Extra=true;
 f.post.current22=f.file('sorted-readonly-capture.json',sorted);
 if(drift==='none'){
  f.invoke();assert.equal(load(f.post.quiescence).roles.find(row=>row.role==='auth').hostConfigSha256,hostSha);
  f.live[prior.auth.Id].HostConfig=structuredClone(prior.auth.HostConfig);f.live[prior.auth.Id].Mounts=structuredClone(prior.auth.Mounts);
  const fresh=verifyOb3ContainmentRuntime({}, {recoveryRef:f.post.authority,readDocker:f.read,phase:'QUIESCENT',outcomes:f.outcomes});
  assert.deepEqual(fresh,f.quiescence,'Original raw-order Q2 receipt still matches the live producer');
 }
 else assert.throws(f.invoke);
});

for(const fault of ['none','wrong-upstream','wrong-health-cause'])test('controlled OB3 maintenance branch resolves bound proxy evidence: '+fault,t=>{
 const f=fixture(t,{proxyEvidence:true}),Module=require('node:module'),filename=require.resolve('./functional-debug-runtime');
 // Expose this private branch only in the isolated test module; execute its
 // unchanged body and real containment/proxy owners, with profile authority stubbed.
 const isolated=new Module(filename,module);isolated.filename=filename;isolated.paths=module.paths;
 isolated._compile(fs.readFileSync(filename,'utf8')+'\nmodule.exports.controlledOb3Branch=verifyOb3QuiescentMaintenance;\n',filename);
 const owner=require('./beta-resource-runtime');t.mock.method(owner,'restartAuthority',()=>({a:{cap:{allRunningRoles:Object.fromEntries(['docs','keycloak','nginx-proxy','openbao','postgres','redis'].map(role=>[role,{health:null}]))}}}));
 const proxy=Object.values(f.live).find(row=>row.Config.Labels['com.docker.compose.service']==='nginx-proxy');
 if(fault==='wrong-upstream')proxy.Config.Env=['GATEWAY_UPSTREAM=foreign:8000'];
 if(fault==='wrong-health-cause')for(const log of proxy.State.Health.Log)log.Output='different failure';
 const fakeRef={sha256:'a'.repeat(64)},profile={baselineDeployment:fakeRef,baselineBuild:fakeRef,debugDeployment:fakeRef,debugBuild:fakeRef,retainedBuilds:{}};
 const invoke=()=>isolated.exports.controlledOb3Branch(profile,f.recovery,f.file('bound-recovery.json',f.recovery),f.state,f.read);
 if(fault!=='none'){assert.throws(invoke);return;}
 const result=invoke();assert.equal(result.ob3QuiescentCheckpoint,true);assert.equal(result.fullStackQualified,false);assert.equal(result.functionalRuntimeQualified,false);
 assert.equal(result.dependencyHealthObservations.length,1);const classification=result.resources.find(row=>row.role==='nginx-proxy').maintenanceHealthClassification;
 assert.equal(classification.state,'EXPECTED_MAINTENANCE_UPSTREAM_STOPPED');assert.equal(classification.functionalReadiness,false);assert.equal(classification.evidenceSha256,f.recovery.proxyDependencyHealth.sha256);
});

test('controlled Flow successor observes 21 roles with historical Bureau proof',t=>{
 const f=observerFixture(t),save=f.file,legacy={...f.nextAuthority,quiescence:f.post.quiescence};
 const legacyRef=save('flow-legacy.json',legacy);
 const secondRef=save('flow-second.json',{schema:'marty.d12-ob3-acknowledged-replacement-recovery/v1',operation:'REPLACE_OB3_AFTER_ACKNOWLEDGED_CREDENTIAL_REPLACEMENT_AND_RESUME',runId:f.inputs.runId,previousRecoveryAuthority:legacyRef});
 const thirdRef=save('flow-third.json',{schema:'marty.d12-ob3-acknowledged-replacement-recovery/v1',operation:'REPLACE_OB3_AFTER_SECOND_ACKNOWLEDGED_CREDENTIAL_REPLACEMENT_AND_RESUME',runId:f.inputs.runId,previousRecoveryAuthority:secondRef});
 const pendingRef=save('flow-pending.json',{schema:'marty.d12-ob3-flow-pending-recovery/v1',operation:'QUIESCE_OB3_FLOW_PENDING_STARTS',runId:f.inputs.runId,dispatchAuthorized:true,draftOnly:false,previousRecoveryAuthority:thirdRef});
 const current=f.read(f.post.current22),roles=Object.entries(current).map(([role,row])=>({role,containerId:row.Id,imageId:row.Image,state:row.State.Status,containerExitCode:row.State.ExitCode}));
 const prefix=roles.filter(row=>!['passport-beta-bureau','flow'].includes(row.role)).slice(0,17);
 const outcomes=Object.fromEntries([...prefix,roles.find(row=>row.role==='flow')].map(row=>[row.role,{observedExitCode:row.containerExitCode}]));
 const observationRef=save('flow-quiescence.json',{schema:'marty.ob3-flow-quiescence/v1',runId:f.inputs.runId,authority:pendingRef,roles,stopOutcomes:outcomes,fullStackQualified:false,releaseQualified:false,recordingQualified:false});
 const stateRef=save('flow-state.json',{schema:'marty.d12-current-native-operation/v1',phase:'OB3_FLOW_PARTIAL_QUIESCENT',runId:f.inputs.runId,recoveryAuthority:pendingRef,ob3Quiescence:observationRef,ob3StopOutcomes:outcomes,priorStartAcks:Object.fromEntries(prefix.map(row=>[row.role,{}])),pendingStep:null,pendingArgv:null,pendingContainerId:null});
 const ancillary6=save('flow-ancillary.json',Object.fromEntries(['docs','nginx-proxy','openbao','postgres','redis','keycloak'].map(role=>[role,{Id:role}])));
 const job=save('flow-job.json',{schema:'marty.windows-job-result/v1',state:'COMPLETE',exitCode:0,jobClosed:true,terminalActiveProcesses:0,forcedTermination:false,timedOut:false,cancelled:false,hostMarginBreached:false});
 const result=save('flow-result.json',{state:'OB3_FLOW_POSTSTOP_JOURNAL_AND_CURRENT28_CAPTURE_COMPLETE',quiescenceJob:job,serviceWrites:false,sqlWrites:false,identity28StableDuringRead:true,journalContentRead:true});
 const post={authority:pendingRef,quiescence:observationRef,quiescenceJob:job,current22:f.post.current22,current22Job:job,ancillary6,journalRead:save('flow-journal.json',{}),result};
 const resource=save('flow-resource.json',{...f.read(legacy.maintenanceResourceRecovery),ob3Quiescent:undefined,ob3FlowQuiescent:post});
 const authority={...legacy,schema:'marty.d12-ob3-flow-quiescent-recovery/v1',operation:'REPLACE_OB3_FLOW_QUIESCENT_CREDENTIALS_AND_RESUME',previousRecoveryAuthority:pendingRef,originalOperationState:stateRef,maintenanceResourceRecovery:resource,postStopOwned22:post.current22,postStopJob:post.current22Job,quiescenceJob:post.quiescenceJob};
 f.inputs.ob3Authority=save('flow-current-authority.json',authority);
 const out=f.invoke();assert.equal(out.roles.length,22);assert.equal(out.deferredFailure.sha256,legacy.deferredFailure.sha256);assert.equal(out.roles.find(row=>row.role==='passport-beta-bureau').processObserved,false);
 f.observer.validateOb3Observation(out);
 const wrongParent=save('flow-wrong-parent.json',{schema:'marty.d12-ob3-flow-pending-recovery/v1',operation:'QUIESCE_OB3_FLOW_PENDING_STARTS',runId:'foreign-run',dispatchAuthorized:true,draftOnly:false,previousRecoveryAuthority:thirdRef});
 authority.previousRecoveryAuthority=wrongParent;f.inputs.ob3Authority=save('flow-wrong-parent-authority.json',authority);assert.throws(f.invoke);
 authority.previousRecoveryAuthority=pendingRef;authority.operation='UNREVIEWED_FLOW_MODE';f.inputs.ob3Authority=save('flow-wrong-authority.json',authority);assert.throws(f.invoke);
});
