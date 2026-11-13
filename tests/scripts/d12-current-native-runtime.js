'use strict';
// Source-bound actual Docker observation for the current D12 native three-role
// generation. This file performs no effects and does not qualify the passport
// business scenario, a release, or a recording.
const assert=require('node:assert/strict');
const runtime=require('./functional-debug-runtime');
const SOURCE='6117cea9290f57406cf109eae56f64f7986e3783';
const CORE='ffa24febcd0fb3fced15da7f28190af6d61ae0f9';
const ROLES=Object.freeze({flow:'marty-flow',gateway:'marty-gateway','issuance-native':'marty-issuance-service'});
const CURRENT10=Object.freeze({profile:'d05-membership-current-functional',source:'47e42c7f61e150e1ece953e02b4041324b6bdea4',core:'ab91a6fd97b2483965e8cb966c3b2e3ddeedf1ca',roles:Object.freeze({'presentation-policy':'marty-presentation-policy','credential-template':'marty-credential-template','trust-profile':'marty-trust-profile','compliance-profile':'marty-compliance-profile','signing-keys':'marty-signing-keys',gateway:'marty-gateway',auth:'marty-auth',flow:'marty-flow','issuance-native':'marty-issuance-service',organization:'marty-organization'})});
const HASH=/^[a-f0-9]{64}$/;
function observe(inputs,transport={}){return Object.hasOwn(inputs,'ob3Authority')?observeOb3(inputs,transport):observeOwned(inputs,transport,null);}
function observeOwned({before:beforeRef,selection:selectionRef,created:createdRef,startAcks:acksRef,runId,engineId},{readDocker}={},ob3=null){
 assert.equal(typeof readDocker,'function','ACTUAL_DOCKER_TRANSPORT_REQUIRED');
 const info=JSON.parse(readDocker(['info','--format','{{json .}}']));assert.equal(info.ID,engineId,'D12_ENGINE_CHANGED');
 const before=runtime.boundJson(beforeRef),selection=runtime.boundJson(selectionRef);
 const created=runtime.boundJson(createdRef),starts=runtime.boundJson(acksRef);
 assert(['d12-passport-current-functional',CURRENT10.profile].includes(selection.profile),'UNREVIEWED_CURRENT_ROLLOUT_PROFILE');
 const current10=selection.profile===CURRENT10.profile;
 const source=current10?CURRENT10.source:SOURCE,core=current10?CURRENT10.core:CORE,roles=current10?CURRENT10.roles:ROLES;
 assert.equal(selection.state,'SELECTED_NOT_DEPLOYED');
 assert.equal(selection.sourceRevision,source);assert.equal(selection.coreRevision,core);
 assert.deepEqual(selection.roleBinaries,roles);assert.deepEqual(Object.keys(selection.binaries).sort(),Object.keys(roles).sort());
 assert.equal(selection.scope,'FUNCTIONAL_ONLY');assert.equal(selection.releaseQualified,false);assert.equal(selection.recordingQualified,false);
 assert.equal(before.roles.length,22);assert.equal(new Set(before.roles.map(x=>x.role)).size,22);
 const ids=new Set(before.roles.map(x=>x.containerId));assert.equal(ids.size,22);
 assert.equal(created.runId,runId);assert.equal(starts.runId,runId);
 assert.equal(created.roles.length,22);assert.equal(new Set(created.roles.map(x=>x.role)).size,22);
 assert.deepEqual(created.roles.map(x=>x.role).sort(),before.roles.map(x=>x.role).sort());
 assert.deepEqual(Object.keys(starts.acks).sort(),before.roles.map(x=>x.role).filter(role=>!ob3||role!=='passport-beta-bureau').sort());
 const createdByRole=Object.fromEntries(created.roles.map(x=>[x.role,x]));
 assert.equal(new Set(created.roles.map(x=>x.containerId)).size,22);
 const rows=before.roles.map(prior=>{
  if(ob3&&prior.role==='passport-beta-bureau')return observeDeferredBureau(prior,createdByRole[prior.role],ob3,readDocker);
  const actual=runtime.observeDocker(prior,readDocker);
  const owned=createdByRole[prior.role],ack=starts.acks[prior.role];
  assert.equal(actual.role,prior.role);assert.equal(actual.project,prior.project);assert.equal(actual.imageId,prior.imageId);
  assert.equal(owned.containerId,ack.containerId,'CREATED_AND_STARTED_CONTAINER_CHANGED');
  assert.equal(actual.containerId,owned.containerId,'D12_FOREIGN_SAME_BINARY_CONTAINER');
  assert.equal(actual.startedAt,ack.startedAt,'D12_UNEXPECTED_RESTART_GENERATION');
  assert.equal(actual.hostPid,ack.hostPid,'D12_UNEXPECTED_RESTART_PROCESS');
  assert.equal(actual.imageId,ack.imageId,'D12_STARTED_IMAGE_CHANGED');
  assert.equal(owned.imageId,prior.imageId,'D12_CREATED_IMAGE_CHANGED');
  assert.equal(owned.state,roles[prior.role]?'created':'exited','D12_CREATED_STATE_CHANGED');
  assert.equal(owned.hostPid,0,'D12_CREATED_ROLE_STILL_RUNNING');
  assert.equal(roles[prior.role]?owned.containerId!==prior.containerId:owned.containerId===prior.containerId,
    true,'D12_CREATED_LINEAGE_CHANGED');
  assert.equal(actual.running,true);assert.equal(actual.status,'running');
  assert(actual.health==='healthy'||prior.role==='canvas-sync-worker'&&actual.health===null,'D12_ROLE_HEALTH_NOT_ESTABLISHED');assert(HASH.test(actual.containerId));
  assert(Number.isInteger(actual.hostPid)&&actual.hostPid>0);assert(Date.parse(actual.startedAt)>Date.parse(prior.startedAt));
  if(prior.binary){assert.equal(actual.binarySha256,roles[prior.role]?selection.binaries[prior.role].sha256:prior.sha256);
   assert.equal(actual.processExecutableSha256,actual.binarySha256);
   assert.equal(actual.executablePath,'/usr/local/bin/'+prior.binary);}
  assert.equal(actual.effectiveUid,prior.effectiveUid);assert.equal(actual.configuredRuntimeUid,prior.configuredRuntimeUid);
  if(roles[prior.role]){
   const binary=roles[prior.role],bound=selection.binaries[prior.role],target='/usr/local/bin/'+binary;
   assert.equal(prior.binary,binary);assert(!ids.has(actual.containerId));assert.equal(actual.binaryMounts.length,1);
   const mount=actual.binaryMounts[0];assert.equal(mount.type,'bind');assert.equal(mount.destination,target);assert.equal(mount.writable,false);
   assert.deepEqual(runtime.comparableBinaryMounts([mount]),runtime.comparableBinaryMounts([{...mount,source:bound.path}]));
   const next={...prior,containerId:actual.containerId,startedAt:actual.startedAt,hostPid:actual.hostPid,
    health:actual.health,source:source,coreSource:core,kind:'SCOPED_NATIVE_FUNCTIONAL_OVERLAY',
    sha256:actual.binarySha256,processExecutableSha256:actual.processExecutableSha256,
    executablePath:actual.executablePath,binaryMounts:actual.binaryMounts,
    requiredContainerId:actual.containerId,requiredStartedAt:actual.startedAt,
    requiredHostPid:actual.hostPid,requiredEffectiveUid:actual.effectiveUid,
    requiredBinaryMounts:actual.binaryMounts};
   if(actual.effectiveGid!==undefined)next.requiredEffectiveGid=actual.effectiveGid;
   delete next.requiredObservation;
   runtime.validateRuntimeObservation(next,actual);
   return next;
  }
  assert.equal(actual.containerId,prior.containerId);
  assert.deepEqual(runtime.comparableBinaryMounts(actual.binaryMounts),runtime.comparableBinaryMounts(prior.binaryMounts));
  runtime.validateRuntimeObservation(prior,actual,true);
  return {...prior,startedAt:actual.startedAt,hostPid:actual.hostPid,health:actual.health};
 });
 assert.equal(new Set(rows.map(x=>x.containerId)).size,22);
 return {roles:rows,scope:'D12_CURRENT_ACTUAL_DOCKER_OBSERVATION',functionalReady:false,releaseQualified:false,recordingQualified:false};
}

const OB3_SCENARIOS=Object.freeze(['D01_ORGANIZATION_OB3','D05_MEMBERSHIP_OB3','D05_MEMBERSHIP_EXPIRED_NEGATIVE','D05_MEMBERSHIP_UNTRUSTED_NEGATIVE','D07_CANVAS_OB3']);
function ob3Context(inputs){
 const authority=runtime.boundJson(inputs.ob3Authority);
 assert.equal(authority.schema,'marty.d12-ob3-quiescent-recovery/v1');assert.equal(authority.operation,'REPLACE_OB3_QUIESCENT_CREDENTIALS_AND_RESUME');
 assert.equal(authority.dispatchAuthorized,true);assert.equal(authority.draftOnly,false);assert.equal(authority.replaceCredentialGeneration,true);assert.equal(authority.runId,inputs.runId);assert.equal(authority.scope,'OB3_FUNCTIONAL_ONLY');
 assert.equal(authority.engineId,inputs.engineId);assert.deepEqual(Object.keys(inputs).sort(),['before','selection','created','startAcks','runId','engineId','ob3Authority'].sort());assert.deepEqual(authority.allowedScenarios,OB3_SCENARIOS);assert.deepEqual(authority.deferredRoles,['passport-beta-bureau']);
 const original=runtime.boundJson(authority.originalInputs);assert.deepEqual(original.runtimeBefore,inputs.before);assert.deepEqual(original.selection,inputs.selection);
 const state=runtime.boundJson(authority.originalOperationState),resource=runtime.boundJson(authority.maintenanceResourceRecovery);
 const context=runtime.maintenanceOb3QuiescentContext(resource,state);
 assert.deepEqual(resource.ob3Quiescent.authority,authority.previousRecoveryAuthority);assert.deepEqual(resource.ob3Quiescent.current22,authority.selected22);assert.deepEqual(resource.ob3Quiescent.current22Job,authority.selected22Job);assert.deepEqual(resource.ob3Quiescent.quiescenceJob,authority.quiescenceJob);
 assert.deepEqual(authority.deferredFailure,state.deferredFailure);runtime.boundJson(authority.deferredFailure);
 return {...context,authority};
}
function observeDeferredBureau(prior,created,context,readDocker){
 const saved=context.current['passport-beta-bureau'];assert.equal(saved.Id,prior.containerId);assert.equal(created.containerId,prior.containerId);
 const inspect=()=>{const rows=JSON.parse(readDocker(['inspect',saved.Id]));assert.equal(rows.length,1);const row=rows[0];assert.equal(row.Id,saved.Id);assert.equal(row.Image,prior.imageId);assert.equal(row.Config?.Labels?.['com.docker.compose.project'],prior.project);assert.equal(row.Config?.Labels?.['com.docker.compose.service'],prior.role);
  assert.equal(row.State.Status,'exited');assert.equal(row.State.Running,false);assert.equal(row.State.Pid,0);assert.equal(row.State.Paused,false);assert.equal(row.State.OOMKilled,false);assert.equal(row.State.StartedAt,saved.State.StartedAt);assert.equal(row.State.ExitCode,saved.State.ExitCode);assert.notEqual(row.State.Health?.Status,'healthy');
  assert.deepEqual(row.HostConfig,saved.HostConfig);const mounts=value=>[...value].sort((a,b)=>a.Destination<b.Destination?-1:a.Destination>b.Destination?1:0);assert.deepEqual(mounts(row.Mounts),mounts(saved.Mounts));
  const proof=context.quiescence.roles.find(value=>value.role===prior.role);assert.equal(require('node:crypto').createHash('sha256').update(JSON.stringify(row.Config)).digest('hex'),proof.configSha256);
  assert(/^\d+(?::\d+)?$/.test(row.Config.User||''));assert.equal(Number(row.Config.User.split(':')[0]),prior.configuredRuntimeUid);return row;
 };
 const first=inspect(),second=inspect();assert.deepEqual(second,first,'OB3_DEFERRED_INSPECTION_CHANGED');
 const binaryPath=prior.binary?'/usr/local/bin/'+prior.binary:null,binaryMounts=binaryPath?(first.Mounts||[]).filter(m=>binaryPath===m.Destination||binaryPath.startsWith(m.Destination.replace(/\/$/,'')+'/')).map(m=>({type:m.Type,source:m.Source,destination:m.Destination,writable:m.RW===true})):[];assert.deepEqual(runtime.comparableBinaryMounts(binaryMounts),runtime.comparableBinaryMounts(prior.binaryMounts));
 const row={...prior,containerId:first.Id,imageId:first.Image,startedAt:first.State.StartedAt,hostPid:0,running:false,paused:false,oomKilled:false,state:'exited',status:'exited',containerExitCode:first.State.ExitCode,health:first.State.Health?.Status||null,
  binaryMounts,configuredRuntimeUid:prior.configuredRuntimeUid,sourceEffectiveUid:prior.effectiveUid,...(prior.effectiveGid!==undefined?{sourceEffectiveGid:prior.effectiveGid}:{}),sourceFactsInherited:true,runningProcessQualified:false,deferred:true,binaryObserved:false,processObserved:false,
  executablePath:null,processExecutableSha256:null,deferredConfigSha256:context.quiescence.roles.find(value=>value.role===prior.role).configSha256};
 delete row.effectiveUid;delete row.effectiveGid;delete row.requiredObservation;return row;
}
function observeOb3(inputs,transport={}){
 const context=ob3Context(inputs),selection=runtime.boundJson(inputs.selection);assert.equal(selection.profile,CURRENT10.profile);
 const observed=observeOwned(inputs,transport,context);
 const result={...observed,schema:'marty.d12-current-native-ob3-observation/v1',scope:'FUNCTIONAL_ONLY',readinessScope:'OB3_FUNCTIONAL_ONLY',fullStackQualified:false,ob3RuntimeReady:true,nativeRuntimeReady:false,deferredRoles:['passport-beta-bureau'],deferredFailure:context.authority.deferredFailure,allowedScenarios:[...OB3_SCENARIOS],inputs};
 validateOb3Observation(result);return result;
}
function validateOb3Observation(value){
 assert(value&&['marty.d12-current-native-ob3-observation/v1','marty.functional-mixed-runtime-binding/v2'].includes(value.schema),'OB3_OBSERVATION_SCHEMA');
 if(value.schema==='marty.functional-mixed-runtime-binding/v2'){assert.equal(value.mixedSourceStack,true);assert(value.receiptDigests&&typeof value.receiptDigests==='object'&&!Array.isArray(value.receiptDigests));}else {assert.equal(value.functionalReady,false);assert.equal(value.mixedSourceStack,undefined);}
 assert.equal(value.scope,'FUNCTIONAL_ONLY');assert.equal(value.readinessScope,'OB3_FUNCTIONAL_ONLY');assert.equal(value.fullStackQualified,false);assert.equal(value.ob3RuntimeReady,true);assert.equal(value.nativeRuntimeReady,false);assert.equal(value.releaseQualified,false);assert.equal(value.recordingQualified,false);
 assert.deepEqual(value.deferredRoles,['passport-beta-bureau']);assert.deepEqual(value.allowedScenarios,OB3_SCENARIOS);
 const context=ob3Context(value.inputs),before=runtime.boundJson(value.inputs.before),selection=runtime.boundJson(value.inputs.selection),created=runtime.boundJson(value.inputs.created),starts=runtime.boundJson(value.inputs.startAcks);
 assert.equal(selection.profile,CURRENT10.profile);assert.equal(selection.sourceRevision,CURRENT10.source);assert.equal(selection.coreRevision,CURRENT10.core);assert.deepEqual(selection.roleBinaries,CURRENT10.roles);assert.deepEqual(Object.keys(selection.binaries).sort(),Object.keys(CURRENT10.roles).sort());
 assert.deepEqual(value.deferredFailure,context.authority.deferredFailure);assert.equal(before.roles.length,22);assert.equal(value.roles.length,22);assert.equal(new Set(value.roles.map(row=>row.role)).size,22);assert.equal(new Set(value.roles.map(row=>row.containerId)).size,22);assert.deepEqual(value.roles.map(row=>row.role).sort(),before.roles.map(row=>row.role).sort());
 assert.equal(created.runId,value.inputs.runId);assert.equal(created.roles.length,22);assert.equal(new Set(created.roles.map(row=>row.role)).size,22);assert.equal(new Set(created.roles.map(row=>row.containerId)).size,22);assert.deepEqual(created.roles.map(row=>row.role).sort(),before.roles.map(row=>row.role).sort());assert.equal(new Set(before.roles.map(row=>row.containerId)).size,22);assert.equal(starts.runId,value.inputs.runId);assert.deepEqual(Object.keys(starts.acks).sort(),before.roles.map(row=>row.role).filter(role=>role!=='passport-beta-bureau').sort());
 for(const prior of before.roles){
  const row=value.roles.find(value=>value.role===prior.role),owned=created.roles.find(value=>value.role===prior.role);assert(row&&owned);assert.equal(row.imageId,prior.imageId);assert.equal(owned.imageId,prior.imageId);assert.equal(owned.state,CURRENT10.roles[prior.role]?'created':'exited');assert.equal(owned.hostPid,0);assert.equal(row.project,prior.project);assert.equal(row.containerId,owned.containerId);assert(HASH.test(row.containerId));
  if(prior.role==='passport-beta-bureau'){
   const saved=context.current[prior.role];assert.equal(row.containerId,prior.containerId);assert.equal(row.containerId,saved.Id);assert.equal(row.startedAt,saved.State.StartedAt);assert.equal(row.containerExitCode,saved.State.ExitCode);assert.equal(row.hostPid,0);assert.equal(row.running,false);assert.equal(row.status,'exited');assert.equal(row.paused,false);assert.equal(row.oomKilled,false);assert.notEqual(row.health,'healthy');
   assert.equal(row.deferred,true);assert.equal(row.runningProcessQualified,false);assert.equal(row.sourceFactsInherited,true);assert.equal(row.binaryObserved,false);assert.equal(row.processObserved,false);assert.equal(row.processExecutableSha256,null);assert.equal(row.executablePath,null);assert.equal(row.effectiveUid,undefined);assert.equal(row.sourceEffectiveUid,prior.effectiveUid);assert.equal(row.configuredRuntimeUid,prior.configuredRuntimeUid);assert.equal(row.source,prior.source);assert.equal(row.kind,prior.kind);assert.equal(row.binary,prior.binary);assert.equal(row.sha256,prior.sha256);if(prior.effectiveGid!==undefined)assert.equal(row.sourceEffectiveGid,prior.effectiveGid);assert.deepEqual(runtime.comparableBinaryMounts(row.binaryMounts),runtime.comparableBinaryMounts(prior.binaryMounts));assert.equal(row.deferredConfigSha256,context.quiescence.roles.find(value=>value.role===prior.role).configSha256);continue;
  }
  const ack=starts.acks[prior.role];assert.equal(row.containerId,ack.containerId);assert.equal(row.imageId,ack.imageId);assert.equal(row.startedAt,ack.startedAt);assert.equal(row.hostPid,ack.hostPid);assert(Number.isSafeInteger(row.hostPid)&&row.hostPid>0);assert(Date.parse(row.startedAt)>Date.parse(prior.startedAt));assert(row.health==='healthy'||prior.role==='canvas-sync-worker'&&row.health===null);
  assert.equal(row.running,true);assert.equal(row.state,'running');assert.equal(row.paused,false);assert.equal(row.oomKilled,false);assert.equal(row.effectiveUid,prior.effectiveUid);assert.equal(row.configuredRuntimeUid,prior.configuredRuntimeUid);if(prior.effectiveGid!==undefined){assert.equal(row.effectiveGid,prior.effectiveGid);assert.equal(row.configuredRuntimeGid,prior.configuredRuntimeGid);}
  if(prior.binary){assert.equal(row.sha256,CURRENT10.roles[prior.role]?selection.binaries[prior.role].sha256:prior.sha256);assert.equal(row.processExecutableSha256,row.sha256);assert.equal(row.executablePath,'/usr/local/bin/'+prior.binary);}
  if(CURRENT10.roles[prior.role]){assert.equal(row.source,CURRENT10.source);assert.equal(row.coreSource,CURRENT10.core);assert.equal(row.kind,'SCOPED_NATIVE_FUNCTIONAL_OVERLAY');assert(!before.roles.some(value=>value.containerId===row.containerId));assert.deepEqual(runtime.comparableBinaryMounts(row.binaryMounts),runtime.comparableBinaryMounts([{type:'bind',source:selection.binaries[prior.role].path,destination:'/usr/local/bin/'+prior.binary,writable:false}]));}
  else {assert.equal(row.containerId,prior.containerId);assert.equal(row.source,prior.source);assert.equal(row.kind,prior.kind);assert.equal(row.binary,prior.binary);assert.equal(row.sha256,prior.sha256);assert.deepEqual(runtime.comparableBinaryMounts(row.binaryMounts),runtime.comparableBinaryMounts(prior.binaryMounts));}
 }
 return value;
}
module.exports={observe,observeOb3,validateOb3Observation,SOURCE,CORE,ROLES,CURRENT10};
