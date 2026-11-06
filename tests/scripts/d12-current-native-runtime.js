'use strict';
// Source-bound actual Docker observation for the current D12 native three-role
// generation. This file performs no effects and does not qualify the passport
// business scenario, a release, or a recording.
const assert=require('node:assert/strict');
const runtime=require('./functional-debug-runtime');
const SOURCE='6117cea9290f57406cf109eae56f64f7986e3783';
const CORE='ffa24febcd0fb3fced15da7f28190af6d61ae0f9';
const ROLES=Object.freeze({flow:'marty-flow',gateway:'marty-gateway','issuance-native':'marty-issuance-service'});
const HASH=/^[a-f0-9]{64}$/;
function observe({before:beforeRef,selection:selectionRef,created:createdRef,startAcks:acksRef,runId,engineId},{readDocker}={}){
 assert.equal(typeof readDocker,'function','ACTUAL_DOCKER_TRANSPORT_REQUIRED');
 const info=JSON.parse(readDocker(['info','--format','{{json .}}']));assert.equal(info.ID,engineId,'D12_ENGINE_CHANGED');
 const before=runtime.boundJson(beforeRef),selection=runtime.boundJson(selectionRef);
 const created=runtime.boundJson(createdRef),starts=runtime.boundJson(acksRef);
 assert.equal(selection.profile,'d12-passport-current-functional');assert.equal(selection.state,'SELECTED_NOT_DEPLOYED');
 assert.equal(selection.sourceRevision,SOURCE);assert.equal(selection.coreRevision,CORE);
 assert.deepEqual(selection.roleBinaries,ROLES);assert.deepEqual(Object.keys(selection.binaries).sort(),Object.keys(ROLES).sort());
 assert.equal(selection.scope,'FUNCTIONAL_ONLY');assert.equal(selection.releaseQualified,false);assert.equal(selection.recordingQualified,false);
 assert.equal(before.roles.length,22);assert.equal(new Set(before.roles.map(x=>x.role)).size,22);
 const ids=new Set(before.roles.map(x=>x.containerId));assert.equal(ids.size,22);
 assert.equal(created.runId,runId);assert.equal(starts.runId,runId);
 assert.equal(created.roles.length,22);assert.equal(new Set(created.roles.map(x=>x.role)).size,22);
 assert.deepEqual(created.roles.map(x=>x.role).sort(),before.roles.map(x=>x.role).sort());
 assert.deepEqual(Object.keys(starts.acks).sort(),before.roles.map(x=>x.role).sort());
 const createdByRole=Object.fromEntries(created.roles.map(x=>[x.role,x]));
 assert.equal(new Set(created.roles.map(x=>x.containerId)).size,22);
 const rows=before.roles.map(prior=>{
  const actual=runtime.observeDocker(prior,readDocker);
  const owned=createdByRole[prior.role],ack=starts.acks[prior.role];
  assert.equal(actual.role,prior.role);assert.equal(actual.project,prior.project);assert.equal(actual.imageId,prior.imageId);
  assert.equal(owned.containerId,ack.containerId,'CREATED_AND_STARTED_CONTAINER_CHANGED');
  assert.equal(actual.containerId,owned.containerId,'D12_FOREIGN_SAME_BINARY_CONTAINER');
  assert.equal(actual.startedAt,ack.startedAt,'D12_UNEXPECTED_RESTART_GENERATION');
  assert.equal(actual.hostPid,ack.hostPid,'D12_UNEXPECTED_RESTART_PROCESS');
  assert.equal(actual.imageId,ack.imageId,'D12_STARTED_IMAGE_CHANGED');
  assert.equal(owned.imageId,prior.imageId,'D12_CREATED_IMAGE_CHANGED');
  assert.equal(owned.state,ROLES[prior.role]?'created':'exited','D12_CREATED_STATE_CHANGED');
  assert.equal(owned.hostPid,0,'D12_CREATED_ROLE_STILL_RUNNING');
  assert.equal(ROLES[prior.role]?owned.containerId!==prior.containerId:owned.containerId===prior.containerId,
    true,'D12_CREATED_LINEAGE_CHANGED');
  assert.equal(actual.running,true);assert.equal(actual.status,'running');
  assert(actual.health==='healthy'||prior.role==='canvas-sync-worker'&&actual.health===null,'D12_ROLE_HEALTH_NOT_ESTABLISHED');assert(HASH.test(actual.containerId));
  assert(Number.isInteger(actual.hostPid)&&actual.hostPid>0);assert(Date.parse(actual.startedAt)>Date.parse(prior.startedAt));
  if(prior.binary){assert.equal(actual.binarySha256,ROLES[prior.role]?selection.binaries[prior.role].sha256:prior.sha256);
   assert.equal(actual.processExecutableSha256,actual.binarySha256);
   assert.equal(actual.executablePath,'/usr/local/bin/'+prior.binary);}
  assert.equal(actual.effectiveUid,prior.effectiveUid);assert.equal(actual.configuredRuntimeUid,prior.configuredRuntimeUid);
  if(ROLES[prior.role]){
   const binary=ROLES[prior.role],bound=selection.binaries[prior.role],target='/usr/local/bin/'+binary;
   assert.equal(prior.binary,binary);assert(!ids.has(actual.containerId));assert.equal(actual.binaryMounts.length,1);
   const mount=actual.binaryMounts[0];assert.equal(mount.type,'bind');assert.equal(mount.destination,target);assert.equal(mount.writable,false);
   assert.deepEqual(runtime.comparableBinaryMounts([mount]),runtime.comparableBinaryMounts([{...mount,source:bound.path}]));
   const next={...prior,containerId:actual.containerId,startedAt:actual.startedAt,hostPid:actual.hostPid,
    health:actual.health,source:SOURCE,coreSource:CORE,kind:'SCOPED_NATIVE_FUNCTIONAL_OVERLAY',
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
module.exports={observe,SOURCE,CORE,ROLES};
