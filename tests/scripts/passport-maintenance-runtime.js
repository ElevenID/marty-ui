'use strict';
// Actual22 generation evidence only, never a runtime profile or apply authority.
const assert=require('node:assert/strict');
const runtime=require('./functional-debug-runtime');
const SOURCE='d2debf0fde2a0c826f8925aca648c9d3dabfbc9f';
const CORE='4320b5fa1c6f41231ee0aa2bc57d8008549f67ac';
const BASE='6877251e868d692b43825761a4ac99fecf133b519f295a347d12221970b5a7f3';
const BEFORE='09b2a8c03ff1907b6444baa91517c8a22ccaeabdbf82992e4198b76c92017fdc';
const ROLES=Object.freeze({flow:'marty-flow',gateway:'marty-gateway','issuance-native':'marty-issuance-service'});
const HASH=/^[a-f0-9]{64}$/;
const LATEST_SOURCE='852dbb5cc0cca79cfe0bbbed5cb8fb94cda0ad34';
const LATEST_PROFILE='native-devtest-passport-four-role';
const LATEST_BUILD='oid4vc-latest-maintenance-all-services';
const LATEST_ROLES=Object.freeze({applicant:'marty-applicant',...ROLES});
const CONTRACTS=Object.freeze({
 'd12-passport-canonical-subset':Object.freeze({source:SOURCE,roles:ROLES,build:'oid4vc-all-services',prepared:'c9b77a332139e5d7eb0e2684b5b54514ecad262531873e2f4c36dcd599da4c1a'}),
 [LATEST_PROFILE]:Object.freeze({source:LATEST_SOURCE,roles:LATEST_ROLES,build:LATEST_BUILD,prepared:null}),
});
function contract(selection){const value=CONTRACTS[selection.profile];assert(value,'Unreviewed maintenance scope');return value;}


function validateGenerations(expected,before,selection,observed){
 assert.equal(expected.length,22);assert.equal(new Set(expected.map(row=>row.role)).size,22);
 assert.deepEqual(before.map(row=>row.role).sort(),expected.map(row=>row.role).sort());
 assert.deepEqual(observed.map(row=>row.role).sort(),expected.map(row=>row.role).sort());
 assert.equal(new Set(before.map(row=>row.containerId)).size,22);
 assert.equal(new Set(observed.map(row=>row.containerId)).size,22);
 const c=contract(selection),roles=c.roles;
 assert.equal(selection.state,'SELECTED_NOT_DEPLOYED');
 assert.equal(selection.sourceRevision,c.source);assert.equal(selection.coreRevision,CORE);
 assert.deepEqual(selection.roleBinaries,roles);assert.deepEqual(Object.keys(selection.binaries).sort(),Object.keys(roles).sort());
 for(const field of ['releaseQualified','recordingQualified'])assert.equal(selection[field],false);
 assert.equal(selection.scope,'FUNCTIONAL_ONLY');
 return expected.map(row=>{
  const old=before.find(item=>item.role===row.role),actual=observed.find(item=>item.role===row.role);
  assert(old&&actual);assert(HASH.test(actual.containerId));
  for(const field of ['source','coreSource','sha256','kind','imageId','binary','project'])assert.deepEqual(old[field],row[field],'Predecessor lineage changed');
  assert(Date.parse(actual.startedAt)>Date.parse(old.startedAt),'All22 require a new maintenance generation');
  if(!roles[row.role]){
   assert.equal(actual.containerId,old.containerId,'Unselected container recreated');
   const validated=runtime.validateRuntimeObservation(row,actual,true);
   return {...validated,requiredObservation:{...row.requiredObservation,startedAt:actual.startedAt,hostPid:actual.hostPid},
    ...(row.requiredStartedAt!==undefined?{requiredStartedAt:actual.startedAt,requiredHostPid:actual.hostPid}:{})};
  }
  const binary=roles[row.role],bound=selection.binaries[row.role],target='/usr/local/bin/'+binary;
  assert(HASH.test(bound.sha256));assert(!before.some(prior=>prior.containerId===actual.containerId),'Selected container is not fresh');
  assert.equal(actual.effectiveUid,10001);assert.equal(actual.configuredRuntimeUid,10001);
  const applicantTransition=selection.profile===LATEST_PROFILE&&row.role==='applicant';
  const previousUid=applicantTransition?0:10001;
  assert.equal(old.effectiveUid,previousUid);assert.equal(old.configuredRuntimeUid,previousUid);
  if(selection.profile===LATEST_PROFILE){assert.equal(actual.effectiveGid,10001);assert.equal(actual.configuredRuntimeGid,10001);}
  assert.equal(actual.binaryMounts.length,1);const mount=actual.binaryMounts[0];
  assert.equal(mount.type,'bind');assert.equal(mount.destination,target);assert.equal(mount.writable,false);
  assert.deepEqual(runtime.comparableBinaryMounts([mount]),runtime.comparableBinaryMounts([{...mount,source:bound.path}]),'Selected executable source changed');
  const next={...row,source:c.source,coreSource:CORE,kind:'SCOPED_NATIVE_FUNCTIONAL_OVERLAY',sha256:bound.sha256,
   requiredContainerId:actual.containerId,requiredStartedAt:actual.startedAt,requiredHostPid:actual.hostPid,
   requiredEffectiveUid:10001,...(selection.profile===LATEST_PROFILE?{requiredEffectiveGid:10001}:{}),requiredBinaryMounts:actual.binaryMounts};
  delete next.requiredObservation;
  return runtime.validateRuntimeObservation(next,actual);
 });
}

function observeMaintenanceReadback({baseProfile,beforeBinding,selection:selectionRef},{readDocker,readJournal}={}){
 assert.equal(typeof readDocker,'function','Pinned actual Docker read transport required');
 assert.equal(typeof readJournal,'function','Original frozen canonical journal read transport required');
 assert.equal(baseProfile.sha256,BASE);assert.equal(beforeBinding.sha256,BEFORE);
 const base=runtime.boundJson(baseProfile),before=runtime.boundJson(beforeBinding),selection=runtime.boundJson(selectionRef);
 const receipt=runtime.boundJson(selection.canonicalBuildReceipt);
 const c=contract(selection);
 if(c.prepared)assert.equal(selection.preparedSource.sha256,c.prepared);
 const prepared=runtime.boundJson(selection.preparedSource);
 assert.deepEqual(selection.journal.specification,prepared.journalBackend);
 assert.equal(selection.journal.runId,prepared.runId);
 assert.deepEqual(receipt.roleBinaries,prepared.roleBinaries);
 assert.deepEqual(Object.keys(receipt.binaries).sort(),Object.values(prepared.roleBinaries).sort());
 for(const field of ['imagesBuilt','releaseQualified','recordingQualified'])assert.equal(receipt[field],false);
 // Exact authoritative bytes are compared with the immutable original receipt,
 // never reconstructed by JSON serialization or replaced by a three-file build.
 const reply=readJournal(selection.journal,'build-receipt.json');
 assert.equal(reply.ok,true);assert.equal(reply.name,'build-receipt.json');
 assert.deepEqual(reply.rootProof,selection.journal.specification.rootProof);
 assert.equal(reply.sha256,selection.canonicalBuildReceipt.sha256);assert.deepEqual(reply.value,receipt);
 assert.equal(receipt.state,'PASSED');assert.equal(receipt.canonicalAllServices,true);
 assert.equal(receipt.exitCode,0);assert.equal(receipt.oomKilled,false);
 assert.equal(receipt.source,c.source);assert.equal(receipt.uiRevision,c.source);assert.equal(receipt.coreRevision,CORE);
 assert.equal(receipt.buildProfile,c.build);assert.equal(prepared.buildProfile,c.build);
 assert.equal(prepared.uiRevision,c.source);assert.equal(prepared.coreRevision,CORE);
 assert.equal(receipt.preparationSha256,selection.preparedSource.sha256);
 assert.equal(receipt.runId,selection.journal.runId);
 assert.equal(Object.keys(receipt.binaries).length,29);
 for(const [role,binary]of Object.entries(c.roles))assert.deepEqual(selection.binaries[role],receipt.binaries[binary]);
 const engine=()=>readDocker(['info','--format','{{.ID}}']).trim();
 const id=engine();assert.equal(id,'3dbbbe66-1c98-4e0c-b0a6-f927c05e7341');
 const expected=runtime.expectedRuntime(base);
 // Enforce exact preimage/source/Core/UID/mount facts even for rows whose prior
 // profile used requiredContainerId instead of a full requiredObservation.
 const frozen=expected.map(row=>{
  const old=before.roles.find(item=>item.role===row.role);assert(old);
  const requiredObservation=Object.fromEntries(['containerId','imageId','health','executablePath','processExecutableSha256','binaryMounts','startedAt','hostPid','effectiveUid','configuredRuntimeUid'].map(field=>[field,old[field]]));
  return {...row,requiredObservation};
 });
 const observed=frozen.map(row=>runtime.observeDocker(row,readDocker));
 const roles=validateGenerations(frozen,before.roles,selection,observed);
 assert.equal(engine(),id);runtime.boundJson(baseProfile);runtime.boundJson(beforeBinding);runtime.boundJson(selectionRef);
 const again=readJournal(selection.journal,'build-receipt.json');assert.deepEqual(again,reply,'Canonical journal changed during actual22 readback');
 return {schema:selection.profile===LATEST_PROFILE?'marty.native-four-role-maintenance-readback/v1':'marty.passport-maintenance-readback/v1',scope:selection.profile===LATEST_PROFILE?'NATIVE_MAINTENANCE_READBACK_ONLY':'D12_MAINTENANCE_READBACK_ONLY',
  baseProfileSha256:BASE,beforeBindingSha256:BEFORE,selectionSha256:selectionRef.sha256,engineId:id,
  ...(selection.profile===LATEST_PROFILE?{observedRoles:observed}:{}),
  binding:{schema:'marty.functional-mixed-runtime-binding/v2',scope:'FUNCTIONAL_ONLY',mixedSourceStack:true,
   roles,releaseQualified:false,recordingQualified:false},
  profileProduced:false,migrationOutcomeQualified:false,applyAuthority:false,releaseQualified:false,recordingQualified:false};
}
module.exports={validateGenerations,observeMaintenanceReadback,ROLES,SOURCE,CORE,LATEST_PROFILE,LATEST_SOURCE,LATEST_ROLES,LATEST_BUILD,BASE,BEFORE};
