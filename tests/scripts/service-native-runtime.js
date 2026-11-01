'use strict';
// Two source-built service executables over the exact Auth mixed predecessor.
const assert=require('node:assert/strict');
const ROLES=Object.freeze({'gateway':'marty-gateway','signing-keys':'marty-signing-keys'});
const SOURCE='5d22484685fc6c8723e419e656252385c0db3654';
const CORE='4320b5fa1c6f41231ee0aa2bc57d8008549f67ac';
const HASH=/^[a-f0-9]{64}$/;
function expected(profile,{boundJson,verifyBoundFile,expectedRuntime,receiptDigests,applyNativeOverlayRows}){
 assert.equal(profile.schema,'marty.functional-mixed-runtime/v2');
 assert.equal(profile.scope,'FUNCTIONAL_ONLY');assert.equal(profile.releaseQualified,false);assert.equal(profile.recordingQualified,false);
 assert.deepEqual(Object.keys(profile).sort(),['baseProfile','recordingQualified','releaseQualified','schema','scope','serviceNativeOverlay']);
 const base=boundJson(profile.baseProfile);
 assert(base.authNativeOverlay&&!base.serviceNativeOverlay,'Exact Auth mixed predecessor required');
 const prior=expectedRuntime(base);assert.equal(prior.length,22);
 const overlay=profile.serviceNativeOverlay;
 assert.deepEqual(Object.keys(overlay).sort(),['buildReceipt','compatibilityPlan','compatibilityResult','deploymentReceipt','preparedSource']);
 const build=boundJson(overlay.buildReceipt),prepared=boundJson(overlay.preparedSource);
 const plan=boundJson(overlay.compatibilityPlan),compatibility=boundJson(overlay.compatibilityResult);
 const deployed=boundJson(overlay.deploymentReceipt);
 assert.equal(build.state,'BUILD_SUCCEEDED');assert.equal(build.exitCode,0);assert.equal(build.oomKilled,false);
 assert.equal(build.uiRevision,SOURCE);assert.equal(build.coreRevision,CORE);
 assert.deepEqual(build.roleBinaries,ROLES);
 assert.equal(build.preparationSha256,overlay.preparedSource.sha256);
 assert.equal(prepared.sources?.ui?.revision,SOURCE);
 assert.equal(prepared.sources?.core?.revision,CORE);
 assert.equal(build.runtimeUidLibrariesValidated,false,'Separate actual-image ABI proof required');
 assert.deepEqual(Object.keys(build.binaries).sort(),Object.values(ROLES).sort());
 assert.equal(plan.scope,'ELF_LOADER_UID_COMPATIBILITY_ONLY');
 assert.equal(plan.buildReceiptAuthoritativeSha256,overlay.buildReceipt.sha256);
 assert.equal(compatibility.schema,1);assert.equal(compatibility.state,'ELF_LOADER_UID_COMPATIBILITY_PASS');
 assert.equal(compatibility.planSha256,overlay.compatibilityPlan.sha256);
 for(const flag of ['candidateServiceEntrypointExecuted','signingOrApi','runtimeDeployed'])assert.equal(compatibility[flag],false);
 assert.equal(compatibility.rows?.length,2);
 assert.equal(new Set(compatibility.rows.map(row=>row.containerId)).size,2);
 const hashes={};
 for(const binary of Object.values(ROLES)){
  const item=build.binaries[binary];assert(HASH.test(item.sha256));
  verifyBoundFile(item,512*1024*1024);hashes[binary]=item.sha256;
  const row=compatibility.rows?.find(candidate=>candidate.binary===binary);
  assert(row);assert.equal(row.sha256,item.sha256);assert.equal(row.exitCode,0);
  assert.equal(row.uid,10001);assert.equal(row.gid,10001);assert.equal(row.imageId,prior.find(expected=>expected.role===Object.keys(ROLES).find(role=>ROLES[role]===binary)).imageId);
  assert.equal(row.candidateReadableExecutable,true);
  assert.equal(row.loaderListSucceeded,true);assert.equal(row.ownedContainerRemoved,true);
 }
 assert.equal(deployed.schema,'marty.scoped-native-overlay-deployment/v1');
 assert.equal(deployed.profile,'current-issuer-ready-two-role');
 assert.equal(deployed.scope,'FUNCTIONAL_ONLY');
 assert.equal(deployed.state,'APPLIED_FUNCTIONAL_ONLY');assert.equal(deployed.actualReadbackVerified,true);
 assert.equal(deployed.baseProfileSha256,profile.baseProfile.sha256);
 assert.equal(deployed.buildReceiptSha256,overlay.buildReceipt.sha256);
 assert.equal(deployed.compatibilityResultSha256,overlay.compatibilityResult.sha256);
 assert.equal(deployed.sourceRevision,SOURCE);assert.equal(deployed.coreRevision,CORE);
 assert.equal(deployed.engineId,boundJson(base.authNativeOverlay.result).engineId);
 for(const field of ['productionTouched','imagesBuilt','releaseQualified','recordingQualified'])assert.equal(deployed[field],false);
 const snapshot=boundJson(deployed.beforeRuntimeBinding);
 assert.equal(snapshot.baseProfileSha256,profile.baseProfile.sha256);
 const before=snapshot.binding;
 assert.deepEqual(before.receiptDigests,receiptDigests(base));
 return applyNativeOverlayRows(prior,before,deployed,{roles:Object.keys(ROLES),source:SOURCE,coreSource:CORE,
  kind:'SCOPED_NATIVE_FUNCTIONAL_OVERLAY',hashes});
}
module.exports={expected};
