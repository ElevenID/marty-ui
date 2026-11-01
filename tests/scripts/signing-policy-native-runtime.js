'use strict';
// Exact Signing Keys correction over the previously observed mixed service pair.
const assert=require('node:assert/strict');
const fs=require('node:fs');
const ROLE='signing-keys', BINARY='marty-signing-keys';
const CORE='4320b5fa1c6f41231ee0aa2bc57d8008549f67ac';
const SOURCES=Object.freeze({
 'bdea3471667c6d413d74afc85c41573941682d5b':1,
 '53138ba3cbddccd063e1d49ef8efa0f28d838a02':4,
});
const HASH=/^[a-f0-9]{64}$/;
function expected(profile,{boundJson,verifyBoundFile,expectedRuntime,receiptDigests,applyNativeOverlayRows}){
 assert.equal(profile.schema,'marty.functional-mixed-runtime/v2');
 assert.equal(profile.scope,'FUNCTIONAL_ONLY');assert.equal(profile.releaseQualified,false);assert.equal(profile.recordingQualified,false);
 assert.deepEqual(Object.keys(profile).sort(),['baseProfile','recordingQualified','releaseQualified','schema','scope','signingPolicyNativeOverlay']);
 const base=boundJson(profile.baseProfile);
 assert(base.serviceNativeOverlay||base.signingPolicyNativeOverlay,'Exact mixed service predecessor required');
 const prior=expectedRuntime(base);assert.equal(prior.length,22);
 const previous=prior.find(row=>row.role===ROLE);assert(previous&&HASH.test(previous.sha256));
 const overlay=profile.signingPolicyNativeOverlay;
 assert.deepEqual(Object.keys(overlay).sort(),['buildReceipt','compatibilityPlan','compatibilityResult','deploymentReceipt','preparedSource']);
 const build=boundJson(overlay.buildReceipt),prepared=boundJson(overlay.preparedSource);
 const plan=boundJson(overlay.compatibilityPlan),compatibility=boundJson(overlay.compatibilityResult);
 const deployed=boundJson(overlay.deploymentReceipt);
 const testCount=SOURCES[build.uiRevision];assert(Number.isInteger(testCount),'Unreviewed Signing Keys source');
 assert.equal(build.state,'BUILD_SUCCEEDED');assert.equal(build.exitCode,0);assert.equal(build.oomKilled,false);
 assert.equal(build.coreRevision,CORE);assert.equal(build.buildProfile,'current-issuer-policy-signing-only');
 assert.deepEqual(build.roleBinaries,{[ROLE]:BINARY});
 assert.equal(build.preparationSha256,overlay.preparedSource.sha256);
 assert.equal(prepared.sources?.ui?.revision,build.uiRevision);assert.equal(prepared.sources?.core?.revision,CORE);
 assert.equal(build.runtimeUidLibrariesValidated,false,'Separate actual-image ABI proof required');
 assert.deepEqual(Object.keys(build.binaries),[BINARY]);
 const binary=build.binaries[BINARY];assert(HASH.test(binary.sha256));verifyBoundFile(binary,512*1024*1024);
 assert.equal(build.focusedRustTest?.exitCode,0);verifyBoundFile(build.focusedRustTest.stdout,1024*1024);
 assert(fs.readFileSync(build.focusedRustTest.stdout.path,'utf8').includes(`test result: ok. ${testCount} passed; 0 failed;`));
 assert.equal(plan.scope,'ELF_LOADER_UID_COMPATIBILITY_ONLY');
 assert.equal(plan.buildReceiptAuthoritativeSha256,overlay.buildReceipt.sha256);
 assert.equal(compatibility.schema,1);assert.equal(compatibility.state,'ELF_LOADER_UID_COMPATIBILITY_PASS');
 assert.equal(compatibility.planSha256,overlay.compatibilityPlan.sha256);
 for(const flag of ['candidateServiceEntrypointExecuted','signingOrApi','runtimeDeployed'])assert.equal(compatibility[flag],false);
 assert.equal(compatibility.rows?.length,1);
 const row=compatibility.rows[0];assert.equal(row.binary,BINARY);assert.equal(row.sha256,binary.sha256);
 assert(HASH.test(row.containerId));assert.equal(row.exitCode,0);assert.equal(row.uid,10001);assert.equal(row.gid,10001);
 assert.equal(row.imageId,previous.imageId);
 for(const field of ['candidateReadableExecutable','loaderListSucceeded','ownedContainerRemoved'])assert.equal(row[field],true);
 assert.equal(deployed.schema,'marty.scoped-native-overlay-deployment/v1');
 assert.equal(deployed.profile,'current-issuer-policy-signing-only');
 assert.equal(deployed.scope,'FUNCTIONAL_ONLY');assert.equal(deployed.state,'APPLIED_FUNCTIONAL_ONLY');
 assert.equal(deployed.actualReadbackVerified,true);assert.equal(deployed.baseProfileSha256,profile.baseProfile.sha256);
 assert.equal(deployed.buildReceiptSha256,overlay.buildReceipt.sha256);
 assert.equal(deployed.compatibilityResultSha256,overlay.compatibilityResult.sha256);
 assert.equal(deployed.sourceRevision,build.uiRevision);assert.equal(deployed.coreRevision,CORE);
 assert.equal(deployed.engineId,boundJson(base.serviceNativeOverlay?.deploymentReceipt||base.signingPolicyNativeOverlay.deploymentReceipt).engineId);
 for(const field of ['productionTouched','imagesBuilt','releaseQualified','recordingQualified'])assert.equal(deployed[field],false);
 const snapshot=boundJson(deployed.beforeRuntimeBinding);
 assert.equal(snapshot.baseProfileSha256,profile.baseProfile.sha256);
 assert.deepEqual(snapshot.binding.receiptDigests,receiptDigests(base));
 const beforeRole=snapshot.binding.roles.find(row=>row.role===ROLE);
 assert.equal(beforeRole.sha256,previous.sha256,'Prior Signing Keys binary changed');
 return applyNativeOverlayRows(prior,snapshot.binding,deployed,{roles:[ROLE],source:build.uiRevision,coreSource:CORE,
  kind:'SCOPED_NATIVE_FUNCTIONAL_OVERLAY',hashes:{[BINARY]:binary.sha256}});
}
module.exports={expected};
