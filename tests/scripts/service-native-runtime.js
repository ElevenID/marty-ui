'use strict';
// Closed policies for the original service pair and D05 native offer successor.
const assert=require('node:assert/strict');
const fs=require('node:fs');
const CORE='4320b5fa1c6f41231ee0aa2bc57d8008549f67ac';
const HASH=/^[a-f0-9]{64}$/;
const POLICIES=Object.freeze({
 service:Object.freeze({field:'serviceNativeOverlay',roles:Object.freeze({gateway:'marty-gateway','signing-keys':'marty-signing-keys'}),source:'5d22484685fc6c8723e419e656252385c0db3654',profile:'current-issuer-ready-two-role'}),
 issuance:Object.freeze({field:'issuanceOfferNativeOverlay',roles:Object.freeze({'issuance-native':'marty-issuance-service'}),source:'e836a700579a1dc0be4894c6bf416c26529d2564',profile:'d05-issuance-offer-format-only',tests:Object.freeze(['public_offer_uses_the_same_format_specific_configuration_id_as_application_offers','native_offer_transaction_reads_match_the_python_oracle_contract'])}),
 fence:Object.freeze({field:'issuanceFenceNativeOverlay',roles:Object.freeze({'issuance-native':'marty-issuance-service'}),source:'3394c6d816c60584f8c8c5e941c3a22144b67350',profile:'canvas-bootstrap-fence-issuance-only',tests:Object.freeze(['public_offer_uses_the_same_format_specific_configuration_id_as_application_offers','native_offer_transaction_reads_match_the_python_oracle_contract'])}),
});
function expectedWithPolicy(profile,{boundJson,verifyBoundFile,expectedRuntime,receiptDigests,applyNativeOverlayRows},policy){
 assert.equal(profile.schema,'marty.functional-mixed-runtime/v2');assert.equal(profile.scope,'FUNCTIONAL_ONLY');
 assert.equal(profile.releaseQualified,false);assert.equal(profile.recordingQualified,false);
 assert.deepEqual(Object.keys(profile).sort(),['baseProfile',policy.field,'recordingQualified','releaseQualified','schema','scope'].sort());
 const base=boundJson(profile.baseProfile);
 if(policy===POLICIES.service)assert(base.authNativeOverlay&&!base.serviceNativeOverlay,'Exact Auth mixed predecessor required');
 else if(policy===POLICIES.fence)assert(base.issuanceOfferNativeOverlay&&!base.issuanceFenceNativeOverlay,'Exact prior Issuance overlay required');
 else assert(base.runtimeResume&&!base.issuanceOfferNativeOverlay,'Exact retained beta predecessor required');
 const prior=expectedRuntime(base);assert.equal(prior.length,22);
 if(policy===POLICIES.issuance){const previous=prior.find(row=>row.role==='issuance-native');
  assert(previous&&previous.kind==='SIGNED_NIGHTLY_IMAGE'&&previous.source==='225818494f4ba716e75df7225d6c43d71b038879');
  assert.equal(previous.binary,'marty-issuance-service');assert.deepEqual(previous.requiredObservation.binaryMounts,[]);}
 if(policy===POLICIES.fence){const previous=prior.find(row=>row.role==='issuance-native');
  assert(previous&&previous.kind==='SCOPED_NATIVE_FUNCTIONAL_OVERLAY'&&previous.source===POLICIES.issuance.source);
  assert.equal(previous.binary,'marty-issuance-service');assert.equal(previous.sha256,'d8c66406134fe638318e9ffb946d81c35eadf29f752720af27ca79949dfd92ff');
  assert.equal(previous.requiredBinaryMounts?.length,1);}
 const overlay=profile[policy.field];
 assert.deepEqual(Object.keys(overlay).sort(),['buildReceipt','compatibilityPlan','compatibilityResult','deploymentReceipt','preparedSource']);
 const build=boundJson(overlay.buildReceipt),prepared=boundJson(overlay.preparedSource);
 const plan=boundJson(overlay.compatibilityPlan),compatibility=boundJson(overlay.compatibilityResult),deployed=boundJson(overlay.deploymentReceipt);
 assert.equal(build.state,'BUILD_SUCCEEDED');assert.equal(build.exitCode,0);assert.equal(build.oomKilled,false);
 assert.equal(build.uiRevision,policy.source);assert.equal(build.coreRevision,CORE);
 assert.deepEqual(build.roleBinaries,policy.roles);
 if(policy===POLICIES.fence){const original=boundJson(build.sourceBuildReceipt);
  assert.equal(build.sourceProof.sha256,overlay.preparedSource.sha256);assert.deepEqual(original.source,prepared);
  assert.equal(original.state,'BUILD_SUCCEEDED');assert.deepEqual(original.binary,build.binaries['marty-issuance-service']);
  assert.equal(prepared.uiRevision,policy.source);assert.equal(prepared.coreRevision,CORE);}
 else{assert.equal(build.preparationSha256,overlay.preparedSource.sha256);
  assert.equal(prepared.sources?.ui?.revision,policy.source);assert.equal(prepared.sources?.core?.revision,CORE);}
 assert.equal(build.runtimeUidLibrariesValidated,false,'Separate actual-image ABI proof required');
 assert.deepEqual(Object.keys(build.binaries).sort(),Object.values(policy.roles).sort());
 if(policy.tests){assert.equal(build.buildProfile,policy.profile);if(policy!==POLICIES.fence)assert.equal(prepared.buildProfile,policy.profile);
  assert.deepEqual(build.focusedRustTests?.map(row=>row.name),policy.tests);
  for(const row of build.focusedRustTests){assert.equal(row.exitCode,0);verifyBoundFile(row.stdout,1024*1024,0);verifyBoundFile(row.stderr,1024*1024,0);
   assert(fs.readFileSync(row.stdout.path,'utf8').includes('test result: ok. 1 passed; 0 failed;'));}}
 assert.equal(plan.scope,'ELF_LOADER_UID_COMPATIBILITY_ONLY');assert.equal(plan.buildReceiptAuthoritativeSha256,overlay.buildReceipt.sha256);
 assert.equal(compatibility.schema,1);assert.equal(compatibility.state,'ELF_LOADER_UID_COMPATIBILITY_PASS');
 assert.equal(compatibility.planSha256,overlay.compatibilityPlan.sha256);
 for(const flag of ['candidateServiceEntrypointExecuted','signingOrApi','runtimeDeployed'])assert.equal(compatibility[flag],false);
 const roles=Object.keys(policy.roles),rows=compatibility.rows;
 assert.equal(rows?.length,roles.length);assert.equal(new Set(rows.map(row=>row.containerId)).size,roles.length);
 const hashes={};
 for(const [role,binary] of Object.entries(policy.roles)){
  const item=build.binaries[binary];assert(item&&HASH.test(item.sha256));verifyBoundFile(item,512*1024*1024);hashes[binary]=item.sha256;
  const row=rows.find(candidate=>candidate.binary===binary);assert(row);assert.equal(row.sha256,item.sha256);
  assert(HASH.test(row.containerId));assert.equal(row.exitCode,0);assert.equal(row.uid,10001);assert.equal(row.gid,10001);
  assert.equal(row.imageId,prior.find(expected=>expected.role===role).imageId);
  for(const flag of ['candidateReadableExecutable','loaderListSucceeded','ownedContainerRemoved'])assert.equal(row[flag],true);
 }
 assert.equal(deployed.schema,'marty.scoped-native-overlay-deployment/v1');assert.equal(deployed.profile,policy.profile);
 assert.equal(deployed.scope,'FUNCTIONAL_ONLY');assert.equal(deployed.state,'APPLIED_FUNCTIONAL_ONLY');assert.equal(deployed.actualReadbackVerified,true);
 assert.equal(deployed.baseProfileSha256,profile.baseProfile.sha256);assert.equal(deployed.buildReceiptSha256,overlay.buildReceipt.sha256);
 assert.equal(deployed.compatibilityResultSha256,overlay.compatibilityResult.sha256);assert.equal(deployed.sourceRevision,policy.source);assert.equal(deployed.coreRevision,CORE);
 const engine=policy===POLICIES.service?boundJson(base.authNativeOverlay.result).engineId:'3dbbbe66-1c98-4e0c-b0a6-f927c05e7341';
 assert.equal(deployed.engineId,engine);
 for(const flag of ['productionTouched','imagesBuilt','releaseQualified','recordingQualified'])assert.equal(deployed[flag],false);
 const snapshot=boundJson(deployed.beforeRuntimeBinding);
 if(policy===POLICIES.fence)assert.equal(snapshot.profileSha256,profile.baseProfile.sha256);
 else assert.equal(snapshot.baseProfileSha256,profile.baseProfile.sha256);
 const before=snapshot.binding;assert.deepEqual(before.receiptDigests,receiptDigests(base));
 if(policy===POLICIES.issuance||policy===POLICIES.fence){const previous=prior.find(row=>row.role==='issuance-native'),beforeRole=before.roles.find(row=>row.role==='issuance-native');
  assert.equal(beforeRole.containerId,previous.requiredContainerId);assert.equal(beforeRole.sha256,previous.sha256);}
 return applyNativeOverlayRows(prior,before,deployed,{roles,source:policy.source,coreSource:CORE,kind:'SCOPED_NATIVE_FUNCTIONAL_OVERLAY',hashes});
}
function expected(profile,deps){return expectedWithPolicy(profile,deps,POLICIES.service);}
function expectedIssuanceOffer(profile,deps){return expectedWithPolicy(profile,deps,POLICIES.issuance);}
function expectedIssuanceFence(profile,deps){return expectedWithPolicy(profile,deps,POLICIES.fence);}
module.exports={expected,expectedIssuanceOffer,expectedIssuanceFence};
