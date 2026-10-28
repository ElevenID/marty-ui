'use strict';
// Opt-in local functionality only. This cannot qualify a release or a recording.
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const crypto=require('node:crypto');
const {execFileSync}=require('node:child_process');
const HASH=/^[a-f0-9]{64}$/,REV=/^[a-f0-9]{40}$/;
const DEBUG_ROLES=Object.freeze({applicant:'marty-applicant',issuance:'marty-issuance-service',
 'issuance-native':'marty-issuance-service',gateway:'marty-gateway',
 'presentation-policy':'marty-presentation-policy','credential-template':'marty-credential-template'});
const ISSUANCE_SOURCE='85a6e31265f465a6a46c0cd97ecc6be4770fe7b4',ISSUANCE_CORE='44040270000f93b7e7499cbec31b3bb3dd7e3df1';
const ISSUANCE_ROLES=Object.freeze(['issuance','issuance-native']);
const RETAINED_ROLES=Object.freeze({flow:'marty-flow','signing-keys':'marty-signing-keys'});
const digest=value=>crypto.createHash('sha256').update(value).digest('hex');
function boundBytes(ref){
 assert(ref&&path.isAbsolute(ref.path)&&HASH.test(ref.sha256),'Explicit hash-bound receipt required');
 assert(fs.lstatSync(ref.path).isFile()&&!fs.lstatSync(ref.path).isSymbolicLink(),'Receipt must be regular');
 const bytes=fs.readFileSync(ref.path);assert(bytes.length>0&&bytes.length<=16*1024*1024,'Receipt size invalid');
 assert.equal(digest(bytes),ref.sha256,'Reviewed receipt changed');
 return bytes;
}
function boundJson(ref){
 const bytes=boundBytes(ref),text=bytes[0]===255&&bytes[1]===254?bytes.subarray(2).toString('utf16le'):bytes.toString('utf8').replace(/^\uFEFF/,'');
 return JSON.parse(text);
}
function binaryFor(role){return ({issuance:'marty-issuance-service','issuance-native':'marty-issuance-service',verification:'marty-verification-service'})[role]||'marty-'+role;}
function expectedRuntime(profile){
 if(profile?.schema==='marty.functional-mixed-runtime/v2'){
  if(profile.nativeOverlay)return expectedScopedNativeOverlay(profile);
  const expected=expectedIssuanceOverlay(profile);
  return profile.maintenanceRestart?expectedMaintenanceRestart(profile,expected):expected;
 }
 assert.equal(profile.schema,'marty.functional-mixed-runtime/v1');
 assert.equal(profile.scope,'FUNCTIONAL_ONLY');assert.equal(profile.releaseQualified,false);assert.equal(profile.recordingQualified,false);
 const baseline=boundJson(profile.baselineDeployment),build=boundJson(profile.baselineBuild);
 assert.equal(baseline.source_kind,'local-worktree-snapshot');assert.equal(baseline.promotion_eligible,false);
 assert.equal(build.state,'BUILD_SUCCEEDED');assert.equal(build.exitCode,0);assert(REV.test(build.sourceRevision));
 assert.equal(baseline.component_revisions['marty-ui'],build.sourceRevision);
 const outputs=new Map(build.actualBinaryOutputs.map(row=>[row.name,row.sha256]));
 assert.equal(outputs.size,build.actualBinaryOutputs.length);assert.equal(outputs.size,32);
 const deployed=boundJson(profile.debugDeployment),debug=boundJson(profile.debugBuild);
 assert.equal(deployed.scope,'BETA_R32_D03_D05_DEBUG_BINARY_FUNCTIONAL_ONLY');
 assert.equal(deployed.state,'BETA_DEBUG_BINARIES_ACTIVE_FUNCTIONAL_ONLY');assert.equal(deployed.releaseQualified,false);
 assert.equal(deployed.productionTouched,false);assert.equal(deployed.imageBuilt,false);
 assert.equal(debug.state,'BUILD_PASS_NOT_DEPLOYED');assert.equal(debug.release_qualified,false);
 assert.equal(debug.profile,'dev');assert.equal(debug.source_clean_before_after,true);
 assert.equal(debug.features,'default package features; KMS-only pinned dependencies; no test/feature overrides');
 assert.equal(debug.builder_image_digest,'sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1');
 assert.equal(debug.source_revision,deployed.sourceRevision);assert(REV.test(debug.source_revision));
 assert.equal(deployed.buildReceiptSha256,profile.debugBuild.sha256);
 assert.deepEqual(debug.binary_sha256,deployed.binarySha256);
 assert.deepEqual(Object.keys(deployed.live.ids).sort(),Object.keys(DEBUG_ROLES).sort());
 assert.deepEqual(Object.keys(debug.binary_sha256).sort(),[...new Set(Object.values(DEBUG_ROLES))].sort());
 assert.deepEqual(Object.keys(profile.retainedBuilds).sort(),Object.keys(RETAINED_ROLES).sort());
 let prior=null;
 if(profile.priorNativeOverlay){
  prior=boundJson(profile.priorNativeOverlay);
  assert.equal(prior.state,'APPLIED_LOCAL_ONLY');assert.equal(prior.productionReleaseQualified,false);
  assert.equal(prior.imagesBuiltForCandidate,false);assert.equal(prior.imageSourceMarkerRemainsBaseline,true);
  assert(REV.test(prior.sourceRevision));
  assert.equal(prior.buildReceiptSha256,profile.priorNativeBuild.sha256);
  assert.equal(prior.buildArtifactsSha256,profile.priorNativeArtifacts.sha256);
  const artifacts=boundJson(profile.priorNativeArtifacts),nativeBuild=boundJson(profile.priorNativeBuild);
  assert.equal(artifacts.state,'PASSED');assert.equal(artifacts.source,prior.sourceRevision);
  assert.equal(artifacts.releaseQualified,false);assert.equal(artifacts.linuxReadbackMatched,true);
  assert.equal(nativeBuild.state,'PASSED');assert.equal(nativeBuild.source,prior.sourceRevision);assert.equal(nativeBuild.exitCode,0);
  const hashes=new Map(artifacts.files.map(row=>[row.binary_name,row.sha256]));
  assert.equal(new Set(prior.rows.map(row=>row.service)).size,prior.rows.length);
  for(const row of prior.rows){assert.equal(row.candidateSha256,hashes.get(row.binary));assert.equal(row.observedAfterSha256,row.candidateSha256);}
 }
 const retained={};
 for(const [role,binary]of Object.entries(RETAINED_ROLES)){
  const row=boundJson(profile.retainedBuilds[role]);assert.equal(row.state,'PASSED');assert.equal(row.exitCode,0);
  assert.equal(path.basename(row.binary.replaceAll('\\','/')),binary);assert(REV.test(row.source));assert(HASH.test(row.binarySha256));
  retained[role]={source:row.source,sha256:row.binarySha256};
 }
 const rows=baseline.images;assert(Array.isArray(rows)&&new Set(rows.map(row=>row.service)).size===rows.length);
 if(prior)assert.deepEqual(prior.rows.map(row=>row.service).sort(),rows.filter(row=>row.service!=='ui-prod').map(row=>row.service).sort(),'Prior overlay must cover exactly the reviewed native roles');
 const expected=rows.map(row=>{
  const role=row.service,binary=role==='ui-prod'?null:binaryFor(role);
  let source=build.sourceRevision,sha256=binary?outputs.get(binary):null,kind='CANONICAL_R32';
  if(prior&&binary){const previous=prior.rows.filter(item=>item.service===role);assert.equal(previous.length,1,'Missing prior role lineage');
   assert.equal(previous[0].binary,binary);assert.equal(previous[0].imageId,row.image_id);
   source=prior.sourceRevision;sha256=previous[0].candidateSha256;kind='PRIOR_CANONICAL_NATIVE_OVERLAY';}
  if(DEBUG_ROLES[role]){source=debug.source_revision;sha256=debug.binary_sha256[binary];kind='DEBUG_PRODUCTION_BINARY';}
  if(retained[role]){({source,sha256}=retained[role]);kind='RETAINED_SOURCE_BOUND_BINARY';}
  assert(!binary||HASH.test(sha256||''),'Missing exact role binary hash');
  return {role,binary,source,sha256,kind,imageId:row.image_id,
   project:role==='ui-prod'?'elevenid-beta-ui':'elevenid-beta',
   ...(DEBUG_ROLES[role]?{requiredContainerId:deployed.live.ids[role]}:{})};
 });
 for(const role of [...Object.keys(DEBUG_ROLES),...Object.keys(RETAINED_ROLES)])assert(expected.some(row=>row.role===role),'Missing required overlay role');
 return expected;
}
function expectedIssuanceOverlay(profile){
 assert.equal(profile.scope,'FUNCTIONAL_ONLY');assert.equal(profile.releaseQualified,false);assert.equal(profile.recordingQualified,false);
 const base=boundJson(profile.baseProfile);assert.equal(base.schema,'marty.functional-mixed-runtime/v1');
 const expected=expectedRuntime(base);assert.equal(expected.length,22);
 const overlay=profile.issuanceOverlay,build=boundJson(overlay.buildReceipt),deployed=boundJson(overlay.deploymentReceipt);
 assert.equal(build.scope,'ISSUANCE_ONLY_NATIVE_FUNCTIONAL_OVERLAY');assert.equal(build.state,'BUILD_SUCCEEDED');assert.equal(build.exitCode,0);
 assert.equal(build.profile,'dev');assert.equal(build.sourceRevision,ISSUANCE_SOURCE);assert.equal(build.coreRevision,ISSUANCE_CORE);
 assert.equal(build.sourceCleanBeforeAfter,true);assert.equal(build.releaseQualified,false);assert.equal(build.recordingQualified,false);assert.equal(build.imageBuilt,false);
 assert.equal(build.cargoCommand,'cargo build --locked --offline --message-format=json -p marty-issuance-service --bin marty-issuance-service');
 assert.equal(build.features,'issuance-package default features; KMS-only sources; no test/feature overrides; functional-only noncanonical selection');
 assert.equal(build.cargoIncremental,0);assert.equal(build.cargoProfileDevDebug,0);assert.equal(build.rustToolchain,'1.95.0');assert.equal(build.builderPlatform,'linux/amd64');
 assert.equal(build.binary?.name,'marty-issuance-service');assert(HASH.test(build.binary.sha256));
 const prepared=boundJson(build.sourcePreparation),artifacts=boundJson(build.coreCompilerArtifacts);
 assert.equal(prepared.uiRevision,ISSUANCE_SOURCE);assert.equal(prepared.coreRevision,ISSUANCE_CORE);
 assert.equal(prepared.uiTree,'3c11b3cee95d533a650ac1f31504ccf320ec2494');assert.equal(prepared.coreTree,'6ac871ff0b6862e2f5f19374b853f6f7c52049bb');
 const inventoryHashes={'ui-source':'33a2fe61469e27e455222042f4ce2a11f9475328052438c05433ec521b8fcc96','core-source':'ffeeacc05f3f409fff877fd75ecf8d33d251794b0245e22cb09f8b0d4407d06f'};
 for(const key of ['ui-source','core-source']){const inventory=prepared.sourceInventories?.[key];
  assert(Number.isInteger(inventory?.files)&&inventory.files>0);assert(Number.isInteger(inventory.bytes)&&inventory.bytes>0);assert.equal(inventory.inventorySha256,inventoryHashes[key]);}
 assert.equal(prepared.recipeSha256,'2beef9b635f8fefeb36470722b0b87089810b0666ecbf37b0d60a6dcf4236fd1');
 assert.equal(prepared.localizerSha256,'b1dd31880f82f91d2f9151d05cb01c29ca702ce057595ff18c2708378d2167f5');
 assert.equal(prepared.builderImage,'sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1');
 assert(Array.isArray(artifacts)&&artifacts.length>0);const compiledNames=new Set();
 const knownCore=['marty-canonical-digest','marty-crypto','marty-didcomm','marty-emrtd-issuance','marty-iso18013','marty-oid4vci','marty-status','marty-verification','marty-x509-verification'];
 const kmsCore=['marty-crypto','marty-didcomm','marty-oid4vci','marty-verification'];
 for(const artifact of artifacts){
  const name=artifact.name;assert(knownCore.includes(name),'Unknown Core compiler package');compiledNames.add(name);
  assert.equal(artifact.manifest,'/build/core/'+name+'/Cargo.toml','Core compiler artifact source is unbound');
  assert.equal(typeof artifact.fresh,'boolean');assert(Array.isArray(artifact.features)&&artifact.features.every(feature=>typeof feature==='string'));
  assert(artifact.features.every(feature=>!['default','local-key-operations','test-fixtures'].includes(feature)),'Forbidden Core features');
  if(kmsCore.includes(name))assert(artifact.features.includes('kms-only'),'Missing KMS-only feature');
  assert(Array.isArray(artifact.filenames)&&artifact.filenames.length>0&&artifact.filenames.every(file=>typeof file==='string'&&path.posix.isAbsolute(file)));
 }
 for(const name of kmsCore)assert(compiledNames.has(name),'Issuer Core compiler artifact absent: '+name);

 assert.equal(deployed.scope,'ISSUANCE_ONLY_NATIVE_FUNCTIONAL_OVERLAY');assert.equal(deployed.state,'APPLIED_FUNCTIONAL_ONLY');
 assert.equal(deployed.baseProfileSha256,profile.baseProfile.sha256);assert.equal(deployed.buildReceiptSha256,overlay.buildReceipt.sha256);
 assert.equal(deployed.sourceRevision,build.sourceRevision);assert.equal(deployed.coreRevision,build.coreRevision);assert.equal(deployed.binarySha256,build.binary.sha256);
 assert.equal(deployed.productionTouched,false);assert.equal(deployed.imagesBuilt,false);assert.equal(deployed.releaseQualified,false);assert.equal(deployed.recordingQualified,false);
 assert.deepEqual(Object.keys(deployed.roles).sort(),[...ISSUANCE_ROLES].sort());
 const snapshot=boundJson(deployed.beforeRuntimeBinding);assert.equal(snapshot.baseProfileSha256,profile.baseProfile.sha256);
 assert.deepEqual(snapshot.binding.receiptDigests,receiptDigests(base));
 return applyNativeOverlayRows(expected,snapshot.binding,deployed,{roles:ISSUANCE_ROLES,source:build.sourceRevision,
  coreSource:build.coreRevision,kind:'ISSUANCE_CORE_FUNCTIONAL_OVERLAY',hashes:{'marty-issuance-service':build.binary.sha256}});
}
function applyNativeOverlayRows(expected,before,deployed,selection){
 assert(['marty.functional-mixed-runtime-binding/v1','marty.functional-mixed-runtime-binding/v2'].includes(before.schema));
 assert.equal(before.scope,'FUNCTIONAL_ONLY');assert.equal(before.releaseQualified,false);assert.equal(before.recordingQualified,false);assert.equal(before.mixedSourceStack,true);
 return applyNativeOverlayObservations(expected,before.roles,deployed,selection);
}
function applyNativeOverlayObservations(expected,priorRoles,deployed,selection){
 assert.equal(expected.length,22);assert.equal(new Set(expected.map(row=>row.role)).size,22);
 assert.equal(priorRoles.length,22);assert.equal(new Set(priorRoles.map(row=>row.role)).size,22);assert.equal(new Set(priorRoles.map(row=>row.containerId)).size,22);
 assert.deepEqual(Object.keys(deployed.roles).sort(),[...selection.roles].sort());
 for(const row of expected){
  const old=priorRoles.find(item=>item.role===row.role);assert(old,'Missing prior role identity');
  for(const field of ['binary','source','sha256','kind','imageId','project'])assert.equal(old[field],row[field],'Prior role lineage mismatch');
  assert.equal(old.coreSource,row.coreSource,'Prior Core lineage mismatch');
  assert(HASH.test(old.containerId));if(row.requiredContainerId)assert.equal(old.containerId,row.requiredContainerId);
  assert(Number.isInteger(old.hostPid)&&old.hostPid>0);assert(Number.isFinite(Date.parse(old.startedAt)));
  assert(Number.isInteger(old.effectiveUid)&&old.effectiveUid>=0);assert(Number.isInteger(old.configuredRuntimeUid)&&old.configuredRuntimeUid>=0);
  assert(Array.isArray(old.binaryMounts));assert(old.binaryMounts.every(mount=>mount.writable===false));
  assert.equal(old.processExecutableSha256,row.sha256);assert.equal(old.executablePath,row.binary?'/usr/local/bin/'+row.binary:null);
  assert(old.health==='healthy'||(row.role==='canvas-sync-worker'&&old.health===null));
  if(row.requiredObservation)for(const [field,value]of Object.entries(row.requiredObservation))assert.deepEqual(old[field],value,'Prior runtime generation drift');
  for(const [required,field]of [['requiredStartedAt','startedAt'],['requiredHostPid','hostPid'],['requiredEffectiveUid','effectiveUid'],['requiredBinaryMounts','binaryMounts']])
   if(row[required]!==undefined)assert.deepEqual(old[field],row[required],'Prior runtime generation drift');
 }
 const ids=new Set();
 return expected.map(row=>{
  const old=priorRoles.find(item=>item.role===row.role);
  if(!selection.roles.includes(row.role))return {...row,requiredObservation:Object.fromEntries(['containerId','imageId','health','executablePath','processExecutableSha256','binaryMounts','startedAt','hostPid','effectiveUid','configuredRuntimeUid'].map(field=>[field,old[field]]))};
  const actual=deployed.roles[row.role],target='/usr/local/bin/'+row.binary,hash=selection.hashes[row.binary];assert(HASH.test(hash));
  assert(HASH.test(actual.containerId));assert(!priorRoles.some(previous=>previous.containerId===actual.containerId),'Native overlay requires a fresh noncolliding container');
  assert(!ids.has(actual.containerId));ids.add(actual.containerId);assert.equal(actual.imageId,row.imageId);
  assert.equal(actual.processExecutablePath,target);assert.equal(actual.processExecutableSha256,hash);assert.equal(actual.mountedBinarySha256,hash);
  assert(Number.isInteger(actual.configuredRuntimeUid)&&actual.configuredRuntimeUid>=0);assert.equal(actual.effectiveUid,actual.configuredRuntimeUid);assert.equal(actual.effectiveUid,old.effectiveUid);assert.equal(actual.configuredRuntimeUid,old.configuredRuntimeUid);
  assert(Number.isInteger(actual.hostPid)&&actual.hostPid>0);assert(Number.isFinite(Date.parse(actual.startedAt)));
  assert(Date.parse(actual.startedAt)>Date.parse(old.startedAt),'Overlay generation must be newer than its predecessor');
  assert.equal(actual.binaryMount?.type,'bind');assert.equal(actual.binaryMount.destination,target);assert.equal(actual.binaryMount.writable,false);assert(path.isAbsolute(actual.binaryMount.source));
  const updated={...row,source:selection.source,coreSource:selection.coreSource,sha256:hash,kind:selection.kind,
   requiredContainerId:actual.containerId,requiredStartedAt:actual.startedAt,requiredHostPid:actual.hostPid,requiredEffectiveUid:actual.effectiveUid,requiredBinaryMounts:[actual.binaryMount]};
  delete updated.requiredObservation;return updated;
 });
}
const D02_NATIVE=Object.freeze({source:'3b862bebdd2cc0707d9a38f6df55db198b6be417',core:'4320b5fa1c6f41231ee0aa2bc57d8008549f67ac',
 base:'ab4b4ac2df9fc63194e0f94cc305e77fd81fc4123c84a7e1edce8e8d211266e6',build:'f75b84553ecc793dc9fe75f3d9d3c44a33fe24cd8b2b76a58a5234734a67b4cb',
 prepared:'2e618ca73c38ec34758b1197f69232ab4a6829151233cc2c0ff576f80bc1a152',artifacts:'4361e285bbe45003cd4995e4ca224649d8749b10d2c7e5f866a32596502e6abd',
 compatibility:'d515a42d7c50c5809fbe6fd28c4032f9a46372320e258392191e7229c4bea699',compatibilityPlan:'312f63030f5869b22bdd2bda4eff17e07c2767e4560302981f1e40a64dec0b0b',
 roles:Object.freeze({'signing-keys':'marty-signing-keys',gateway:'marty-gateway'})});
// Expected rows only: a failed API gate can establish an observed preimage,
// never a qualified binding. The enclosing profile must bind these documents
// to reviewed immutable refs before using the successor's actual readback.
function expectedUnqualifiedNativePreimage(expected,before,raw,disposition,selection){
 assert.equal(disposition.phase,'DEPLOYED_UNQUALIFIED_ETAG_GATE_FAILED');
 assert.equal(disposition.releaseQualified,false);assert.equal(disposition.recordingQualified,false);
 assert.equal(disposition.headerGateFailure?.authOutcomeKnown,true);
 assert.equal(disposition.headerGateFailure?.authCleanupComplete,true);
 assert.equal(disposition.headerGateFailure?.runtimeRestartPerformed,false);
 assert.equal(selection.source,D02_NATIVE.source);assert.equal(selection.coreSource,D02_NATIVE.core);
 assert.deepEqual([...selection.roles].sort(),Object.keys(D02_NATIVE.roles).sort());
 assert.equal(selection.kind,'SCOPED_NATIVE_FUNCTIONAL_OVERLAY');
 assert.equal(raw.releaseQualified,false);assert.equal(raw.rows.length,22);
 assert.equal(new Set(raw.rows.map(row=>row.role)).size,22);
 assert.equal(new Set(raw.rows.map(row=>row.containerId)).size,22);
 assert.deepEqual(raw.rows.map(row=>row.role).sort(),expected.map(row=>row.role).sort());
 const deployed={roles:Object.fromEntries(selection.roles.map(role=>{
  const actual=raw.rows.find(row=>row.role===role);assert.equal(actual.binaryMounts.length,1);
  return [role,{...actual,processExecutablePath:actual.executablePath,
   mountedBinarySha256:actual.binarySha256,binaryMount:actual.binaryMounts[0]}];
 }))};
 const rows=applyNativeOverlayRows(expected,before,deployed,selection);
 for(const row of rows)validateRuntimeObservation(row,raw.rows.find(actual=>actual.role===row.role));
 return rows;
}
const D02_HEADER=Object.freeze({source:'9b1efd21163dadeff7cf1ced5fe47c5e046d2121',core:D02_NATIVE.core,base:D02_NATIVE.base,
 profile:'d02-signing-cas-no-transform',build:'b620c4d184af2f7e9652ee59944ac74d58f23ea50e36cdb9ac3b46625c7f7848',
 prepared:'c39572315e1982bb28e97bbf7c40876570e6dbe6cfa5ced6cf4b1184f32435c2',artifacts:'11104e1fc1ee5cce1298f33970fd4d53ff5bda38fe1250e27b7c4837f85cd8e0',
 compatibility:'9612c78b915063f1e5306adc19333c7b6956628326a537ea2143d585e3e3c374',compatibilityPlan:'23d2a605e21cbde167f33986a9fcc4329e4a66211394e90bb029b60cfac450cd',
 before:'5e692c8355ed89c380646553febf2bb69c8c5388a29a2f9046d0bc27b0acc482',observed:'75c3628415065733602b399e0d185d20e6e38be4dde09a01632c22297d837495',
 failedAuthority:'c18570fd8f89585200df021904b1e0f7bf639efdb83adc5a90c6f724349d0686',roles:Object.freeze({'signing-keys':'marty-signing-keys'})});
function nativeBuildEvidence(overlay,pins){
 for(const [key,pin]of [['buildReceipt','build'],['preparedSource','prepared'],['compatibilityResult','compatibility'],['compatibilityPlan','compatibilityPlan']])assert.equal(overlay[key].sha256,pins[pin],'Unreviewed native-overlay evidence');
 const build=boundJson(overlay.buildReceipt),prepared=boundJson(overlay.preparedSource),compatibility=boundJson(overlay.compatibilityResult),compatibilityPlan=boundJson(overlay.compatibilityPlan);
 assert.equal(build.state,'BUILD_SUCCEEDED');assert.equal(build.exitCode,0);assert.equal(build.oomKilled,false);assert.equal(build.buildProfile,pins.profile);
 assert.equal(build.uiRevision,pins.source);assert.equal(build.coreRevision,pins.core);assert.deepEqual(build.roleBinaries,pins.roles);
 assert.equal(build.preparationSha256,overlay.preparedSource.sha256);assert.equal(prepared.uiRevision,build.uiRevision);assert.equal(prepared.coreRevision,build.coreRevision);assert.deepEqual(prepared.roleBinaries,pins.roles);
 assert.equal(build.releaseQualified,false);assert.equal(build.recordingQualified,false);assert.equal(build.coreCompilerArtifacts.sha256,pins.artifacts);boundJson(build.coreCompilerArtifacts);
 if(pins.profile==='d02-signing-cas-no-transform'){assert.equal(compatibility.schema,1);assert.equal(compatibility.state,'ELF_LOADER_UID_COMPATIBILITY_PASS');}
 else{assert.equal(compatibility.scope,'ELF_LOADER_UID_COMPATIBILITY_ONLY');assert.equal(compatibility.status,'PASSED');}
 assert.equal(compatibilityPlan.scope,'ELF_LOADER_UID_COMPATIBILITY_ONLY');assert.equal(compatibility.planSha256,overlay.compatibilityPlan.sha256);
 assert.equal(compatibilityPlan.buildReceiptAuthoritativeSha256,overlay.buildReceipt.sha256);assert.equal(compatibility.candidateServiceEntrypointExecuted,false);assert.equal(compatibility.signingOrApi,false);assert.equal(compatibility.runtimeDeployed,false);
 assert.deepEqual(Object.keys(build.binaries).sort(),Object.values(pins.roles).sort());
 assert.equal(compatibility.rows.length,Object.keys(pins.roles).length);assert.equal(new Set(compatibility.rows.map(row=>row.binary)).size,Object.keys(pins.roles).length);
 for(const [binary,output]of Object.entries(build.binaries)){
  assert(HASH.test(output.sha256));const row=compatibility.rows.find(item=>item.binary===binary);assert(row);assert.equal(row.sha256,output.sha256);assert.equal(row.exitCode,0);assert.equal(row.uid,10001);
  for(const field of ['candidateReadableExecutable','loaderListSucceeded','ownedContainerRemoved'])assert.equal(row[field],true);
 }
 return {build,prepared,compatibility,compatibilityPlan};
}
function expectedScopedNativeOverlay(profile){
 assert.equal(profile.scope,'FUNCTIONAL_ONLY');assert.equal(profile.releaseQualified,false);assert.equal(profile.recordingQualified,false);
 assert.deepEqual(Object.keys(profile).sort(),['baseProfile','nativeOverlay','recordingQualified','releaseQualified','schema','scope']);
 assert.equal(profile.baseProfile.sha256,D02_NATIVE.base,'Foreign native-overlay base');
 const base=boundJson(profile.baseProfile);assert.equal(base.schema,'marty.functional-mixed-runtime/v2');assert(!base.nativeOverlay);assert(base.maintenanceRestart);
 const expected=expectedRuntime(base),overlay=profile.nativeOverlay;
 if(overlay.profile===D02_HEADER.profile)return expectedHeaderSuccessor(profile,base,expected);
 assert.equal(overlay.profile,'d02-signing-cas');
 assert.deepEqual(Object.keys(overlay).sort(),['buildReceipt','compatibilityPlan','compatibilityResult','deploymentReceipt','preparedSource','profile']);
 const {build}=nativeBuildEvidence(overlay,{...D02_NATIVE,profile:'d02-signing-cas'});
 const deployed=boundJson(overlay.deploymentReceipt);assert.equal(deployed.schema,'marty.scoped-native-overlay-deployment/v1');assert.equal(deployed.profile,overlay.profile);
 assert.equal(deployed.state,'APPLIED_FUNCTIONAL_ONLY');assert.equal(deployed.actualReadbackVerified,true);assert.equal(deployed.baseProfileSha256,profile.baseProfile.sha256);
 assert.equal(deployed.buildReceiptSha256,overlay.buildReceipt.sha256);assert.equal(deployed.compatibilityResultSha256,overlay.compatibilityResult.sha256);
 assert.equal(deployed.sourceRevision,build.uiRevision);assert.equal(deployed.coreRevision,build.coreRevision);assert.equal(deployed.engineId,boundJson(base.maintenanceRestart).engineId);
 for(const field of ['productionTouched','imagesBuilt','releaseQualified','recordingQualified'])assert.equal(deployed[field],false);
 const snapshot=boundJson(deployed.beforeRuntimeBinding);assert.equal(snapshot.baseProfileSha256,profile.baseProfile.sha256);assert.deepEqual(snapshot.binding.receiptDigests,receiptDigests(base));
 return applyNativeOverlayRows(expected,snapshot.binding,deployed,{roles:Object.keys(D02_NATIVE.roles),source:build.uiRevision,coreSource:build.coreRevision,
  kind:'SCOPED_NATIVE_FUNCTIONAL_OVERLAY',hashes:Object.fromEntries(Object.entries(build.binaries).map(([binary,row])=>[binary,row.sha256]))});
}

function headerSuccessorPreimage(profile,base,expected){
 const overlay=profile.nativeOverlay;
 assert.deepEqual(Object.keys(overlay).sort(),['buildReceipt','compatibilityPlan','compatibilityResult','deploymentReceipt','predecessor','preparedSource','profile']);
 const {build}=nativeBuildEvidence(overlay,D02_HEADER),prior=overlay.predecessor;
 assert.deepEqual(Object.keys(prior).sort(),['beforeRuntimeBinding','buildReceipt','compatibilityPlan','compatibilityResult','failedAuthority','observedRuntime','preparedSource']);
 const {build:priorBuild}=nativeBuildEvidence(prior,{...D02_NATIVE,profile:'d02-signing-cas'});
 for(const [key,pin]of [['beforeRuntimeBinding','before'],['observedRuntime','observed'],['failedAuthority','failedAuthority']])assert.equal(prior[key].sha256,D02_HEADER[pin],'Foreign unqualified predecessor');
 const snapshot=boundJson(prior.beforeRuntimeBinding);assert.equal(snapshot.baseProfileSha256,profile.baseProfile.sha256);assert.deepEqual(snapshot.binding.receiptDigests,receiptDigests(base));
 const authority=boundJson(prior.failedAuthority);assert.equal(authority.authority,'LINUX_PRIVATE_JOURNAL');assert.equal(authority.windowsDurabilityClaimed,false);
 assert(HASH.test(authority.authoritativeSha256));
 const observed=boundJson(prior.observedRuntime),preimage=expectedUnqualifiedNativePreimage(expected,snapshot.binding,observed,authority.value,
  {roles:Object.keys(D02_NATIVE.roles),source:priorBuild.uiRevision,coreSource:priorBuild.coreRevision,kind:'SCOPED_NATIVE_FUNCTIONAL_OVERLAY',
   hashes:Object.fromEntries(Object.entries(priorBuild.binaries).map(([binary,row])=>[binary,row.sha256]))});
 return {preimage,build,authority,prior};
}
function expectedHeaderSuccessorPreimage(profile){
 assert.equal(profile.schema,'marty.functional-mixed-runtime/v2');assert.equal(profile.scope,'FUNCTIONAL_ONLY');
 assert.equal(profile.releaseQualified,false);assert.equal(profile.recordingQualified,false);assert.equal(profile.baseProfile.sha256,D02_NATIVE.base);
 assert.equal(profile.nativeOverlay.profile,D02_HEADER.profile);const base=boundJson(profile.baseProfile);
 assert(!base.nativeOverlay&&base.maintenanceRestart);return headerSuccessorPreimage(profile,base,expectedRuntime(base)).preimage;
}
function expectedHeaderSuccessor(profile,base,expected){
 const overlay=profile.nativeOverlay,{preimage,build,authority,prior}=headerSuccessorPreimage(profile,base,expected);
 const deployed=boundJson(overlay.deploymentReceipt);assert.equal(deployed.schema,'marty.scoped-native-overlay-deployment/v1');assert.equal(deployed.profile,overlay.profile);
 assert.equal(deployed.state,'APPLIED_FUNCTIONAL_ONLY');assert.equal(deployed.actualReadbackVerified,true);assert.equal(deployed.baseProfileSha256,profile.baseProfile.sha256);
 assert.equal(deployed.buildReceiptSha256,overlay.buildReceipt.sha256);assert.equal(deployed.compatibilityResultSha256,overlay.compatibilityResult.sha256);
 assert.equal(deployed.sourceRevision,build.uiRevision);assert.equal(deployed.coreRevision,build.coreRevision);assert.equal(deployed.engineId,boundJson(base.maintenanceRestart).engineId);
 assert.equal(deployed.predecessorAuthoritySha256,prior.failedAuthority.sha256);
 for(const field of ['productionTouched','imagesBuilt','releaseQualified','recordingQualified'])assert.equal(deployed[field],false);
 validateHeaderSuccessorGate(deployed,boundJson(authority.value.headerGateFailure.signingDomainReadback));
 const current=boundJson(deployed.beforeObservedRuntime);assert.equal(current.releaseQualified,false);assert.equal(current.rows.length,22);
 assert.equal(new Set(current.rows.map(row=>row.role)).size,22);
 const priorRoles=preimage.map(row=>validateRuntimeObservation(row,current.rows.find(actual=>actual.role===row.role)));
 return applyNativeOverlayObservations(preimage,priorRoles,deployed,{roles:['signing-keys'],source:build.uiRevision,coreSource:build.coreRevision,
  kind:'SCOPED_NATIVE_FUNCTIONAL_OVERLAY',hashes:Object.fromEntries(Object.entries(build.binaries).map(([binary,row])=>[binary,row.sha256]))});
}

function validateHeaderSuccessorGate(deployed,priorDomain){
 assert.equal(deployed.state,'APPLIED_FUNCTIONAL_ONLY');assert.equal(deployed.actualReadbackVerified,true);
 const gate=deployed.configGate;assert.equal(gate.registryUnchanged,true);assert.equal(gate.revisionBindingVerified,true);
 const before=boundJson(gate.signingDomainBefore),after=boundJson(gate.signingDomainAfter);
 validateSigningDomainTransition(priorDomain,before);
 validateSigningDomainTransition(before,after,boundJson(gate.authResult).etag);
 const auth=boundJson(gate.authResult);assert.equal(auth.state,'PASSED');assert.equal(auth.scope,'D02_EXPLICIT_SIGNING_CONFIG_GET_WRITE_CAPABLE');
 assert.equal(auth.httpStatus,200);assert.equal(auth.explicitConfigGetCount,1);assert.equal(auth.providerEditRequested,false);
 assert.equal(auth.strongOpaqueRevision,true);assert.equal(auth.cacheControlNoStore,true);assert.equal(auth.cacheControlNoTransform,true);
 assert(typeof auth.etag==='string'&&/^"r-[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}"$/.test(auth.etag),'INVALID_STRONG_ETAG');
 for(const field of ['sessionRetired','privateCookieRetired','browserClosed'])assert.equal(auth[field],true);assert(!auth.cleanupFailure);
 const body=boundBytes(auth.privateResponse);assert(body.length<=1024*1024,'CONFIG_BODY_BOUND');assert(auth.bodySha256===digest(body),'CONFIG_BODY_DIGEST');
 let document;try{document=JSON.parse(body.toString('utf8'));}catch{throw new Error('CONFIG_BODY_JSON');}assert(Array.isArray(document.services),'CONFIG_BODY_SCHEMA');assert(document.services.length===auth.serviceCount,'CONFIG_SERVICE_COUNT');
}

function signingDomainRows(snapshot){
 assert(snapshot&&snapshot.database===2&&snapshot.complete===true,'SIGNING_DB_OR_SCAN');
 assert(snapshot.configuredBy==='SIGNING_KEYS_REDIS_URL'&&snapshot.credentialMatchesConfiguredUrl===true&&snapshot.redisWrites===false,'SIGNING_CONFIG_AUTHORITY');
 assert(Array.isArray(snapshot.blockers)&&snapshot.blockers.length===0,'ROTATION_NOT_QUIESCENT');
 assert(Array.isArray(snapshot.rows)&&snapshot.rows.length<=2048,'SIGNING_ROWS_BOUND');
 const rows=new Map();
 for(const row of snapshot.rows){
  assert(typeof row.key==='string'&&row.key.length>0&&!rows.has(row.key),'SIGNING_DUPLICATE_KEY');
  assert(typeof row.dumpHex==='string'&&/^(?:[a-f0-9]{2})+$/.test(row.dumpHex),'SIGNING_DUMP_ENCODING');
  assert(typeof row.valueHex==='string'&&/^(?:[a-f0-9]{2})*$/.test(row.valueHex),'SIGNING_VALUE_ENCODING');
  assert(Number.isInteger(row.pttl)&&row.pttl>=-1,'SIGNING_KEY_EXPIRED');
  assert(['string','hash','list','set','zset','stream'].includes(row.type),'SIGNING_KEY_TYPE');rows.set(row.key,row);
 }
 return rows;
}
function validateSigningDomainTransition(before,after,etag){
 const old=signingDomainRows(before),current=signingDomainRows(after);
 for(const key of ['containerId','image','networkId','hostname','port'])assert(before[key]===after[key],'SIGNING_REDIS_IDENTITY');
 const org='00000000-0000-0000-0000-000000000001',permitted=etag===undefined?null:'org:'+org+':signing-key-services-revision';
 for(const key of new Set([...old.keys(),...current.keys()])){
  if(key===permitted)continue;
  const a=old.get(key),b=current.get(key);
  // Never print private DUMP or value bytes through assertion diffs.
  assert(a&&b&&a.dumpHex===b.dumpHex&&a.type===b.type&&a.valueHex===b.valueHex,'SIGNING_DOMAIN_CHANGED');
 }
 if(permitted){
  assert(typeof etag==='string'&&/^"r-[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}"$/.test(etag),'INVALID_STRONG_ETAG');
  const sidecar=current.get(permitted),raw=current.get('org:'+org+':signing-key-services');
  assert(sidecar&&sidecar.type==='string'&&sidecar.pttl===-1,'REVISION_SIDECAR_MISSING');
  assert(!raw||raw.type==='string','SIGNING_REGISTRY_TYPE');
  const payload=raw?Buffer.concat([Buffer.from('present\0'),Buffer.from(raw.valueHex,'hex')]):Buffer.from('absent\0');
  const expected=Buffer.from(etag.slice(3,-1)+':'+digest(payload),'ascii');
  assert(Buffer.from(sidecar.valueHex,'hex').equals(expected),'REVISION_PAYLOAD_BINDING_FAILED');
 }
}

function maintenanceAuthority(ref,expected){
 const authority=boundJson(ref);
 assert.equal(authority.schema,'marty.functional-runtime-maintenance-authority/v1');
 assert.equal(authority.scope,'FUNCTIONAL_ONLY');assert.equal(authority.releaseQualified,false);assert.equal(authority.recordingQualified,false);
 assert.match(authority.engineId,/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/);
 boundBytes(authority.operator);boundBytes(authority.restoreSource);
 const journal=boundJson(authority.journal),restore=boundJson(authority.restoreIntent);
 assert.equal(journal.sourceSha256,authority.operator.sha256);
 assert.equal(journal.phase,'RESTORED_225_CONFIG_67_RUNNING');assert.equal(journal.state,'RESTORED_PENDING_ROOT_ENDPOINT_AND_RUNTIME_REBIND');
 assert.equal(journal.appStopIntent,true);assert.equal(journal.appStartIntent,true);assert.equal(journal.freshBackupComplete,true);
 assert.equal(restore.sourceSha256,authority.operator.sha256);assert.equal(restore.scope,'RESTORE_ONLY_NO_DESKTOP_COMMAND');
 assert.deepEqual(restore.normalization,{Dns:'None to []',DnsSearch:'None to []',DnsOptions:'None to []'});
 assert.equal(restore.expectedContainerCount,225);
 assert.equal(restore.observedRunningBeforeRestore,4);
 assert.deepEqual(authority.restoredCounts,{containers:225,running:67});
 if(journal.freshBackupFileCount!==undefined){
  assert(Number.isInteger(journal.freshBackupFileCount)&&journal.freshBackupFileCount>0);
  const backup=boundJson(authority.freshBackupIntegrity);
  assert.equal(Object.keys(backup).length+1,journal.freshBackupFileCount,'Fresh backup count differs');
 }
 assert(Array.isArray(journal.originalRunning)&&journal.originalRunning.length===67);
 assert.equal(new Set(journal.originalRunning).size,67);assert(journal.originalRunning.every(id=>HASH.test(id)));
 assert.deepEqual([...journal.stopIntents].sort(),[...journal.originalRunning].sort(),'Maintenance did not stop every original runtime');
 for(const row of expected){const id=row.requiredContainerId||row.requiredObservation?.containerId;
  assert(HASH.test(id||'')&&journal.originalRunning.includes(id),'Role is outside the reviewed maintenance runtime');}
 return authority;
}
function expectedMaintenanceRestart(profile,expected){
 const receipt=boundJson(profile.maintenanceRestart);
 assert.equal(receipt.schema,'marty.functional-runtime-maintenance-restart/v1');
 assert.equal(receipt.scope,'FUNCTIONAL_ONLY');assert.equal(receipt.releaseQualified,false);assert.equal(receipt.recordingQualified,false);
 const base=boundJson(receipt.baseProfile);assert(!base.maintenanceRestart,'Maintenance restart cannot hide another restart layer');
 const original={...profile};delete original.maintenanceRestart;
 assert.deepEqual(original,base,'Maintenance restart must retain the exact prior profile');
 const authority=maintenanceAuthority(receipt.authority,expected);assert.equal(receipt.engineId,authority.engineId);
 assert(Array.isArray(receipt.roles)&&receipt.roles.length===22);assert.equal(new Set(receipt.roles.map(row=>row.role)).size,22);
 assert.equal(new Set(receipt.roles.map(row=>row.containerId)).size,22);
 return expected.map(row=>{
  const actual=receipt.roles.find(item=>item.role===row.role);assert(actual,'Restart role missing');
  validateRestartObservation(row,actual);
  return {...row,...(row.requiredObservation?{requiredObservation:{...row.requiredObservation,startedAt:actual.startedAt,hostPid:actual.hostPid}}:{}),
   ...(row.requiredStartedAt!==undefined?{requiredStartedAt:actual.startedAt,requiredHostPid:actual.hostPid}:{})};
 });
}
function produceMaintenanceRestart(profileRef,authorityRef,options={}){
 assert(Object.keys(options).every(key=>key==='readDocker'),'Restart producer requires actual Docker reads, not supplied observations');
 const read=options.readDocker||defaultDockerRead;assert.equal(typeof read,'function');
 const profile=boundJson(profileRef);assert.equal(profile.schema,'marty.functional-mixed-runtime/v2');assert(!profile.maintenanceRestart);
 const expected=expectedRuntime(profile),authority=maintenanceAuthority(authorityRef,expected);
 const engine=()=>JSON.parse(read(['info','--format','{{json .}}']));
 const beforeEngine=engine();assert.equal(beforeEngine.ID,authority.engineId,'Maintenance engine changed');
 const counts=value=>{
  assert(Number.isSafeInteger(value.Containers)&&value.Containers>=0,'Docker container count is invalid');
  assert(Number.isSafeInteger(value.ContainersRunning)&&value.ContainersRunning>=0
    &&value.ContainersRunning<=value.Containers,'Docker running count is invalid');
  return {containers:value.Containers,running:value.ContainersRunning};
 };
 const beforeCounts=counts(beforeEngine);
 const roles=expected.map(row=>{
  const actual=observeDocker(row,read);validateRestartObservation(row,actual);return actual;
 });
 const afterEngine=engine();assert.equal(afterEngine.ID,authority.engineId,'Maintenance engine changed during observation');
 const afterCounts=counts(afterEngine);
 boundJson(profileRef);maintenanceAuthority(authorityRef,expected);expectedRuntime(profile);
 return {schema:'marty.functional-runtime-maintenance-restart/v1',scope:'FUNCTIONAL_ONLY',releaseQualified:false,recordingQualified:false,
  baseProfile:profileRef,authority:authorityRef,engineId:authority.engineId,
  engineCounts:{before:beforeCounts,after:afterCounts},roles};
}
function configuredUid(value){
 if(value===''||value==='root'||value==='root:root')return 0;
 if(/^\d+(?::[^:]+)?$/.test(value))return Number(value.split(':')[0]);
 return null;
}
function receiptDigests(profile){if(profile.nativeOverlay)return {baseProfile:profile.baseProfile.sha256,nativeBuild:profile.nativeOverlay.buildReceipt.sha256,nativeDeployment:profile.nativeOverlay.deploymentReceipt.sha256,nativeCompatibility:profile.nativeOverlay.compatibilityResult.sha256,...(profile.nativeOverlay.predecessor?{nativePredecessorAuthority:profile.nativeOverlay.predecessor.failedAuthority.sha256,nativePriorBuild:profile.nativeOverlay.predecessor.buildReceipt.sha256}:{})};return profile.schema==='marty.functional-mixed-runtime/v2'?{baseProfile:profile.baseProfile.sha256,issuanceBuild:profile.issuanceOverlay.buildReceipt.sha256,issuanceDeployment:profile.issuanceOverlay.deploymentReceipt.sha256,...(profile.maintenanceRestart?{maintenanceRestart:profile.maintenanceRestart.sha256}:{})}:{baselineDeployment:profile.baselineDeployment.sha256,baselineBuild:profile.baselineBuild.sha256,
   debugDeployment:profile.debugDeployment.sha256,debugBuild:profile.debugBuild.sha256,
   retainedBuilds:Object.fromEntries(Object.entries(profile.retainedBuilds).map(([role,ref])=>[role,ref.sha256])),
   ...(profile.priorNativeOverlay?{priorNativeOverlay:profile.priorNativeOverlay.sha256,priorNativeBuild:profile.priorNativeBuild.sha256,priorNativeArtifacts:profile.priorNativeArtifacts.sha256}:{})};}
const defaultDockerRead=args=>execFileSync('docker',args,{encoding:'utf8',timeout:30000,maxBuffer:4*1024*1024,windowsHide:true});
function comparableBinaryMounts(mounts){
 assert(Array.isArray(mounts));
 return mounts.map(mount=>{
  const source=mount.source;assert(typeof source==='string'&&source.length>0&&!/[\x00-\x1f\x7f]/.test(source),'Invalid executable mount source');
  const windows=source.match(/^([cd]):[\\/](.+)$/i),desktop=source.match(/^\/run\/desktop\/mnt\/host\/([cd])\/(.+)$/);
  let normalized=source;
  if(windows||desktop){
   const match=windows||desktop,suffix=windows?match[2].replaceAll('\\','/'):match[2];
   assert(!suffix.includes('\\')&&suffix.split('/').every(part=>part&&part!=='.'&&part!=='..'),'Noncanonical host mount source');
   normalized='/run/desktop/mnt/host/'+match[1].toLowerCase()+'/'+suffix;
  }else{
   assert(path.posix.isAbsolute(source)&&!source.startsWith('//')&&!/^\/(?:mnt\/host|host_mnt|run\/desktop\/mnt\/host)(?:\/|$)/i.test(source),'Unsupported host mount alias');
   assert(source.split('/').every(part=>part!=='.'&&part!=='..'),'Mount source traversal');
  }
  return {...mount,source:normalized};
 });
}
function observeDocker(expected,read=defaultDockerRead){
 assert.equal(typeof read,'function','Docker transport must read the actual engine');
 const ids=read(['ps','-q','--no-trunc','--filter','label=com.docker.compose.project='+expected.project,
  '--filter','label=com.docker.compose.service='+expected.role]).trim().split(/\s+/).filter(Boolean);
 assert.equal(ids.length,1,'Missing or ambiguous role');
 const row=JSON.parse(read(['inspect',ids[0]]))[0];
 const labels=row.Config?.Labels||{};
 const binaryPath=expected.binary?'/usr/local/bin/'+expected.binary:null;
 const executablePath=expected.binary?read(['exec',row.Id,'readlink','/proc/1/exe']).trim():null;
 const processHash=expected.binary?read(['exec',row.Id,'sha256sum','/proc/1/exe']).trim().split(/\s+/)[0]:null;
 const hash=expected.binary?read(['exec',row.Id,'sha256sum',binaryPath]).trim().split(/\s+/)[0]:null;
 const binaryMounts=expected.binary?(row.Mounts||[]).filter(mount=>binaryPath===mount.Destination||binaryPath.startsWith(mount.Destination.replace(/\/$/,'')+'/')).map(mount=>({type:mount.Type,source:mount.Source,destination:mount.Destination,writable:mount.RW===true})):[];
 const uidStatus=read(['exec',row.Id,'cat','/proc/1/status']);
 const uidMatch=uidStatus.match(/^Uid:\s+\d+\s+(\d+)\s+/m);assert(uidMatch,'PID1 effective UID unavailable');
 const effectiveUid=Number(uidMatch[1]),configuredRuntimeUid=configuredUid(row.Config?.User||'');
 const after=JSON.parse(read(['inspect',row.Id]))[0];
 assert.equal(after.State?.StartedAt,row.State?.StartedAt,'Role restarted during executable observation');
 assert.equal(after.State?.Pid,row.State?.Pid,'Role process changed during executable observation');
 return {role:expected.role,containerId:row.Id,imageId:row.Image,project:labels['com.docker.compose.project'],
  service:labels['com.docker.compose.service'],running:row.State?.Running===true,
  status:row.State?.Status,health:row.State?.Health?.Status||null,binarySha256:hash,
  binaryMounts,executablePath,processExecutableSha256:processHash,startedAt:row.State?.StartedAt,hostPid:row.State?.Pid,
  effectiveUid,configuredRuntimeUid};
}
function isNativeOverlayRow(row){return ['ISSUANCE_CORE_FUNCTIONAL_OVERLAY','SCOPED_NATIVE_FUNCTIONAL_OVERLAY'].includes(row.kind);}
function validateRuntimeObservation(row,actual,ignoreGeneration=false){
 assert.equal(actual.role,row.role);assert.equal(actual.project,row.project);
 assert.equal(actual.service,row.role);assert.equal(actual.imageId,row.imageId);assert(HASH.test(actual.containerId));
 if(row.requiredObservation)for(const [field,value]of Object.entries(row.requiredObservation)){if(ignoreGeneration&&['startedAt','hostPid'].includes(field))continue;assert.deepEqual(field==='binaryMounts'?comparableBinaryMounts(actual[field]):actual[field],field==='binaryMounts'?comparableBinaryMounts(value):value,'Unchanged role observation differs: '+row.role+'/'+field);}
 if(row.requiredContainerId)assert.equal(actual.containerId,row.requiredContainerId,'Reviewed debug container changed');
 if(!ignoreGeneration&&row.requiredStartedAt!==undefined){assert.equal(actual.startedAt,row.requiredStartedAt);assert.equal(actual.hostPid,row.requiredHostPid);}
 if(isNativeOverlayRow(row)){
  assert(Number.isInteger(row.requiredEffectiveUid)&&row.requiredEffectiveUid>=0,'Native overlay effective UID expectation is missing');
  assert(Array.isArray(row.requiredBinaryMounts)&&row.requiredBinaryMounts.length>0,'Native overlay executable mount expectation is missing');
  assert(Number.isFinite(Date.parse(row.requiredStartedAt))&&Number.isInteger(row.requiredHostPid)&&row.requiredHostPid>0,'Native overlay generation expectation is missing');
  assert.equal(actual.effectiveUid,row.requiredEffectiveUid);assert.equal(actual.configuredRuntimeUid,row.requiredEffectiveUid);
  assert.deepEqual(comparableBinaryMounts(actual.binaryMounts),comparableBinaryMounts(row.requiredBinaryMounts),'Reviewed native overlay executable mount changed');}
 assert.equal(actual.running,true);assert.equal(actual.status,'running');
 assert(actual.health==='healthy'||(row.role==='canvas-sync-worker'&&actual.health===null),'Role health not established');
 assert.equal(actual.binarySha256,row.sha256,'Actual mounted executable differs from source-bound role');
 if(row.binary){assert.equal(actual.executablePath,'/usr/local/bin/'+row.binary,'PID1 is not the exact expected service');
  assert.equal(actual.processExecutableSha256,row.sha256,'Running inode differs from source-bound executable');
  assert(Array.isArray(actual.binaryMounts));assert(actual.binaryMounts.every(mount=>mount.writable===false),'Executable mount must be read-only');
  if(row.kind==='DEBUG_PRODUCTION_BINARY'||row.kind==='RETAINED_SOURCE_BOUND_BINARY')assert(actual.binaryMounts.length>0,'Expected reviewed executable mount is absent');}
 assert(Number.isInteger(actual.hostPid)&&actual.hostPid>0);assert(typeof actual.startedAt==='string'&&Number.isFinite(Date.parse(actual.startedAt)));
 return {...row,containerId:actual.containerId,health:actual.health,startedAt:actual.startedAt,hostPid:actual.hostPid,
  executablePath:actual.executablePath,processExecutableSha256:actual.processExecutableSha256,binaryMounts:actual.binaryMounts,
  ...(actual.effectiveUid!==undefined?{effectiveUid:actual.effectiveUid,configuredRuntimeUid:actual.configuredRuntimeUid}:{})};
}
function validateRestartObservation(row,actual){
 validateRuntimeObservation(row,actual,true);
 const previous=row.requiredStartedAt??row.requiredObservation?.startedAt;
 assert(Number.isFinite(Date.parse(previous))&&Date.parse(actual.startedAt)>Date.parse(previous),'Maintenance generation must be newer');
}
function verifyFunctionalRuntime(profile,{qualification='FUNCTIONAL_ONLY',observe,readDocker}={}){
 if(profile.maintenanceRestart||profile.nativeOverlay){assert(!observe,'Maintenance verification requires actual Docker transport');readDocker=readDocker||defaultDockerRead;}
 assert(!(observe&&readDocker),'Select one observation transport');
 if(readDocker)assert.equal(typeof readDocker,'function');
 observe=observe||(readDocker?(expected=>observeDocker(expected,readDocker)):observeDocker);
 assert.equal(qualification,'FUNCTIONAL_ONLY','Mixed/debug stack cannot qualify release or recording');
 const expected=expectedRuntime(profile),roles=[];
 const maintenance=profile.maintenanceRestart?boundJson(profile.maintenanceRestart):profile.nativeOverlay?boundJson(profile.nativeOverlay.deploymentReceipt):null;
 if(maintenance)assert.equal(JSON.parse(readDocker(['info','--format','{{json .}}'])).ID,maintenance.engineId);
 for(const row of expected){
  let actual;
  try{actual=observe(row);}catch{
   // Identify the failed role without exposing Docker arguments or stderr.
   const error=new Error('Functional runtime observation failed for role '+row.role);
   error.code='FUNCTIONAL_RUNTIME_OBSERVATION_FAILED';error.role=row.role;throw error;
  }
  roles.push(validateRuntimeObservation(row,actual));
 }
 // A changed receipt during the observation window cannot acquire a binding.
 expectedRuntime(profile);
 if(maintenance)assert.equal(JSON.parse(readDocker(['info','--format','{{json .}}'])).ID,maintenance.engineId);
 return {schema:profile.schema==='marty.functional-mixed-runtime/v2'?'marty.functional-mixed-runtime-binding/v2':'marty.functional-mixed-runtime-binding/v1',scope:'FUNCTIONAL_ONLY',
  releaseQualified:false,recordingQualified:false,mixedSourceStack:true,roles,
  receiptDigests:receiptDigests(profile)};
}
module.exports={expectedHeaderSuccessorPreimage,applyNativeOverlayObservedRows:applyNativeOverlayObservations,validateSigningDomainTransition,validateHeaderSuccessorGate,expectedUnqualifiedNativePreimage,applyNativeOverlayRows,validateRuntimeObservation,observeDocker,DOCKER_READ_TRANSPORT_SCHEMA:'marty.functional-runtime-docker-read/v1',boundJson,expectedRuntime,verifyFunctionalRuntime,produceMaintenanceRestart,DEBUG_ROLES,RETAINED_ROLES,ISSUANCE_SOURCE,ISSUANCE_CORE};
