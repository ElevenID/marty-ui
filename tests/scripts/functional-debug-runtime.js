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
 const before=snapshot.binding;assert.equal(before.schema,'marty.functional-mixed-runtime-binding/v1');assert.equal(before.scope,'FUNCTIONAL_ONLY');
 assert.equal(before.releaseQualified,false);assert.equal(before.recordingQualified,false);assert.equal(before.mixedSourceStack,true);
 assert.deepEqual(before.receiptDigests,receiptDigests(base));assert.equal(before.roles.length,22);
 assert.equal(new Set(before.roles.map(row=>row.role)).size,22);assert.equal(new Set(before.roles.map(row=>row.containerId)).size,22);
 for(const row of expected){
  const old=before.roles.find(item=>item.role===row.role);assert(old,'Missing prior role identity');
  for(const field of ['binary','source','sha256','kind','imageId','project'])assert.equal(old[field],row[field],'Prior role lineage mismatch');
  assert(HASH.test(old.containerId));if(row.requiredContainerId)assert.equal(old.containerId,row.requiredContainerId);
  assert(Number.isInteger(old.hostPid)&&old.hostPid>0);assert(Number.isFinite(Date.parse(old.startedAt)));
  assert(Number.isInteger(old.effectiveUid)&&old.effectiveUid>=0);assert(Number.isInteger(old.configuredRuntimeUid)&&old.configuredRuntimeUid>=0);
  assert(Array.isArray(old.binaryMounts));assert(old.binaryMounts.every(mount=>mount.writable===false));
  assert.equal(old.processExecutableSha256,row.sha256);assert.equal(old.executablePath,row.binary?'/usr/local/bin/'+row.binary:null);
  assert(old.health==='healthy'||(row.role==='canvas-sync-worker'&&old.health===null));
 }
 const ids=new Set();
 return expected.map(row=>{
  const old=before.roles.find(item=>item.role===row.role);
  if(!ISSUANCE_ROLES.includes(row.role))return {...row,requiredObservation:Object.fromEntries(['containerId','imageId','health','executablePath','processExecutableSha256','binaryMounts','startedAt','hostPid','effectiveUid','configuredRuntimeUid'].map(field=>[field,old[field]]))};
  const actual=deployed.roles[row.role],target='/usr/local/bin/marty-issuance-service';
  assert(HASH.test(actual.containerId));assert(!before.roles.some(previous=>previous.containerId===actual.containerId),'Issuance overlay requires a fresh noncolliding container');
  assert(!ids.has(actual.containerId));ids.add(actual.containerId);assert.equal(actual.imageId,row.imageId);
  assert.equal(actual.processExecutablePath,target);assert.equal(actual.processExecutableSha256,build.binary.sha256);assert.equal(actual.mountedBinarySha256,build.binary.sha256);
  assert(Number.isInteger(actual.configuredRuntimeUid)&&actual.configuredRuntimeUid>=0);assert.equal(actual.effectiveUid,actual.configuredRuntimeUid);assert.equal(actual.effectiveUid,old.effectiveUid);assert.equal(actual.configuredRuntimeUid,old.configuredRuntimeUid);
  assert(Number.isInteger(actual.hostPid)&&actual.hostPid>0);assert(Number.isFinite(Date.parse(actual.startedAt)));
  assert.equal(actual.binaryMount?.type,'bind');assert.equal(actual.binaryMount.destination,target);assert.equal(actual.binaryMount.writable,false);assert(path.isAbsolute(actual.binaryMount.source));
  return {...row,source:build.sourceRevision,coreSource:build.coreRevision,sha256:build.binary.sha256,kind:'ISSUANCE_CORE_FUNCTIONAL_OVERLAY',
   requiredContainerId:actual.containerId,requiredStartedAt:actual.startedAt,requiredHostPid:actual.hostPid,requiredEffectiveUid:actual.effectiveUid,requiredBinaryMounts:[actual.binaryMount]};
 });
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
 assert.equal(beforeEngine.Containers,225);assert.equal(beforeEngine.ContainersRunning,67);
 const roles=expected.map(row=>{
  const actual=observeDocker(row,read);validateRestartObservation(row,actual);return actual;
 });
 const afterEngine=engine();assert.equal(afterEngine.ID,authority.engineId,'Maintenance engine changed during observation');
 assert.equal(afterEngine.Containers,225);assert.equal(afterEngine.ContainersRunning,67);
 boundJson(profileRef);maintenanceAuthority(authorityRef,expected);expectedRuntime(profile);
 return {schema:'marty.functional-runtime-maintenance-restart/v1',scope:'FUNCTIONAL_ONLY',releaseQualified:false,recordingQualified:false,
  baseProfile:profileRef,authority:authorityRef,engineId:authority.engineId,roles};
}
function configuredUid(value){
 if(value===''||value==='root'||value==='root:root')return 0;
 if(/^\d+(?::[^:]+)?$/.test(value))return Number(value.split(':')[0]);
 return null;
}
function receiptDigests(profile){return profile.schema==='marty.functional-mixed-runtime/v2'?{baseProfile:profile.baseProfile.sha256,issuanceBuild:profile.issuanceOverlay.buildReceipt.sha256,issuanceDeployment:profile.issuanceOverlay.deploymentReceipt.sha256,...(profile.maintenanceRestart?{maintenanceRestart:profile.maintenanceRestart.sha256}:{})}:{baselineDeployment:profile.baselineDeployment.sha256,baselineBuild:profile.baselineBuild.sha256,
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
function validateRuntimeObservation(row,actual,ignoreGeneration=false){
 assert.equal(actual.role,row.role);assert.equal(actual.project,row.project);
 assert.equal(actual.service,row.role);assert.equal(actual.imageId,row.imageId);assert(HASH.test(actual.containerId));
 if(row.requiredObservation)for(const [field,value]of Object.entries(row.requiredObservation)){if(ignoreGeneration&&['startedAt','hostPid'].includes(field))continue;assert.deepEqual(field==='binaryMounts'?comparableBinaryMounts(actual[field]):actual[field],field==='binaryMounts'?comparableBinaryMounts(value):value,'Unchanged role observation differs: '+row.role+'/'+field);}
 if(row.requiredContainerId)assert.equal(actual.containerId,row.requiredContainerId,'Reviewed debug container changed');
 if(!ignoreGeneration&&row.requiredStartedAt!==undefined){assert.equal(actual.startedAt,row.requiredStartedAt);assert.equal(actual.hostPid,row.requiredHostPid);}
 if(row.kind==='ISSUANCE_CORE_FUNCTIONAL_OVERLAY'){
  assert.equal(actual.effectiveUid,row.requiredEffectiveUid);assert.equal(actual.configuredRuntimeUid,row.requiredEffectiveUid);
  assert.deepEqual(comparableBinaryMounts(actual.binaryMounts),comparableBinaryMounts(row.requiredBinaryMounts),'Reviewed issuance executable mount changed');}
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
 if(profile.maintenanceRestart){assert(!observe,'Maintenance verification requires actual Docker transport');readDocker=readDocker||defaultDockerRead;}
 assert(!(observe&&readDocker),'Select one observation transport');
 if(readDocker)assert.equal(typeof readDocker,'function');
 observe=observe||(readDocker?(expected=>observeDocker(expected,readDocker)):observeDocker);
 assert.equal(qualification,'FUNCTIONAL_ONLY','Mixed/debug stack cannot qualify release or recording');
 const expected=expectedRuntime(profile),roles=[];
 const maintenance=profile.maintenanceRestart?boundJson(profile.maintenanceRestart):null;
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
module.exports={DOCKER_READ_TRANSPORT_SCHEMA:'marty.functional-runtime-docker-read/v1',boundJson,expectedRuntime,verifyFunctionalRuntime,produceMaintenanceRestart,DEBUG_ROLES,RETAINED_ROLES,ISSUANCE_SOURCE,ISSUANCE_CORE};
