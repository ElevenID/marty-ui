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
const RETAINED_ROLES=Object.freeze({flow:'marty-flow','signing-keys':'marty-signing-keys'});
const digest=value=>crypto.createHash('sha256').update(value).digest('hex');
function boundJson(ref){
 assert(ref&&path.isAbsolute(ref.path)&&HASH.test(ref.sha256),'Explicit hash-bound receipt required');
 assert(fs.lstatSync(ref.path).isFile()&&!fs.lstatSync(ref.path).isSymbolicLink(),'Receipt must be regular');
 const bytes=fs.readFileSync(ref.path);assert(bytes.length>0&&bytes.length<=16*1024*1024,'Receipt size invalid');
 assert.equal(digest(bytes),ref.sha256,'Reviewed receipt changed');
 const text=bytes[0]===255&&bytes[1]===254?bytes.subarray(2).toString('utf16le'):bytes.toString('utf8').replace(/^\uFEFF/,'');
 return JSON.parse(text);
}
function binaryFor(role){return ({issuance:'marty-issuance-service','issuance-native':'marty-issuance-service',verification:'marty-verification-service'})[role]||'marty-'+role;}
function expectedRuntime(profile){
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
function observeDocker(expected){
 const read=args=>execFileSync('docker',args,{encoding:'utf8',timeout:30000,maxBuffer:4*1024*1024,windowsHide:true});
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
 const after=JSON.parse(read(['inspect',row.Id]))[0];
 assert.equal(after.State?.StartedAt,row.State?.StartedAt,'Role restarted during executable observation');
 assert.equal(after.State?.Pid,row.State?.Pid,'Role process changed during executable observation');
 return {role:expected.role,containerId:row.Id,imageId:row.Image,project:labels['com.docker.compose.project'],
  service:labels['com.docker.compose.service'],running:row.State?.Running===true,
  status:row.State?.Status,health:row.State?.Health?.Status||null,binarySha256:hash,
  binaryMounts,executablePath,processExecutableSha256:processHash,startedAt:row.State?.StartedAt,hostPid:row.State?.Pid};
}
function verifyFunctionalRuntime(profile,{qualification='FUNCTIONAL_ONLY',observe=observeDocker}={}){
 assert.equal(qualification,'FUNCTIONAL_ONLY','Mixed/debug stack cannot qualify release or recording');
 const expected=expectedRuntime(profile),roles=[];
 for(const row of expected){
  let actual;
  try{actual=observe(row);}catch{
   // Identify the failed role without exposing Docker arguments or stderr.
   const error=new Error('Functional runtime observation failed for role '+row.role);
   error.code='FUNCTIONAL_RUNTIME_OBSERVATION_FAILED';error.role=row.role;throw error;
  }
  assert.equal(actual.role,row.role);assert.equal(actual.project,row.project);
  assert.equal(actual.service,row.role);assert.equal(actual.imageId,row.imageId);assert(HASH.test(actual.containerId));
  if(row.requiredContainerId)assert.equal(actual.containerId,row.requiredContainerId,'Reviewed debug container changed');
  assert.equal(actual.running,true);assert.equal(actual.status,'running');
  assert(actual.health==='healthy'||(row.role==='canvas-sync-worker'&&actual.health===null),'Role health not established');
  assert.equal(actual.binarySha256,row.sha256,'Actual mounted executable differs from source-bound role');
  if(row.binary){assert.equal(actual.executablePath,'/usr/local/bin/'+row.binary,'PID1 is not the exact expected service');
   assert.equal(actual.processExecutableSha256,row.sha256,'Running inode differs from source-bound executable');
   assert(Array.isArray(actual.binaryMounts));assert(actual.binaryMounts.every(mount=>mount.writable===false),'Executable mount must be read-only');
   if(row.kind==='DEBUG_PRODUCTION_BINARY'||row.kind==='RETAINED_SOURCE_BOUND_BINARY')assert(actual.binaryMounts.length>0,'Expected reviewed executable mount is absent');}
  assert(Number.isInteger(actual.hostPid)&&actual.hostPid>0);assert(typeof actual.startedAt==='string'&&Number.isFinite(Date.parse(actual.startedAt)));
  roles.push({...row,containerId:actual.containerId,health:actual.health,startedAt:actual.startedAt,hostPid:actual.hostPid,
   executablePath:actual.executablePath,processExecutableSha256:actual.processExecutableSha256,binaryMounts:actual.binaryMounts});
 }
 // A changed receipt during the observation window cannot acquire a binding.
 expectedRuntime(profile);
 return {schema:'marty.functional-mixed-runtime-binding/v1',scope:'FUNCTIONAL_ONLY',
  releaseQualified:false,recordingQualified:false,mixedSourceStack:true,roles,
  receiptDigests:{baselineDeployment:profile.baselineDeployment.sha256,baselineBuild:profile.baselineBuild.sha256,
   debugDeployment:profile.debugDeployment.sha256,debugBuild:profile.debugBuild.sha256,
   retainedBuilds:Object.fromEntries(Object.entries(profile.retainedBuilds).map(([role,ref])=>[role,ref.sha256])),
   ...(profile.priorNativeOverlay?{priorNativeOverlay:profile.priorNativeOverlay.sha256,priorNativeBuild:profile.priorNativeBuild.sha256,priorNativeArtifacts:profile.priorNativeArtifacts.sha256}:{})}};
}
module.exports={boundJson,expectedRuntime,verifyFunctionalRuntime,DEBUG_ROLES,RETAINED_ROLES};
