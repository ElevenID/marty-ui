'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const {verifyFunctionalRuntime,expectedRuntime,DEBUG_ROLES,RETAINED_ROLES}=require('./functional-debug-runtime');
const H=char=>char.repeat(64),R=char=>char.repeat(40),image='sha256:'+H('1');
function fixture(t){
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'functional-runtime-'));t.after(()=>fs.rmSync(dir,{recursive:true}));
 const roles=['auth','organization','credential-template','trust-profile','applicant','notification','compliance-profile','presentation-policy','deployment-profile','signing-keys','flow','verification','revocation-profile','device-registration','event-stream','issuance','issuance-native','canvas-sync-worker','gateway','passport-callback-signer','passport-beta-bureau','ui-prod'];
 const binary=role=>({issuance:'marty-issuance-service','issuance-native':'marty-issuance-service',verification:'marty-verification-service'})[role]||'marty-'+role;
 const outputs=[...new Set(roles.filter(role=>role!=='ui-prod').map(binary))].map(name=>({name,sha256:H('2')}));
 while(outputs.length<32)outputs.push({name:'marty-extra-'+outputs.length,sha256:H('2')});
 const baseline={source_kind:'local-worktree-snapshot',promotion_eligible:false,component_revisions:{'marty-ui':R('a')},images:roles.map(service=>({service,image_id:image}))};
 const build={state:'BUILD_SUCCEEDED',exitCode:0,sourceRevision:R('a'),actualBinaryOutputs:outputs};
 const debugHashes=Object.fromEntries([...new Set(Object.values(DEBUG_ROLES))].map(name=>[name,H('3')]));
 const write=(name,value,utf16=false)=>{const file=path.join(dir,name);fs.writeFileSync(file,utf16?Buffer.concat([Buffer.from([255,254]),Buffer.from(JSON.stringify(value),'utf16le')]):JSON.stringify(value));return {path:file,sha256:crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex')};};
 const debugBuild=write('debug.json',{state:'BUILD_PASS_NOT_DEPLOYED',release_qualified:false,profile:'dev',source_clean_before_after:true,features:'default package features; KMS-only pinned dependencies; no test/feature overrides',builder_image_digest:'sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1',source_revision:R('b'),binary_sha256:debugHashes});
 const debugDeployment=write('deployment.json',{scope:'BETA_R32_D03_D05_DEBUG_BINARY_FUNCTIONAL_ONLY',state:'BETA_DEBUG_BINARIES_ACTIVE_FUNCTIONAL_ONLY',releaseQualified:false,productionTouched:false,imageBuilt:false,sourceRevision:R('b'),buildReceiptSha256:debugBuild.sha256,binarySha256:debugHashes,live:{ids:Object.fromEntries(Object.keys(DEBUG_ROLES).map((role,index)=>[role,H((index+4).toString(16))]))}},true);
 const retainedBuilds=Object.fromEntries(Object.entries(RETAINED_ROLES).map(([role,name])=>[role,write(role+'.json',{state:'PASSED',exitCode:0,binary:'/retained/'+name,source:R(role==='flow'?'c':'d'),binarySha256:H(role==='flow'?'a':'b')})]));
 const profile={schema:'marty.functional-mixed-runtime/v1',scope:'FUNCTIONAL_ONLY',releaseQualified:false,recordingQualified:false,baselineDeployment:write('base.json',baseline),baselineBuild:write('build.json',build),debugDeployment,debugBuild,retainedBuilds};
 const observe=row=>({role:row.role,project:row.project,service:row.role,imageId:row.imageId,containerId:row.requiredContainerId||H('f'),running:true,status:'running',health:row.role==='canvas-sync-worker'?null:'healthy',binarySha256:row.sha256,executablePath:row.binary?'/usr/local/bin/'+row.binary:null,processExecutableSha256:row.sha256,binaryMounts:row.kind==='DEBUG_PRODUCTION_BINARY'||row.kind==='RETAINED_SOURCE_BOUND_BINARY'?[{type:'bind',source:'/source/'+row.binary,destination:'/usr/local/bin/'+row.binary,writable:false}]:[],hostPid:123,startedAt:'2026-10-26T00:00:00Z'});
 return {profile,observe,write};
}
test('eight executable overrides remain separate from baseline and cannot qualify release',t=>{const {profile,observe}=fixture(t);const result=verifyFunctionalRuntime(profile,{observe});assert.equal(result.roles.length,22);assert.equal(result.roles.filter(row=>row.kind==='DEBUG_PRODUCTION_BINARY').length,6);assert.equal(result.roles.filter(row=>row.kind==='RETAINED_SOURCE_BOUND_BINARY').length,2);assert.equal(result.releaseQualified,false);assert.equal(result.recordingQualified,false);assert.equal(result.roles.find(row=>row.role==='flow').source,R('c'));});
for(const mode of ['RELEASE','RECORDING'])test('reject '+mode+' before observing beta',t=>{const {profile}=fixture(t);assert.throws(()=>verifyFunctionalRuntime(profile,{qualification:mode,observe:()=>assert.fail('Must not observe')}),/cannot qualify/)});
for(const change of ['process','mounted','pidPath','health','tenant','container','image','writableMount'])test('reject actual runtime mismatch '+change,t=>{const {profile,observe}=fixture(t);assert.throws(()=>verifyFunctionalRuntime(profile,{observe:row=>{const actual=observe(row);if(row.role==='gateway'){
 if(change==='process')actual.processExecutableSha256=H('0');if(change==='mounted')actual.binarySha256=H('0');if(change==='pidPath')actual.executablePath='/usr/local/bin/marty-gateway (deleted)';if(change==='health')actual.health='unhealthy';if(change==='tenant')actual.project='elevenid-selfhost';if(change==='container')actual.containerId=H('0');if(change==='image')actual.imageId='sha256:'+H('0');if(change==='writableMount')actual.binaryMounts[0].writable=true;}return actual;}}));});
test('changed receipt rejects before runtime observation',t=>{const {profile}=fixture(t);fs.appendFileSync(profile.debugBuild.path,' ');assert.throws(()=>verifyFunctionalRuntime(profile,{observe:()=>assert.fail('No observation')}),/changed/);});
test('missing retained source cannot be silently labeled R32',t=>{const {profile}=fixture(t);delete profile.retainedBuilds.flow;assert.throws(()=>expectedRuntime(profile));});

test('prior in-place canonical overlay is explicit rather than relabeled R32',t=>{
 const {profile,observe,write}=fixture(t),roles=expectedRuntime(profile).filter(row=>row.binary);
 const files=[...new Set(roles.map(row=>row.binary))].map(binary_name=>({binary_name,sha256:H('5')}));
 profile.priorNativeBuild=write('prior-build.json',{state:'PASSED',source:R('e'),exitCode:0});
 profile.priorNativeArtifacts=write('prior-artifacts.json',{state:'PASSED',source:R('e'),releaseQualified:false,linuxReadbackMatched:true,files});
 profile.priorNativeOverlay=write('prior-overlay.json',{state:'APPLIED_LOCAL_ONLY',productionReleaseQualified:false,imagesBuiltForCandidate:false,imageSourceMarkerRemainsBaseline:true,sourceRevision:R('e'),buildReceiptSha256:profile.priorNativeBuild.sha256,buildArtifactsSha256:profile.priorNativeArtifacts.sha256,
  rows:roles.map(row=>({service:row.role,binary:row.binary,imageId:row.imageId,candidateSha256:H('5'),observedAfterSha256:H('5')}))});
 const result=verifyFunctionalRuntime(profile,{observe});const auth=result.roles.find(row=>row.role==='auth');
 assert.equal(auth.kind,'PRIOR_CANONICAL_NATIVE_OVERLAY');assert.equal(auth.source,R('e'));assert.equal(auth.sha256,H('5'));
 assert.equal(result.roles.find(row=>row.role==='gateway').source,R('b'));assert.equal(result.roles.find(row=>row.role==='flow').source,R('c'));
});
