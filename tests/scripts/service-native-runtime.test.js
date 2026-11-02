'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {applyNativeOverlayRows}=require('./functional-debug-runtime');
const {expectedIssuanceFence}=require('./service-native-runtime');
const id=c=>c.repeat(64),image='sha256:'+id('a');
const oldTime='2026-11-01T10:00:00Z',newTime='2026-11-01T20:00:00Z';
const original=Array.from({length:22},(_,i)=>({role:i===0?'gateway':i===1?'signing-keys':`other${i}`,
 binary:i===0?'marty-gateway':i===1?'marty-signing-keys':`marty-other${i}`,source:'signed',coreSource:'core',sha256:id('b'),kind:'SIGNED_NIGHTLY_IMAGE',imageId:image,project:'elevenid-beta',
 requiredObservation:{role:i===0?'gateway':i===1?'signing-keys':`other${i}`,service:i===0?'gateway':i===1?'signing-keys':`other${i}`,containerId:i.toString(16).padStart(64,'0'),health:'healthy',startedAt:oldTime}}));
const observed=original.map(row=>({role:row.role,binary:row.binary,source:row.source,coreSource:row.coreSource,sha256:row.sha256,kind:row.kind,imageId:row.imageId,project:row.project,
 containerId:row.requiredObservation.containerId,health:'healthy',startedAt:oldTime,hostPid:100,effectiveUid:10001,configuredRuntimeUid:10001,
 binaryMounts:[],executablePath:'/usr/local/bin/'+row.binary,processExecutableSha256:row.sha256,requiredObservation:row.requiredObservation}));
const deployed={roles:{gateway:{containerId:id('c'),imageId:image,processExecutablePath:'/usr/local/bin/marty-gateway',processExecutableSha256:id('d'),mountedBinarySha256:id('d'),
 configuredRuntimeUid:10001,effectiveUid:10001,hostPid:200,startedAt:newTime,binaryMount:{type:'bind',source:'/host/gateway',destination:'/usr/local/bin/marty-gateway',writable:false}},
 'signing-keys':{containerId:id('e'),imageId:image,processExecutablePath:'/usr/local/bin/marty-signing-keys',processExecutableSha256:id('f'),mountedBinarySha256:id('f'),
 configuredRuntimeUid:10001,effectiveUid:10001,hostPid:201,startedAt:newTime,binaryMount:{type:'bind',source:'/host/signing-keys',destination:'/usr/local/bin/marty-signing-keys',writable:false}}}};
const selected={roles:['gateway','signing-keys'],source:'selected',coreSource:'core',kind:'SCOPED_NATIVE_FUNCTIONAL_OVERLAY',hashes:{'marty-gateway':id('d'),'marty-signing-keys':id('f')}};
const before=rows=>({schema:'marty.functional-mixed-runtime-binding/v2',scope:'FUNCTIONAL_ONLY',releaseQualified:false,recordingQualified:false,mixedSourceStack:true,roles:rows});
test('pair overlay binds exactly two new role generations and retains twenty',()=>{const rows=applyNativeOverlayRows(original,before(observed),deployed,selected);assert.equal(rows.length,22);
 assert.deepEqual(rows.slice(2).map(x=>x.requiredObservation.containerId),original.slice(2).map(x=>x.requiredObservation.containerId));
 assert.equal(rows[0].sha256,id('d'));assert.equal(rows[1].sha256,id('f'));});
test('nested prior observation is required and top-level conflict wins',()=>{for(const mutate of [
 rows=>{rows[2].requiredObservation.service='wrong';},rows=>{rows[2].service='wrong';},rows=>{delete rows[2].requiredObservation.service;},
 ]){const rows=structuredClone(observed);mutate(rows);assert.throws(()=>applyNativeOverlayRows(original,before(rows),deployed,selected));}});
test('wrong executable or mount is refused',()=>{for(const mutate of [
 d=>{d.roles.gateway.processExecutableSha256=id('0');},d=>{d.roles.gateway.binaryMount.destination='/tmp/wrong';},
 ]){const d=structuredClone(deployed);mutate(d);assert.throws(()=>applyNativeOverlayRows(original,before(observed),d,selected));}});

function fenceFixture(t){
 const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'issuance-fence-policy-'));t.after(()=>fs.rmSync(tmp,{recursive:true,force:true}));
 const stdout=path.join(tmp,'one-pass.txt');fs.writeFileSync(stdout,'test result: ok. 1 passed; 0 failed;\n');
 const oldCid=id('1'),newCid=id('2'),oldHash='d8c66406134fe638318e9ffb946d81c35eadf29f752720af27ca79949dfd92ff',newHash=id('3');
 const source='3394c6d816c60584f8c8c5e941c3a22144b67350',oldSource='e836a700579a1dc0be4894c6bf416c26529d2564';
 const core='4320b5fa1c6f41231ee0aa2bc57d8008549f67ac',profileName='canvas-bootstrap-fence-issuance-only';
 const rows=original.map((row,i)=>({...row,role:i===0?'issuance-native':row.role,binary:i===0?'marty-issuance-service':row.binary,
  source:i===0?oldSource:'signed',coreSource:core,sha256:i===0?oldHash:row.sha256,kind:i===0?'SCOPED_NATIVE_FUNCTIONAL_OVERLAY':row.kind,
  requiredContainerId:i===0?oldCid:row.requiredObservation.containerId,
  ...(i===0?{requiredStartedAt:oldTime,requiredHostPid:100,requiredEffectiveUid:10001,
   requiredBinaryMounts:[{type:'bind',source:'/host/old-issuance',destination:'/usr/local/bin/marty-issuance-service',writable:false}]}:{})}));
 delete rows[0].requiredObservation;
 const prior=rows.map((row,i)=>({role:row.role,binary:row.binary,source:row.source,coreSource:row.coreSource,sha256:row.sha256,kind:row.kind,
  imageId:row.imageId,project:row.project,containerId:row.requiredContainerId,health:'healthy',startedAt:oldTime,hostPid:100,
  effectiveUid:10001,configuredRuntimeUid:10001,executablePath:'/usr/local/bin/'+row.binary,processExecutableSha256:row.sha256,
  binaryMounts:i===0?row.requiredBinaryMounts:[],...(row.requiredObservation?{requiredObservation:row.requiredObservation}:{})}));
 const docs=new Map(),put=(name,value)=>{const ref={path:name,sha256:id(name[0]),bytes:1};docs.set(name,value);return ref;};
 const sourceProof={uiRevision:source,coreRevision:core};
 const binary={path:'/host/new-issuance',sha256:newHash,bytes:100};
 const originalBuild={state:'BUILD_SUCCEEDED',source:sourceProof,binary};
 const sourceRef=put('source-proof',sourceProof),originalRef=put('original-build',originalBuild);
 const build={state:'BUILD_SUCCEEDED',exitCode:0,oomKilled:false,uiRevision:source,coreRevision:core,
  roleBinaries:{'issuance-native':'marty-issuance-service'},buildProfile:profileName,runtimeUidLibrariesValidated:false,
  binaries:{'marty-issuance-service':binary},sourceProof:{...sourceRef},sourceBuildReceipt:{...originalRef},
  focusedRustTests:['public_offer_uses_the_same_format_specific_configuration_id_as_application_offers',
   'native_offer_transaction_reads_match_the_python_oracle_contract'].map(name=>({name,exitCode:0,
    stdout:{path:stdout,sha256:id('a')},stderr:{path:stdout,sha256:id('b')}}))};
 const buildRef=put('build',build),planRef=put('plan',{scope:'ELF_LOADER_UID_COMPATIBILITY_ONLY',buildReceiptAuthoritativeSha256:buildRef.sha256});
 const abiRef=put('abi',{schema:1,state:'ELF_LOADER_UID_COMPATIBILITY_PASS',planSha256:planRef.sha256,
  candidateServiceEntrypointExecuted:false,signingOrApi:false,runtimeDeployed:false,rows:[{binary:'marty-issuance-service',sha256:newHash,
   containerId:id('4'),imageId:image,exitCode:0,uid:10001,gid:10001,candidateReadableExecutable:true,loaderListSucceeded:true,ownedContainerRemoved:true}]});
 const baseRef=put('base',{issuanceOfferNativeOverlay:{}}),snapshotRef=put('snapshot',{profileSha256:baseRef.sha256,
  binding:{schema:'marty.functional-mixed-runtime-binding/v2',scope:'FUNCTIONAL_ONLY',releaseQualified:false,recordingQualified:false,
   mixedSourceStack:true,receiptDigests:{base:'digest'},roles:prior}});
 const deployedRef=put('deployed',{schema:'marty.scoped-native-overlay-deployment/v1',profile:profileName,scope:'FUNCTIONAL_ONLY',
  state:'APPLIED_FUNCTIONAL_ONLY',actualReadbackVerified:true,baseProfileSha256:baseRef.sha256,buildReceiptSha256:buildRef.sha256,
  compatibilityResultSha256:abiRef.sha256,sourceRevision:source,coreRevision:core,engineId:'3dbbbe66-1c98-4e0c-b0a6-f927c05e7341',
  productionTouched:false,imagesBuilt:false,releaseQualified:false,recordingQualified:false,beforeRuntimeBinding:snapshotRef,
  roles:{'issuance-native':{containerId:newCid,imageId:image,processExecutablePath:'/usr/local/bin/marty-issuance-service',
   processExecutableSha256:newHash,mountedBinarySha256:newHash,configuredRuntimeUid:10001,effectiveUid:10001,hostPid:201,
   startedAt:newTime,binaryMount:{type:'bind',source:'/host/new-issuance',destination:'/usr/local/bin/marty-issuance-service',writable:false}}}});
 const profile={schema:'marty.functional-mixed-runtime/v2',scope:'FUNCTIONAL_ONLY',releaseQualified:false,recordingQualified:false,
  baseProfile:baseRef,issuanceFenceNativeOverlay:{buildReceipt:buildRef,preparedSource:sourceRef,compatibilityPlan:planRef,
   compatibilityResult:abiRef,deploymentReceipt:deployedRef}};
 const deps={boundJson:ref=>docs.get(ref.path),verifyBoundFile:()=>{},expectedRuntime:()=>rows,receiptDigests:()=>({base:'digest'}),applyNativeOverlayRows};
 return {rows,prior,docs,profile,deps,build,snapshot:docs.get('snapshot')};
}
test('closed Issuance fence policy binds the native predecessor and one fresh generation',t=>{
 const f=fenceFixture(t),result=expectedIssuanceFence(f.profile,f.deps);
 assert.equal(result.length,22);assert.equal(result[0].source,'3394c6d816c60584f8c8c5e941c3a22144b67350');
 assert.equal(result[0].requiredContainerId,id('2'));assert.equal(result[1].requiredObservation.containerId,f.prior[1].containerId);
});
test('closed Issuance fence policy refuses wrong predecessor, runtime, profile and build lineage',t=>{
 for(const change of [f=>{f.rows[0].kind='SIGNED_NIGHTLY_IMAGE';},f=>{f.rows[0].source='foreign-native';},
  f=>{f.prior[0].processExecutableSha256=id('f');},f=>{f.snapshot.profileSha256=id('f');},
  f=>{f.build.sourceProof.sha256=id('f');},f=>{f.docs.delete('original-build');}]){
  const f=fenceFixture(t);change(f);assert.throws(()=>expectedIssuanceFence(f.profile,f.deps));
 }
});
