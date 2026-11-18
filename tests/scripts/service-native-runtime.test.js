'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {applyNativeOverlayRows}=require('./functional-debug-runtime');
const id=c=>c.repeat(64),image='sha256:'+id('a');
const oldTime='2026-11-01T10:00:00Z',newTime='2026-11-01T20:00:00Z';
const original=['gateway','signing-keys',...require('./platform-runtime-roles').PLATFORM_RUNTIME_ROLES.filter(role=>!['gateway','signing-keys'].includes(role))].map((role,i)=>({role,
 binary:i===0?'marty-gateway':i===1?'marty-signing-keys':`marty-other${i}`,source:'signed',coreSource:'core',sha256:id('b'),kind:'SIGNED_NIGHTLY_IMAGE',imageId:image,project:'elevenid-beta',
 requiredObservation:{role,service:role,containerId:i.toString(16).padStart(64,'0'),health:'healthy',startedAt:oldTime}}));
const observed=original.map(row=>({role:row.role,binary:row.binary,source:row.source,coreSource:row.coreSource,sha256:row.sha256,kind:row.kind,imageId:row.imageId,project:row.project,
 containerId:row.requiredObservation.containerId,health:'healthy',startedAt:oldTime,hostPid:100,effectiveUid:10001,configuredRuntimeUid:10001,
 binaryMounts:[],executablePath:'/usr/local/bin/'+row.binary,processExecutableSha256:row.sha256,requiredObservation:row.requiredObservation}));
const deployed={roles:{gateway:{containerId:id('c'),imageId:image,processExecutablePath:'/usr/local/bin/marty-gateway',processExecutableSha256:id('d'),mountedBinarySha256:id('d'),
 configuredRuntimeUid:10001,effectiveUid:10001,hostPid:200,startedAt:newTime,binaryMount:{type:'bind',source:'/host/gateway',destination:'/usr/local/bin/marty-gateway',writable:false}},
 'signing-keys':{containerId:id('e'),imageId:image,processExecutablePath:'/usr/local/bin/marty-signing-keys',processExecutableSha256:id('f'),mountedBinarySha256:id('f'),
 configuredRuntimeUid:10001,effectiveUid:10001,hostPid:201,startedAt:newTime,binaryMount:{type:'bind',source:'/host/signing-keys',destination:'/usr/local/bin/marty-signing-keys',writable:false}}}};
const selected={roles:['gateway','signing-keys'],source:'selected',coreSource:'core',kind:'SCOPED_NATIVE_FUNCTIONAL_OVERLAY',hashes:{'marty-gateway':id('d'),'marty-signing-keys':id('f')}};
const before=rows=>({schema:'marty.functional-mixed-runtime-binding/v2',scope:'FUNCTIONAL_ONLY',releaseQualified:false,recordingQualified:false,mixedSourceStack:true,roles:rows});
test('pair overlay binds exactly two new role generations and retains nineteen',()=>{const rows=applyNativeOverlayRows(original,before(observed),deployed,selected);assert.equal(rows.length,21);
 assert.deepEqual(rows.slice(2).map(x=>x.requiredObservation.containerId),original.slice(2).map(x=>x.requiredObservation.containerId));
 assert.equal(rows[0].sha256,id('d'));assert.equal(rows[1].sha256,id('f'));});
test('nested prior observation is required and top-level conflict wins',()=>{for(const mutate of [
 rows=>{rows[2].requiredObservation.service='wrong';},rows=>{rows[2].service='wrong';},rows=>{delete rows[2].requiredObservation.service;},
 ]){const rows=structuredClone(observed);mutate(rows);assert.throws(()=>applyNativeOverlayRows(original,before(rows),deployed,selected));}});
test('wrong executable or mount is refused',()=>{for(const mutate of [
 d=>{d.roles.gateway.processExecutableSha256=id('0');},d=>{d.roles.gateway.binaryMount.destination='/tmp/wrong';},
 ]){const d=structuredClone(deployed);mutate(d);assert.throws(()=>applyNativeOverlayRows(original,before(observed),d,selected));}});

test('retired provider overlays refuse before receipt readers or live operations',()=>{
 const runtime=require('./functional-debug-runtime');
 for(const field of [null,false,{}])assert.throws(()=>runtime.expectedRuntime({schema:'marty.functional-mixed-runtime/v2',issuanceFenceNativeOverlay:field}),/RETIRED_PROVIDER_RUNTIME_PROFILE/);
 assert.throws(()=>runtime.expectedRuntime({schema:'marty.functional-mixed-runtime/v2',scope:'FUNCTIONAL_ONLY',releaseQualified:false,recordingQualified:false,baseProfile:{path:'not-read',sha256:'0'.repeat(64)},nativeOverlay:{profile:'canvas-issuer-scoped-jobs'}}),/RETIRED_PROVIDER_RUNTIME_PROFILE/);
 assert.equal(require('./service-native-runtime').expectedIssuanceFence,undefined);
 assert.equal(runtime.verifyCanvasIssuerPreimage,undefined);
 assert.equal(runtime.expectedCanvasIssuerPreimage,undefined);
});

test('mixed resource profiles cannot hide retired selectors at shared or direct entry points',()=>{
 const runtime=require('./functional-debug-runtime'),resource=require('./beta-resource-runtime');
 const never=()=>assert.fail('retired selector reached a reader');
 for(const field of ['resourceRecreation','resourceRestart'])for(const selector of ['issuanceFenceNativeOverlay','nativeMaintenance','signedImageDeployment'])for(const retired of [null,false,{}]){
  const profile={schema:'marty.functional-mixed-runtime/v2',[field]:{},[selector]:retired};
  assert.throws(()=>runtime.produceSignedImageObservation(profile,{readDocker:never}),/RETIRED_SIGNED_IMAGE_GENERATION/);
  for(const run of [()=>runtime.expectedRuntime(profile),()=>runtime.verifyFunctionalRuntime(profile,{readDocker:never}),
    ()=>runtime.verifyResourceAncillary(profile,never),()=>runtime.resourceRecreationSuccessor({},profile),
    ()=>resource.authority(profile,{boundJson:never}),()=>resource.restartAuthority(profile,{boundJson:never})])assert.throws(run,/RETIRED_PROVIDER_RUNTIME_PROFILE/);
 }
 for(const field of ['resourceRecreation','resourceRestart'])assert.throws(()=>runtime.expectedRuntime({schema:'marty.functional-mixed-runtime/v2',[field]:{},nativeOverlay:{profile:'canvas-issuer-scoped-jobs'}}),/RETIRED_PROVIDER_RUNTIME_PROFILE/);
 const inherited=Object.assign(Object.create({issuanceFenceNativeOverlay:false}),{schema:'marty.functional-mixed-runtime/v2',resourceRecreation:{}});
 assert.throws(()=>runtime.expectedRuntime(inherited),/RETIRED_PROVIDER_RUNTIME_PROFILE/);
});

test('off-cohort and header preimage exports reject retired wrappers and predecessor layers',t=>{
 const runtime=require('./functional-debug-runtime'),crypto=require('node:crypto');
 const initial={issuanceFenceNativeOverlay:false};
 Object.defineProperty(initial,'baseProfile',{get:()=>assert.fail('retired wrapper read its predecessor')});
 assert.throws(()=>runtime.retainedBetaOffAuthority(initial),/RETIRED_PROVIDER_RUNTIME_PROFILE/);
 assert.throws(()=>runtime.expectedHeaderSuccessorPreimage(initial),/RETIRED_PROVIDER_RUNTIME_PROFILE/);
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'retired-predecessor-'));t.after(()=>fs.rmSync(dir,{recursive:true}));
 for(const retired of [false,null,{}]){
  const file=path.join(dir,'middle.json'),body=JSON.stringify({issuanceFenceNativeOverlay:retired,baseProfile:{path:path.join(dir,'must-not-read.json'),sha256:'0'.repeat(64)}});
  fs.writeFileSync(file,body);const ref={path:file,sha256:crypto.createHash('sha256').update(body).digest('hex')};
  assert.throws(()=>runtime.retainedBetaOffAuthority({baseProfile:ref}),/RETIRED_PROVIDER_RUNTIME_PROFILE/);
 }
});
