'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {applyNativeOverlayRows}=require('./functional-debug-runtime');
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
