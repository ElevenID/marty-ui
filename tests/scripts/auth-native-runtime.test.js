'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const {expected}=require('./auth-native-runtime');
const operatorSha='04f5d9635d885c6a7901e23883099d2fae49fd9bd4dbc8d68d0b457d1d2a452c';
const binarySha='36eb8f9fcbc727c99348c4072a9b591a1463e7e2a4b3d44670d6e57da278a8e6';
const oldId='1'.repeat(64),newId='2'.repeat(64),imageId='sha256:'+'3'.repeat(64);
const started='2026-11-01T10:00:00Z',later='2026-11-01T19:00:00Z';
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'auth-native-runtime-'));
test.after(()=>fs.rmSync(temp,{recursive:true,force:true}));
let sequence=0;
const save=value=>{const file=path.join(temp,`${++sequence}.json`),bytes=Buffer.from(JSON.stringify(value));fs.writeFileSync(file,bytes);return {path:file,sha256:crypto.createHash('sha256').update(bytes).digest('hex')};};
const read=ref=>{const bytes=fs.readFileSync(ref.path);assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'),ref.sha256);return JSON.parse(bytes);};
const old={role:'auth',kind:'SIGNED_NIGHTLY_IMAGE',requiredContainerId:oldId,requiredStartedAt:started,imageId,
 source:'signed-image-source',sha256:'4'.repeat(64),binary:'marty-auth',project:'elevenid-beta'};
const prior=[old,...Array.from({length:21},(_,index)=>({role:`other${index}`,kind:'SIGNED_NIGHTLY_IMAGE',requiredContainerId:(index+10).toString(16).padStart(64,'0')}))];
const refs={operator:{path:'/reviewed/auth-operator.py',sha256:operatorSha},binary:{path:'/host/bin',sha256:binarySha}};
const base=save({signedImageDeployment:{}});
function fixture(change=()=>{}){
 const model='a'.repeat(64),overlay='b'.repeat(64);
 const input=save({schema:'marty.d05-auth-native-overlay-input/v1',sourceSha256:operatorSha,executeAuthorized:true,
  binary:{sha256:binarySha},baseModel:{sha256:model},overlayModel:{sha256:overlay},oldAuthCid:oldId});
 const result=save({state:'D05_LOCAL_SOURCE_AUTH_OVERLAY_HEALTHY',qualifiedSignedNightly:false,
  oldCid:oldId,newCid:newId,oldStartedAt:started,startedAt:later,hostPid:123,
  sourceSha256:operatorSha,binarySha256:binarySha,modelSha256:overlay,engineId:'engine',
  binaryMount:{type:'bind',source:'/host/bin',destination:'/usr/local/bin/marty-auth',writable:false}});
 const value={baseline:save({modelSha256:model,oldCid:oldId,oldStartedAt:started}),binary:{...refs.binary},
  createIntent:save({oldCid:oldId,modelSha256:overlay,noBuild:true,noPull:true,noDeps:true,noStart:true}),
  created:save({cid:newId,imageId}),input,operator:{...refs.operator},result,
  stopReceipt:save({cid:oldId,exitCode:0,pid:0})};
 const profile={schema:'marty.functional-mixed-runtime/v2',scope:'FUNCTIONAL_ONLY',releaseQualified:false,
  recordingQualified:false,baseProfile:base,authNativeOverlay:value};
 change(profile);return profile;
}
const deps={boundJson:read,verifyBoundFile:()=>{},expectedRuntime:()=>prior,
 comparableBinaryMounts:rows=>rows.map(row=>({...row,source:row.source.replaceAll('\\','/')})),
 signedAuthority:()=>({engineId:'engine'})};
test('only Auth becomes a source-bound read-only binary overlay',()=>{
 const rows=expected(fixture(),deps);
 assert.equal(rows.length,22);assert.equal(rows[0].kind,'SCOPED_NATIVE_FUNCTIONAL_OVERLAY');
 assert.equal(rows[0].sha256,binarySha);assert.equal(rows[0].requiredContainerId,newId);
 assert.deepEqual(rows[0].requiredBinaryMounts,[{type:'bind',source:'/host/bin',destination:'/usr/local/bin/marty-auth',writable:false}]);
 assert.deepEqual(rows.slice(1),prior.slice(1));
});
test('missing or changed Auth authority and wrong binary or mount fail closed',()=>{
 for(const edit of [
  value=>delete value.authNativeOverlay.result,
  value=>{value.authNativeOverlay.result.sha256='0'.repeat(64);},
  value=>{value.authNativeOverlay.binary.sha256='0'.repeat(64);},
  value=>{const r=read(value.authNativeOverlay.result);r.binaryMount.source='/foreign/bin';value.authNativeOverlay.result=save(r);},
  value=>{const r=read(value.authNativeOverlay.result);r.engineId='foreign';value.authNativeOverlay.result=save(r);},
 ])assert.throws(()=>expected(fixture(edit),deps));
});
