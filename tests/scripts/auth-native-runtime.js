'use strict';
// Exact Auth executable successor over the signed nightly functional binding.
const assert=require('node:assert/strict');
const HASH=/^[a-f0-9]{64}$/;
function expected(profile,{boundJson,verifyBoundFile,expectedRuntime,comparableBinaryMounts,signedAuthority}){
 assert.equal(profile.schema,'marty.functional-mixed-runtime/v2');
 assert.equal(profile.scope,'FUNCTIONAL_ONLY');assert.equal(profile.releaseQualified,false);assert.equal(profile.recordingQualified,false);
 assert.deepEqual(Object.keys(profile).sort(),['authNativeOverlay','baseProfile','recordingQualified','releaseQualified','schema','scope']);
 const base=boundJson(profile.baseProfile);assert(base.signedImageDeployment&&!base.authNativeOverlay,'Signed nightly predecessor required');
 const prior=expectedRuntime(base);assert.equal(prior.length,22);
 const old=prior.find(row=>row.role==='auth');assert(old&&old.kind==='SIGNED_NIGHTLY_IMAGE');
 const v=profile.authNativeOverlay;
 assert.deepEqual(Object.keys(v).sort(),['baseline','binary','createIntent','created','input','operator','result','stopReceipt'].sort());
 verifyBoundFile(v.operator,1024*1024);verifyBoundFile(v.binary,512*1024*1024);
 const source='ce00e4f28989cdd9f6a3a10cd354042e2100b190';
 const hash='36eb8f9fcbc727c99348c4072a9b591a1463e7e2a4b3d44670d6e57da278a8e6';
 assert.equal(v.operator.sha256,'04f5d9635d885c6a7901e23883099d2fae49fd9bd4dbc8d68d0b457d1d2a452c');
 assert.equal(v.binary.sha256,hash);
 const input=boundJson(v.input),result=boundJson(v.result),baseline=boundJson(v.baseline);
 const stopped=boundJson(v.stopReceipt),intent=boundJson(v.createIntent),created=boundJson(v.created);
 assert.equal(input.schema,'marty.d05-auth-native-overlay-input/v1');assert.equal(input.sourceSha256,v.operator.sha256);
 assert.equal(input.executeAuthorized,true);assert.equal(input.binary.sha256,hash);
 assert.equal(input.baseModel.sha256,baseline.modelSha256);assert.equal(input.overlayModel.sha256,result.modelSha256);
 assert.equal(input.oldAuthCid,old.requiredContainerId);assert.equal(baseline.oldCid,old.requiredContainerId);
 assert.equal(baseline.oldStartedAt,old.requiredStartedAt);assert.equal(stopped.cid,old.requiredContainerId);
 assert.equal(stopped.exitCode,0);assert.equal(stopped.pid,0);
 assert.equal(intent.oldCid,old.requiredContainerId);assert.equal(intent.modelSha256,result.modelSha256);
 for(const flag of ['noBuild','noPull','noDeps','noStart'])assert.equal(intent[flag],true);
 assert.equal(created.cid,result.newCid);assert.equal(created.imageId,old.imageId);
 assert.equal(result.state,'D05_LOCAL_SOURCE_AUTH_OVERLAY_HEALTHY');assert.equal(result.qualifiedSignedNightly,false);
 assert.equal(result.oldCid,old.requiredContainerId);assert.equal(result.oldStartedAt,old.requiredStartedAt);
 assert.equal(result.sourceSha256,v.operator.sha256);assert.equal(result.binarySha256,hash);
 assert.equal(result.engineId,signedAuthority(base).engineId);
 assert(HASH.test(result.newCid)&&!prior.some(row=>row.requiredContainerId===result.newCid));
 assert(Number.isFinite(Date.parse(result.startedAt))&&Date.parse(result.startedAt)>Date.parse(old.requiredStartedAt));
 assert(Number.isSafeInteger(result.hostPid)&&result.hostPid>0);
 const mount=result.binaryMount,target='/usr/local/bin/marty-auth';
 assert.equal(mount.type,'bind');assert.equal(mount.destination,target);assert.equal(mount.writable,false);
 assert.equal(comparableBinaryMounts([mount])[0].source,comparableBinaryMounts([{source:v.binary.path}])[0].source);
 return prior.map(row=>{if(row.role!=='auth')return row;
  const next={...row,source,kind:'SCOPED_NATIVE_FUNCTIONAL_OVERLAY',sha256:hash,
   requiredContainerId:result.newCid,requiredStartedAt:result.startedAt,requiredHostPid:result.hostPid,
   requiredEffectiveUid:10001,requiredBinaryMounts:[mount]};
  delete next.requiredObservation;return next;});
}
module.exports={expected};
