const test=require('node:test');
const assert=require('node:assert/strict');
const {applyLocalNativeReadiness}=require('./demo-live-evidence');
const binding={nativeSourceRevision:'a'.repeat(40),imageSourceId:'b'.repeat(40),receiptSha256:'c'.repeat(64),
  betaImageMarkersRemainBaseline:true,releaseQualified:false};
const environment={DEMO_LOCAL_NATIVE_LIVE_BINDING:'1',RECORD_VIDEO:'0',DEMO_LOCAL_NATIVE_OVERLAY_SHA256:'c'.repeat(64)};

test('actual success and cleanup can qualify local operations but never a release',()=>{
 const report={releaseReady:true,cleanup:{ok:true}};
 assert.equal(applyLocalNativeReadiness(report,{nativeRuntimeBinding:binding},{ready:true,cleanupComplete:true},environment),true);
 assert.equal(report.releaseReady,false);assert.equal(report.functionalReady,true);
 assert.equal(report.operations_verified,true);assert.equal(report.signedManifestVerified,false);
 assert.equal(report.demo_qualified,false);assert.equal(report.cleanup.complete,true);
 assert.deepEqual(report.localOverlayBinding,binding);
});
test('feature, cleanup or recorded errors remain unqualified',()=>{
 for(const state of [{ready:false,cleanupComplete:true},{ready:true,cleanupComplete:false},{ready:true,cleanupComplete:true,error:'actual operation failed'}]){
  const report={releaseReady:true,...(state.error?{error:state.error}:{})};
  assert.equal(applyLocalNativeReadiness(report,{nativeRuntimeBinding:binding},state,environment),false);
  assert.equal(report.releaseReady,false);assert.equal(report.operations_verified,false);
 }
});
test('missing acknowledgement, substituted receipt and recording mode fail closed',()=>{
 const state={ready:true,cleanupComplete:true};
 assert.throws(()=>applyLocalNativeReadiness({releaseReady:true},{},state,environment),/Missing recorder-owned/);
 for(const changed of [{RECORD_VIDEO:'1'},{DEMO_LOCAL_NATIVE_OVERLAY_SHA256:'d'.repeat(64)}])
  assert.throws(()=>applyLocalNativeReadiness({releaseReady:true},{nativeRuntimeBinding:binding},state,{...environment,...changed}));
});
test('ordinary released runs keep their existing report contract',()=>{
 const report={releaseReady:true,cleanup:{ok:true}},before=structuredClone(report);
 assert.equal(applyLocalNativeReadiness(report,{}, {ready:true,cleanupComplete:true},{}),true);
 assert.deepEqual(report,before);
});
