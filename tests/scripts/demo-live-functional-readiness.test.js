'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const os = require('node:os');
const {createHash} = require('node:crypto');

// Portable source controls model only the recorder API boundary. The recorder's
// own controls exercise its real mounted-receipt loader and authenticated IPC.
function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'd06-functional-source-'));
  const privateRoot = path.join(root,'.codex','private');
  const sourceRoot = path.join(root,'recorder','src');
  fs.mkdirSync(privateRoot,{recursive:true});fs.mkdirSync(sourceRoot,{recursive:true});
  const receipt=path.join(privateRoot,'runtime.json');fs.writeFileSync(receipt,'source fixture');
  const binding = {kind:'FUNCTIONAL_RUNTIME_V2',profileSha256:'a'.repeat(64),receiptSha256:'b'.repeat(64),
    scope:'FUNCTIONAL_ONLY',releaseQualified:false,recordingQualified:false};
  const helper = path.join(sourceRoot,'externalLiveEvidenceHelper.js'), bytes = Buffer.from('reviewed helper');
  fs.writeFileSync(helper,bytes);
  for(const name of ['externalLiveEvidence.js','canvasNativeRuntime.js']) fs.writeFileSync(path.join(sourceRoot,name),'source fixture');
  const environment = {DEMO_EXECUTION_EVIDENCE_HELPER:helper,
    DEMO_EXECUTION_EVIDENCE_HELPER_SHA256:createHash('sha256').update(bytes).digest('hex'),
    DEMO_LOCAL_FUNCTIONAL_RUNTIME_RECEIPT:receipt,
    DEMO_LOCAL_FUNCTIONAL_RUNTIME_SHA256:binding.receiptSha256,RECORD_VIDEO:'0'};
  let closed = false, loads = 0;
  const client = {functionalRuntimeBinding:binding,close(){closed=true;}};
  const module = {exports:{}};
  const source = fs.readFileSync(path.join(__dirname,'demo-live-evidence.js'),'utf8');
  vm.runInNewContext(source, {module,process:{env:environment,connected:true},Buffer,
    require(name) {
      if(name==='node:os') return {homedir:()=>root};
      if(name===helper) return {createLiveEvidenceClient:async()=>client};
      if(path.basename(name)==='externalLiveEvidence.js') return {
        validateFunctionalRuntimeContext(value) {
          assert.deepEqual(Object.keys(value || {}).sort(),Object.keys(binding).sort());
          assert.equal(value.kind,'FUNCTIONAL_RUNTIME_V2');
          assert.equal(value.scope,'FUNCTIONAL_ONLY');
          assert.equal(value.releaseQualified,false);assert.equal(value.recordingQualified,false);
          return value;
        }, functionalRuntimeContext:()=>binding};
      if(path.basename(name)==='canvasNativeRuntime.js') return {loadFunctionalRuntimeObservation(file,hash,options) {
        loads++;assert.equal(file,environment.DEMO_LOCAL_FUNCTIONAL_RUNTIME_RECEIPT);
        assert.equal(hash,binding.receiptSha256);assert.equal(options.functionalRerun,true);
        return {};
      }};
      return require(name);
    }});
  return {api:module.exports,client,environment,binding,root,receipt,helper,
    close:()=>fs.rmSync(root,{recursive:true,force:true}),closed:()=>closed,loads:()=>loads};
}
test('functional acknowledgement accepts actual private host path and sibling module layout',async t=>{
  const f=fixture();t.after(f.close);await f.api.createDemoLiveEvidence();
  const report={releaseReady:true};
  assert.equal(f.api.applyLocalNativeReadiness(report,f.client,{ready:true,cleanupComplete:true},f.environment),true);
  assert.equal(f.loads(),2);assert.equal(report.releaseReady,false);
  assert.equal(report.demo_qualified,false);assert.equal(report.signedManifestVerified,false);
  assert.equal(report.localFunctionalRuntime.profileSha256,f.binding.profileSha256);
  assert.equal(report.localFunctionalRuntime.recordingQualified,false);
});
test('failed operations, cleanup and errors stay failed',t=>{
  for(const state of [{ready:false,cleanupComplete:true},{ready:true,cleanupComplete:false},{ready:true,cleanupComplete:true,error:'failed'}]) {
    const f=fixture(),report={releaseReady:true,...(state.error?{error:state.error}:{})};t.after(f.close);
    assert.equal(f.api.applyLocalNativeReadiness(report,f.client,state,f.environment),false);
    assert.equal(report.releaseReady,false);assert.equal(report.operations_verified,false);
  }
});
test('missing, cross-mode, promoted and mismatched acknowledgements close IPC',async t=>{
  for(const mutate of [
    f=>delete f.client.functionalRuntimeBinding,
    f=>f.client.nativeRuntimeBinding={},
    f=>f.environment.DEMO_LOCAL_NATIVE_LIVE_BINDING='1',
    f=>f.environment.RECORD_VIDEO='1',
    f=>f.environment.DEMO_LOCAL_FUNCTIONAL_RUNTIME_SHA256='c'.repeat(64),
    f=>f.client.functionalRuntimeBinding={...f.binding,profileSha256:'c'.repeat(64)},
    f=>f.client.functionalRuntimeBinding={...f.binding,releaseQualified:true},
    f=>f.client.functionalRuntimeBinding={...f.binding,extra:true},
    f=>delete f.environment.DEMO_LOCAL_FUNCTIONAL_RUNTIME_RECEIPT,
  ]) {
    const f=fixture();t.after(f.close);mutate(f);await assert.rejects(f.api.createDemoLiveEvidence());assert.equal(f.closed(),true);
  }
});
test('receipt and helper drift are rechecked at report completion',t=>{
  for(const mutate of [f=>f.environment.DEMO_LOCAL_FUNCTIONAL_RUNTIME_SHA256='c'.repeat(64),
    f=>f.environment.DEMO_EXECUTION_EVIDENCE_HELPER_SHA256='d'.repeat(64)]) {
    const f=fixture();t.after(f.close);mutate(f);
    assert.throws(()=>f.api.applyLocalNativeReadiness({},f.client,{ready:true,cleanupComplete:true},f.environment));
  }
});
test('outside custody, relative, traversing, directory and standalone helper layouts fail closed',async t=>{
  for(const mutate of [
    f=>{const file=path.join(f.root,'public.json');fs.writeFileSync(file,'public');f.environment.DEMO_LOCAL_FUNCTIONAL_RUNTIME_RECEIPT=file;},
    f=>f.environment.DEMO_LOCAL_FUNCTIONAL_RUNTIME_RECEIPT='relative.json',
    f=>f.environment.DEMO_LOCAL_FUNCTIONAL_RUNTIME_RECEIPT=path.dirname(f.receipt),
    f=>f.environment.DEMO_LOCAL_FUNCTIONAL_RUNTIME_RECEIPT=path.dirname(f.receipt)+path.sep+'..'+path.sep+'private'+path.sep+'runtime.json',
    f=>fs.unlinkSync(path.join(path.dirname(f.helper),'canvasNativeRuntime.js')),
  ]) {
    const f=fixture();t.after(f.close);mutate(f);
    await assert.rejects(f.api.createDemoLiveEvidence());assert.equal(f.closed(),true);
  }
});
test('receipt symlink or junction traversal is refused',async t=>{
  const f=fixture();t.after(f.close);
  const linked=path.join(f.root,'.codex','private-link');
  fs.symlinkSync(path.dirname(f.receipt),linked,process.platform==='win32'?'junction':'dir');
  f.environment.DEMO_LOCAL_FUNCTIONAL_RUNTIME_RECEIPT=path.join(linked,'runtime.json');
  await assert.rejects(f.api.createDemoLiveEvidence(),/symlinks/);assert.equal(f.closed(),true);
});
