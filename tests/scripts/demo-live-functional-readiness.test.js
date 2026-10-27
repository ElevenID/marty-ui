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
  for(const name of ['externalLiveEvidence.js','canvasNativeRuntime.js','ownedWalletRuntime.js']) fs.writeFileSync(path.join(sourceRoot,name),'source fixture');
  const environment = {DEMO_EXECUTION_EVIDENCE_HELPER:helper,
    DEMO_EXECUTION_EVIDENCE_HELPER_SHA256:createHash('sha256').update(bytes).digest('hex'),
    DEMO_LOCAL_FUNCTIONAL_RUNTIME_RECEIPT:receipt,
    DEMO_LOCAL_FUNCTIONAL_RUNTIME_SHA256:binding.receiptSha256,RECORD_VIDEO:'0'};
  let closed = false, loads = 0, ownedContext=null, ownedPolicy=null, ownedReceipt=null;
  const client = {functionalRuntimeBinding:binding,close(){closed=true;}};
  const module = {exports:{}};
  const source = fs.readFileSync(path.join(__dirname,'demo-live-evidence.js'),'utf8');
  vm.runInNewContext(source, {module,process:{env:environment,connected:true},Buffer,
    require(name) {
      if(name==='node:os') return {homedir:()=>root};
      if(name===helper) return {createLiveEvidenceClient:async()=>client};
      if(path.basename(name)==='ownedWalletRuntime.js') return {
        ownedWalletAuthority:env=>({path:env.DEMO_LOCAL_FUNCTIONAL_WALLET_AUTHORITY_INPUT,sha256:env.DEMO_LOCAL_FUNCTIONAL_WALLET_AUTHORITY_SHA256}),
        validateOwnedWalletContext:value=>{assert.deepEqual(value,ownedContext);return value;},
        loadOwnedWalletRuntime:(file,sha,options)=>{assert.equal(file,ownedReceipt.path);assert.equal(sha,ownedReceipt.sha256);assert.equal(options.functionalRerun,true);assert.deepEqual(options.expectedAuthority,ownedPolicy);return {context:ownedContext};},
      };
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
  const owned=()=>{
    const file=path.join(privateRoot,'owned-wallet.json');fs.writeFileSync(file,'OWNED_WALLET_SOURCE_ONLY');
    ownedReceipt={path:file,sha256:createHash('sha256').update(fs.readFileSync(file)).digest('hex')};
    const policyFile=path.join(privateRoot,'policy.ref');fs.writeFileSync(policyFile,'SOURCE_ONLY_POLICY');
    ownedPolicy={path:policyFile,sha256:createHash('sha256').update(fs.readFileSync(policyFile)).digest('hex')};
    ownedContext={kind:'OWNED_NATIVE_WALLET_V1',receiptSha256:ownedReceipt.sha256,origin:'http://127.0.0.1:8789',instanceId:'11111111-1111-4111-8111-111111111111',runId:'22222222-2222-4222-8222-222222222222',sourceRevision:'d'.repeat(40),scope:'FUNCTIONAL_ONLY',releaseQualified:false,recordingQualified:false};
    Object.assign(environment,{DEMO_LOCAL_FUNCTIONAL_WALLET_RECEIPT:file,DEMO_LOCAL_FUNCTIONAL_WALLET_SHA256:ownedReceipt.sha256,
      DEMO_LOCAL_FUNCTIONAL_WALLET_AUTHORITY_INPUT:policyFile,DEMO_LOCAL_FUNCTIONAL_WALLET_AUTHORITY_SHA256:ownedPolicy.sha256,MARTY_TEST_WALLET_ORIGIN:ownedContext.origin});
    client.ownedWalletBinding={...ownedContext};return ownedContext;
  };
  return {api:module.exports,client,environment,binding,root,receipt,helper,owned,
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
test('alternate wallet needs recorder-owned private receipt ACK and exact closed session instance',async t=>{
  const f=fixture();t.after(f.close);const context=f.owned();await f.api.createDemoLiveEvidence();
  const report={walletSession:{instanceId:context.instanceId,closed:true}};
  assert.equal(f.api.applyLocalNativeReadiness(report,f.client,{ready:true,cleanupComplete:true},f.environment),true);
  assert.deepEqual(JSON.parse(JSON.stringify(report.localFunctionalWallet)),context);assert.equal(report.releaseReady,false);
  assert.equal(f.api.applyLocalNativeReadiness({walletSession:{instanceId:'foreign'}},f.client,{ready:true,cleanupComplete:true},f.environment),false);
});
test('arbitrary loopback override, foreign wallet ACK and policy/receipt substitutions are refused',async t=>{
  const unbound=fixture();t.after(unbound.close);unbound.environment.MARTY_TEST_WALLET_ORIGIN='http://127.0.0.1:8789';
  await assert.rejects(unbound.api.createDemoLiveEvidence());assert.equal(unbound.closed(),true);
  for(const mutate of [f=>delete f.client.ownedWalletBinding,f=>f.client.ownedWalletBinding={...f.client.ownedWalletBinding,instanceId:'foreign'},
    f=>f.environment.DEMO_LOCAL_FUNCTIONAL_WALLET_SHA256='f'.repeat(64),f=>f.environment.DEMO_LOCAL_FUNCTIONAL_WALLET_AUTHORITY_SHA256='f'.repeat(64),
    f=>f.environment.MARTY_TEST_WALLET_ORIGIN='http://127.0.0.1:8790',f=>f.client.nativeRuntimeBinding={}]){
    const f=fixture();t.after(f.close);f.owned();mutate(f);await assert.rejects(f.api.createDemoLiveEvidence());assert.equal(f.closed(),true);
  }
});
