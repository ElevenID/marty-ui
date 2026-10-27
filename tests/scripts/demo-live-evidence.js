'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');
const os = require('node:os');

function regularSource(file) {
  assert.equal(typeof file, 'string');
  assert.ok(!/[\x00-\x1f\x7f]/.test(file), 'Invalid source path');
  assert.ok(path.isAbsolute(file), 'Absolute recorder-owned source path required');
  let current = path.parse(file).root;
  for (const part of file.slice(current.length).split(/[\\/]/)) {
    assert.ok(part && part !== '.' && part !== '..', 'Canonical source path required');
    current = path.join(current, part);
    assert.equal(fs.lstatSync(current).isSymbolicLink(), false, 'Recorder source cannot traverse symlinks');
  }
  assert.ok(fs.statSync(file).isFile(), 'Regular recorder-owned source file required');
  return file;
}

function functionalBinding(client, environment) {
  const binding = client.functionalRuntimeBinding;
  if (!binding && environment.DEMO_LOCAL_FUNCTIONAL_RUNTIME_RECEIPT === undefined) return null;
  assert.equal(environment.DEMO_LOCAL_NATIVE_LIVE_BINDING, undefined, 'Select one runtime evidence mode');
  assert.ok(!client.nativeRuntimeBinding, 'Select one runtime acknowledgement');
  assert.equal(environment.RECORD_VIDEO, '0', 'Functional evidence cannot record a release demo');
  const receipt = regularSource(environment.DEMO_LOCAL_FUNCTIONAL_RUNTIME_RECEIPT);
  const relative = path.relative(path.join(os.homedir(), '.codex', 'private'), receipt);
  assert.ok(receipt === '/capture-prerequisites/functional-runtime.json'
    || (relative && relative !== '..' && !relative.startsWith('..' + path.sep) && !path.isAbsolute(relative)),
  'Functional runtime receipt must be in private custody or the owned capture mount');
  const helper = regularSource(environment.DEMO_EXECUTION_EVIDENCE_HELPER);
  assert.ok(helper, 'Recorder evidence helper required');
  assert.equal(createHash('sha256').update(fs.readFileSync(helper)).digest('hex'),
    environment.DEMO_EXECUTION_EVIDENCE_HELPER_SHA256, 'Recorder evidence helper hash mismatch');
  const directory = path.dirname(helper);
  const {validateFunctionalRuntimeContext, functionalRuntimeContext} = require(regularSource(path.join(directory, 'externalLiveEvidence.js')));
  const {loadFunctionalRuntimeObservation} = require(regularSource(path.join(directory, 'canvasNativeRuntime.js')));
  const acknowledged = validateFunctionalRuntimeContext(binding);
  const runtime = loadFunctionalRuntimeObservation(receipt,
    environment.DEMO_LOCAL_FUNCTIONAL_RUNTIME_SHA256, {functionalRerun:true});
  assert.deepEqual(acknowledged, functionalRuntimeContext(runtime), 'Functional runtime acknowledgement differs from mounted receipt');
  return acknowledged;
}

function ownedWalletBinding(client, environment, functional) {
  const binding=client.ownedWalletBinding;
  const selected=['DEMO_LOCAL_FUNCTIONAL_WALLET_RECEIPT','DEMO_LOCAL_FUNCTIONAL_WALLET_SHA256',
    'DEMO_LOCAL_FUNCTIONAL_WALLET_AUTHORITY_INPUT','DEMO_LOCAL_FUNCTIONAL_WALLET_AUTHORITY_SHA256'].some(key=>environment[key]!==undefined);
  if(!binding&&!selected){
    assert.equal(environment.MARTY_TEST_WALLET_ORIGIN||'http://127.0.0.1:8787','http://127.0.0.1:8787');
    return null;
  }
  assert.ok(functional&&!client.nativeRuntimeBinding,'Owned wallet requires an explicit functional runtime');
  assert.equal(environment.RECORD_VIDEO,'0');
  const directory=path.dirname(regularSource(environment.DEMO_EXECUTION_EVIDENCE_HELPER));
  const {loadOwnedWalletRuntime,ownedWalletAuthority,validateOwnedWalletContext}=require(regularSource(path.join(directory,'ownedWalletRuntime.js')));
  const runtime=loadOwnedWalletRuntime(environment.DEMO_LOCAL_FUNCTIONAL_WALLET_RECEIPT,
    environment.DEMO_LOCAL_FUNCTIONAL_WALLET_SHA256,{functionalRerun:true,expectedAuthority:ownedWalletAuthority(environment)});
  const acknowledged=validateOwnedWalletContext(binding);
  assert.deepEqual(acknowledged,runtime.context,'Owned wallet acknowledgement differs from bound host receipt');
  assert.equal(environment.MARTY_TEST_WALLET_ORIGIN,acknowledged.origin);
  return acknowledged;
}

async function createDemoLiveEvidence() {
  assert.equal(process.env.BETA_ORIGIN || 'https://beta.elevenidllc.com', 'https://beta.elevenidllc.com');
  assert.notEqual(process.env.BETA_LOCAL_PROXY, '1');
  assert.ok(!process.env.NODE_TLS_REJECT_UNAUTHORIZED || process.env.NODE_TLS_REJECT_UNAUTHORIZED === '1');
  assert.ok(!process.env.MARTY_UI_CANDIDATE_DIST);
  const helper = process.env.DEMO_EXECUTION_EVIDENCE_HELPER;
  assert.ok(helper && process.connected, 'Demo qualification requires recorder-owned live IPC');
  assert.equal(createHash('sha256').update(fs.readFileSync(helper)).digest('hex'),
    process.env.DEMO_EXECUTION_EVIDENCE_HELPER_SHA256, 'Recorder evidence helper hash mismatch');
  const client = await require(helper).createLiveEvidenceClient();
  try { const functional=functionalBinding(client, process.env);ownedWalletBinding(client,process.env,functional); }
  catch (error) { client.close(); throw error; }
  if (process.env.DEMO_LOCAL_NATIVE_LIVE_BINDING !== undefined) {
    try {
      assert.equal(process.env.DEMO_LOCAL_NATIVE_LIVE_BINDING, '1');
      assert.equal(process.env.RECORD_VIDEO, '0', 'Local native evidence cannot record a release demo');
      const binding = client.nativeRuntimeBinding;
      assert.ok(binding, 'Recorder did not acknowledge the actual local native runtime');
      assert.match(binding.nativeSourceRevision || '', /^[a-f0-9]{40}$/);
      assert.match(binding.imageSourceId || '', /^[a-f0-9]{40}$/);
      assert.equal(binding.receiptSha256, process.env.DEMO_LOCAL_NATIVE_OVERLAY_SHA256);
      assert.equal(binding.releaseQualified, false);
      assert.equal(binding.betaImageMarkersRemainBaseline, true);
    } catch (error) { client.close(); throw error; }
  }
  return client;
}

// Apply only recorder-observed provenance after real operations and owned
// cleanup. This never turns a failed feature or cleanup into a successful run.
function applyLocalNativeReadiness(report, client, {ready, cleanupComplete}, environment=process.env) {
  const functional = functionalBinding(client, environment);
  const wallet = ownedWalletBinding(client,environment,functional);
  if (functional) {
    report.releaseReady = false;
    report.qualification = 'LOCAL_MIXED_RUNTIME_FUNCTIONAL_OPERATIONS';
    report.localFunctionalRuntime = {profileSha256:functional.profileSha256, receiptSha256:functional.receiptSha256,
      scope:functional.scope, releaseQualified:false, recordingQualified:false};
    if(wallet)report.localFunctionalWallet={...wallet};
    report.signedManifestVerified = false;
    report.demo_qualified = false;
    report.cleanup = {...report.cleanup, complete:cleanupComplete === true};
    report.functionalReady = ready === true && cleanupComplete === true && !report.error
      && (!wallet||report.walletSession?.instanceId===wallet.instanceId);
    report.operations_verified = report.functionalReady;
    return report.functionalReady;
  }
  const binding = client.nativeRuntimeBinding;
  if (!binding) {
    assert.equal(environment.DEMO_LOCAL_NATIVE_LIVE_BINDING, undefined,
      'Missing recorder-owned native runtime acknowledgement');
    return report.releaseReady === true;
  }
  assert.equal(environment.DEMO_LOCAL_NATIVE_LIVE_BINDING, '1');
  assert.equal(environment.RECORD_VIDEO, '0');
  assert.equal(binding.releaseQualified, false);
  assert.equal(binding.betaImageMarkersRemainBaseline, true);
  assert.equal(binding.receiptSha256, environment.DEMO_LOCAL_NATIVE_OVERLAY_SHA256);
  report.releaseReady = false;
  report.qualification = 'LOCAL_MIXED_RUNTIME_FUNCTIONAL_OPERATIONS';
  report.localOverlayBinding = {...binding};
  report.signedManifestVerified = false;
  report.demo_qualified = false;
  report.cleanup = {...report.cleanup, complete:cleanupComplete === true};
  report.functionalReady = ready === true && cleanupComplete === true && !report.error;
  report.operations_verified = report.functionalReady;
  return report.functionalReady;
}

async function acknowledgeDemoInputs(artifactDir, file, expected, client) {
  assert.equal(path.basename(file), file);
  fs.writeFileSync(path.join(artifactDir, file), JSON.stringify(expected, null, 2), { flag: 'wx' });
  const actual = JSON.parse((await client.readFixture(file)).toString('utf8'));
  assert.deepEqual(actual, expected, 'Recorder fixture differs from actual demo inputs');
  await client.seal();
  return actual;
}

module.exports = { createDemoLiveEvidence, acknowledgeDemoInputs, applyLocalNativeReadiness };
