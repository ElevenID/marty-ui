'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');

async function createDemoLiveEvidence() {
  assert.equal(process.env.BETA_ORIGIN || 'https://beta.elevenidllc.com', 'https://beta.elevenidllc.com');
  assert.equal(process.env.MARTY_TEST_WALLET_ORIGIN || 'http://127.0.0.1:8787', 'http://127.0.0.1:8787');
  assert.notEqual(process.env.BETA_LOCAL_PROXY, '1');
  assert.ok(!process.env.NODE_TLS_REJECT_UNAUTHORIZED || process.env.NODE_TLS_REJECT_UNAUTHORIZED === '1');
  assert.ok(!process.env.MARTY_UI_CANDIDATE_DIST);
  const helper = process.env.DEMO_EXECUTION_EVIDENCE_HELPER;
  assert.ok(helper && process.connected, 'Demo qualification requires recorder-owned live IPC');
  assert.equal(createHash('sha256').update(fs.readFileSync(helper)).digest('hex'),
    process.env.DEMO_EXECUTION_EVIDENCE_HELPER_SHA256, 'Recorder evidence helper hash mismatch');
  const client = await require(helper).createLiveEvidenceClient();
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
