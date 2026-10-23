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
  return require(helper).createLiveEvidenceClient();
}

async function acknowledgeDemoInputs(artifactDir, file, expected, client) {
  assert.equal(path.basename(file), file);
  fs.writeFileSync(path.join(artifactDir, file), JSON.stringify(expected, null, 2), { flag: 'wx' });
  const actual = JSON.parse((await client.readFixture(file)).toString('utf8'));
  assert.deepEqual(actual, expected, 'Recorder fixture differs from actual demo inputs');
  await client.seal();
  return actual;
}

module.exports = { createDemoLiveEvidence, acknowledgeDemoInputs };
