'use strict';
// Tests the actual caller's isolated selector body; no beta or browser run.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { createHash } = require('node:crypto');
const { createPrivateReviewRealPagePreflight } = require('./demo-private-review-preflight');
const policySha256 = createHash('sha256').update(fs.readFileSync(path.join(__dirname,'demo-recording.js'))).digest('hex');

const source = fs.readFileSync(path.join(__dirname, 'verify-beta-credential-login.js'), 'utf8');
const selected = source.match(/function selectRealPagePreflight\([\s\S]*?\r?\n}\r?\n/);
assert(selected, 'Current D05 caller selector required');
const select = vm.runInNewContext('(' + selected[0] + ')', { assert, createPrivateReviewRealPagePreflight });
const options = () => ({ retainedMembership: true, privateReview: null, recordVideo: false,
  walletOrigin: 'http://127.0.0.1:8787', loginOrigin: 'https://beta.elevenidllc.com',
  evidence: { privateReviewPagePreflightSource: () => ({ runId: '11111111-1111-4111-8111-111111111111',
    sourceRevision: 'a'.repeat(40), sourceSha256: policySha256 }) } });

test('D05 default stays disabled without a source getter or any capture context', () => {
  assert.equal(select({ ...options(), mode: undefined, evidence: null }), null);
  assert.equal(select({ ...options(), mode: '0', evidence: null }), null);
  assert.throws(() => select({ ...options(), mode: 'yes' }));
});
test('D05 opt-in requires the exact owned, functional and no-video source getter', () => {
  for (const changed of [{ retainedMembership: false }, { privateReview: {} }, { recordVideo: true }, { evidence: null }])
    assert.throws(() => select({ ...options(), mode: '1', ...changed }));
  const preflight = select({ ...options(), mode: '1' });
  assert.equal(preflight.contextOptions.recordVideo, undefined);
  assert.equal(typeof preflight.prepareContext, 'function');
  assert.equal(typeof preflight.probePage, 'function');
});
