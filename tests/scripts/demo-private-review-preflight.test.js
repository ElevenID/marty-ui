'use strict';
// Controlled page objects only; these tests do not qualify actual rendered pages.
const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');
const { createPrivateReviewRealPagePreflight } = require('./demo-private-review-preflight');

const policySha256 = createHash('sha256').update(fs.readFileSync(path.join(__dirname,'demo-recording.js'))).digest('hex');
const input = () => ({ runId: '11111111-1111-4111-8111-111111111111', sourceRevision: 'a'.repeat(40),
  sourceSha256: policySha256, expectedOrigins: { wallet: 'http://127.0.0.1:8787', login: 'https://beta.elevenidllc.com' } });
function context() {
  const bindings = {};
  return { bindings, pages: () => [], async exposeBinding(name, callback) { bindings[name] = callback; },
    async addInitScript({ content }) { this.init = content; } };
}
function page(owner, origin, { frames = ['same', 'same', 'same'], video = null, evaluate } = {}) {
  let index = 0;
  return { context: () => owner, video: () => video, url: () => origin + '/private-route?nonce=redacted',
    screenshot: async () => Buffer.from(frames[index++]), evaluate: evaluate || (async fn => fn.name === 'protectedMutation'
      ? { textCount: 1, valueCount: 1, graphicsCount: 1 } : undefined) };
}
async function activate(preflight, owner, role, target) {
  await preflight.prepareContext(owner, role);
  assert(owner.init.includes('installPrivateReviewPage'));
  await owner.bindings.__martyPrivateReviewSurfaceEvent({ page: target }, { role, state: 'POLICY_ACTIVE', code: null });
}

test('real-page preflight binds source, two origins and roles without any video or promotion', async () => {
  const preflight = createPrivateReviewRealPagePreflight(input());
  assert.equal(preflight.contextOptions.recordVideo, undefined);
  const walletContext = context(), loginContext = context();
  const wallet = page(walletContext, 'http://127.0.0.1:8787');
  const login = page(loginContext, 'https://beta.elevenidllc.com');
  await activate(preflight, walletContext, 'wallet', wallet);
  await activate(preflight, loginContext, 'login', login);
  await preflight.probePage('wallet', wallet);
  await preflight.probePage('login', login);
  const result = preflight.finish();
  assert.equal(result.pages.length, 2);
  assert.equal(result.pages.every(row => row.mutatedProtectedPixelsEqual), true);
  assert.equal(result.runId, input().runId);
  assert.equal(result.sourceRevision, input().sourceRevision);
  for (const key of ['credentialBearingPagesQualified', 'continuousVideoFramesQualified', 'renderedPrivacyQualified', 'actualCaptureGo', 'mediaCreated']) assert.equal(result[key], false);
  assert.throws(() => preflight.finish());
});

test('missing policy, captured page, changed origin or changed protected pixels refuse', async () => {
  for (const variant of ['policy', 'video', 'origin', 'pixels']) {
    const preflight = createPrivateReviewRealPagePreflight(input()), owner = context();
    const target = page(owner, variant === 'origin' ? 'https://wrong.example' : 'http://127.0.0.1:8787',
      { video: variant === 'video' ? {} : null, frames: variant === 'pixels' ? ['before', 'changed', 'before'] : undefined });
    await preflight.prepareContext(owner, 'wallet');
    if (variant !== 'policy') await owner.bindings.__martyPrivateReviewSurfaceEvent({ page: target }, { role: 'wallet', state: 'POLICY_ACTIVE', code: null });
    await assert.rejects(preflight.probePage('wallet', target));
    assert.throws(() => preflight.finish());
  }
});

test('protected page mutation restores secret values even if a later graphic is visible', async () => {
  const field = { tagName: 'INPUT', value: 'secret', childNodes: [] };
  const graphic = { tagName: 'SVG', childNodes: [] };
  const sandbox = vm.createContext({ document: { querySelectorAll: () => [field, graphic] },
    getComputedStyle: node => node === field
      ? { opacity: '0', visibility: 'visible', color: 'rgba(0, 0, 0, 0)', webkitTextFillColor: 'rgba(0, 0, 0, 0)' }
      : { opacity: '1', visibility: 'visible', color: 'rgba(0, 0, 0, 0)', webkitTextFillColor: 'rgba(0, 0, 0, 0)' } });
  const preflight = createPrivateReviewRealPagePreflight(input()), owner = context();
  const target = page(owner, 'http://127.0.0.1:8787', { evaluate: async fn => vm.runInContext('(' + fn.toString() + ')()', sandbox) });
  await activate(preflight, owner, 'wallet', target);
  await assert.rejects(preflight.probePage('wallet', target), /PRIVATE_PREFLIGHT_GRAPHIC_VISIBLE/);
  assert.equal(field.value, 'secret');
});

test('actual protected-value mutation has identical hidden pixels and restores the page', async () => {
  const field = { tagName: 'INPUT', value: 'secret', childNodes: [] };
  const textNode = { nodeType: 3, nodeValue: 'credential-uuid' };
  const dynamic = { tagName: 'DIV', childNodes: [textNode] };
  const graphic = { tagName: 'SVG', childNodes: [] };
  const sandbox = vm.createContext({ document: { querySelectorAll: () => [field, dynamic, graphic] },
    getComputedStyle: node => node === field
      ? { opacity: '0', visibility: 'visible', color: 'rgba(0, 0, 0, 0)', webkitTextFillColor: 'rgba(0, 0, 0, 0)' }
      : { opacity: '0', visibility: 'hidden', color: 'rgba(0, 0, 0, 0)', webkitTextFillColor: 'rgba(0, 0, 0, 0)' } });
  const preflight = createPrivateReviewRealPagePreflight(input()), owner = context();
  const target = page(owner, 'http://127.0.0.1:8787', { evaluate: async fn => vm.runInContext('(' + fn.toString() + ')()', sandbox) });
  await activate(preflight, owner, 'wallet', target);
  const result = await preflight.probePage('wallet', target);
  assert.equal(result.valueCount, 1);
  assert.equal(result.textCount, 1);
  assert.equal(result.graphicsCount, 1);
  assert.equal(field.value, 'secret');
  assert.equal(textNode.nodeValue, 'credential-uuid');
  assert.throws(() => preflight.finish(), /Both real pages required/);
});

test('blocked page event and malformed source or origin never qualify', async () => {
  assert.throws(() => createPrivateReviewRealPagePreflight({ ...input(), sourceRevision: 'not-a-revision' }));
  assert.throws(() => createPrivateReviewRealPagePreflight({ ...input(), sourceSha256: 'f'.repeat(64) }), /Loaded D05 page policy differs/);
  assert.throws(() => createPrivateReviewRealPagePreflight({ ...input(), expectedOrigins: { wallet: 'https://wallet.example', login: 'https://beta.elevenidllc.com' } }));
  const preflight = createPrivateReviewRealPagePreflight(input()), owner = context();
  const target = page(owner, 'http://127.0.0.1:8787');
  await activate(preflight, owner, 'wallet', target);
  await owner.bindings.__martyPrivateReviewSurfaceEvent({ page: target }, { role: 'wallet', state: 'BLOCKED', code: 'UNSAFE_VALUE_ATTRIBUTE' });
  await assert.rejects(preflight.probePage('wallet', target));
});
