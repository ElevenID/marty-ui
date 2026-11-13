'use strict';
// No video or artifact writes. This probes real pages with the exact capture veil
// before a separate, still-gated recording run can be considered.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const { createHash } = require('node:crypto');
const { privateReviewPageInitScript, VIDEO_SIZE } = require('./demo-recording');

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const SHA = /^[a-f0-9]{64}$/;
const REV = /^[a-f0-9]{40}$/;

function protectedMutation() {
  const originals = [];
  let textCount = 0, valueCount = 0, hiddenSelectCount = 0, graphicsCount = 0;
  const swap = value => String(value).replace(/\S/g, character => character === 'M' ? 'W' : 'M');
  const transparent = value => value === 'transparent' || /^rgba?\([^)]*,\s*0(?:\.0+)?\)$/.test(value);
  const nodes = [...document.querySelectorAll('*')];
  if (nodes.length > 5000) throw Error('PRIVATE_PREFLIGHT_SURFACE_BOUND');
  try { for (const node of nodes) {
    if (['SCRIPT', 'STYLE', 'LINK', 'META', 'HEAD', 'TITLE'].includes(node.tagName)) continue;
    const style = getComputedStyle(node);
    if (['SVG', 'IMG', 'CANVAS'].includes(node.tagName)) {
      if (style.visibility !== 'hidden' || Number(style.opacity) !== 0) throw Error('PRIVATE_PREFLIGHT_GRAPHIC_VISIBLE');
      graphicsCount++;
    }
    if (node.tagName === 'SELECT') {
      if (Number(style.opacity) !== 0) throw Error('PRIVATE_PREFLIGHT_VALUE_VISIBLE');
      hiddenSelectCount++;
    }
    if (['INPUT', 'TEXTAREA'].includes(node.tagName) && node.value) {
      if (Number(style.opacity) !== 0) throw Error('PRIVATE_PREFLIGHT_VALUE_VISIBLE');
      const original = node.value;
      originals.push(() => { node.value = original; });
      node.value = swap(original);
      valueCount++;
    }
    if (!transparent(style.color) || !transparent(style.webkitTextFillColor)) continue;
    for (const child of node.childNodes) {
      if (child.nodeType !== 3 || !/\S/.test(child.nodeValue || '')) continue;
      const original = child.nodeValue;
      originals.push(() => { child.nodeValue = original; });
      child.nodeValue = swap(original);
      textCount++;
    }
  }
  if (!textCount && !valueCount) throw Error('PRIVATE_PREFLIGHT_NO_MUTABLE_PROTECTED_VALUE');
  // Originals remain only in this isolated page's closure and are never sent
  // to Node, an evidence file, or a log.
  globalThis.__martyRestorePrivatePreflight = () => {
    for (let i = originals.length - 1; i >= 0; i--) originals[i]();
    delete globalThis.__martyRestorePrivatePreflight;
  };
  return { textCount, valueCount, hiddenSelectCount, graphicsCount };
  } catch (error) {
    for (let i = originals.length - 1; i >= 0; i--) originals[i]();
    throw error;
  }
}

function restoreMutation() {
  const restore = globalThis.__martyRestorePrivatePreflight;
  if (typeof restore !== 'function') throw Error('PRIVATE_PREFLIGHT_RESTORE_MISSING');
  restore();
}

function createPrivateReviewRealPagePreflight({ runId, sourceRevision, sourceSha256, expectedOrigins }) {
  assert(UUID.test(runId), 'Current owned run ID required');
  assert(REV.test(sourceRevision) && SHA.test(sourceSha256), 'Exact bound UI source required');
  assert.equal(createHash('sha256').update(fs.readFileSync(require.resolve('./demo-recording'))).digest('hex'),
    sourceSha256, 'Loaded D05 page policy differs from Recorder-bound source');
  assert(expectedOrigins && Object.keys(expectedOrigins).sort().join(',') === 'login,wallet');
  for (const role of ['wallet', 'login']) {
    const url = new URL(expectedOrigins[role]);
    assert.equal(url.origin, expectedOrigins[role], 'Exact page origin required');
    assert(!url.username && !url.password && !url.search && !url.hash);
    if (role === 'login') assert.equal(url.protocol, 'https:');
    else assert(url.protocol === 'http:' && ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname));
  }
  const contexts = new Map(), pages = new Map(), events = [];
  let finished = false;
  const blocked = () => events.some(event => event.state === 'BLOCKED');
  return {
    contextOptions: Object.freeze({ viewport: VIDEO_SIZE }),
    async prepareContext(context, role) {
      assert(!finished && ['wallet', 'login'].includes(role) && !contexts.has(role));
      assert.equal(context.pages().length, 0, 'Policy must precede actual pages');
      contexts.set(role, context);
      await context.exposeBinding('__martyPrivateReviewPointerEvent', ({ page }, event) => {
        assert.equal(page.context(), context);
        assert.equal(event.role, role);
      });
      await context.exposeBinding('__martyPrivateReviewSurfaceEvent', ({ page }, event) => {
        assert.equal(page.context(), context);
        assert.equal(event.role, role);
        assert.deepEqual(Object.keys(event).sort(), ['code', 'role', 'state']);
        assert(['POLICY_ACTIVE', 'BLOCKED'].includes(event.state));
        assert(event.code === null || /^[A-Z_]{1,64}$/.test(event.code));
        assert(events.length < 256, 'Surface evidence bound exceeded');
        events.push({ role, state: event.state, code: event.code });
      });
      await context.addInitScript({ content: privateReviewPageInitScript(role) });
    },
    async probePage(role, page) {
      assert(!finished && contexts.get(role) === page.context() && !pages.has(role));
      assert.equal(page.video(), null, 'Real-page preflight must not record');
      const url = new URL(page.url());
      assert.equal(url.origin, expectedOrigins[role], 'Actual page origin changed');
      const options = { animations: 'disabled', caret: 'hide' };
      const before = Buffer.from(await page.screenshot(options));
      assert(before.length > 0 && before.length <= 32 * 1024 * 1024);
      let changed, during, restored;
      try {
        changed = await page.evaluate(protectedMutation);
        during = Buffer.from(await page.screenshot(options));
      } finally {
        if (changed) await page.evaluate(restoreMutation);
      }
      restored = Buffer.from(await page.screenshot(options));
      assert(before.equals(during) && before.equals(restored), 'Protected real-page pixels changed');
      assert(events.some(event => event.role === role && event.state === 'POLICY_ACTIVE'), 'Actual page policy not active');
      assert(!blocked(), 'Actual page surface policy blocked');
      pages.set(role, { role, ...changed, mutatedProtectedPixelsEqual: true });
      return Object.freeze({ ...pages.get(role) });
    },
    finish() {
      assert(!finished && pages.has('wallet') && pages.has('login') && !blocked(), 'Both real pages required');
      finished = true;
      return Object.freeze({ scope: 'REAL_PAGE_NO_VIDEO_PREFLIGHT_ONLY', runId, sourceRevision, sourceSha256,
        pages: Object.freeze(['wallet', 'login'].map(role => Object.freeze({ ...pages.get(role) }))),
        credentialBearingPagesQualified: false, continuousVideoFramesQualified: false,
        renderedPrivacyQualified: false, actualCaptureGo: false, mediaCreated: false });
    },
  };
}

module.exports = { createPrivateReviewRealPagePreflight };
