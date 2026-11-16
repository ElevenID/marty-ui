'use strict';

// Browser transport only. Ownership, storage isolation and expiry are enforced
// by marty-core's Rust test wallet, shared by all first-party browser demos.
const { randomUUID } = require('node:crypto');
const assert = require('node:assert/strict');
const sessions = new WeakMap();
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const COOKIE = 'marty_test_wallet_session';

function walletOrigin(value) {
  const url = new URL(value);
  if (!['http:', 'https:'].includes(url.protocol)
    || !['127.0.0.1', '[::1]', 'localhost'].includes(url.hostname)
    || url.username || url.password || url.pathname !== '/' || url.search || url.hash) {
    throw new Error('A loopback browser test-wallet origin is required');
  }
  return url.origin;
}

async function acquireWalletSession(context, { origin, runId = randomUUID() } = {}) {
  origin = walletOrigin(origin);
  if (!/^[A-Za-z0-9._-]{1,160}$/.test(runId)) throw new Error('Invalid wallet run ID');
  if (sessions.has(context) || (await context.cookies(origin)).some((cookie) => cookie.name === COOKIE)) {
    throw new Error('Use a fresh browser context for each wallet run');
  }
  const options = { timeout: 15000 };
  const readyResponse = await context.request.get(`${origin}/ready`, options);
  const ready = await readyResponse.json().catch(() => null);
  if (!readyResponse.ok() || ready?.status !== 'ready'
    || ready?.features?.isolated_sessions !== 1 || !UUID.test(ready?.instance_id || '')) {
    throw new Error('This demo requires the Rust test wallet with isolated_sessions v1; no shared wallet reset was attempted');
  }
  const response = await context.request.post(`${origin}/api/sessions`, { ...options, data: { run_id: runId } });
  const created = await response.json().catch(() => null);
  if (response.status() !== 201 || !UUID.test(created?.session_id || '')
    || created?.instance_id !== ready.instance_id || created?.run_id !== runId) {
    throw new Error('The wallet did not return a run-owned session; session creation may require reconciliation');
  }
  const evidence = {
    implementation: 'marty-core/marty-test-wallet', protocol: 'isolated_sessions_v1',
    instanceId: created.instance_id, sessionId: created.session_id, runId,
    acquiredAt: new Date().toISOString(), closed: false,
  };
  const requestOptions = { ...options, headers: { 'x-marty-wallet-run-id': runId } };
  let closed = false;
  async function assertOwned() {
    if (closed) throw new Error('The owned wallet session is closed');
    const currentResponse = await context.request.get(`${origin}/api/session`, requestOptions);
    const current = await currentResponse.json().catch(() => null);
    if (!currentResponse.ok() || current?.instance_id !== evidence.instanceId
      || current?.session_id !== evidence.sessionId || current?.run_id !== runId
      || !Number.isSafeInteger(current?.credential_count) || current.credential_count < 0) {
      throw new Error('Wallet session ownership changed or expired; refusing a shared wallet operation');
    }
    return current;
  }
  const session = {
    origin, evidence,
    assertOwned,
    async reset() {
      await assertOwned();
      const reset = await context.request.post(`${origin}/api/reset`, { ...requestOptions, data: {} });
      if (reset.status() !== 204 || (await assertOwned()).credential_count !== 0) {
        throw new Error('The owned wallet reset did not complete');
      }
    },
    async close() {
      if (closed) return;
      await assertOwned();
      const removed = await context.request.delete(`${origin}/api/session`, requestOptions);
      if (removed.status() !== 204) throw new Error('The owned wallet session could not be closed');
      closed = true;
      sessions.delete(context);
      evidence.closed = true;
      evidence.closedAt = new Date().toISOString();
    },
  };
  sessions.set(context, session);
  if ((await assertOwned()).credential_count !== 0) {
    throw new Error('A new owned wallet session must start empty');
  }
  return session;
}

function ownedWalletSession(page, origin) {
  const session = sessions.get(page.context());
  if (!session || session.origin !== walletOrigin(origin)) {
    throw new Error('Acquire a run-owned Rust wallet session before opening or resetting the wallet');
  }
  return session;
}

async function openIsolatedWallet(page, origin) {
  const session = ownedWalletSession(page, origin);
  await session.assertOwned();
  await page.goto(`${session.origin}/?wallet_run=${encodeURIComponent(session.evidence.runId)}`, {
    waitUntil: 'domcontentloaded', timeout: 60000,
  });
}

async function resetIsolatedWallet(page, origin) {
  return ownedWalletSession(page, origin).reset();
}

// One presentation UI transport for all first-party test-wallet consumers.
// The caller retains recording/masking and interprets its own response contract.
async function presentWalletRequest(page, requestUri, { origin, holderDecision = null } = {}) {
  assert([null, 'Approve', 'Cancel'].includes(holderDecision));
  origin = walletOrigin(origin);
  const current = new URL(page.url());
  assert(current.origin === origin && current.pathname === '/', 'Owned wallet UI context changed');
  assert(typeof requestUri === 'string' && requestUri.length > 0, 'Wallet request URI is required');
  const requestInput = page.getByLabel('Presentation request URI');
  await requestInput.fill(requestUri);
  assert(await requestInput.inputValue() === requestUri, 'Wallet request input changed');
  // Distinguish the static client before Present. A missing/late dialog after
  // dispatch, malformed dialog, or failed click never authorizes a fallback.
  const consent = page.locator('#presentation-consent');
  const dialogCount = await consent.count();
  assert([0, 1].includes(dialogCount), 'Ambiguous wallet consent UI');
  if (dialogCount === 1) {
    assert.equal(await consent.evaluate(element => element.tagName), 'DIALOG');
    for (const name of ['Approve', 'Cancel']) {
      assert.equal(await consent.getByRole('button', { name, exact: true, includeHidden: true }).count(), 1);
    }
  } else assert.equal(holderDecision, null, 'This holder decision requires the reviewed consent UI');
  const decision = dialogCount === 1 ? holderDecision || 'Approve' : null;
  const endpoint = decision === 'Cancel' ? '/api/presentation-decline' : '/api/present';
  const responsePromise = page.waitForResponse(response => {
    if (response.url() !== `${origin}${endpoint}` || response.request().method() !== 'POST') return false;
    try { return response.request().postDataJSON()?.request_uri === requestUri; } catch { return false; }
  }, { timeout: 60_000 });
  responsePromise.catch(() => {});
  await page.getByRole('button', { name: /^present$/i }).click();
  if (decision !== null) {
    await consent.waitFor({ state: 'visible', timeout: 15000 });
    await consent.getByRole('button', { name: decision, exact: true }).click({ timeout: 15000 });
    await consent.waitFor({ state: 'hidden', timeout: 15000 });
  }
  return { response: await responsePromise, holderDecision: decision,
    consentProtocol: dialogCount === 1 ? 'EXPLICIT_TEST_WALLET_DIALOG_V1' : 'LEGACY_PRESENT_UI' };
}

module.exports = { acquireWalletSession, openIsolatedWallet, resetIsolatedWallet, walletOrigin, presentWalletRequest };
