'use strict';

const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const test = require('node:test');
const { acquireWalletSession, openIsolatedWallet, walletOrigin } = require('./demo-wallet-session');

function walletTransport({ supported = true, resetStatus = 204 } = {}) {
  const instanceId = randomUUID();
  const calls = [];
  let current;
  let cookie = [];
  const response = (status, body) => ({ status: () => status,
    ok: () => status >= 200 && status < 300, json: async () => structuredClone(body) });
  const send = async (method, url, options) => {
    const route = new URL(url).pathname;
    calls.push({ method, route, runId: options?.headers?.['x-marty-wallet-run-id'] });
    if (route === '/ready') return response(200, { status: 'ready', instance_id: instanceId,
      features: supported ? { isolated_sessions: 1 } : {} });
    if (route === '/api/sessions' && method === 'POST') {
      current = { session_id: randomUUID(), instance_id: instanceId,
        run_id: options.data.run_id, credential_count: 0 };
      cookie = [{ name: 'marty_test_wallet_session', value: 'opaque-cookie-not-reportable' }];
      return response(201, current);
    }
    if (route === '/api/session' && method === 'GET') return response(current ? 200 : 410, current);
    if (route === '/api/reset' && method === 'POST') {
      if (resetStatus === 204) current.credential_count = 0;
      return response(resetStatus, null);
    }
    if (route === '/api/session' && method === 'DELETE') {
      current = null;
      cookie = [];
      return response(204, null);
    }
    throw new Error(`Unexpected ${method} ${route}`);
  };
  const context = { cookies: async () => cookie, request: {
    get: (url, options) => send('GET', url, options),
    post: (url, options) => send('POST', url, options),
    delete: (url, options) => send('DELETE', url, options),
  } };
  return { context, calls, setCurrent: (changes) => Object.assign(current, changes) };
}

const origin = 'http://127.0.0.1:8787';

test('old wallet capability blocks before any session creation or global reset', async () => {
  const wallet = walletTransport({ supported: false });
  await assert.rejects(acquireWalletSession(wallet.context, { origin }), /isolated_sessions v1/);
  assert.deepEqual(wallet.calls.map(({ method, route }) => `${method} ${route}`), ['GET /ready']);
});

test('a changed run, session or process cannot be reset or closed by a prior owner', async () => {
  for (const changes of [{ run_id: 'other-run' }, { session_id: randomUUID() }, { instance_id: randomUUID() }]) {
    const wallet = walletTransport();
    const session = await acquireWalletSession(wallet.context, { origin, runId: 'owned-run' });
    wallet.setCurrent(changes);
    await assert.rejects(session.reset(), /ownership changed or expired/);
    await assert.rejects(session.close(), /ownership changed or expired/);
    assert.equal(wallet.calls.filter((call) => call.route === '/api/reset' || call.method === 'DELETE').length, 0);
    assert.equal(session.evidence.closed, false);
  }
});

test('visible wallet actions keep the server run guard and cleanup erases only their session', async () => {
  const wallet = walletTransport();
  const session = await acquireWalletSession(wallet.context, { origin, runId: 'owned-run' });
  const navigations = [];
  await openIsolatedWallet({ context: () => wallet.context, goto: async (url) => navigations.push(url) }, origin);
  assert.deepEqual(navigations, [`${origin}/?wallet_run=owned-run`]);
  wallet.setCurrent({ credential_count: 2 });
  await session.reset();
  await session.close();
  await session.close();
  assert.equal(wallet.calls.filter((call) => call.method === 'DELETE').length, 1);
  for (const call of wallet.calls.filter((call) => ['/api/reset', '/api/session'].includes(call.route))) {
    assert.equal(call.runId, 'owned-run');
  }
  assert.equal(session.evidence.closed, true);
  assert.equal(JSON.stringify(session.evidence).includes('opaque-cookie'), false);
  await assert.rejects(session.reset(), /closed/);
});

test('failed owned reset remains a failure and one browser context cannot acquire another session', async () => {
  const wallet = walletTransport({ resetStatus: 500 });
  const session = await acquireWalletSession(wallet.context, { origin });
  await assert.rejects(session.reset(), /reset did not complete/);
  await assert.rejects(acquireWalletSession(wallet.context, { origin }), /fresh browser context/);
  await session.close();
});

test('wallet transport rejects public hosts, credentials and route-bearing origins', () => {
  for (const url of ['https://wallet.example', 'http://user:secret@localhost:8787',
    'http://localhost:8787/another-wallet', 'http://localhost:8787/?wallet_run=other', 'file:///tmp/wallet']) {
    assert.throws(() => walletOrigin(url), /loopback/);
  }
  assert.equal(walletOrigin(origin), origin);
});
