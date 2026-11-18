'use strict';

// Execute the real driver orchestration with the real wallet-session client.
// Only browser transport and artifact writes are local doubles. Every run stops
// before product configuration; this fixture never qualifies a business journey.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const { openIsolatedWallet } = require('./demo-wallet-session');

const ORIGIN = 'http://localhost:9876';
const INSTANCE_ID = '15a13e8d-5839-419c-98a9-0f6591c08c15';
const SESSION_ID = '2ed65542-25cb-4e14-84ab-302a539cd3de';
const STOP = 'Synthetic stop before product configuration';
const NATIVE_EVIDENCE = Buffer.from('{"scope":"native source fixture only"}');
const NATIVE_DIGEST = require('node:crypto').createHash('sha256').update(NATIVE_EVIDENCE).digest('hex');

function loadWalletDriver(filename, { loseAcquisition = false, failClose = false } = {}) {
  const operations = [];
  const reports = [];
  const contexts = [];
  const response = (status, body) => ({
    status: () => status,
    ok: () => status >= 200 && status < 300,
    json: async () => structuredClone(body),
  });
  const browser = {
    async newContext() {
      const name = contexts.length === 0 ? 'admin' : 'applicant';
      let closed = false;
      let current = null;
      const send = async (method, url, options) => {
        assert.equal(closed, false, 'Wallet teardown requires its still-open browser context');
        assert.equal(name, 'admin', 'The receiver wallet belongs to the admin context');
        assert.equal(new URL(url).origin, ORIGIN);
        const route = new URL(url).pathname;
        operations.push(`${name}:${method} ${route}`);
        if (method === 'GET' && route === '/ready') {
          return response(200, { status: 'ready', instance_id: INSTANCE_ID, features: { isolated_sessions: 1 } });
        }
        if (method === 'POST' && route === '/api/sessions') {
          current = { instance_id: INSTANCE_ID, session_id: SESSION_ID,
            run_id: options.data.run_id, credential_count: 0 };
          if (loseAcquisition) throw new Error('Lost session creation response');
          return response(201, current);
        }
        assert.equal(options.headers['x-marty-wallet-run-id'], current?.run_id);
        if (method === 'GET' && route === '/api/session') return response(200, current);
        if (method === 'DELETE' && route === '/api/session') {
          if (failClose) return response(503, null);
          current = null;
          return response(204, null);
        }
        throw new Error(`Unexpected wallet operation ${method} ${route}`);
      };
      const context = {
        name,
        pages: [],
        cookies: async () => current ? [{ name: 'marty_test_wallet_session', value: 'private-session-cookie' }] : [],
        request: {
          get: (url, options) => send('GET', url, options),
          post: (url, options) => send('POST', url, options),
          delete: (url, options) => send('DELETE', url, options),
        },
        async newPage() {
          operations.push(`${name}:new-page`);
          const page = {
            context: () => context,
            on() {},
            video: () => null,
            async goto(url) { operations.push(`wallet:open:${url}`); },
            async evaluate() { throw new Error('No product mutation is permitted in this fixture'); },
          };
          context.pages.push(page);
          return page;
        },
        async close() { operations.push(`${name}:close`); closed = true; },
      };
      contexts.push(context);
      operations.push(`${name}:new-context`);
      return context;
    },
    async close() { operations.push('browser:close'); },
  };
  const processDouble = { env: {
    TEST_VENDOR_EMAIL: 'admin@example.test', TEST_VENDOR_PASSWORD: 'synthetic-admin-password',
    TEST_APPLICANT_EMAIL: 'applicant@example.test', TEST_APPLICANT_PASSWORD: 'synthetic-applicant-password',
    BETA_AUDIT_VERIFIER_DID: 'did:web:demo.example.test:verifier',
    BETA_ORIGIN: 'https://demo.example.test', MARTY_TEST_WALLET_ORIGIN: ORIGIN,
    D01_PASSPORT_EVIDENCE_SHA256: NATIVE_DIGEST, RECORD_VIDEO: '0',
  }, exitCode: 0 };
  const module = { exports: {} };
  const requireDouble = (name) => {
    if (name === 'node:fs') return {
      writeFileSync: (_filename, text) => { operations.push('report:write'); reports.push(JSON.parse(text)); },
    };
    if (name === '@playwright/test') return { chromium: { launch: async () => browser } };
    if (name === './demo-live-evidence') return {
      createDemoLiveEvidence: async () => ({ bindPage() {}, close() {},
        async readFixture(file) { assert.equal(file, 'passport-validation-evidence.json'); return NATIVE_EVIDENCE; },
        complete: async () => assert.fail('Stopped wallet fixture cannot complete business evidence') }),
      acknowledgeDemoInputs: async (_directory, _file, expected) => expected,
      applyLocalNativeReadiness: require(name).applyLocalNativeReadiness,
    };
    if (name === './verify-beta-waltid-acceptance') return {
      ...require(name), loadEnvFile() {},
    };
    if (name === './demo-recording') return {
      ...require(name), createArtifactDir: () => '/memory/wallet-driver-fixture',
    };
    if (name === './audit-beta-credential-lifecycle') return {
      ...require(name),
      async login(page) {
        operations.push('product:login-boundary');
        assert.equal(page.context(), contexts[0]);
        assert.equal(contexts[0].pages.length, 2);
        // The same registry used by receiveCredential must already recognize
        // the driver's wallet page, not a separate or applicant context.
        await openIsolatedWallet(contexts[0].pages[1], ORIGIN);
        throw new Error(STOP);
      },
    };
    if (name === './beta-demo-resource-helpers') return {
      ...require(name),
      async cleanupApplicationCredential(...args) {
        operations.push('product:owned-cleanup');
        return require(name).cleanupApplicationCredential(...args);
      },
    };
    return require(name);
  };
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, filename), 'utf8'), {
    require: requireDouble, module, __dirname, process: processDouble,
    console: { log() {} }, URL,
  }, { filename });
  return { main: module.exports.main, operations, reports, contexts, process: processDouble };
}

function walletSessionDriverRegressions(filename, scenario) {
  test(`${scenario} acquires the receiver context before configuration and closes it before browser teardown`, async () => {
    const run = loadWalletDriver(filename);
    await assert.rejects(run.main(), new RegExp(STOP));
    assert.equal(run.reports.length, 1);
    const report = run.reports[0];
    assert.equal(report.walletSession.instanceId, INSTANCE_ID);
    assert.equal(report.walletSession.sessionId, SESSION_ID);
    assert.equal(report.walletSession.runId, report.ownedResources.runId);
    assert.equal(report.walletSession.closed, true);
    assert.ok(report.walletSession.closedAt);
    assert.ok(run.operations.indexOf('admin:POST /api/sessions') < run.operations.indexOf('product:login-boundary'));
    assert.ok(run.operations.includes(`wallet:open:${ORIGIN}/?wallet_run=${report.ownedResources.runId}`));
    assert.deepEqual(run.operations.slice(-5), [
      'admin:DELETE /api/session', 'applicant:close', 'admin:close', 'browser:close', 'report:write',
    ]);
    assert.ok(run.operations.indexOf('product:owned-cleanup') < run.operations.indexOf('admin:DELETE /api/session'));
    assert.equal(report.cleanup.ok, true);
    assert.deepEqual(report.finalizationFailures, []);
    assert.equal(report.releaseReady, false);
    assert.equal(run.process.exitCode, 1);
    assert.equal(JSON.stringify(report).includes('private-session-cookie'), false);
    assert.equal(run.operations.some((operation) => operation.includes('/api/reset')), false);
  });

  test(`${scenario} retains unknown wallet acquisition and refuses product actions or success`, async () => {
    const run = loadWalletDriver(filename, { loseAcquisition: true });
    await assert.rejects(run.main(), /Lost session creation response/);
    const report = run.reports[0];
    assert.equal(report.walletSession, undefined);
    assert.deepEqual(report.finalizationFailures, [{ operation: 'wallet_session_acquisition', outcome: 'UNCONFIRMED' }]);
    assert.deepEqual(run.operations, [
      'admin:new-context', 'admin:GET /ready', 'admin:POST /api/sessions',
      'admin:close', 'browser:close', 'report:write',
    ]);
    assert.equal(report.releaseReady, false);
    assert.equal(run.process.exitCode, 1);
    assert.equal(report.ownedResources.applicationId, null);
    assert.equal(report.ownedResources.transactionId, null);
    assert.equal(report.ownedResources.credentialId, null);
  });

  test(`${scenario} reports failed owned-wallet closure while still finalizing both contexts`, async () => {
    const run = loadWalletDriver(filename, { failClose: true });
    await assert.rejects(run.main(), new RegExp(STOP));
    const report = run.reports[0];
    assert.equal(report.walletSession.sessionId, SESSION_ID);
    assert.equal(report.walletSession.closed, false);
    assert.equal(report.finalizationFailures.length, 1);
    assert.equal(report.finalizationFailures[0].operation, 'wallet_session_close');
    assert.match(report.finalizationFailures[0].error, /could not be closed/);
    assert.deepEqual(run.operations.slice(-5), [
      'admin:DELETE /api/session', 'applicant:close', 'admin:close', 'browser:close', 'report:write',
    ]);
    assert.equal(run.operations.filter((operation) => operation === 'admin:DELETE /api/session').length, 1);
    assert.equal(report.releaseReady, false);
    assert.equal(run.process.exitCode, 1);
  });
}

module.exports = { walletSessionDriverRegressions };
