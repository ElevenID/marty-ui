'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { EventEmitter } = require('node:events');
const { spawnSync } = require('node:child_process');
const { options, authorization, createJourney, api, anonymous, identity, membership,
  applicationCookies, prepareOutput, qualify } = require('./run-external-oidc-login.cjs');

const ORIGIN = 'https://beta.example.invalid';
const ENDPOINT = 'https://identity.example.invalid/authorize';
const SECRET_SENTINEL = 'NEVER_PRINT_RAW_TOKEN_OR_PASSWORD';
function config(output = '/private/new-run', overrides = {}) {
  return { origin: ORIGIN, 'authorization-endpoint': ENDPOINT, 'client-id': 'test-client',
    email: 'operator@example.invalid', 'user-id': 'marty-user-1', 'organization-id': 'org-1',
    'source-sha': 'a'.repeat(40), 'output-dir': output, 'required-role': 'administrator',
    'timeout-seconds': '30', 'export-session': 'false', ...overrides };
}
function args(cfg = config()) { return Object.entries(cfg).flatMap(([key, value]) => ['--' + key, value]); }
function authUrl(cfg = config()) {
  const url = new URL(ENDPOINT);
  url.search = new URLSearchParams({ client_id: cfg['client-id'], response_type: 'code',
    redirect_uri: cfg.origin + '/v1/auth/callback', scope: 'openid email profile',
    code_challenge_method: 'S256', code_challenge: 'a'.repeat(43), state: 's'.repeat(32), nonce: 'n'.repeat(32) });
  return url.href;
}
function callbackUrl(state = 's'.repeat(32)) {
  return ORIGIN + '/v1/auth/callback?' + new URLSearchParams({ code: SECRET_SENTINEL, state });
}
function me(cfg = config()) {
  return { authenticated: true, user: { user_id: cfg['user-id'], email: cfg.email, roles: ['administrator'] } };
}
function cookie(patch = {}) {
  return { name: 'marty_session', value: SECRET_SENTINEL, domain: new URL(ORIGIN).hostname,
    path: '/v1', secure: true, httpOnly: true, expires: -1, sameSite: 'Lax', ...patch };
}
function freshDir(t) {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'oidc-qualification-'));
  fs.chmodSync(parent, 0o700);
  t.after(() => fs.rmSync(parent, { recursive: true, force: true }));
  return path.join(parent, 'run');
}
function startedJourney() {
  const journey = createJourney(config());
  journey.response(journey.loginUrl, 302, authUrl(), 'GET');
  journey.request(authUrl(), 'GET');
  return journey;
}

test('accepts canonical, isolated configuration', () => assert.deepEqual(options(args()), config()));
for (const [key, value] of [['origin', 'http://beta.example.invalid'], ['origin', ORIGIN + '/'],
  ['origin', 'https://name:password@beta.example.invalid'], ['authorization-endpoint', ENDPOINT + '?preset=yes'],
  ['source-sha', 'main'], ['timeout-seconds', '0'], ['timeout-seconds', '901'],
  ['export-session', 'yes'], ['output-dir', '../state'], ['email', 'x\ny']]) {
  test('rejects invalid option ' + key + '=' + JSON.stringify(value), () => {
    assert.throws(() => options(args(config(undefined, { [key]: value }))));
  });
}
test('rejects duplicate, unknown and valueless arguments', () => {
  for (const suffix of [['--origin', ORIGIN], ['--password', 'secret'], ['--email']]) {
    assert.throws(() => options([...args(), ...suffix]));
  }
});
test('rejects diagnostic environments that could expose authentication URLs', () => {
  for (const key of ['DEBUG', 'PWDEBUG', 'PW_TEST_CONNECT_WS_ENDPOINT', 'NODE_TLS_REJECT_UNAUTHORIZED']) {
    const previous = process.env[key];
    try { process.env[key] = key === 'NODE_TLS_REJECT_UNAUTHORIZED' ? '0' : 'pw:api';
      assert.throws(() => options(args()), /unsafe_runtime_environment/);
    } finally { if (previous === undefined) delete process.env[key]; else process.env[key] = previous; }
  }
});
test('validates authorization code, S256, callback and client binding', () => {
  assert.deepEqual(authorization(authUrl(), config()), { state: 's'.repeat(32), url: authUrl() });
});
for (const [key, value] of [['client_id', 'other-client'], ['response_type', 'token'],
  ['redirect_uri', 'https://production.example.invalid/v1/auth/callback'], ['scope', 'email'],
  ['code_challenge_method', 'plain'], ['code_challenge', 'short'], ['nonce', 'short'], ['state', 'short']]) {
  test('rejects authorization mismatch: ' + key, () => {
    const url = new URL(authUrl()); url.searchParams.set(key, value);
    assert.throws(() => authorization(url.href, config()));
  });
}
test('rejects duplicate authorization fields and misplaced secrets', () => {
  for (const key of ['client_id', 'state', 'nonce', 'scope', 'client_secret', 'access_token', 'id_token']) {
    const url = new URL(authUrl()); url.searchParams.append(key, SECRET_SENTINEL);
    assert.throws(() => authorization(url.href, config()));
  }
});
test('rejects a different endpoint even when client and callback match', () => {
  assert.throws(() => authorization(authUrl().replace('identity.', 'attacker.'), config()), /endpoint_mismatch/);
});
test('requires the actual authorization navigation before accepting callback', () => {
  const journey = createJourney(config());
  journey.response(journey.loginUrl, 302, authUrl(), 'GET');
  journey.response(callbackUrl(), 302, ORIGIN + '/', 'GET');
  assert.throws(() => journey.assertHealthy(), /unexpected_callback/);
});
test('accepts an observed redirect and matching callback without retaining sensitive evidence', () => {
  const journey = startedJourney();
  journey.response(callbackUrl(), 302, ORIGIN + '/', 'GET');
  journey.assertHealthy(); assert.equal(journey.complete, true);
  assert.equal(JSON.stringify(journey).includes(SECRET_SENTINEL), false);
});
test('irrelevant provider navigation fragments do not invalidate the observed flow', () => {
  const journey = startedJourney();
  journey.request('https://login.example.invalid/#challenge', 'GET');
  journey.response('https://login.example.invalid/#challenge', 200, undefined, 'GET');
  journey.response(callbackUrl(), 302, ORIGIN + '/', 'GET');
  assert.equal(journey.complete, true);
});
for (const [name, url, status, destination] of [
  ['mismatched state', callbackUrl('different-state'), 302, ORIGIN + '/'],
  ['duplicate state', callbackUrl() + '&state=other', 302, ORIGIN + '/'],
  ['denied consent', callbackUrl() + '&error=access_denied', 302, ORIGIN + '/'],
  ['server failure', callbackUrl(), 503, ORIGIN + '/'],
  ['Auth rejection redirect', callbackUrl(), 302, ORIGIN + '/?auth_error=expired'],
  ['foreign redirect', callbackUrl(), 302, 'https://attacker.example.invalid/'],
  ['missing redirect', callbackUrl(), 302, undefined],
]) {
  test('fails closed on ' + name, () => {
    const journey = startedJourney(); journey.response(url, status, destination, 'GET');
    assert.throws(() => journey.assertHealthy()); assert.equal(journey.complete, false);
  });
}
test('does not accept a replayed callback', () => {
  const journey = startedJourney(); journey.response(callbackUrl(), 302, ORIGIN, 'GET');
  journey.response(callbackUrl(), 302, ORIGIN, 'GET'); assert.throws(() => journey.assertHealthy());
});
test('requires exact account, role, and non-impersonated session', () => {
  identity(me(), config());
  for (const patch of [{ email: 'other@example.invalid' }, { user_id: 'other' },
    { roles: ['viewer'] }, { impersonation: { active: true } }]) {
    assert.throws(() => identity({ authenticated: true, user: { ...me().user, ...patch } }, config()));
  }
  assert.throws(() => identity({ authenticated: false }, config()));
});
test('requires an unambiguous application membership', () => {
  membership([{ id: 'org-1' }], config());
  for (const value of [[], [{ id: 'other' }], [{ id: 'org-1' }, { id: 'org-1' }], { items: [{ id: 'org-1' }] }]) {
    assert.throws(() => membership(value, config()));
  }
});
test('anonymous proof requires an explicit negative authentication result', () => {
  anonymous({ authenticated: false });
  for (const value of [null, {}, { authenticated: true }, { authenticated: 'false' }]) assert.throws(() => anonymous(value));
});
test('exports only exact-host secure HTTP-only application cookies', () => {
  const values = [cookie(), cookie({ domain: '.example.invalid' }), cookie({ domain: 'identity.example.invalid' }),
    cookie({ secure: false }), cookie({ httpOnly: false }), cookie({ path: '/console' }),
    cookie({ expires: 1 }), cookie({ partitionKey: ORIGIN })];
  assert.deepEqual(applicationCookies(values, ORIGIN), [cookie()]);
  assert.throws(() => applicationCookies([cookie(), cookie()], ORIGIN), /ambiguous/);
  assert.throws(() => applicationCookies([], ORIGIN), /session_cookie_required/);
  assert.throws(() => applicationCookies([cookie({ value: 'line\nbreak' })], ORIGIN), /ambiguous/);
});
test('private output is new, exclusive, and permission restricted', t => {
  const directory = freshDir(t); const write = prepareOutput(directory);
  write('receipt.json', { result: 'stopped' });
  assert.equal(fs.statSync(directory).mode & 0o777, 0o700);
  assert.equal(fs.statSync(path.join(directory, 'receipt.json')).mode & 0o777, 0o600);
  assert.throws(() => write('receipt.json', {}));
  assert.throws(() => write('../escape', {}));
  assert.throws(() => prepareOutput(directory));
});
test('refuses symlinked or public output parents and checkout output', t => {
  const directory = freshDir(t); const parent = path.dirname(directory);
  const link = path.join(parent, 'link'); fs.symlinkSync(parent, link);
  assert.throws(() => prepareOutput(path.join(link, 'new')), /symlink/);
  fs.chmodSync(parent, 0o755);
  assert.throws(() => prepareOutput(directory), /private_output_parent/);
  fs.chmodSync(parent, 0o700);
  assert.throws(() => prepareOutput(path.resolve(__dirname, '../receipt')), /outside_checkout/);
});

function response(status, value, headers = {}) {
  let disposed = false;
  const body = Buffer.from(typeof value === 'string' ? value : JSON.stringify(value));
  return { status: () => status, headers: () => ({ 'content-type': 'application/json', ...headers }),
    body: async () => body, dispose: async () => { disposed = true; }, get disposed() { return disposed; } };
}
test('API reads reject redirects, HTML, oversized bodies and server failures', async () => {
  for (const value of [response(302, {}), response(503, {}), response(200, {}, { 'content-type': 'text/html' }),
    response(200, 'not-json'), response(200, 'x'.repeat(262145)),
    response(200, {}, { 'content-length': '262145' })]) {
    await assert.rejects(api({ fetch: async (_url, opts) => { assert.equal(opts.maxRedirects, 0); return value; } }, ORIGIN, '/v1/auth/me'));
    assert.equal(value.disposed, true);
  }
});
test('API 401 is anonymous only for the explicit identity endpoint', async () => {
  const request = { fetch: async () => response(401, {}) };
  assert.deepEqual(await api(request, ORIGIN, '/v1/auth/me'), { authenticated: false });
  await assert.rejects(api(request, ORIGIN, '/v1/organizations/mine'));
});

// This executes the production orchestration with a deterministic browser/API
// test double, not a real IdP. It never upgrades unit evidence to live proof.
function fakePlaywright(cfg, faults = {}) {
  const contexts = []; const revoked = new Set(); let serial = 0;
  const browser = {
    closed: false,
    async newContext(opts) {
      assert.deepEqual(opts, { ignoreHTTPSErrors: false, serviceWorkers: 'block' });
      const context = { jar: [], closed: false,
        async cookies() { return context.jar; },
        async addCookies(cookies) { context.jar = cookies.map(c => ({ ...c })); },
        async close() { context.closed = true; },
        async newPage() {
          const page = new EventEmitter(); const frame = {};
          page.mainFrame = () => frame; page.isClosed = () => false; page.close = async () => {};
          page.goto = async loginUrl => {
            const request = url => ({ url: () => url, method: () => 'GET', isNavigationRequest: () => true, frame: () => frame });
            const emitResponse = (url, location) => page.emit('response', {
              url: () => url, status: () => 302, headers: () => ({ location }), request: () => request(url) });
            emitResponse(loginUrl, authUrl(cfg)); page.emit('request', request(authUrl(cfg)));
            const callback = faults.badState ? callbackUrl('WRONG') : callbackUrl();
            emitResponse(callback, cfg.origin + '/');
            context.jar = [cookie({ value: 'test-session-' + (++serial) }), cookie({ domain: 'identity.example.invalid', value: SECRET_SENTINEL })];
          };
          return page;
        },
      };
      context.request = { fetch: async (url, opts) => {
        assert.equal(opts.maxRedirects, 0); assert.equal(opts.headers.Origin, ORIGIN);
        const route = new URL(url).pathname;
        if (faults.networkFailure) throw new Error(SECRET_SENTINEL);
        const session = context.jar.find(c => c.domain === new URL(ORIGIN).hostname)?.value;
        if (route === '/v1/auth/provider') return response(200, { provider_mode: faults.managed ? 'keycloak' : 'external' });
        if (route === '/v1/auth/me') {
          if (faults.afterLogout503 && revoked.size) return response(503, {});
          if (faults.alreadyAuthenticated || (session && !revoked.has(session))) {
            const value = me(cfg); if (faults.wrongAccount) value.user.email = 'wrong@example.invalid';
            return response(200, value);
          }
          return response(200, { authenticated: false });
        }
        if (route === '/v1/organizations/mine') return response(200, faults.missingMembership ? [] : [{ id: cfg['organization-id'] }]);
        if (route === '/v1/auth/logout') {
          assert.equal(opts.method, 'POST');
          if (!faults.logoutDoesNotRevoke) revoked.add(session);
          context.jar = []; return response(302, {});
        }
        throw new Error('Unexpected route');
      } };
      contexts.push(context); return context;
    },
    async close() { browser.closed = true; if (faults.cleanupFailure) throw new Error(SECRET_SENTINEL); },
  };
  return { chromium: { launch: async opts => { assert.deepEqual(opts, { headless: false }); return browser; } }, contexts, browser };
}
test('executes login, membership, logout and independent old-cookie rejection', async t => {
  const cfg = config(freshDir(t)); const pw = fakePlaywright(cfg);
  const result = await qualify(cfg, pw, () => {}, async () => {});
  assert.equal(result.result, 'passed'); assert.equal(result.loginVerified, true);
  assert.equal(result.localLogoutVerified, true); assert.equal(result.oldSessionRejected, true);
  assert.equal(result.configurationSha256.length, 64);
  for (const key of ['mfaVerified', 'providerLogoutVerified', 'issuanceVerified', 'persistenceVerified', 'rotationVerified', 'sourceDeploymentVerified']) {
    assert.equal(result[key], false);
  }
  assert.ok(pw.contexts.every(c => c.closed)); assert.equal(pw.browser.closed, true);
  assert.equal(JSON.stringify(result).includes(SECRET_SENTINEL), false);
  assert.equal(JSON.stringify(result).includes(cfg.email), false);
});
for (const fault of ['networkFailure', 'managed', 'badState', 'wrongAccount', 'missingMembership', 'alreadyAuthenticated', 'logoutDoesNotRevoke', 'afterLogout503', 'cleanupFailure']) {
  test('orchestration stops and closes resources for ' + fault, async t => {
    const cfg = config(freshDir(t)); const pw = fakePlaywright(cfg, { [fault]: true });
    const result = await qualify(cfg, pw, () => {}, async () => {});
    assert.equal(result.result, 'stopped'); assert.ok(pw.contexts.every(c => c.closed));
    assert.equal(pw.browser.closed, true); assert.equal(JSON.stringify(result).includes(SECRET_SENTINEL), false);
    assert.equal(fs.existsSync(path.join(cfg['output-dir'], 'session-export.json')), false);
  });
}
test('export requires a second login and contains no provider cookies or local storage', async t => {
  const cfg = config(freshDir(t), { 'export-session': 'true' }); const pw = fakePlaywright(cfg);
  const result = await qualify(cfg, pw, () => {}, async () => {});
  assert.equal(result.result, 'passed'); assert.equal(result.repeatLoginVerified, true); assert.equal(result.exportedSession, true);
  assert.equal(pw.contexts.length, 3);
  const output = JSON.parse(fs.readFileSync(path.join(cfg['output-dir'], 'session-export.json')));
  assert.deepEqual(output.origins, []); assert.equal(output.cookies.length, 1);
  assert.equal(output.cookies[0].value, 'test-session-2');
  assert.equal(fs.statSync(path.join(cfg['output-dir'], 'session-export.json')).mode & 0o777, 0o600);
});
test('help works without Playwright or provider access', () => {
  const run = spawnSync(process.execPath, [path.join(__dirname, 'run-external-oidc-login.cjs'), '--help'], { encoding: 'utf8' });
  assert.equal(run.status, 0); assert.match(run.stdout, /isolated test browser/); assert.equal(run.stderr, '');
});
test('invalid command prints only a stable failure code', () => {
  const run = spawnSync(process.execPath, [path.join(__dirname, 'run-external-oidc-login.cjs'), '--password', SECRET_SENTINEL], { encoding: 'utf8' });
  assert.equal(run.status, 1); assert.equal((run.stdout + run.stderr).includes(SECRET_SENTINEL), false);
  assert.equal(JSON.parse(run.stdout).code, 'invalid_arguments');
});

test('cleanup failure prevents exporting a new authenticated session', async t => {
  const cfg = config(freshDir(t), { 'export-session': 'true' });
  const result = await qualify(cfg, fakePlaywright(cfg, { cleanupFailure: true }), () => {}, async () => {});
  assert.equal(result.result, 'stopped'); assert.equal(result.code, 'browser_cleanup_failed');
  assert.equal(fs.existsSync(path.join(cfg['output-dir'], 'session-export.json')), false);
});
test('receipt configuration binding changes with client or expected account', async t => {
  const a = config(freshDir(t)); const b = config(freshDir(t), { 'client-id': 'different-client' });
  const first = await qualify(a, fakePlaywright(a), () => {}, async () => {});
  const second = await qualify(b, fakePlaywright(b), () => {}, async () => {});
  assert.equal(first.result, 'passed'); assert.equal(second.result, 'passed');
  assert.notEqual(first.configurationSha256, second.configurationSha256);
});
