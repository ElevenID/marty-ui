'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const vm = require('node:vm');
const { createRequire } = require('node:module');

const REPO = path.resolve(__dirname, '../..');
const DRIVER = path.join(__dirname, 'run-kubernetes-acceptance.cjs');
const SOURCE = fs.readFileSync(DRIVER, 'utf8');
const HELPER = path.join(__dirname, 'run-canvas-oss-standard-contract.js');
const routes = require('../../contracts/gateway-routes.json').routes;
const issuanceSchema = require('../../contracts/gateway-public-openapi-schemas.json')
  .schemas.schemas__issuance_request;
const ORIGIN = 'https://marty.example:8443';
const ISSUER = 'did:web:marty.example%3A8443:orgs:marty-dev';
const DID_URL = ORIGIN + '/orgs/marty-dev/did.json';
const ORGANIZATION = '00000000-0000-0000-0000-000000000001';
const SOURCE_TEMPLATE = '50000000-0000-0000-0000-000000000040';
const SELECTED_TEMPLATE = '50000000-0000-0000-0000-000000000041';
const TRANSACTION = '70000000-0000-0000-0000-000000000001';
const CREDENTIAL = 'urn:uuid:80000000-0000-0000-0000-000000000001';
const VCT = ORIGIN + '/credentials/marty-badge';
const EMAIL = 'operator@localhost';
const USER_ID = 'synthetic-operator';
const PASSWORD = 'synthetic-only-operator-password';
const COOKIE = 'synthetic-only-exported-session';
const FOREIGN_COOKIE = 'synthetic-only-provider-session';
const CUSTOMER_ORGANIZATION = '750e8400-e29b-41d4-a716-446655440001';
const SCENARIO_FILE = path.join(REPO, 'deploy/helm/marty/examples/customer-education-claims.json');
const CUSTOMER_CLAIMS = JSON.parse(fs.readFileSync(SCENARIO_FILE, 'utf8'));
const jsonCopy = value => JSON.parse(JSON.stringify(value));
const hash = value => crypto.createHash('sha256').update(value).digest('hex');

function publicRoute(method, pathname) {
  const actual = pathname.split('/');
  return routes.some(route => route.method === method
    && route.path.split('/').length === actual.length
    && route.path.split('/').every((segment, index) => (
      segment.startsWith('{') ? Boolean(actual[index]) : segment === actual[index]
    )));
}

function apiResponse(status, body) {
  return { ok: () => status >= 200 && status < 300, status: () => status,
    json: async () => jsonCopy(body), body: async () => Buffer.from(JSON.stringify(body)) };
}

function fixture(t, organizationId = ORGANIZATION) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'marty-kubernetes-acceptance-'));
  fs.chmodSync(directory, 0o700);
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const passwordFile = path.join(directory, 'password');
  fs.writeFileSync(passwordFile, PASSWORD + '\n', { mode: 0o600 });
  const keys = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const f = { stateDir: path.join(directory, 'state'), passwordFile, organizationId,
    requests: [], protocol: [], contexts: [], launches: 0, logins: 0, closes: 0, redemptions: 0, identities: [],
    didKey: keys.publicKey.export({ format: 'jwk' }), transaction: null, record: null };
  const templates = new Map([[SOURCE_TEMPLATE, { id: SOURCE_TEMPLATE,
    organization_id: organizationId, status: 'ACTIVE', credential_type: 'open_badge',
    credential_payload_format: 'VC_JWT', vct: VCT,
    issuer_did: 'did:web:marty.example:orgs:marty-dev' }]]);
  const credentialIssuer = ORIGIN + '/org/' + organizationId;
  const offerUri = 'openid-credential-offer://?credential_offer=' + encodeURIComponent(JSON.stringify({
    credential_issuer: credentialIssuer, credential_configuration_ids: ['open_badge'],
    grants: { 'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
      'pre-authorized_code': 'synthetic-pre-authorized-code' } },
  }));

  async function request(address, options) {
    const url = new URL(address);
    const { method, data } = options;
    const route = url.pathname;
    f.requests.push({ method, route, data: data === undefined ? undefined : jsonCopy(data) });
    assert.equal(url.origin, ORIGIN);
    assert.equal(options.maxRedirects, 0);
    // Use the published route table and closed DTO, not the driver's paths.
    if (!publicRoute(method, route)) return apiResponse(404, { detail: 'Route not found' });
    if (method === 'GET' && route === '/v1/auth/me') {
      return apiResponse(f.meStatus ?? 200,
        f.me ?? { authenticated: true, user: { user_id: USER_ID, email: EMAIL } });
    }
    if (method === 'GET' && route === '/v1/credential-templates') {
      assert.equal(url.searchParams.get('organization_id'), organizationId);
      return apiResponse(200, [...templates.values()]);
    }
    if (route === '/v1/signing-keys/issuer-identities') {
      assert.equal(url.searchParams.get('organization_id'), organizationId);
      if (method === 'POST') {
        assert.equal(data.organization_id, organizationId);
        f.identities.push({ ...data, status: 'active' });
      } else assert.equal(method, 'GET');
      return apiResponse(200, { identities: f.identities });
    }
    if (route.startsWith('/v1/credential-templates/')) {
      const [, , , id, operation] = route.split('/');
      const template = templates.get(id);
      assert.ok(template);
      if (method === 'POST' && operation === 'new-version') {
        const draft = { ...template, id: SELECTED_TEMPLATE, status: 'DRAFT' };
        templates.set(draft.id, draft);
        return apiResponse(200, draft);
      }
      if (method === 'PATCH') template.issuer_did = data.issuer_did;
      else if (method === 'POST' && operation === 'activate') template.status = 'ACTIVE';
      else assert.equal(method, 'GET');
      return apiResponse(200, template);
    }
    if (method === 'POST' && route === '/v1/issuance') {
      assert.equal(issuanceSchema.additionalProperties, false);
      if (Object.keys(data).some(key => !Object.hasOwn(issuanceSchema.properties, key))
        || issuanceSchema.required.some(key => !Object.hasOwn(data, key))) {
        return apiResponse(422, { detail: 'Issuance request is outside the public contract' });
      }
      assert.equal(f.transaction, null, 'accept must initiate only one credential');
      assert.equal(data.credential_template_id, SELECTED_TEMPLATE);
      assert.equal(data.issuer_did, ISSUER);
      assert.equal(templates.get(SELECTED_TEMPLATE).status, 'ACTIVE');
      f.transaction = { id: TRANSACTION, organization_id: organizationId,
        credential_template_id: SELECTED_TEMPLATE, application_id: null, status: 'pending' };
      return apiResponse(200, { ...f.transaction, credential_offer_uri: offerUri });
    }
    if (method === 'GET' && route === '/v1/issuance/' + TRANSACTION) {
      assert.ok(f.transaction);
      return apiResponse(200, f.transaction);
    }
    if (method === 'GET' && decodeURIComponent(route) === '/v1/issued-credentials/' + CREDENTIAL) {
      assert.ok(f.record);
      return apiResponse(200, f.record);
    }
    assert.fail('Unexpected fixture request: ' + method + ' ' + route);
  }

  // These are the only HTTP responses available to the real OID4VCI helper.
  f.fetch = async (address, options = {}) => {
    const url = String(address);
    const method = options.method || 'GET';
    f.protocol.push({ method, url });
    const response = body => new Response(JSON.stringify(body), { status: 200 });
    if (url === ORIGIN + '/.well-known/openid-credential-issuer/org/' + organizationId) {
      assert.equal(method, 'GET');
      return response({ credential_issuer: credentialIssuer,
        token_endpoint: ORIGIN + '/v1/issuance/token',
        nonce_endpoint: ORIGIN + '/v1/issuance/nonce',
        credential_endpoint: ORIGIN + '/v1/issuance/credential' });
    }
    if (url === ORIGIN + '/v1/issuance/token') {
      assert.equal(method, 'POST');
      assert.equal(new URLSearchParams(options.body).get('pre-authorized_code'), 'synthetic-pre-authorized-code');
      return response({ access_token: 'synthetic-access-token' });
    }
    if (url === ORIGIN + '/v1/issuance/nonce') {
      assert.equal(method, 'POST');
      return response({ c_nonce: 'synthetic-proof-nonce' });
    }
    if (url === ORIGIN + '/v1/issuance/credential') {
      assert.equal(method, 'POST');
      assert.equal(options.headers.Authorization, 'Bearer synthetic-access-token');
      const body = JSON.parse(options.body);
      assert.equal(body.credential_configuration_id, 'open_badge');
      const [header, payload, signature] = body.proofs.jwt[0].split('.');
      const proofHeader = JSON.parse(Buffer.from(header, 'base64url'));
      const proof = JSON.parse(Buffer.from(payload, 'base64url'));
      assert.equal(proof.aud, credentialIssuer);
      assert.equal(proof.nonce, 'synthetic-proof-nonce');
      assert.ok(crypto.verify('sha256', Buffer.from(header + '.' + payload), {
        key: crypto.createPublicKey({ key: proofHeader.jwk, format: 'jwk' }), dsaEncoding: 'ieee-p1363',
      }, Buffer.from(signature, 'base64url')));
      const signedHeader = { alg: 'ES256', kid: ISSUER + '#key-1' };
      const signedPayload = { iss: ISSUER, sub: proof.iss, jti: CREDENTIAL,
        vc: { id: CREDENTIAL, type: ['VerifiableCredential', 'OpenBadgeCredential'],
          credentialSubject: { id: proof.iss, achievement: { id: VCT,
            criteria: jsonCopy(f.requests.find(entry => entry.method === 'POST'
              && entry.route === '/v1/issuance').data.claims.achievement_criteria),
          } } } };
      f.mutateSignedCredential?.(signedPayload);
      const input = [signedHeader, signedPayload].map(value => Buffer.from(JSON.stringify(value)).toString('base64url')).join('.');
      const signed = crypto.sign('sha256', Buffer.from(input), { key: keys.privateKey, dsaEncoding: 'ieee-p1363' });
      const credential = input + '.' + signed.toString('base64url');
      f.redemptions += 1;
      f.transaction.status = 'issued';
      f.record = { id: CREDENTIAL, credential_id: CREDENTIAL, organization_id: organizationId,
        application_id: null, credential_template_id: SELECTED_TEMPLATE,
        credential_hash: hash(credential), status: 'ACTIVE', flow_execution_id: TRANSACTION };
      return response({ credentials: [{ credential }] });
    }
    if (url === DID_URL) {
      assert.equal(method, 'GET');
      return response({ id: ISSUER, verificationMethod: [{ id: ISSUER + '#key-1', publicKeyJwk: f.didKey }],
        assertionMethod: [ISSUER + '#key-1'] });
    }
    assert.fail('Unexpected fixture protocol request: ' + method + ' ' + url);
  };
  const page = { goto: async url => assert.equal(url, ORIGIN), request: { fetch: request } };
  f.playwright = { chromium: { launch: async () => {
    f.launches += 1;
    return {
      newContext: async options => {
        assert.equal(options.baseURL, ORIGIN);
        assert.equal(options.ignoreHTTPSErrors, false);
        f.contexts.push(jsonCopy(options));
        return { setDefaultTimeout: () => {}, newPage: async () => page };
      }, close: async () => { f.closes += 1; },
    };
  } } };
  f.AuthHelpers = class {
    constructor(actualPage) { assert.equal(actualPage, page); }
    async login(email, password) {
      assert.equal(email, EMAIL);
      assert.equal(password, PASSWORD);
      f.logins += 1;
    }
  };
  return f;
}

async function run(f, phase = 'accept', extraOptions = []) {
  let output = '';
  const authOptions = f.storageStateFile
    ? ['--storage-state-file', f.storageStateFile] : ['--password-file', f.passwordFile];
  if (f.expectedUserId !== undefined && f.expectedUserId !== null) {
    authOptions.push('--user-id', f.expectedUserId);
  }
  const processBoundary = { argv: ['node', DRIVER, '--phase', phase, '--origin', ORIGIN,
    '--issuer-did', ISSUER, '--organization-id', f.organizationId,
    ...authOptions, '--state-dir', f.stateDir, ...extraOptions],
  env: {}, exitCode: 0, stdout: { write: chunk => { output += chunk; } } };
  const globals = { Buffer, URL, URLSearchParams, AbortController, setTimeout, clearTimeout,
    process: processBoundary, console: { log() {}, warn() {}, error() {} } };
  const helperModule = { exports: {} };
  const requireFromHelper = createRequire(HELPER);
  vm.runInNewContext(fs.readFileSync(HELPER, 'utf8'), { ...globals,
    __dirname, module: helperModule, exports: helperModule.exports, fetch: f.fetch,
    require: id => id === '@playwright/test' ? f.playwright : requireFromHelper(id),
  }, { filename: HELPER });
  const fromDriver = createRequire(DRIVER);
  const load = id => {
    if (id === 'node:module') return { createRequire: () => name => {
      assert.equal(name, '@playwright/test');
      return f.playwright;
    } };
    if (id === path.join(REPO, 'tests/utils/test-helpers.js')) return { AuthHelpers: f.AuthHelpers };
    if (id === HELPER) return helperModule.exports;
    return fromDriver(id);
  };
  await vm.runInNewContext(SOURCE, { ...globals, __dirname, require: load }, { filename: DRIVER });
  const receipts = output.trim().split('\n').map(line => JSON.parse(line));
  assert.equal(receipts.length, 1);
  return { code: processBoundary.exitCode, receipt: receipts[0], output };
}

function cookie(overrides = {}) {
  return { name: 'marty_session', value: COOKIE, domain: new URL(ORIGIN).hostname,
    path: '/', expires: Math.floor(Date.now() / 1000) + 3600,
    httpOnly: true, secure: true, sameSite: 'Lax', ...overrides };
}

function useStorageState(f, state = { cookies: [cookie()], origins: [] }) {
  f.storageStateFile = path.join(path.dirname(f.stateDir), 'operator-state.json');
  f.expectedUserId = USER_ID;
  fs.writeFileSync(f.storageStateFile, JSON.stringify(state), { mode: 0o600 });
}

test('accept uses the public issuance contract and retains a verified credential', async t => {
  const f = fixture(t);
  const result = await run(f);
  assert.equal(result.code, 0, result.output);
  assert.equal(result.receipt.result, 'passed');
  assert.equal(result.receipt.credentialTemplateId, SELECTED_TEMPLATE);
  assert.equal(Object.hasOwn(result.receipt, 'scenarioClaims'), false);
  assert.equal(Object.hasOwn(result.receipt, 'scenarioClaimsSha256'), false);
  for (const field of ['loginVerified', 'signatureVerified', 'holderBindingVerified', 'persistenceVerified']) {
    assert.equal(result.receipt[field], true);
  }
  assert.equal(f.logins, 1);
  assert.equal(result.receipt.authenticationMethod, 'password');
  assert.equal(result.receipt.operatorUserId, USER_ID);
  assert.equal(f.closes, 1);
  assert.equal(f.redemptions, 1);
  assert.equal(f.requests.filter(request => request.method === 'POST' && request.route === '/v1/issuance').length, 1);
  assert.equal(fs.statSync(f.stateDir).mode & 0o777, 0o700);
  for (const name of fs.readdirSync(f.stateDir)) {
    assert.equal(fs.statSync(path.join(f.stateDir, name)).mode & 0o777, 0o600);
  }
  const stored = JSON.parse(fs.readFileSync(path.join(f.stateDir, 'credential-private.json')));
  assert.equal(hash(stored.credential), result.receipt.credentialSha256);
  assert.deepEqual(stored.payload.vc.credentialSubject.achievement.criteria,
    f.requests.find(entry => entry.method === 'POST' && entry.route === '/v1/issuance')
      .data.claims.achievement_criteria);
  for (const privateValue of [PASSWORD, stored.credential, 'synthetic-pre-authorized-code']) {
    assert.equal(result.output.includes(privateValue), false);
  }
});

test('imported session verifies identity and acceptance without a password login or browser-state copy', async t => {
  const f = fixture(t);
  const expectedCookie = cookie({ expires: -1 });
  useStorageState(f, { cookies: [expectedCookie,
    cookie({ domain: 'provider.example', value: FOREIGN_COOKIE }),
    cookie({ domain: '.marty.example', value: FOREIGN_COOKIE }),
    cookie({ name: 'auth-only', path: '/v1/auth', value: FOREIGN_COOKIE }),
    cookie({ name: 'insecure', secure: false, value: FOREIGN_COOKIE }),
    cookie({ name: 'expired', expires: 1, value: FOREIGN_COOKIE })],
  origins: [{ origin: ORIGIN, localStorage: [{ name: 'token', value: FOREIGN_COOKIE }] },
    { origin: 'https://provider.example', localStorage: [{ name: 'idp', value: FOREIGN_COOKIE }] }] });
  const result = await run(f);
  assert.equal(result.code, 0, result.output);
  assert.equal(result.receipt.authenticationMethod, 'stored-session');
  assert.equal(result.receipt.sessionVerified, true);
  assert.equal(result.receipt.loginVerified, false);
  assert.equal(result.receipt.operatorUserId, USER_ID);
  assert.equal(result.receipt.operatorEmail, EMAIL);
  assert.equal(f.logins, 0);
  assert.equal(f.redemptions, 1);
  assert.deepEqual(f.contexts[0].storageState, { cookies: [expectedCookie], origins: [] });
  assert.equal(f.requests[0].route, '/v1/auth/me');
  for (const value of [COOKIE, FOREIGN_COOKIE, PASSWORD]) {
    assert.equal(result.output.includes(value), false);
    for (const name of fs.readdirSync(f.stateDir)) {
      assert.equal(fs.readFileSync(path.join(f.stateDir, name), 'utf8').includes(value), false);
    }
  }
  const requestCount = f.requests.length;
  f.expectedUserId = undefined; // New receipts retain the exact expected operator.
  const resumed = await run(f, 'resume');
  assert.equal(resumed.code, 0, resumed.output);
  assert.equal(resumed.receipt.operatorUserId, USER_ID);
  assert.equal(resumed.receipt.loginVerified, false);
  assert.equal(f.requests[requestCount].route, '/v1/auth/me');
  assert.ok(f.requests.slice(requestCount).every(request => request.method === 'GET'));
  assert.equal(f.logins, 0);
  assert.equal(f.redemptions, 1);
});

for (const [name, response, code] of [
  ['wrong email despite matching username', { authenticated: true,
    user: { user_id: USER_ID, email: 'another@example.com', username: EMAIL } }, 'authenticated_operator_mismatch'],
  ['different user with the same email', { authenticated: true,
    user: { user_id: 'another-operator', email: EMAIL } }, 'authenticated_operator_id_mismatch'],
  ['missing user identity', { authenticated: true, user: { email: EMAIL } }, 'authenticated_user_id_missing'],
  ['unauthenticated session', { authenticated: false, user: { user_id: USER_ID, email: EMAIL } }, 'authenticated_operator_mismatch'],
]) {
  test('imported session refuses ' + name + ' before any API mutation', async t => {
    const f = fixture(t);
    useStorageState(f);
    f.me = response;
    const result = await run(f);
    assert.equal(result.code, 1);
    assert.equal(result.receipt.code, code);
    assert.deepEqual(f.requests.map(({ method, route }) => ({ method, route })),
      [{ method: 'GET', route: '/v1/auth/me' }]);
    assert.equal(f.logins, 0);
    assert.equal(f.redemptions, 0);
    assert.equal(f.protocol.length, 0);
  });
}

test('imported-session HTTP refusal never writes a reflected cookie body', async t => {
  const f = fixture(t);
  useStorageState(f);
  f.meStatus = 401;
  f.me = { detail: COOKIE };
  const result = await run(f);
  assert.equal(result.code, 1);
  assert.equal(result.receipt.code, 'api_http_401');
  assert.equal(result.output.includes(COOKIE), false);
  assert.deepEqual(fs.readdirSync(f.stateDir), []);
  assert.equal(f.redemptions, 0);
});

test('password login checks an explicitly expected user ID before mutation', async t => {
  const f = fixture(t);
  f.expectedUserId = 'another-operator';
  const result = await run(f);
  assert.equal(result.code, 1);
  assert.equal(result.receipt.code, 'authenticated_operator_id_mismatch');
  assert.equal(f.logins, 1);
  assert.equal(f.requests.length, 1);
  assert.equal(f.redemptions, 0);
});

for (const [name, setup, code] of [
  ['missing expected user ID', f => { f.expectedUserId = undefined; }, 'expected_operator_user_id_required'],
  ['relative storage path', f => { f.storageStateFile = 'operator-state.json'; }, 'absolute_paths_required'],
  ['nonprivate mode', f => { fs.chmodSync(f.storageStateFile, 0o644); }, 'private_storage_state_required'],
  ['read-only mode', f => { fs.chmodSync(f.storageStateFile, 0o400); }, 'private_storage_state_required'],
  ['oversized file', f => { fs.writeFileSync(f.storageStateFile, ' '.repeat(1024 * 1024 + 1)); }, 'private_storage_state_required'],
  ['empty file', f => { fs.writeFileSync(f.storageStateFile, ''); }, 'private_storage_state_required'],
  ['malformed JSON', f => { fs.writeFileSync(f.storageStateFile, '{' + COOKIE); }, 'storage_state_invalid'],
  ['invalid UTF-8', f => { fs.writeFileSync(f.storageStateFile, Buffer.from([0xff, 0xfe])); }, 'storage_state_invalid'],
  ['file symlink', f => {
    const link = f.storageStateFile + '.link';
    fs.symlinkSync(f.storageStateFile, link);
    f.storageStateFile = link;
  }, 'storage_state_symlink_refused'],
  ['parent symlink', f => {
    const directory = path.dirname(f.stateDir);
    const link = path.join(directory, 'linked-parent');
    fs.symlinkSync(directory, link);
    f.storageStateFile = path.join(link, path.basename(f.storageStateFile));
  }, 'storage_state_symlink_refused'],
  ['hardlinked state', f => { fs.linkSync(f.storageStateFile, f.storageStateFile + '.link'); }, 'private_storage_state_required'],
]) {
  test('storage state refuses ' + name + ' before evidence/browser creation', async t => {
    const f = fixture(t);
    useStorageState(f);
    setup(f);
    const result = await run(f);
    assert.equal(result.code, 1);
    assert.equal(result.receipt.code, code, result.output);
    assert.equal(f.launches, 0);
    assert.equal(f.requests.length, 0);
    assert.equal(fs.existsSync(f.stateDir), false);
    assert.equal(result.output.includes(COOKIE), false);
  });
}

for (const [name, input, code] of [
  ['null', null, 'storage_state_invalid'],
  ['array', [], 'storage_state_invalid'],
  ['non-array cookies', { cookies: {} }, 'storage_state_invalid'],
  ['malformed origin collection', { cookies: [], origins: {} }, 'storage_state_invalid'],
  ['no cookies', { cookies: [] }, 'storage_state_scoped_cookies_required'],
  ['no cookie domain', { cookies: [{}] }, 'storage_state_cookie_invalid'],
  ['insecure cookies only', { cookies: [cookie({ secure: false })] }, 'storage_state_scoped_cookies_required'],
  ['expired cookies only', { cookies: [cookie({ expires: 1 })] }, 'storage_state_scoped_cookies_required'],
  ['foreign cookies only', { cookies: [cookie({ domain: 'provider.example' })] }, 'storage_state_scoped_cookies_required'],
  ['domain-wide cookies only', { cookies: [cookie({ domain: '.marty.example' })] }, 'storage_state_scoped_cookies_required'],
  ['different API path identity', { cookies: [cookie({ path: '/v1/auth' })] }, 'storage_state_scoped_cookies_required'],
  ['partitioned cookie', { cookies: [cookie({ partitionKey: 'https://provider.example' })] }, 'storage_state_scoped_cookies_required'],
  ['invalid cookie expiry', { cookies: [cookie({ expires: 'never' })] }, 'storage_state_cookie_invalid'],
  ['invalid cookie flag', { cookies: [cookie({ httpOnly: 'true' })] }, 'storage_state_cookie_invalid'],
  ['invalid cookie value', { cookies: [cookie({ value: COOKIE + '\n' })] }, 'storage_state_cookie_invalid'],
  ['invalid same-site policy', { cookies: [cookie({ sameSite: 'Other' })] }, 'storage_state_cookie_invalid'],
  ['ambiguous cookie identity', { cookies: [cookie(), cookie({ path: '/v1' })] }, 'storage_state_cookie_ambiguous'],
]) {
  test('storage state refuses ' + name, async t => {
    const f = fixture(t);
    useStorageState(f, input);
    const result = await run(f);
    assert.equal(result.code, 1);
    assert.equal(result.receipt.code, code, result.output);
    assert.equal(f.launches, 0);
    assert.equal(f.requests.length, 0);
    assert.equal(fs.existsSync(f.stateDir), false);
  });
}

test('password and storage-state arguments are mutually exclusive', async t => {
  const f = fixture(t);
  useStorageState(f);
  const result = await run(f, 'accept', ['--password-file', f.passwordFile]);
  assert.equal(result.code, 1);
  assert.equal(result.receipt.code, 'exactly_one_authentication_source_required');
  assert.equal(f.launches, 0);
  assert.equal(fs.existsSync(f.stateDir), false);
});

test('resume refuses a different operator before signature/readback or mutations', async t => {
  const f = fixture(t);
  assert.equal((await run(f)).code, 0);
  f.me = { authenticated: true, user: { user_id: 'different-operator', email: EMAIL } };
  const before = f.requests.length;
  const result = await run(f, 'resume');
  assert.equal(result.code, 1);
  assert.equal(result.receipt.code, 'authenticated_operator_id_mismatch');
  assert.equal(f.requests.length, before + 1);
  assert.equal(f.redemptions, 1);
  assert.equal(fs.readdirSync(f.stateDir).some(name => name.startsWith('resume-receipt-')), false);
});

test('legacy receipts require an explicit expected user ID on resume', async t => {
  const f = fixture(t);
  assert.equal((await run(f)).code, 0);
  const file = path.join(f.stateDir, 'accept-receipt.json');
  const original = JSON.parse(fs.readFileSync(file));
  delete original.operatorUserId;
  delete original.operatorEmail;
  fs.writeFileSync(file, JSON.stringify(original));
  const refused = await run(f, 'resume');
  assert.equal(refused.code, 1);
  assert.equal(refused.receipt.code, 'legacy_receipt_operator_user_id_required');
  assert.equal(f.launches, 1);
  const resumed = await run(f, 'resume', ['--user-id', USER_ID]);
  assert.equal(resumed.code, 0, resumed.output);
  assert.equal(resumed.receipt.operatorUserId, USER_ID);
  assert.equal(f.redemptions, 1);
});

for (const [name, mutate] of [
  ['omitted', payload => { delete payload.vc.credentialSubject.achievement.criteria; }],
  ['changed', payload => { payload.vc.credentialSubject.achievement.criteria = { narrative: 'Unrelated criterion' }; }],
]) {
  test('accept refuses signature-valid ' + name + ' achievement criteria', async t => {
    const f = fixture(t);
    f.mutateSignedCredential = mutate;
    const result = await run(f);
    assert.equal(result.code, 1);
    assert.equal(result.receipt.code, 'synthetic_achievement_criteria_changed');
    assert.equal(f.redemptions, 1);
    assert.equal(fs.existsSync(path.join(f.stateDir, 'accept-receipt.json')), false);
  });
}

test('resume performs fresh login and signature/readback checks without another API mutation', async t => {
  const f = fixture(t);
  assert.equal((await run(f)).code, 0);
  const retained = new Map(fs.readdirSync(f.stateDir).map(name => [name, fs.readFileSync(path.join(f.stateDir, name))]));
  const requestCount = f.requests.length;
  const protocolCount = f.protocol.length;
  const result = await run(f, 'resume');
  assert.equal(result.code, 0, result.output);
  assert.equal(result.receipt.phase, 'resume');
  assert.equal(result.receipt.transactionId, TRANSACTION);
  assert.equal(result.receipt.credentialId, CREDENTIAL);
  assert.equal(f.logins, 2);
  assert.equal(f.closes, 2);
  assert.equal(f.redemptions, 1);
  assert.ok(f.requests.slice(requestCount).every(request => request.method === 'GET'));
  assert.deepEqual(f.protocol.slice(protocolCount), [{ method: 'GET', url: DID_URL }]);
  for (const [name, contents] of retained) assert.deepEqual(fs.readFileSync(path.join(f.stateDir, name)), contents);
  assert.equal(fs.readdirSync(f.stateDir).filter(name => name.startsWith('resume-receipt-')).length, 1);
});

for (const [name, change, stage, code] of [
  ['changed persisted credential hash', f => { f.record.credential_hash = '0'.repeat(64); },
    'credential-persistence-readback', 'issued_credential_readback_failed'],
  ['changed live issuer key', f => {
    f.didKey = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ format: 'jwk' });
  }, 'stored-credential-signature', 'credential_signature_invalid'],
]) {
  test('resume rejects a ' + name + ' without replaying issuance', async t => {
    const f = fixture(t);
    assert.equal((await run(f)).code, 0);
    change(f);
    const requestCount = f.requests.length;
    const result = await run(f, 'resume');
    assert.equal(result.code, 1);
    assert.equal(result.receipt.stage, stage);
    assert.equal(result.receipt.code, code);
    assert.equal(f.redemptions, 1);
    assert.ok(f.requests.slice(requestCount).every(request => request.method === 'GET'));
    assert.equal(fs.readdirSync(f.stateDir).some(file => file.startsWith('resume-receipt-')), false);
  });
}

test('customer claims customize the request and receipt while canonical identity stays owned', async t => {
  const f = fixture(t, CUSTOMER_ORGANIZATION);
  const started = Date.now();
  const result = await run(f, 'accept', ['--scenario-claims-file', SCENARIO_FILE]);
  assert.equal(result.code, 0, result.output);
  const request = f.requests.find(entry => entry.method === 'POST' && entry.route === '/v1/issuance').data;
  for (const [name, value] of Object.entries(CUSTOMER_CLAIMS)) assert.equal(request.claims[name], value);
  assert.equal(request.organization_id, CUSTOMER_ORGANIZATION);
  assert.equal(request.claims.organization_id, CUSTOMER_ORGANIZATION);
  assert.equal(request.claims.member_id, 'synthetic-operator');
  assert.equal(request.claims.email, EMAIL);
  assert.equal(request.claims.role, 'applicant');
  assert.ok(Date.parse(request.claims.issued_at) >= started);
  assert.ok(Date.parse(request.claims.issued_at) <= Date.now());
  assert.deepEqual(result.receipt.scenarioClaims, CUSTOMER_CLAIMS);
  assert.equal(result.receipt.scenarioClaimsSha256, hash(JSON.stringify(CUSTOMER_CLAIMS)));
  const receipt = JSON.parse(fs.readFileSync(path.join(f.stateDir, 'accept-receipt.json'), 'utf8'));
  assert.deepEqual(receipt.scenarioClaims, CUSTOMER_CLAIMS);
  assert.equal(receipt.scenarioClaimsSha256, result.receipt.scenarioClaimsSha256);
  assert.equal(result.receipt.organizationId, CUSTOMER_ORGANIZATION);
  assert.equal(result.receipt.signatureVerified, true);
  assert.equal(result.receipt.holderBindingVerified, true);
  assert.equal(f.redemptions, 1);
});

test('customer resume binds the same claims independent of JSON formatting and performs no mutation', async t => {
  const f = fixture(t, CUSTOMER_ORGANIZATION);
  const accepted = await run(f, 'accept', ['--scenario-claims-file', SCENARIO_FILE]);
  assert.equal(accepted.code, 0, accepted.output);
  const alternate = path.join(path.dirname(f.stateDir), 'reformatted-scenario.json');
  fs.writeFileSync(alternate, JSON.stringify(Object.fromEntries(Object.entries(CUSTOMER_CLAIMS).reverse())));
  const requests = f.requests.length;
  const result = await run(f, 'resume', ['--scenario-claims-file', alternate]);
  assert.equal(result.code, 0, result.output);
  assert.deepEqual(result.receipt.scenarioClaims, accepted.receipt.scenarioClaims);
  assert.equal(result.receipt.scenarioClaimsSha256, accepted.receipt.scenarioClaimsSha256);
  assert.equal(f.redemptions, 1);
  assert.ok(f.requests.slice(requests).every(request => request.method === 'GET'));
});

for (const prohibited of ['organization_id', 'member_id', 'email', 'issued_at', 'role', 'issuer_did']) {
  test('scenario refuses a canonical claim override before browser/state/API: ' + prohibited, async t => {
    const f = fixture(t);
    const file = path.join(path.dirname(f.stateDir), 'invalid-scenario.json');
    fs.writeFileSync(file, JSON.stringify({ ...CUSTOMER_CLAIMS, [prohibited]: 'synthetic-override' }));
    const result = await run(f, 'accept', ['--scenario-claims-file', file]);
    assert.equal(result.code, 1);
    assert.equal(result.receipt.stage, 'scenario-claims');
    assert.equal(result.receipt.code, 'scenario_claims_invalid');
    assert.equal(f.launches, 0);
    assert.equal(f.requests.length, 0);
    assert.equal(f.redemptions, 0);
    assert.equal(fs.existsSync(f.stateDir), false);
    assert.equal(result.output.includes('synthetic-override'), false);
  });
}

for (const [name, value] of [
  ['empty object', {}], ['array', []], ['null', null],
  ['nested value', { given_name: { value: 'Avery' } }],
  ['empty text', { given_name: '   ' }],
  ['control character', { achievement_description: 'Synthetic\nnewline' }],
  ['oversized field', { achievement_description: 'x'.repeat(1025) }],
]) {
  test('scenario refuses invalid descriptive data before browser: ' + name, async t => {
    const f = fixture(t);
    const file = path.join(path.dirname(f.stateDir), 'invalid-scenario.json');
    fs.writeFileSync(file, JSON.stringify(value));
    const result = await run(f, 'accept', ['--scenario-claims-file', file]);
    assert.equal(result.code, 1);
    assert.equal(result.receipt.code, 'scenario_claims_invalid');
    assert.equal(f.launches, 0);
    assert.equal(f.requests.length, 0);
    assert.equal(fs.existsSync(f.stateDir), false);
  });
}

test('scenario bounds the entire file before browser or evidence creation', async t => {
  const f = fixture(t);
  const file = path.join(path.dirname(f.stateDir), 'large-scenario.json');
  fs.writeFileSync(file, ' '.repeat(8193));
  const result = await run(f, 'accept', ['--scenario-claims-file', file]);
  assert.equal(result.code, 1);
  assert.equal(result.receipt.code, 'scenario_file_invalid');
  assert.equal(f.launches, 0);
  assert.equal(fs.existsSync(f.stateDir), false);
});

for (const changed of ['changed', 'omitted', 'added', 'receipt']) {
  test('resume refuses ' + changed + ' scenario binding before browser or API', async t => {
    const f = fixture(t);
    const originalOptions = changed === 'added' ? [] : ['--scenario-claims-file', SCENARIO_FILE];
    assert.equal((await run(f, 'accept', originalOptions)).code, 0);
    let options = ['--scenario-claims-file', SCENARIO_FILE];
    if (changed === 'changed') {
      const file = path.join(path.dirname(f.stateDir), 'changed-scenario.json');
      fs.writeFileSync(file, JSON.stringify({ ...CUSTOMER_CLAIMS, organization_name: 'Another Academy' }));
      options = ['--scenario-claims-file', file];
    } else if (changed === 'omitted') options = [];
    else if (changed === 'receipt') {
      const file = path.join(f.stateDir, 'accept-receipt.json');
      const receipt = JSON.parse(fs.readFileSync(file));
      receipt.scenarioClaims.organization_name = 'Another Academy';
      fs.writeFileSync(file, JSON.stringify(receipt));
    }
    const requests = f.requests.length;
    const files = fs.readdirSync(f.stateDir);
    const result = await run(f, 'resume', options);
    assert.equal(result.code, 1);
    assert.equal(result.receipt.stage, 'state-scope');
    assert.equal(result.receipt.code, 'readback_scenario_changed');
    assert.equal(f.launches, 1);
    assert.equal(f.logins, 1);
    assert.equal(f.requests.length, requests);
    assert.equal(f.redemptions, 1);
    assert.deepEqual(fs.readdirSync(f.stateDir), files);
  });
}
