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
const PASSWORD = 'synthetic-only-operator-password';
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
    requests: [], protocol: [], launches: 0, logins: 0, closes: 0, redemptions: 0, identities: [],
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
      return apiResponse(200, { authenticated: true, user: { user_id: 'synthetic-operator', email: EMAIL } });
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
          credentialSubject: { id: proof.iss, achievement: { id: VCT } } } };
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
  const processBoundary = { argv: ['node', DRIVER, '--phase', phase, '--origin', ORIGIN,
    '--issuer-did', ISSUER, '--organization-id', f.organizationId,
    '--password-file', f.passwordFile, '--state-dir', f.stateDir, ...extraOptions],
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
  assert.equal(f.closes, 1);
  assert.equal(f.redemptions, 1);
  assert.equal(f.requests.filter(request => request.method === 'POST' && request.route === '/v1/issuance').length, 1);
  assert.equal(fs.statSync(f.stateDir).mode & 0o777, 0o700);
  for (const name of fs.readdirSync(f.stateDir)) {
    assert.equal(fs.statSync(path.join(f.stateDir, name)).mode & 0o777, 0o600);
  }
  const stored = JSON.parse(fs.readFileSync(path.join(f.stateDir, 'credential-private.json')));
  assert.equal(hash(stored.credential), result.receipt.credentialSha256);
  for (const privateValue of [PASSWORD, stored.credential, 'synthetic-pre-authorized-code']) {
    assert.equal(result.output.includes(privateValue), false);
  }
});

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
