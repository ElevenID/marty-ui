'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
  DEFAULT_CREDENTIAL_RANKING_STRATEGY,
  cleanupApplicationCredential,
  compactObject,
  ensureActiveResource,
  requestedClaim,
  requireJson,
  safeErrorDetail,
  selectOrganization,
} = require('./beta-demo-resource-helpers');

test('requestedClaim emits the strict public presentation-policy DTO', () => {
  assert.equal(DEFAULT_CREDENTIAL_RANKING_STRATEGY, 'FRESHEST_FIRST');
  assert.deepEqual(requestedClaim('clearance_status', {
    displayName: 'Clearance status',
    equals: 'CLEARED',
  }), {
    claim_name: 'clearance_status',
    display_name: 'Clearance status',
    description: null,
    required: true,
    selective_disclosure: true,
    accept_derived: true,
    predicate_spec: null,
    constraints: [{
      claim_name: 'clearance_status',
      constraint_type: 'equals',
      value: 'CLEARED',
      description: null,
    }],
  });
});

function fakePage(responses) {
  const requests = [];
  return {
    requests,
    async evaluate(_callback, request) {
      requests.push(request);
      const response = responses.shift();
      if (!response) throw new Error(`Unexpected request to ${request.requestPath}`);
      return response;
    },
  };
}

test('compactObject removes only undefined values', () => {
  assert.deepEqual(compactObject({
    missing: undefined,
    empty: null,
    disabled: false,
    count: 0,
    text: '',
  }), {
    empty: null,
    disabled: false,
    count: 0,
    text: '',
  });
});

test('requireJson reports bounded validation detail without leaking secret fields', async () => {
  const page = fakePage([{
    ok: false,
    status: 422,
    body: {
      error: 'invalid_request',
      detail: [{ field: 'credential_payload_format', message: 'unsupported format' }],
      access_token: 'must-not-leak',
    },
  }]);

  await assert.rejects(
    () => requireJson(page, '/v1/resources', {}, 'Create resource'),
    (error) => {
      assert.match(error.message, /HTTP 422/);
      assert.match(error.message, /credential_payload_format/);
      assert.match(error.message, /unsupported format/);
      assert.doesNotMatch(error.message, /must-not-leak/);
      assert.match(error.message, /\[REDACTED\]/);
      return true;
    },
  );
});

test('safeErrorDetail bounds untrusted response strings', () => {
  const detail = safeErrorDetail({ message: `bad ${'x'.repeat(2000)}` });
  assert.ok(detail.length <= 1020);
  assert.doesNotMatch(detail, /[\r\n\t]/);
});

test('ensureActiveResource creates, validates, activates, and reloads one organization resource', async () => {
  const page = fakePage([
    { ok: true, status: 200, body: [] },
    { ok: true, status: 201, body: { id: 'resource/1', name: 'D-01', status: 'DRAFT' } },
    { ok: true, status: 200, body: { valid: true } },
    { ok: true, status: 200, body: { id: 'resource/1', name: 'D-01', status: 'ACTIVE' } },
    { ok: true, status: 200, body: { id: 'resource/1', name: 'D-01', status: 'ACTIVE' } },
  ]);

  const resource = await ensureActiveResource(page, {
    organizationId: 'org/a',
    collectionPath: '/v1/resources?kind=demo',
    name: 'D-01',
    payload: { name: 'D-01' },
    idempotencyKey: 'd01-resource-v1',
    validate: true,
  });

  assert.equal(resource.created, true);
  assert.deepEqual(page.requests, [
    {
      requestPath: '/v1/resources?kind=demo&organization_id=org%2Fa',
      requestOptions: {},
    },
    {
      requestPath: '/v1/resources?kind=demo',
      requestOptions: {
        method: 'POST',
        headers: { 'Idempotency-Key': 'd01-resource-v1' },
        body: JSON.stringify({ name: 'D-01' }),
      },
    },
    {
      requestPath: '/v1/resources?kind=demo/resource%2F1/validate',
      requestOptions: { method: 'POST' },
    },
    {
      requestPath: '/v1/resources?kind=demo/resource%2F1/activate',
      requestOptions: { method: 'POST' },
    },
    {
      requestPath: '/v1/resources?kind=demo/resource%2F1',
      requestOptions: {},
    },
  ]);
});

test('ensureActiveResource fails closed for duplicate or inactive resources', async () => {
  const duplicatePage = fakePage([{
    ok: true,
    status: 200,
    body: [
      { id: 'one', name: 'D-01', status: 'ACTIVE' },
      { id: 'two', name: 'D-01', status: 'ACTIVE' },
    ],
  }]);
  await assert.rejects(() => ensureActiveResource(duplicatePage, {
    organizationId: 'org-1',
    collectionPath: '/v1/resources',
    name: 'D-01',
    payload: {},
    idempotencyKey: 'd01-resource-v1',
  }), /Multiple resources/);

  const inactivePage = fakePage([
    { ok: true, status: 200, body: [{ id: 'one', name: 'D-01', status: 'SUSPENDED' }] },
    { ok: true, status: 200, body: { id: 'one', name: 'D-01', status: 'SUSPENDED' } },
  ]);
  await assert.rejects(() => ensureActiveResource(inactivePage, {
    organizationId: 'org-1',
    collectionPath: '/v1/resources',
    name: 'D-01',
    payload: {},
    idempotencyKey: 'd01-resource-v1',
  }), /is not active/);
});

test('cleanupApplicationCredential revokes and withdraws only named transaction records', async () => {
  const page = fakePage([
    { ok: true, status: 200, body: {} },
    { ok: true, status: 200, body: {} },
  ]);
  const result = await cleanupApplicationCredential(page, {
    organizationId: 'org/1',
    applicationId: 'application/1',
    credentialId: 'credential/1',
    reason: 'release qualification cleanup',
  });

  assert.deepEqual(result, { credentialRevoked: true, applicationWithdrawn: true });
  assert.deepEqual(page.requests, [
    {
      requestPath: '/v1/issued-credentials/credential%2F1/revoke',
      requestOptions: {
        method: 'POST',
        body: JSON.stringify({ reason: 'release qualification cleanup' }),
      },
    },
    {
      requestPath: '/v1/organizations/org%2F1/applicants/application%2F1/withdraw',
      requestOptions: {
        method: 'POST',
        body: JSON.stringify({ reason: 'release qualification cleanup' }),
      },
    },
  ]);
});

test('selectOrganization persists org mode before navigating and waits for UI restoration', async () => {
  const page = fakePage([
    {
      ok: true,
      status: 200,
      body: [{
        id: 'org/1',
        display_name: 'Release Audit',
        membership: { has_org_console_access: true },
      }],
    },
    {
      ok: true,
      status: 200,
      body: { last_view_mode: 'org_admin', last_active_org_id: 'org/1' },
    },
  ]);
  page.gotoCalls = [];
  page.waitCalls = [];
  page.goto = async (...args) => page.gotoCalls.push(args);
  page.waitForFunction = async (...args) => page.waitCalls.push(args);

  const selection = await selectOrganization(page, {
    organizationId: 'org/1',
    consoleOrigin: 'https://beta.example.test',
  });

  assert.deepEqual(selection, {
    ok: true,
    membershipsStatus: 200,
    targetName: 'Release Audit',
    activeOrgId: 'org/1',
  });
  assert.deepEqual(page.requests, [
    { requestPath: '/v1/organizations/mine', requestOptions: {} },
    {
      requestPath: '/v1/me/preferences',
      requestOptions: {
        method: 'PUT',
        body: JSON.stringify({
          last_view_mode: 'org_admin',
          last_active_org_id: 'org/1',
        }),
      },
    },
  ]);
  assert.deepEqual(page.gotoCalls, [[
    'https://beta.example.test/console/org',
    { waitUntil: 'domcontentloaded', timeout: 60_000 },
  ]]);
  assert.equal(page.waitCalls.length, 1);
  assert.equal(page.waitCalls[0][1], 'org/1');
  assert.deepEqual(page.waitCalls[0][2], { timeout: 60_000 });
});

test('selectOrganization fails closed without an eligible organization membership', async () => {
  const page = fakePage([{
    ok: true,
    status: 200,
    body: [{ id: 'org/1', membership: { has_org_console_access: false } }],
  }]);

  const selection = await selectOrganization(page, {
    organizationId: 'org/1',
    consoleOrigin: 'https://beta.example.test',
  });

  assert.deepEqual(selection, {
    ok: false,
    membershipsStatus: 200,
    targetName: null,
    activeOrgId: null,
  });
  assert.equal(page.requests.length, 1);
});
