'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
  cleanupApplicationCredential,
  compactObject,
  ensureActiveResource,
} = require('./beta-demo-resource-helpers');

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
