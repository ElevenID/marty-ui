'use strict';
const assert = require('node:assert/strict');
const test = require('node:test');
const { createOwnedActiveConfiguration, retireOwnedConfiguration } = require('./demo-owned-configuration');

function owned() {
  return { organizationId: 'org-one', runId: 'run-one', configuration: [
    { collectionPath: '/v1/credential-templates', id: 'credential-one', organizationId: 'org-one', name: 'Credential [run-one]' },
    { collectionPath: '/v1/flows/definitions', id: 'flow-one', organizationId: 'org-one', name: 'Flow [run-one]' },
  ] };
}

function transport(scope, { foreign = false, lostResponse = false, failedMutation = false } = {}) {
  const requests = [];
  const state = new Map(scope.configuration.map(resource => [resource.id, {
    id: resource.id, name: resource.name, organization_id: 'org-one', status: 'ACTIVE', trigger: { event: 'approval' },
  }]));
  if (foreign) state.get('credential-one').organization_id = 'other-org';
  const page = { async evaluate(_fn, request) {
    request = { ...request, ...request.requestOptions, method: request.requestOptions.method || 'GET' };
    requests.push(request);
    const id = request.requestPath.split('/').find(part => state.has(part));
    const resource = state.get(id);
    assert.ok(resource);
    if (request.method !== 'GET') {
      if (!failedMutation) resource.status = request.method === 'PATCH' ? 'DRAFT' : 'DEPRECATED';
      if (lostResponse) throw Error('Lost mutation response');
    }
    return { ok: true, status: 200, body: structuredClone(resource) };
  } };
  return { page, requests };
}

test('owned configuration proves all tenants before any retirement mutation', async () => {
  const scope = owned(), peer = transport(scope, { foreign: true });
  await assert.rejects(retireOwnedConfiguration(peer.page, scope));
  assert.ok(peer.requests.every(request => request.method === 'GET'));
});

test('owned configuration retains history and confirms retirement after a lost response', async () => {
  const scope = owned(), peer = transport(scope, { lostResponse: true });
  const result = await retireOwnedConfiguration(peer.page, scope);
  assert.equal(result.ok, true);
  assert.deepEqual(result.retired.map(r => r.status), ['DRAFT', 'DEPRECATED']);
  assert.ok(peer.requests.every(request => request.method !== 'DELETE'));
  const patch = peer.requests.find(request => request.method === 'PATCH');
  assert.deepEqual(JSON.parse(patch.body), { organization_id: 'org-one', trigger: null });
});

test('owned configuration rejects uncertain creation and unconfirmed retirement', async () => {
  const scope = owned(), peer = transport(scope, { failedMutation: true });
  await assert.rejects(retireOwnedConfiguration(peer.page, { ...scope, pendingConfigurationCreations: [{}] }), /uncertain/);
  assert.equal(peer.requests.length, 0);
  await assert.rejects(retireOwnedConfiguration(peer.page, scope), /not confirmed/);
});

test('a same-name existing configuration never transfers creation ownership', async () => {
  const scope = owned();
  let calls = 0;
  const page = { async evaluate() {
    calls++;
    return { ok: true, status: 200, body: [{ id: 'prior', name: 'Credential [run-one]', organization_id: 'org-one', status: 'ACTIVE' }] };
  } };
  await assert.rejects(createOwnedActiveConfiguration(page, scope, {
    collectionPath: '/v1/credential-templates', name: 'Credential', payload: {},
  }), /cannot acquire/);
  assert.equal(calls, 1);
  assert.equal(scope.configuration.length, 2);
});
