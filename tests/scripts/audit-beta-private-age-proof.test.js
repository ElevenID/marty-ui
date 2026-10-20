const assert = require('node:assert/strict');
const test = require('node:test');
const { createAgeProofController } = require('./audit-beta-private-age-proof');

const expected = { run_id: 'run-1', organization_id: 'org-1', trusted_template_id: 'template-1',
  rejected_template_id: 'template-2', policy_id: 'policy-1', trust_profile_id: 'trust-1',
  service_origin: 'https://demo.example.test' };
const lane = 'eudi-age-proof-interoperability';
const okay = body => ({ status: 200, body });
const plan = {
  trusted_issuance: { method: 'POST', path: '/v1/issuance', body: { credential_template_id: 'template-1' } },
  rejected_issuance: { method: 'POST', path: '/v1/issuance', body: { credential_template_id: 'template-2' } },
  verification: { method: 'POST', path: '/v1/flows/verification/start', body: { organization_id: 'org-1' } },
  setup_sha256: 'a'.repeat(64),
};

function fixture({ onApi, onCheck, readRequest, page = {} } = {}) {
  const calls = [];
  const states = [];
  const controller = createAgeProofController({
    page, expected, syntheticClaims: { age_over_21: true },
    api: async (_page, route, options = {}) => {
      const call = { route, method: options.method || 'GET', body: options.body && JSON.parse(options.body) };
      calls.push(call);
      const reply = await onApi?.(call);
      if (reply !== undefined) return reply;
      return okay({ name: 'Fixture resource' });
    },
    check: (operation, bound, observed) => {
      assert.equal(bound, expected);
      const result = onCheck?.(operation, observed);
      if (result !== undefined) return result;
      if (operation === 'prepare') return plan;
      if (operation === 'cleanup') return { actions: [], pending_offers: observed.owned_issuance.map(item => item.id) };
      return {};
    },
    readRequest: readRequest || (async () => 'measured-request'),
    onState: state => states.push(state),
  });
  return { controller, calls, states };
}

test('D03 dependency reads fail before mutation and do not report an uncertain creation', async () => {
  const { controller, calls } = fixture({ onApi: call => {
    if (call.route.includes('credential-templates')) throw Error('Template unavailable');
  } });
  await assert.rejects(controller.preflight(), /Template unavailable/);
  assert.equal((await controller.cleanup()).ok, true);
  assert.deepEqual(controller.owned, { issuance: [], instances: [], uncertainMutations: [] });
  assert.equal(calls.filter(call => call.method !== 'GET').length, 0);
});

test('D03 retains an issuance ID before a lost verification creation response', async () => {
  const { controller, states } = fixture({ onApi: call => {
    if (call.route === '/v1/issuance') return okay({ id: 'transaction-1', organization_id: 'org-1', credential_template_id: 'template-1' });
    if (call.route === '/v1/flows/verification/start') throw Error('Lost creation response');
    if (call.route.startsWith('/v1/issued-credentials?')) return okay([]);
  } });
  await controller.preflight();
  await assert.rejects(controller.prepareLane(lane), /Lost creation response/);
  assert.equal(controller.owned.issuance[0].id, 'transaction-1');
  assert.equal(controller.owned.uncertainMutations.length, 1);
  assert.equal(states.at(-1).ownedResources.issuance[0].id, 'transaction-1');
  const cleanup = await controller.cleanup();
  assert.equal(cleanup.ok, false);
  assert.deepEqual(cleanup.pendingOffers, ['transaction-1']);
  assert.equal(cleanup.uncertainMutations[0].operation, `${lane}-trusted-verification`);
});

test('D03 never reports clean after a successful issuance response without its public ID', async () => {
  const { controller, calls } = fixture({ onApi: call => {
    if (call.route === '/v1/issuance') return okay({ transaction_id: 'legacy-or-unknown' });
  } });
  await controller.preflight();
  await assert.rejects(controller.prepareLane(lane), /no exact resource ID/);
  const cleanup = await controller.cleanup();
  assert.equal(cleanup.ok, false);
  assert.equal(cleanup.uncertainMutations.length, 1);
  assert.equal(calls.filter(call => call.method !== 'GET').length, 1);
});

test('D03 pending cleanup uses exact shared cancellation and retains unconfirmed outcomes', async () => {
  for (const confirmed of [true, false]) {
    const requests = [];
    let revoked = false;
    const page = { evaluate: async (_fn, request) => {
      requests.push(request);
      const { requestPath, requestOptions } = request;
      if (requestPath === '/v1/issued-credentials?organization_id=org-1') {
        return { ok: true, ...okay([{ id: 'unrelated-credential', organization_id: 'org-1', flow_execution_id: 'previous-run' }]) };
      }
      if (requestPath === '/v1/issuance/transaction-1/revoke') {
        assert.equal(requestOptions.method, 'POST');
        assert.deepEqual(JSON.parse(requestOptions.body), { reason: 'D03 current-run cleanup' });
        revoked = confirmed;
        // A successful mutation response alone cannot prove cleanup.
        return { ok: true, ...okay({ id: 'transaction-1', status: 'revoked' }) };
      }
      assert.equal(requestPath, '/v1/issuance/transaction-1?organization_id=org-1');
      return { ok: true, ...okay({ id: 'transaction-1', organization_id: 'org-1',
        credential_template_id: 'template-1', application_id: null, status: revoked ? 'revoked' : 'expired' }) };
    } };
    const { controller, states } = fixture({ page, onApi: call => {
      if (call.route === '/v1/issuance') return okay({ id: 'transaction-1', organization_id: 'org-1', credential_template_id: 'template-1' });
      if (call.route === '/v1/flows/verification/start') return { status: 409, body: { error: 'conflict' } };
      if (call.route.startsWith('/v1/issued-credentials?')) return okay([]);
    } });
    await controller.preflight();
    await assert.rejects(controller.prepareLane(lane), /HTTP 409/);
    const cleanup = await controller.cleanup();
    const uncertainty = confirmed ? [] : [{ operation: 'transaction_cancellation', transactionId: 'transaction-1' }];
    assert.equal(cleanup.ok, confirmed);
    assert.deepEqual(cleanup.pendingOffers, confirmed ? [] : ['transaction-1']);
    assert.deepEqual(cleanup.uncertainMutations, uncertainty);
    assert.deepEqual(states.at(-1).ownedResources.uncertainMutations, uncertainty);
    assert.equal(cleanup.actions[0].id, 'transaction-1');
    assert.equal(cleanup.actions[0].ok, confirmed);
    assert.equal(cleanup.actions[0].cancellation.scope, 'TRANSACTION_CANCELLATION_ONLY');
    assert.deepEqual(requests.map(({ requestPath, requestOptions }) => [requestOptions.method || 'GET', requestPath]), [
      ['GET', '/v1/issuance/transaction-1?organization_id=org-1'],
      ['GET', '/v1/issued-credentials?organization_id=org-1'],
      ['POST', '/v1/issuance/transaction-1/revoke'],
      ['GET', '/v1/issuance/transaction-1?organization_id=org-1'],
    ]);
  }
});

test('D03 retains both exact IDs before request inspection fails and cleans only those resources', async () => {
  const { controller, calls } = fixture({
    readRequest: async () => { throw Error('Signed request missing'); },
    onApi: call => {
      if (call.route === '/v1/issuance') return okay({ id: 'transaction-1', organization_id: 'org-1', credential_template_id: 'template-1' });
      if (call.route === '/v1/flows/verification/start') return okay({ instance_id: 'instance-1' });
      if (call.route.startsWith('/v1/issued-credentials?')) return okay([
        { id: 'owned-credential', flow_execution_id: 'transaction-1' },
        { id: 'unrelated-credential', flow_execution_id: 'old-transaction' },
      ]);
      if (call.route === '/v1/issued-credentials/owned-credential') return okay({ id: 'owned-credential', organization_id: 'org-1', status: 'REVOKED' });
      if (call.route === '/v1/flows/instances/instance-1') return okay({ id: 'instance-1', organization_id: 'org-1', status: 'CANCELLED' });
    },
    onCheck: (operation, observed) => {
      if (operation !== 'cleanup') return;
      assert.deepEqual(observed.owned_issuance.map(item => item.id), ['transaction-1']);
      assert.deepEqual(observed.owned_instances.map(item => item.id), ['instance-1']);
      return { pending_offers: [], actions: [
        { resource: 'credential', id: 'owned-credential', method: 'POST', path: '/v1/issued-credentials/owned-credential/revoke', body: {}, expected_status: 'REVOKED' },
        { resource: 'instance', id: 'instance-1', method: 'POST', path: '/v1/flows/instances/instance-1/cancel', body: {}, expected_status: 'CANCELLED' },
      ] };
    },
  });
  await controller.preflight();
  await assert.rejects(controller.prepareLane(lane), /Signed request missing/);
  assert.deepEqual(controller.owned.instances.map(item => item.id), ['instance-1']);
  assert.equal(controller.owned.uncertainMutations.length, 0);
  const cleanup = await controller.cleanup();
  assert.equal(cleanup.ok, true);
  assert.deepEqual(calls.filter(call => call.method === 'POST').map(call => call.route), [
    '/v1/issuance', '/v1/flows/verification/start',
    '/v1/issued-credentials/owned-credential/revoke', '/v1/flows/instances/instance-1/cancel',
  ]);
  await assert.rejects(controller.prepareLane(lane), /duplicated/);
});

test('D03 proven request rejection leaves no uncertain mutation', async () => {
  const { controller } = fixture({ onApi: call => {
    if (call.route === '/v1/issuance') return { status: 409, body: { error: 'conflict' } };
  } });
  await controller.preflight();
  await assert.rejects(controller.prepareLane(lane), /HTTP 409/);
  assert.equal((await controller.cleanup()).ok, true);
  assert.deepEqual(controller.owned.issuance, []);
});

test('D03 Rust ownership rejection prevents every cleanup mutation', async () => {
  const { controller, calls } = fixture({
    onApi: call => {
      if (call.route === '/v1/issuance') return okay({ id: 'transaction-1', organization_id: 'other-org', credential_template_id: 'template-1' });
      if (call.route.startsWith('/v1/issued-credentials?')) return okay([{ id: 'foreign-record' }]);
    },
    onCheck: operation => { if (operation === 'cleanup') throw Error('Inventory crossed organization boundary'); },
  });
  await controller.preflight();
  await assert.rejects(controller.prepareLane(lane), /organization or template boundary/);
  const cleanup = await controller.cleanup();
  assert.equal(cleanup.ok, false);
  assert.match(cleanup.errors[0], /organization boundary/);
  assert.equal(calls.filter(call => call.method !== 'GET').length, 1);
});

test('D03 generic rejection diagnostics cannot become the issuer-trust assertion', async () => {
  const { controller } = fixture({ onCheck: operation => {
    if (operation === 'denied') return { observation: 'UNTRUSTED_FIXTURE_REJECTED', issuer_trust_denial_observed: false };
  } });
  const item = templateId => ({ templateId, instanceId: 'instance-1', issuanceReply: okay({}), requestBinding: {} });
  await assert.rejects(controller.completeLane(lane, { trusted: item('template-1'), rejected: item('template-2') }, {
    report: {}, rejectionText: 'Presentation failed', scenarioSha256: 'f'.repeat(64), denialActionIndex: 1,
  }), /BLOCKED: generic wallet rejection/);
  assert.deepEqual(controller.laneResults, []);
});
