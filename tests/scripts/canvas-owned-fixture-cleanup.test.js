'use strict';

// Transport safety controls only; these never qualify a Canvas demo.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const test = require('node:test');
const { requireCanvasExternalToolKey, findCanvasInventoryRecord, retireOwnedCanvasFixtures, retireCanvasApplication } = require('./canvas-owned-fixture-cleanup');

function fixture() {
  const runSuffix = 'owned-canvas-run-0001';
  const email = `learner+${crypto.createHash('sha256').update(runSuffix).digest('hex').slice(0, 16)}@marty.demo`;
  const owned = { scope: 'OWNED_CANVAS_SETUP_RESOURCES', runSuffix, learnerEmail: email,
    resources: { course: '10', learner: '20', externalTool: '30', ltiDeveloperKey: '40',
      oauthDeveloperKey: '50', learnerAccessToken: '60', adminAccessToken: '70', assignment: '80' } };
  const resources = new Map([
    ['/api/v1/courses/10', { id: 10, account_id: 1, name: `ElevenID OSS portability ${runSuffix}`, course_code: `OSS-${runSuffix}` }],
    ['/api/v1/accounts/1/external_tools/30', { id: 30, developer_key_id: 40 }],
    ['/api/v1/users/20/profile', { id: 20, primary_email: email, login_id: email, name: `Portable Learner ${runSuffix}` }],
    ['/api/v1/users/20/tokens/60', { id: 60, user_id: 20, purpose: `OSS contract learner ${runSuffix}` }],
    ['/api/v1/users/1/tokens/70', { id: 70, user_id: 1, purpose: `OSS contract admin ${runSuffix}` }],
  ]);
  const calls = [];
  let learnerRemoved = false;
  const client = name => ({ origin: 'https://canvas-test.elevenidllc.com', disabled: false,
    async request(method, path, options) {
      calls.push({ name, method, path, options });
      assert.equal(options.includeStatus, true);
      if (method === 'DELETE') {
        if (path.includes('/tokens/')) this.disabled = true;
        if (path === '/api/v1/accounts/1/users/20') learnerRemoved = true;
        resources.delete(path);
        return { status: 200, body: {} };
      }
      if (path === '/api/v1/users/self/profile' && this.disabled) return { status: 401, body: {} };
      if (path.startsWith('/api/v1/accounts/1/users?')) return { status: 200, body: learnerRemoved ? [] : [{ id: 20 }] };
      return resources.has(path) ? { status: 200, body: resources.get(path) } : { status: 404, body: {} };
    } });
  const input = { owned, runSuffix, canvasOrigin: 'https://canvas-test.elevenidllc.com', accountId: '1', adminId: '1',
    adminCanvas: client('admin'), learnerCanvas: client('learner'), retirementConfirmed: true, oauthDisconnected: true,
    developerKeys: {
      async identity({ id }) { return { id, binding: { developer_key_id: id, account_id: '1', account_owns_binding: true } }; },
      async check() { return true; }, async remove(key) { calls.push({ method: 'UI_DELETE', key }); },
    } };
  return { input, resources, calls };
}

test('owned fixture retirement verifies every target before mutations and revokes admin last', async () => {
  const { input, calls } = fixture();
  const result = await retireOwnedCanvasFixtures(input);
  assert.equal(result.complete, true);
  assert.equal(result.resources.length, Object.keys(input.owned.resources).length);
  const mutations = calls.filter(call => call.method === 'DELETE' || call.method === 'UI_DELETE');
  assert.equal(mutations.at(-1).path, '/api/v1/users/1/tokens/70');
  assert.equal(mutations.find(call => call.path === '/api/v1/courses/10').options.form.event, 'delete');
  assert.equal(result.resources.find(row => row.kind === 'assignment').state, 'RETIRED_WITH_COURSE');
});

for (const [name, change] of [
  ['foreign course account', f => { f.resources.get('/api/v1/courses/10').account_id = 2; }],
  ['renamed course', f => { f.resources.get('/api/v1/courses/10').name = 'Unowned course'; }],
  ['foreign learner', f => { f.resources.get('/api/v1/users/20/profile').primary_email = 'other@marty.demo'; }],
  ['foreign token purpose', f => { f.resources.get('/api/v1/users/20/tokens/60').purpose = 'Other run'; }],
  ['foreign tool key', f => { f.resources.get('/api/v1/accounts/1/external_tools/30').developer_key_id = 41; }],
  ['unknown resource kind', f => { f.input.owned.resources.globalAccount = '1'; }],
  ['unretired issuance', f => { f.input.retirementConfirmed = false; }],
  ['connected OAuth', f => { f.input.oauthDisconnected = false; }],
  ['changed run', f => { f.input.runSuffix = 'owned-canvas-run-0002'; }],
  ['foreign origin', f => { f.input.canvasOrigin = 'https://canvas.example.test'; }],
  ['administrator learner', f => { f.input.owned.resources.learner = '1'; }],
]) {
  test(`reject ${name} before deleting any fixture`, async () => {
    const f = fixture(); change(f);
    await assert.rejects(retireOwnedCanvasFixtures(f.input));
    assert.equal(f.calls.filter(call => call.method === 'DELETE' || call.method === 'UI_DELETE').length, 0);
  });
}

test('a denied key-custody check precedes all REST deletion', async () => {
  const f = fixture(); f.input.developerKeys.check = async () => { throw Error('Changed key'); };
  await assert.rejects(retireOwnedCanvasFixtures(f.input));
  assert.equal(f.calls.filter(call => call.method === 'DELETE').length, 0);
});

test('planning validates custody but neither mutates nor claims complete cleanup', async () => {
  const f = fixture();
  const result = await retireOwnedCanvasFixtures({ ...f.input, planOnly: true });
  assert.equal(result.complete, false);
  assert.equal(result.state, 'PLANNED_NOT_RETIRED');
  assert.equal(f.calls.filter(call => call.method === 'DELETE' || call.method === 'UI_DELETE').length, 0);
  assert.ok(!JSON.stringify(result).includes('disabled'));
});

test('stock local tool IDs join globally serialized client IDs only within their owned account shard', () => {
  const key = { id: '10000000000102', binding: { developer_key_id: '10000000000102',
    account_id: '10000000000001', account_owns_binding: true } };
  requireCanvasExternalToolKey('102', key, key.id, '1');
  requireCanvasExternalToolKey(key.id, key, key.id, '1');
  assert.throws(() => requireCanvasExternalToolKey('20000000000102', key, key.id, '1'));
  assert.throws(() => requireCanvasExternalToolKey('102', key, key.id, '2'));
  assert.throws(() => requireCanvasExternalToolKey('102', {
    ...key, binding: { ...key.binding, account_id: '20000000000001' },
  }, key.id, '1'));
});

test('removed account membership does not require erasing its surviving global user profile', async () => {
  const f = fixture();
  f.resources.get('/api/v1/users/20/profile').primary_email = null;
  const request = f.input.adminCanvas.request.bind(f.input.adminCanvas);
  f.input.adminCanvas.request = async (method, path, options) => path.startsWith('/api/v1/accounts/1/users?')
    ? { status: 200, body: [] } : request(method, path, options);
  const result = await retireOwnedCanvasFixtures(f.input);
  assert.equal(result.complete, true);
  assert.equal(result.resources.find(row => row.kind === 'learner').state, 'ALREADY_ABSENT');
  assert.ok(f.resources.has('/api/v1/users/20/profile'));
  assert.equal(f.calls.filter(call => call.method === 'DELETE' && call.path === '/api/v1/accounts/1/users/20').length, 0);
});

for (const link of [
  '<https://foreign.example/api/v1/accounts/1/users?page=2>; rel="next"',
  '<https://canvas-test.elevenidllc.com/api/v1/accounts/2/users?page=2>; rel="next"',
  '<https://canvas-test.elevenidllc.com/api/v1/accounts/1/users?per_page=100>; rel="next"',
]) {
  test(`an incomplete or foreign account inventory cannot prove absence: ${link}`, async () => {
    const client = { async request() { return { status: 200, body: [], link }; } };
    await assert.rejects(findCanvasInventoryRecord(client, 'https://canvas-test.elevenidllc.com',
      '/api/v1/accounts/1/users', user => user.id === 20));
  });
}

test('unknown approval outcome is retained without retiring a platform or credential', async () => {
  let calls = 0;
  await assert.rejects(retireCanvasApplication({ applicationId: 'a'.repeat(36),
    marty: { async get() { calls++; } }, reconcile() { throw Error('Unknown approval'); } }));
  assert.equal(calls, 0);
});

test('a foreign issued credential is never revoked', async () => {
  const id = value => `${value}0000000-0000-0000-0000-000000000000`;
  let revocations = 0;
  await assert.rejects(retireCanvasApplication({ organizationId: id('1'), applicationId: id('2'),
    credentialTemplateId: id('3'), transactionId: id('4'), marty: {
      async get() { return [{ application_id: id('2'), organization_id: id('9') }]; },
      async post() { revocations++; },
    } }));
  assert.equal(revocations, 0);
});

function applicationFixture() {
  const id = value => `${value}0000000-0000-0000-0000-000000000000`;
  const record = { credential_id: `urn:uuid:${id('5')}`, organization_id: id('1'),
    application_id: id('2'), credential_template_id: id('3'), flow_execution_id: id('4'), status: 'ACTIVE' };
  const review = { id: id('6'), organization_id: id('1'), application_id: id('2'),
    credential_id: record.credential_id, binding_id: id('7'), status: 'open' };
  const unrelated = { ...review, id: id('8'), application_id: id('9') };
  const state = { reviews: [review, unrelated], calls: [], record, retainReview: false };
  const input = { organizationId: id('1'), applicationId: id('2'), credentialTemplateId: id('3'),
    transactionId: id('4'), bindingId: id('7'), marty: {
      async get(route) {
        state.calls.push(['GET', route]);
        if (route.startsWith('/v1/issued-credentials?')) return [record];
        if (route.startsWith('/v1/integrations/canvas/evidence-policy-reviews?')) return state.reviews;
        assert.equal(route, `/v1/issued-credentials/${encodeURIComponent(record.credential_id)}`);
        return record;
      },
      async post(route, body) {
        state.calls.push(['POST', route, body]);
        const operation = record.status === 'REVOKED' ? 'reconcile-revocation' : 'resolve';
        record.status = 'REVOKED';
        if (route.endsWith('/resolve') || route.endsWith('/reconcile-revocation')) {
          assert.equal(route, `/v1/integrations/canvas/evidence-policy-reviews/${review.id}/${operation}`);
          assert.equal(body.action, 'revoke');
          if (!state.retainReview) state.reviews = state.reviews.filter(row => row.id !== review.id);
          return { ...review, status: 'revoked', resolution_action: 'revoke' };
        }
        return record;
      },
    } };
  return { state, input, review, unrelated };
}

test('failed capture retires its correction through the Rust lifecycle resolver and preserves unrelated reviews', async () => {
  const f = applicationFixture();
  const receipt = await retireCanvasApplication(f.input);
  assert.deepEqual(receipt.correctionReviewIds, [f.review.id]);
  assert.equal(receipt.complete, true);
  assert.deepEqual(f.state.reviews, [f.unrelated]);
  assert.equal(f.state.calls.filter(([method]) => method === 'POST').length, 1);
});

for (const [name, change] of [
  ['foreign review organization', f => { f.review.organization_id = 'foreign'; }],
  ['foreign review binding', f => { f.review.binding_id = 'foreign'; }],
  ['foreign review credential', f => { f.review.credential_id = 'foreign'; }],
  ['missing binding custody', f => { delete f.input.bindingId; }],
  ['duplicate open correction', f => { f.state.reviews.push({ ...f.review }); }],
  ['full bounded inventory', f => { f.state.reviews = Array(500).fill(f.unrelated); }],
  ['review without owned credential', f => {
    const get = f.input.marty.get;
    f.input.marty.get = route => route.startsWith('/v1/issued-credentials?') ? [] : get(route);
  }],
]) {
  test(`correction retirement rejects ${name} before any lifecycle mutation`, async () => {
    const f = applicationFixture(); change(f);
    await assert.rejects(retireCanvasApplication(f.input));
    assert.equal(f.state.calls.filter(([method]) => method === 'POST').length, 0);
  });
}

test('a successful resolver response cannot hide an open review in fresh inventory', async () => {
  const f = applicationFixture(); f.state.retainReview = true;
  await assert.rejects(retireCanvasApplication(f.input), /remains open/);
});

test('cleanup without an open review still revokes through the credential owner', async () => {
  const f = applicationFixture(); f.state.reviews = [f.unrelated];
  const receipt = await retireCanvasApplication(f.input);
  assert.deepEqual(receipt.correctionReviewIds, []);
  assert.equal(f.state.calls.find(([method]) => method === 'POST')[1],
    `/v1/issued-credentials/${encodeURIComponent(f.state.record.credential_id)}/revoke`);
});

test('repeated cleanup reconciles a revoked credential through the idempotent transaction owner', async () => {
  const f = applicationFixture(); f.state.reviews = [f.unrelated]; f.state.record.status = 'REVOKED';
  await retireCanvasApplication(f.input);
  assert.equal(f.state.calls.find(([method]) => method === 'POST')[1], `/v1/issuance/${f.input.transactionId}/revoke`);
});

test('an already revoked credential uses explicit review recovery without changing public resolve', async () => {
  const f = applicationFixture(); f.state.record.status = 'REVOKED';
  const receipt = await retireCanvasApplication(f.input);
  assert.equal(receipt.complete, true);
  assert.equal(f.state.calls.find(([method]) => method === 'POST')[1],
    `/v1/integrations/canvas/evidence-policy-reviews/${f.review.id}/reconcile-revocation`);
  assert.deepEqual(f.state.reviews, [f.unrelated]);
});
