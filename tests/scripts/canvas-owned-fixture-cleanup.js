'use strict';

// Stock Canvas transport only. Rust remains the authority for credential
// retirement; callers must prove that before removing these external fixtures.
// API contracts: developerdocs.instructure.com/services/canvas/resources/
// courses, accounts, external_tools and access_tokens. LTI registrations are
// removed through the stock Developer Keys UI, never an API-key-only shortcut.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const ID = /^[1-9][0-9]*$/;
const TYPES = new Set(['adminAccessToken', 'ltiDeveloperKey', 'externalTool', 'learner',
  'course', 'assignment', 'quiz', 'question', 'module', 'learnerAccessToken',
  'oauthDeveloperKey', 'externalAssignment']);

function same(actual, expected, label) {
  assert.equal(String(actual), String(expected), `Canvas cleanup ${label} mismatch`);
}

function requireOwnedLedger(owned, runSuffix) {
  assert.equal(owned?.scope, 'OWNED_CANVAS_SETUP_RESOURCES');
  assert.match(runSuffix || '', /^[A-Za-z0-9-]{8,100}$/);
  same(owned.runSuffix, runSuffix, 'run');
  assert.ok(owned.resources && !Array.isArray(owned.resources));
  for (const [kind, id] of Object.entries(owned.resources)) {
    assert.ok(TYPES.has(kind), 'Unknown Canvas resource needs explicit retirement');
    assert.match(String(id), ID);
  }
  const email = /^([a-z0-9._-]+)\+([a-f0-9]{16})@(marty\.demo|[a-z0-9.-]+\.test)$/i.exec(owned.learnerEmail || '');
  assert.ok(email, 'Canvas cleanup requires a run-owned synthetic learner');
  same(email[2], crypto.createHash('sha256').update(runSuffix).digest('hex').slice(0, 16), 'learner nonce');
  if (['assignment', 'quiz', 'question', 'module', 'externalAssignment'].some(kind => owned.resources[kind])) {
    assert.ok(owned.resources.course, 'Canvas child resources lack an owned course');
  }
}

function requireCanvasExternalToolKey(toolKey, key, expectedKey, accountId) {
  same(key?.id, expectedKey, 'developer key metadata');
  const binding = key?.binding;
  assert.equal(binding?.account_owns_binding, true, 'Canvas account does not own the key');
  same(binding.developer_key_id, key.id, 'developer key binding');
  const numeric = value => {
    if (typeof value === 'number') assert.ok(Number.isSafeInteger(value));
    assert.match(String(value), ID);
    return BigInt(value);
  };
  const declared = numeric(key.id), actual = numeric(toolKey);
  const boundAccount = numeric(binding.account_id), account = numeric(accountId);
  if (declared === actual && boundAccount === account) return;
  // The running stock image's Switchman 4.2.4 Shard::IDS_PER_SHARD. Canvas
  // serializes Developer Keys globally but external_tools.developer_key_id
  // locally. Join only within the same observed account shard, never by a
  // suffix/substr comparison that could accept a foreign global client ID.
  const perShard = 10_000_000_000_000n;
  const shard = declared / perShard;
  assert.ok(shard > 0n && boundAccount / perShard === shard, 'Canvas key/account shard mismatch');
  assert.ok(actual === declared || (actual < perShard && actual === declared % perShard), 'Canvas external tool key mismatch');
  assert.ok(account === boundAccount || (account < perShard && account === boundAccount % perShard), 'Canvas bound account mismatch');
}

async function observed(client, method, path, form) {
  const result = await client.request(method, path, {
    expected: [200, 204, 404], includeStatus: true, ...(form ? { form } : {}),
  });
  assert.ok([200, 204, 404].includes(result?.status), 'Canvas cleanup requires an observed HTTP result');
  return result;
}

async function findCanvasInventoryRecord(client, origin, collection, match) {
  let next = `${collection}?per_page=100`;
  const seen = new Set();
  while (next) {
    assert.ok(!seen.has(next) && seen.size < 100, 'Canvas inventory pagination is incomplete');
    seen.add(next);
    const response = await observed(client, 'GET', next);
    assert.equal(response.status, 200);
    assert.ok(Array.isArray(response.body), 'Canvas inventory is not an array');
    const found = response.body.find(match);
    if (found) return found;
    const link = /<([^>]+)>;\s*rel="next"/.exec(response.link || '');
    if (!link) return null;
    const url = new URL(link[1], origin);
    assert.equal(url.origin, origin);
    assert.equal(url.pathname, collection);
    next = url.pathname + url.search;
  }
  return null;
}

async function retireOwnedCanvasFixtures({ owned, runSuffix, canvasOrigin, accountId, adminId,
  adminCanvas, learnerCanvas, adminTokenCanvas = adminCanvas, learnerTokenCanvas = learnerCanvas,
  retirementConfirmed, oauthDisconnected, developerKeys, planOnly = false }) {
  requireOwnedLedger(owned, runSuffix);
  assert.equal(canvasOrigin, 'https://canvas-test.elevenidllc.com');
  assert.equal(adminCanvas?.origin, canvasOrigin);
  assert.match(String(accountId), ID);
  assert.match(String(adminId), ID);
  assert.equal(retirementConfirmed, true, 'Marty retirement must complete before Canvas cleanup');
  assert.equal(oauthDisconnected, true, 'Marty OAuth must disconnect before Canvas cleanup');
  const ids = owned.resources;
  if (ids.learner) assert.notEqual(String(ids.learner), String(adminId), 'Never delete the Canvas administrator');
  const report = { scope: 'OWNED_CANVAS_FIXTURE_RETIREMENT', runSuffix, complete: false, resources: [] };
  const plans = [];
  const add = async (kind, client, path, validate, form, deletePath = path) => {
    if (!ids[kind]) return;
    const current = await observed(client, 'GET', path);
    if (current.status === 404) {
      report.resources.push({ kind, id: String(ids[kind]), state: 'ALREADY_ABSENT' });
      return;
    }
    assert.equal(current.status, 200);
    same(current.body?.id, ids[kind], kind);
    await validate(current.body);
    plans.push({ kind, client, path: deletePath, form });
  };
  // Validate every target before the first mutation. In particular, a changed
  // learner/key must not be discovered after deleting an otherwise valid course.
  await add('course', adminCanvas, `/api/v1/courses/${ids.course}`, course => {
    same(course.account_id, accountId, 'course account');
    same(course.name, `ElevenID OSS portability ${runSuffix}`, 'course name');
    same(course.course_code, `OSS-${runSuffix}`, 'course code');
  }, { event: 'delete' });
  await add('externalTool', adminCanvas, `/api/v1/accounts/${accountId}/external_tools/${ids.externalTool}`, async tool => {
    assert.ok(developerKeys?.identity, 'Canvas external tool requires its observed key/account binding');
    requireCanvasExternalToolKey(tool.developer_key_id,
      await developerKeys.identity({ id: String(ids.ltiDeveloperKey), name: `Marty LTI ${runSuffix}` }),
      ids.ltiDeveloperKey, accountId);
  });
  const accountUser = () => findCanvasInventoryRecord(adminCanvas, canvasOrigin,
    `/api/v1/accounts/${accountId}/users`, user => String(user.id) === String(ids.learner));
  if (ids.learner) {
    if (!(await accountUser())) report.resources.push({ kind: 'learner', id: String(ids.learner), state: 'ALREADY_ABSENT' });
    else await add('learner', adminCanvas, `/api/v1/users/${ids.learner}/profile`, user => {
      same(user.primary_email, owned.learnerEmail, 'learner email');
      if (user.login_id != null) same(user.login_id, owned.learnerEmail, 'learner login');
      same(user.name, `Portable Learner ${runSuffix}`, 'learner name');
    }, undefined, `/api/v1/accounts/${accountId}/users/${ids.learner}`);
  }
  for (const [kind, userId, client, purpose] of [
    ['learnerAccessToken', ids.learner, learnerTokenCanvas, `OSS contract learner ${runSuffix}`],
    ['adminAccessToken', adminId, adminTokenCanvas, `OSS contract admin ${runSuffix}`],
  ]) {
    if (!ids[kind]) continue;
    assert.ok(userId && client, 'Canvas token custody requires its owning user transport');
    assert.equal(client.origin, canvasOrigin);
    await add(kind, client, `/api/v1/users/${userId}/tokens/${ids[kind]}`, token => {
      same(token.user_id, userId, 'token owner');
      same(token.purpose, purpose, 'token purpose');
    });
  }
  const keys = [['ltiDeveloperKey', `Marty LTI ${runSuffix}`], ['oauthDeveloperKey', `Marty OAuth ${runSuffix}`]]
    .filter(([kind]) => ids[kind]);
  const presentKeys = [];
  for (const [kind, name] of keys) {
    assert.ok(developerKeys?.check && developerKeys?.remove, 'Canvas keys require stock UI custody');
    const present = await developerKeys.check({ id: String(ids[kind]), name });
    assert.equal(typeof present, 'boolean', 'Canvas key custody requires a complete current inventory');
    if (present) presentKeys.push([kind, name]);
    else report.resources.push({ kind, id: String(ids[kind]), state: 'ALREADY_ABSENT' });
  }
  if (planOnly) return { ...report, state: 'PLANNED_NOT_RETIRED', targets: [
    ...plans.map(({ kind }) => ({ kind, id: String(ids[kind]) })),
    ...presentKeys.map(([kind]) => ({ kind, id: String(ids[kind]) })),
  ] };
  // Tokens are revoked while their owning user still exists. The administrator
  // token remains usable until all other REST operations finish.
  const order = ['learnerAccessToken', 'course', 'externalTool', 'learner'];
  for (const kind of order) {
    const plan = plans.find(item => item.kind === kind);
    if (!plan) continue;
    await observed(plan.client, 'DELETE', plan.path, plan.form);
    const readback = kind === 'learnerAccessToken'
      ? await plan.client.request('GET', plan.path, { expected: [200, 401, 404], includeStatus: true })
      : kind === 'learner'
        ? await accountUser()
        : await observed(plan.client, 'GET', plan.path);
    if (kind === 'learner') {
      assert.equal(readback, null, 'Canvas learner still belongs to the account');
    } else if (kind === 'learnerAccessToken') {
      assert.ok([401, 404].includes(readback.status)
        || (readback.status === 200 && readback.body?.workflow_state === 'deleted'),
      'Canvas learner token is still usable');
    } else {
      assert.equal(readback.status, 404, 'Canvas retirement requires a fresh terminal readback');
    }
    report.resources.push({ kind, id: String(ids[kind]), state: 'RETIRED' });
  }
  for (const [kind, name] of presentKeys) {
    await developerKeys.remove({ id: String(ids[kind]), name });
    report.resources.push({ kind, id: String(ids[kind]), state: 'RETIRED' });
  }
  const adminToken = plans.find(item => item.kind === 'adminAccessToken');
  if (adminToken) {
    await observed(adminToken.client, 'DELETE', adminToken.path);
    const readback = await adminToken.client.request('GET', adminToken.path, { expected: [200, 401, 404], includeStatus: true });
    assert.ok([401, 404].includes(readback.status)
      || (readback.status === 200 && readback.body?.workflow_state === 'deleted'),
    'Canvas administrator token is still usable');
    report.resources.push({ kind: 'adminAccessToken', id: String(ids.adminAccessToken), state: 'RETIRED' });
  }
  for (const kind of ['assignment', 'quiz', 'question', 'module', 'externalAssignment']) {
    if (ids[kind]) report.resources.push({ kind, id: String(ids[kind]), state: 'RETIRED_WITH_COURSE', parentId: String(ids.course) });
  }
  report.complete = true;
  return report;
}

async function retireCanvasApplication({ marty, organizationId, applicationId,
  credentialTemplateId, transactionId, bindingId, reconcile = () => {} }) {
  reconcile();
  if (!applicationId) return;
  for (const id of [organizationId, applicationId, credentialTemplateId]) {
    assert.match(id || '', /^[a-f0-9-]{36}$/i);
  }
  const enc = encodeURIComponent;
  const records = await marty.get(`/v1/issued-credentials?organization_id=${enc(organizationId)}`);
  assert.ok(Array.isArray(records));
  const owned = records.filter(record => record.application_id === applicationId);
  assert.ok(owned.length <= 1, 'Canvas application has duplicate credential custody');
  // Validate all credential custody before touching either lifecycle or reviews.
  for (const record of owned) {
    assert.match(transactionId || '', /^[a-f0-9-]{36}$/i);
    same(record.organization_id, organizationId, 'credential organization');
    same(record.credential_template_id, credentialTemplateId, 'credential template');
    same(record.flow_execution_id, transactionId, 'credential transaction');
    const id = record.credential_id || record.id;
    assert.ok(typeof id === 'string' && id.length > 0);
  }
  const reviewsPath = `/v1/integrations/canvas/evidence-policy-reviews?organization_id=${enc(organizationId)}&status=open&limit=500`;
  const openReviews = async () => {
    const reviews = await marty.get(reviewsPath);
    // The production collection is bounded, without pagination. A full page
    // cannot prove absence; retain custody for an operator instead of guessing.
    assert.ok(Array.isArray(reviews) && reviews.length < 500, 'Canvas correction inventory is incomplete');
    for (const review of reviews) {
      same(review.organization_id, organizationId, 'review organization');
      assert.equal(review.status, 'open');
    }
    return reviews.filter(review => review.application_id === applicationId);
  };
  const reviews = await openReviews();
  assert.ok(reviews.length <= 1, 'Canvas application has duplicate open correction reviews');
  for (const review of reviews) {
    assert.match(review.id || '', /^[a-f0-9-]{36}$/i);
    assert.match(bindingId || '', /^[a-f0-9-]{36}$/i);
    same(review.binding_id, bindingId, 'review binding');
    assert.equal(owned.length, 1, 'Canvas correction lacks an owned issued credential');
    same(review.credential_id, owned[0].credential_id || owned[0].id, 'review credential');
  }
  for (const review of reviews) {
    // Existing Rust resolver owns both the credential lifecycle transition and
    // the durable review disposition/audit event. Never dismiss a failure or
    // edit queue rows directly merely to make cleanup appear successful.
    const operation = String(owned[0].status).toUpperCase() === 'REVOKED'
      ? 'reconcile-revocation' : 'resolve';
    const result = await marty.post(`/v1/integrations/canvas/evidence-policy-reviews/${enc(review.id)}/${operation}`,
      { action: 'revoke', note: 'Run-owned Canvas capture cleanup' }, [200]);
    for (const field of ['id', 'organization_id', 'application_id', 'credential_id', 'binding_id']) {
      same(result[field], review[field], `resolved review ${field}`);
    }
    assert.equal(result.status, 'revoked');
    assert.equal(result.resolution_action, 'revoke');
  }
  for (const record of owned) {
    const id = record.credential_id || record.id;
    if (!reviews.length) {
      // Public credential revocation deliberately rejects AlreadyRevoked. The
      // transaction owner provides idempotent publication/Canvas recovery.
      const route = String(record.status).toUpperCase() === 'REVOKED'
        ? `/v1/issuance/${enc(transactionId)}/revoke`
        : `/v1/issued-credentials/${enc(id)}/revoke`;
      await marty.post(route, { reason: 'Run-owned Canvas capture cleanup' }, [200]);
    }
    const current = await marty.get(`/v1/issued-credentials/${enc(id)}`);
    same(current.organization_id, organizationId, 'retired credential organization');
    same(current.application_id, applicationId, 'retired credential application');
    same(current.credential_id || current.id, id, 'retired credential');
    same(current.credential_template_id, credentialTemplateId, 'retired credential template');
    same(current.flow_execution_id, transactionId, 'retired credential transaction');
    assert.equal(String(current.status).toUpperCase(), 'REVOKED');
  }
  if (!owned.length && transactionId) {
    assert.match(transactionId, /^[a-f0-9-]{36}$/i);
    const path = `/v1/issuance/${enc(transactionId)}`;
    const scoped = `${path}?organization_id=${enc(organizationId)}`;
    const exact = transaction => {
      same(transaction.id, transactionId, 'transaction');
      same(transaction.application_id, applicationId, 'transaction application');
      same(transaction.organization_id, organizationId, 'transaction organization');
      same(transaction.credential_template_id, credentialTemplateId, 'transaction template');
      assert.ok(!transaction.issued_at, 'Canvas transaction already issued');
    };
    exact(await marty.get(scoped));
    await marty.post(`${path}/revoke`, { reason: 'Run-owned Canvas capture cleanup' }, [200]);
    const current = await marty.get(scoped);
    exact(current);
    assert.equal(String(current.status).toLowerCase(), 'revoked');
  }
  assert.equal((await openReviews()).length, 0, 'Canvas correction review remains open after retirement');
  return { scope: 'OWNED_CANVAS_APPLICATION_RETIREMENT', applicationId,
    credentialIds: owned.map(record => record.credential_id || record.id),
    correctionReviewIds: reviews.map(review => review.id), complete: true };
}

module.exports = { requireOwnedLedger, requireCanvasExternalToolKey, findCanvasInventoryRecord,
  retireOwnedCanvasFixtures, retireCanvasApplication };
