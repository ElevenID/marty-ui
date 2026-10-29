'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const {
  GRANT, assertions, awaitNaturalExpiry, expiryWindow, loginInstanceBinding, nativeLoginResult,
  validateFixture, validateIssuerSetup, validateLoginSetup,
} = require('./beta-membership-support-contract');
const { createSupportController, guards, main, prepareFixture,startLogin } = require('./audit-beta-membership-support');

const uuid = (n) => `10000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const ORIGIN = 'https://service.example.test';
const VCT = `${ORIGIN}/credentials/member`;
const NOW = Date.parse('2026-10-20T00:00:00Z');
function fixture() {
  const trusted = { organizationId: uuid(1), credentialTemplateId: uuid(2), applicationTemplateId: uuid(3),
    trustProfileId: uuid(4), issuerEntityId: uuid(5), issuerDid: 'did:web:trusted.example.test',
    credentialFormat: 'VC_JWT', credentialConfigurationId: 'open_badge' };
  return { schemaVersion: 1, kind: 'membership-support-fixture', synthetic: true,
    authorization: 'PREPROVISIONED_DEMO_FIXTURE',
    applicant: { id: uuid(6), email: 'member@example.test', formData: { email: 'member@example.test', role: 'applicant' } },
    trusted,
    foreign: { ...trusted, credentialTemplateId: uuid(12), applicationTemplateId: uuid(13),
      trustProfileId: uuid(14), issuerEntityId: uuid(15), issuerDid: 'did:web:foreign.example.test' },
    login: { organizationId: uuid(1), presentationPolicyId: uuid(7), trustProfileId: uuid(4),
      verifierDid: 'did:web:verifier.example.test', vct: VCT },
    expiry: { isolatedDeployment: true, expectedServerOfferTtlSeconds: 60, maximumWaitSeconds: 120 } };
}

function issuerSetup(binding) {
  return {
    credential: { id: binding.credentialTemplateId, organization_id: binding.organizationId, status: 'ACTIVE',
      issuer_did: binding.issuerDid, trust_profile_id: binding.trustProfileId, vct: VCT,
      credential_type: 'open_badge', credential_payload_format: 'VC_JWT', supported_formats: ['VC_JWT'],
      issuer_algorithm: 'ES256', revocation_profile_id: uuid(8), claims: [{ name: 'email', type: 'string' }] },
    application: { id: binding.applicationTemplateId, organization_id: binding.organizationId, status: 'ACTIVE',
      credential_template_id: binding.credentialTemplateId, approval_strategy: 'MANUAL', required_checks: [], evidence_requirements: [] },
    trust: { id: binding.trustProfileId, organization_id: binding.organizationId, status: 'ACTIVE',
      allowed_issuers: [binding.issuerDid], denied_issuers: [], trust_sources: [], system_issuer_overrides: {} },
    // Exact native identity_projection shape: no invented internal profile ID.
    identities: { identities: [{ issuer_did: binding.issuerDid, key_purpose: 'vc_jwt_issuer',
      credential_format: 'VC_JWT', algorithm: 'ES256', status: 'active' }] },
    issuers: [{ id: binding.issuerEntityId, organization_id: binding.organizationId, issuer_id: binding.issuerDid,
      is_system_issuer: false, metadata: { verification_keys: [{ kty: 'EC', crv: 'P-256', x: 'public-x', y: 'public-y' }] } }],
    relationships: [{ id: uuid(9), trust_profile_id: binding.trustProfileId, issuer_id: binding.issuerEntityId, relationship_status: 'TRUSTED' }],
    revocation: { id: uuid(8), organization_id: binding.organizationId, status: 'ACTIVE' },
  };
}

function loginSetup(f) {
  const issuer = issuerSetup(f.trusted);
  return { trust: issuer.trust, relationships: issuer.relationships, issuers: issuer.issuers,
    policy: { id: f.login.presentationPolicyId, organization_id: f.login.organizationId, status: 'ACTIVE',
      trust_profile_id: f.login.trustProfileId, alternative_requirements: [], credential_requirements: [{
        credential_template_id: f.trusted.credentialTemplateId, required: true, credential_payload_format: 'VC_JWT',
        trust_profile_id: null, requested_claims: [{ claim_name: 'email', required: true }],
      }] } };
}

function fakeService(f = fixture(), options = {}) {
  const requests = []; const applications = []; const transactions = []; const credentials = [];
  const offers = new Map();
  const setups = [issuerSetup(f.trusted), issuerSetup(f.foreign)];
  const login = loginSetup(f);
  const reply = (body, status = 200) => ({ ok: status >= 200 && status < 300, status, body });
  const endpoint = async ({ requestPath, requestOptions }) => {
    const method = requestOptions.method || 'GET'; requests.push({ path: requestPath, method, body: requestOptions.body });
    const route = new URL(requestPath, ORIGIN).pathname;
    if (options.fail && options.fail({ route, method, applications, transactions })) throw new Error('Lost public response');
    if (route === '/v1/organizations/mine') return reply([{ id: f.trusted.organizationId, membership: { has_org_console_access: true } }]);
    if (route === '/v1/me/applicant-profile') return reply({ id: f.applicant.id, email: f.applicant.email });
    for (const setup of setups) {
      for (const [collection, field] of [['credential-templates', 'credential'], ['application-templates', 'application'], ['trust-profiles', 'trust']]) {
        if (route === `/v1/${collection}/${setup[field].id}`) return reply(setup[field]);
      }
      if (route === `/v1/trust-profiles/${setup.trust.id}/issuers`) return reply(setup.relationships);
    }
    if (route === '/v1/signing-keys/issuer-identities') return reply({ identities: setups.flatMap((item) => item.identities.identities) });
    if (route === '/v1/issuer-entities') return reply(setups.flatMap((item) => item.issuers));
    if (route === '/v1/revocation-profiles') return reply([setups[0].revocation]);
    if (route === `/v1/presentation-policies/${f.login.presentationPolicyId}`) return reply(login.policy);
    if (route === '/v1/signing-keys/config') return reply({ default_service_id: uuid(19), format_defaults: {}, type_defaults: {} });
    if (route.startsWith('/.well-known/openid-credential-issuer/org/')) return reply({ credential_issuer: `${ORIGIN}/org/${f.trusted.organizationId}` });
    if (route === '/v1/me/applications' && method === 'GET') return reply({ items: applications, total: applications.length, offset: 0, limit: 500 });
    if (route === '/v1/me/applications' && method === 'POST') {
      const body = JSON.parse(requestOptions.body); const id = uuid(100 + applications.length);
      const template = setups.find((item) => item.application.id === body.application_template_id);
      const app = { id, organization_id: body.organization_id, application_template_id: body.application_template_id,
        credential_template_id: template.credential.id, applicant_id: f.applicant.id,
        integration_context: body.integration_context, form_data: body.form_data, status: 'DRAFT' };
      applications.push(app); return reply(app, 201);
    }
    for (const app of applications) {
      const adminPath = `/v1/organizations/${app.organization_id}/applicants/${app.id}`;
      if (route === adminPath && method === 'GET') return reply(app);
      if (route === `/v1/me/applications/${app.id}/submit`) { app.status = 'SUBMITTED'; return reply(app); }
      if (route === `${adminPath}/approve`) { app.status = 'APPROVED'; return reply(app); }
      if (route === `${adminPath}/withdraw`) {
        if (['APPROVED', 'OFFERED', 'CREDENTIALED', 'SUSPENDED'].includes(app.status)) {
          return reply({ detail: 'Issuance reconciliation is required' }, 409);
        }
        app.status = 'WITHDRAWN'; return reply(app);
      }
      if (route === `${adminPath}/issue`) {
        const transaction = { id: uuid(200 + transactions.length), organization_id: app.organization_id,
          credential_template_id: app.credential_template_id, application_id: app.id, status: 'pending',
          created_at: new Date(NOW).toISOString(), expires_at: new Date(NOW + (options.ttlSeconds || 60) * 1000).toISOString() };
        transactions.push(transaction); app.status = 'OFFERED'; app.offer_expires_at = transaction.expires_at;
        const offer = { credential_issuer: `${ORIGIN}/org/${app.organization_id}`, credential_configuration_ids: ['open_badge'],
          grants: { [GRANT]: { 'pre-authorized_code': `fixture-code-${transaction.id}` } } };
        offers.set(transaction.id, offer);
        app.credential_offer_uri = `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(offer))}`;
        return reply(app);
      }
    }
    if (route === '/v1/issuance') return reply(transactions.map(({ expires_at, issued_at, revoked_at, ...summary }) => ({
      ...summary, expires_at: null, issued_at: null, revoked_at: null,
    })));
    if (route === '/v1/issued-credentials') return reply(credentials);
    for (const credential of credentials) {
      if (route === `/v1/issued-credentials/${credential.id}/revoke`) {
        credential.status = 'REVOKED'; return reply(credential);
      }
    }
    for (const tx of transactions) {
      if (route === `/v1/issuance/offers/${tx.id}`) return reply(offers.get(tx.id));
      if (route === `/v1/issuance/${tx.id}`) return reply(tx);
      if (route === `/v1/issuance/${tx.id}/revoke`) { tx.status = 'revoked'; return reply({ id: tx.id, status: tx.status }); }
    }
    throw new Error(`Unexpected fake native route: ${method} ${route}`);
  };
  const page = { evaluate: (_callback, request) => endpoint(request) };
  const controller = createSupportController({ operator: page, applicantPage: page, fixture: f, lane: 'expired-offer', origin: ORIGIN,
    runId: uuid(20), waitFor: (probe) => probe() });
  return { controller, requests, setups, login, applications, transactions, credentials, offers, page };
}

test('expired-offer preflight requires an explicit isolated short server TTL before any native issuance', () => {
  assert.equal(validateFixture(fixture(), 'expired-offer').expiry.expectedServerOfferTtlSeconds, 60);
  for (const replacement of [undefined, { isolatedDeployment: false, expectedServerOfferTtlSeconds: 60, maximumWaitSeconds: 120 },
    { isolatedDeployment: true, expectedServerOfferTtlSeconds: 604800, maximumWaitSeconds: 180 },
    { isolatedDeployment: true, expectedServerOfferTtlSeconds: 60, maximumWaitSeconds: 10000 }]) {
    assert.throws(() => validateFixture({ ...fixture(), expiry: replacement }, 'expired-offer'));
  }
});

test('fixture cannot smuggle provider secrets or replace the authorized foreign/trusted binding', () => {
  for (const change of [
    (f) => { f.providerToken = 'not-a-real-token'; },
    (f) => { f.applicant.formData.access_token = 'not-a-real-token'; },
    (f) => { f.foreign.issuerDid = f.trusted.issuerDid; },
    (f) => { f.foreign.trustProfileId = f.login.trustProfileId; },
    (f) => { f.foreign.credentialFormat = 'MDOC'; },
  ]) {
    const f = fixture(); change(f); assert.throws(() => validateFixture(f, 'untrusted-issuer'));
  }
});

test('fixture preflight consumes actual public identity tuples and ignores unrelated system catalog rows', () => {
  const f = fixture(); const setup = issuerSetup(f.trusted);
  setup.issuers.push({ id: uuid(99), organization_id: null, is_system_issuer: true, issuer_id: 'did:web:system.example.test' });
  assert.equal(validateIssuerSetup(f.trusted, setup, f.login.vct).issuerDid, f.trusted.issuerDid);
  setup.identities.identities[0].issuer_did = f.foreign.issuerDid;
  assert.throws(() => validateIssuerSetup(f.trusted, setup, f.login.vct), /exact preprovisioned/);
});

test('login preflight rejects dynamic or already-trusted foreign issuer configuration without changing it', () => {
  const f = fixture(); const observed = loginSetup(f);
  assert.equal(validateLoginSetup(f, observed, 'untrusted-issuer').policyId, f.login.presentationPolicyId);
  observed.trust.trust_sources = [{ registry_url: 'https://registry.example.test' }];
  assert.throws(() => validateLoginSetup(f, observed, 'untrusted-issuer'), /explicit local trust profile/);
  observed.trust.trust_sources = []; observed.trust.allowed_issuers.push(f.foreign.issuerDid);
  assert.throws(() => validateLoginSetup(f, observed, 'untrusted-issuer'), /explicitly allows/);
});

test('controller validates all fixture dependencies with GET only before creating an owned application', async () => {
  const service = fakeService();
  const result = await service.controller.preflight();
  assert.match(result.configurationSha256, /^[a-f0-9]{64}$/);
  assert.ok(service.requests.every((request) => request.method === 'GET'));
  assert.equal(service.controller.ownedApplications.length, 0);
  service.setups[0].credential.organization_id = uuid(90);
  await assert.rejects(service.controller.preflight(), /organization mismatch/);
  assert.ok(service.requests.every((request) => request.method === 'GET'));
  await assert.rejects(service.controller.issue(fixture().trusted, 'after-failed-preflight'), /preflight must complete/);
});

test('application issue resolves the exact transaction and reads admin detail rather than treating application id as transaction id', async () => {
  const f = fixture(); const service = fakeService(f); await service.controller.preflight();
  const result = await service.controller.issue(f.trusted, 'expired-offer');
  assert.equal(result.owned.applicationId, uuid(100));
  assert.equal(result.owned.transactionId, uuid(200));
  assert.notEqual(result.owned.applicationId, result.owned.transactionId);
  assert.equal(result.transaction.expires_at, new Date(NOW + 60000).toISOString());
  assert.equal(result.owned.runId, `${uuid(20)}.expired-offer`);
  assert.equal(service.requests.at(-2).path, `/v1/issuance/${uuid(200)}?organization_id=${uuid(1)}`);
  assert.equal(service.requests.at(-1).path, `/v1/issuance/offers/${uuid(200)}`);
});

test('actual seven-day TTL mismatch remains blocked while exact owned offer is cancelled and history retained', async () => {
  const f = fixture(); const service = fakeService(f, { ttlSeconds: 604800 }); await service.controller.preflight();
  const result = await service.controller.issue(f.trusted, 'expired-offer');
  assert.throws(() => expiryWindow(result.transaction, result.application, f.expiry, NOW + 1000), /Actual server offer TTL differs/);
  const cleanup = await service.controller.cleanupOne(result.owned);
  assert.equal(cleanup.ok, true); assert.equal(cleanup.cancellation.ok, true);
  assert.equal(service.transactions[0].status, 'revoked');
  assert.equal(service.applications[0].status, 'OFFERED');
  assert.equal(cleanup.applicationHistoryPreserved, true);
  assert.equal(cleanup.applicationWithdrawn, false);
  assert.equal(service.requests.filter((request) => request.method === 'POST').at(-1).path, `/v1/issuance/${uuid(200)}/revoke`);
  assert.ok(service.requests.every((request) => !request.path.endsWith('/withdraw')));
  // A new application remains forbidden by the production duplicate guard.
  const postCount = service.requests.filter(({ method }) => method === 'POST').length;
  await assert.rejects(service.controller.issue(f.trusted, 'fresh-reissue'), /Existing application.*blocks this demo/);
  assert.equal(service.requests.filter(({ method }) => method === 'POST').length, postCount);
  const replacement = await service.controller.reissue(result, f.trusted);
  assert.equal(replacement.owned.transactionId, uuid(201));
  assert.equal(replacement.owned.applicationId, result.owned.applicationId);
  assert.equal(replacement.owned.runId, result.owned.runId);
  assert.notEqual(replacement.offerUri, result.offerUri);
  assert.equal(service.applications.length, 1);
  assert.equal(service.controller.ownedApplications.length, 1);
  assert.deepEqual(replacement.owned.retiredTransactions, [{
    id: uuid(200), organization_id: uuid(1), credential_template_id: uuid(2), application_id: uuid(100),
  }]);
  const finalCleanup = await service.controller.cleanup();
  assert.equal(finalCleanup.ok, true);
  assert.equal(finalCleanup.applications[0].applicationHistoryPreserved, true);
  assert.equal(service.transactions[0].status, 'revoked');
  assert.equal(service.transactions[1].status, 'revoked');
  assert.equal(service.applications[0].status, 'OFFERED');
});

test('same-application reissue rejects foreign, active, ambiguous, issued, or uncertain history before mutation', async () => {
  const changes = {
    foreignApplication: (service) => { service.applications[0].integration_context.demo_run_id = 'another-run'; },
    foreignTransaction: (service) => { service.transactions[0].organization_id = uuid(90); },
    activeTransaction: (service) => { service.transactions[0].status = 'pending'; },
    issuedTransaction: (service) => { service.transactions[0].issued_at = new Date(NOW).toISOString(); },
    missingTransaction: (service) => { service.transactions.length = 0; },
    unknownTransaction: (service) => { service.transactions.push({ ...service.transactions[0], id: uuid(299), status: 'pending' }); },
    issuedCredential: (service) => { service.credentials.push({ id: uuid(300), organization_id: uuid(1), application_id: uuid(100),
      credential_template_id: uuid(2), flow_execution_id: uuid(200), status: 'ACTIVE' }); },
    claimedApplication: (service) => { service.applications[0].claim_state = 'CLAIMED'; },
    uncertainIssuance: (_service, issuance) => { issuance.owned.uncertainMutations.push({ operation: 'issuance' }); },
  };
  for (const [name, change] of Object.entries(changes)) {
    const f = fixture(); const service = fakeService(f); await service.controller.preflight();
    const issuance = await service.controller.issue(f.trusted, 'expired-offer');
    assert.equal((await service.controller.cleanupOne(issuance.owned)).ok, true);
    change(service, issuance);
    const postCount = service.requests.filter(({ method }) => method === 'POST').length;
    await assert.rejects(service.controller.reissue(issuance, f.trusted), undefined, name);
    assert.equal(service.requests.filter(({ method }) => method === 'POST').length, postCount, name);
  }
  const f = fixture(); const service = fakeService(f); await service.controller.preflight();
  const issuance = await service.controller.issue(f.trusted, 'expired-offer');
  await service.controller.cleanupOne(issuance.owned);
  const before = service.requests.length;
  await assert.rejects(service.controller.reissue({ ...issuance, owned: { ...issuance.owned } }, f.trusted), /captured by this controller/);
  await assert.rejects(service.controller.reissue(issuance, f.foreign), /cannot change.*binding/);
  assert.equal(service.requests.length, before);
});

test('reissued credential retirement preserves the same application and freshly proves the old canceled offer', async () => {
  const f = fixture(); const service = fakeService(f); await service.controller.preflight();
  const expired = await service.controller.issue(f.trusted, 'expired-offer');
  await service.controller.cleanupOne(expired.owned);
  const recovery = await service.controller.reissue(expired, f.trusted);
  service.transactions[1].status = 'issued';
  service.applications[0].status = 'CREDENTIALED';
  service.applications[0].claim_state = 'CLAIMED';
  service.applications[0].issued_at = new Date(NOW).toISOString();
  service.credentials.push({ id: uuid(300), organization_id: uuid(1), application_id: uuid(100),
    credential_template_id: uuid(2), flow_execution_id: uuid(201), status: 'ACTIVE',
    issuer_did: f.trusted.issuerDid, credential_format: f.trusted.credentialFormat });
  assert.equal((await service.controller.issuedCredential(recovery, f.trusted)).transactionId, uuid(201));
  const cleanup = await service.controller.cleanup();
  assert.equal(cleanup.ok, true);
  assert.equal(cleanup.applications.length, 1);
  assert.equal(cleanup.applications[0].credentialRevoked, true);
  assert.equal(cleanup.applications[0].applicationWithdrawn, false);
  assert.equal(cleanup.applications[0].applicationHistoryPreserved, true);
  assert.equal(service.transactions[0].status, 'revoked');
  assert.equal(service.credentials[0].status, 'REVOKED');
  assert.equal(service.applications[0].status, 'CREDENTIALED');
  assert.ok(service.requests.every(({ path }) => !path.endsWith('/withdraw')));
});

test('lost reissue responses recover only through one exact new transaction and preserve unresolved uncertainty', async () => {
  for (const createTransaction of [true, false]) {
    const f = fixture(); const service = fakeService(f); await service.controller.preflight();
    const expired = await service.controller.issue(f.trusted, 'expired-offer');
    await service.controller.cleanupOne(expired.owned);
    const original = service.page.evaluate;
    service.page.evaluate = async (callback, request) => {
      if (request.requestOptions.method === 'POST' && request.requestPath.endsWith('/issue')) {
        if (createTransaction) await original(callback, request);
        throw new Error('Lost reissue response');
      }
      return original(callback, request);
    };
    await assert.rejects(service.controller.reissue(expired, f.trusted), /Lost reissue response/);
    const current = service.controller.ownedApplications[0];
    assert.equal(current.applicationId, expired.owned.applicationId);
    assert.equal(current.transactionId, null);
    assert.deepEqual(current.uncertainMutations, [{ operation: 'issuance' }]);
    const cleanup = await service.controller.cleanup();
    assert.equal(cleanup.ok, createTransaction);
    assert.deepEqual(current.uncertainMutations, createTransaction ? [] : [{ operation: 'issuance' }]);
    assert.equal(service.transactions[0].status, 'revoked');
    assert.equal(service.applications[0].status, 'OFFERED');
    if (createTransaction) assert.equal(service.transactions[1].status, 'revoked');
  }
});

test('a stale returned offer or reused old transaction cannot qualify same-application recovery', async () => {
  for (const createTransaction of [true, false]) {
    const f = fixture(); const service = fakeService(f); await service.controller.preflight();
    const expired = await service.controller.issue(f.trusted, 'expired-offer');
    await service.controller.cleanupOne(expired.owned);
    const original = service.page.evaluate;
    service.page.evaluate = async (callback, request) => {
      if (request.requestOptions.method === 'POST' && request.requestPath.endsWith('/issue')) {
        if (createTransaction) await original(callback, request);
        return { ok: true, status: 200, body: { ...service.applications[0], credential_offer_uri: expired.offerUri } };
      }
      return original(callback, request);
    };
    await assert.rejects(service.controller.reissue(expired, f.trusted));
    const cleanup = await service.controller.cleanup();
    assert.equal(cleanup.ok, createTransaction);
    assert.equal(service.applications.length, 1);
    assert.equal(service.applications[0].status, 'OFFERED');
  }
});

test('retained transaction history is revalidated before any later cleanup mutation', async () => {
  const changes = {
    active: (service) => { service.transactions[0].status = 'pending'; },
    foreign: (service) => { service.transactions[0].application_id = uuid(99); },
    issued: (service) => { service.transactions[0].issued_at = new Date(NOW).toISOString(); },
    credential: (service) => { service.credentials.push({ id: uuid(300), organization_id: uuid(1), application_id: uuid(100),
      credential_template_id: uuid(2), flow_execution_id: uuid(200), status: 'ACTIVE' }); },
  };
  for (const [name, change] of Object.entries(changes)) {
    const f = fixture(); const service = fakeService(f); await service.controller.preflight();
    const expired = await service.controller.issue(f.trusted, 'expired-offer');
    await service.controller.cleanupOne(expired.owned);
    await service.controller.reissue(expired, f.trusted);
    change(service);
    const postCount = service.requests.filter(({ method }) => method === 'POST').length;
    const cleanup = await service.controller.cleanup();
    assert.equal(cleanup.ok, false, name);
    assert.equal(service.requests.filter(({ method }) => method === 'POST').length, postCount, name);
    assert.equal(service.transactions[1].status, 'pending', name);
  }
});

test('reissue preserves ambiguity when an unknown additional transaction appears during the mutation', async () => {
  const f = fixture(); const service = fakeService(f); await service.controller.preflight();
  const expired = await service.controller.issue(f.trusted, 'expired-offer');
  await service.controller.cleanupOne(expired.owned);
  const original = service.page.evaluate;
  service.page.evaluate = async (callback, request) => {
    const response = await original(callback, request);
    if (request.requestOptions.method === 'POST' && request.requestPath.endsWith('/issue')) {
      service.transactions.push({ ...service.transactions[1], id: uuid(299) });
    }
    return response;
  };
  await assert.rejects(service.controller.reissue(expired, f.trusted), /multiple issuance transactions/);
  const current = service.controller.ownedApplications[0];
  assert.equal(current.transactionId, null);
  assert.deepEqual(current.uncertainMutations, [{ operation: 'issuance' }]);
  const postCount = service.requests.filter(({ method }) => method === 'POST').length;
  assert.equal((await service.controller.cleanup()).ok, false);
  assert.equal(service.requests.filter(({ method }) => method === 'POST').length, postCount);
});

test('partial approval failure still cleans the exact application and never invents a transaction', async () => {
  const f = fixture(); const service = fakeService(f, { fail: ({ route }) => route.endsWith('/approve') });
  await service.controller.preflight();
  await assert.rejects(service.controller.issue(f.trusted, 'partial'), /Lost public response/);
  const cleanup = await service.controller.cleanup();
  assert.equal(cleanup.ok, true);
  assert.equal(service.applications[0].status, 'WITHDRAWN');
  assert.equal(service.transactions.length, 0);
  assert.ok(service.requests.every((request) => !request.path.endsWith('/revoke')));
});

test('failed and expired unused transactions are publicly revoked with issuance history retained', async () => {
  for (const status of ['failed', 'expired']) {
    const f = fixture(); const service = fakeService(f); await service.controller.preflight();
    const issuance = await service.controller.issue(f.trusted, status);
    service.transactions[0].status = status;
    const cleanup = await service.controller.cleanupOne(issuance.owned);
    assert.equal(cleanup.ok, true); assert.equal(cleanup.cancellation.status, 'revoked');
    assert.equal(service.applications[0].status, 'OFFERED');
    assert.equal(cleanup.applicationHistoryPreserved, true);
    assert.equal(cleanup.applicationWithdrawn, false);
    assert.equal(service.requests.filter((request) => request.method === 'POST').at(-1).path, `/v1/issuance/${uuid(200)}/revoke`);
    assert.ok(service.requests.every((request) => !request.path.endsWith('/withdraw')));
  }
});

test('lost expired-offer cancellation keeps cleanup incomplete until exact revoked readback clears uncertainty', async () => {
  let loseRevoke = true;
  const f = fixture(); const service = fakeService(f, { fail: ({ route, method }) =>
    loseRevoke && method === 'POST' && route.endsWith('/revoke') });
  await service.controller.preflight();
  const issuance = await service.controller.issue(f.trusted, 'expired');
  service.transactions[0].status = 'expired';
  const blocked = await service.controller.cleanup();
  assert.equal(blocked.ok, false);
  assert.deepEqual(issuance.owned.uncertainMutations, [{ operation: 'transaction_cancellation' }]);
  assert.equal(service.applications[0].status, 'OFFERED');
  loseRevoke = false;
  const resolved = await service.controller.cleanup();
  assert.equal(resolved.ok, true);
  assert.equal(service.transactions[0].status, 'revoked');
  assert.deepEqual(issuance.owned.uncertainMutations, []);
});

test('lost creation response retains mutation uncertainty and cannot report fixture cleanup complete', async () => {
  const f = fixture(); const service = fakeService(f, { fail: ({ route, method }) => route === '/v1/me/applications' && method === 'POST' });
  await service.controller.preflight();
  await assert.rejects(service.controller.issue(f.trusted, 'lost-create'), /Lost public response/);
  const cleanup = await service.controller.cleanup();
  assert.equal(cleanup.ok, false);
  assert.deepEqual(cleanup.applications[0].uncertainMutations, [{ operation: 'application_creation' }]);
});

test('natural expiry waits for the server 410 and has a strict maximum with no clock override', async () => {
  let now = NOW; let reads = 0; const waited = [];
  const window = { expiresAt: new Date(NOW + 2000).toISOString(), deadlineMs: NOW + 5000 };
  const result = await awaitNaturalExpiry({ window, now: () => now,
    delay: async (ms) => { waited.push(ms); now += ms; },
    readOffer: async () => { reads += 1; return { status: 410 }; } });
  assert.equal(result.expiredOfferHttpStatus, 410); assert.equal(reads, 1);
  assert.deepEqual(waited, [1000, 1000, 1000]);
  now = NOW;
  await assert.rejects(awaitNaturalExpiry({ window, now: () => now, delay: async (ms) => { now += ms; },
    readOffer: async () => ({ status: 200 }) }), /explicit maximum wait/);
  assert.equal(now, window.deadlineMs);
});

function nativeResult(f, allowed) {
  return { instance_id: uuid(30), status: allowed ? 'COMPLETED' : 'FAILED', result: allowed ? 'passed' : 'failed',
    decision: allowed ? 'allow' : 'deny', evaluation_timestamp: new Date(NOW).toISOString(), credential_results: [{
      credential_template_id: f.trusted.credentialTemplateId, issuer_did: allowed ? f.trusted.issuerDid : f.foreign.issuerDid,
      signature_valid: true, trust_check_passed: allowed, satisfied: allowed,
    }] };
}

test('untrusted evidence requires the exact native instance and authenticated foreign signature with trust denial', () => {
  const f = fixture(); const result = nativeResult(f, false); const binding = { instanceId: uuid(30) };
  assert.equal(nativeLoginResult(result, binding, f, f.foreign.issuerDid, false).trustCheckPassed, false);
  for (const change of [
    (value) => { value.instance_id = uuid(31); }, (value) => { value.status = 'AWAITING_WALLET'; },
    (value) => { value.credential_results[0].signature_valid = false; },
    (value) => { value.credential_results[0].trust_check_passed = true; },
    (value) => { value.credential_results[0].issuer_did = f.trusted.issuerDid; },
    (value) => { value.credential_results[0].credential_template_id = f.foreign.credentialTemplateId; },
    (value) => { delete value.credential_results; },
  ]) { const copy = structuredClone(result); change(copy); assert.throws(() => nativeLoginResult(copy, binding, f, f.foreign.issuerDid, false)); }
});

test('actual login page Flow binding rejects changed org, policy, trust and request origin', () => {
  const f = fixture(); const details = { nonce: 'fixture-login-nonce', href: 'openid4vp://?request_uri=fixture',
    dcApiRequestUrl: `/v1/flows/instances/${uuid(30)}/request?transport=dc_api` };
  const instance = { id: uuid(30), organization_id: f.login.organizationId, context_data: {
    presentation_policy_id: f.login.presentationPolicyId, trust_profile_id: f.login.trustProfileId, oid4vp_issuer_did: f.login.verifierDid } };
  assert.equal(loginInstanceBinding(details, instance, f, ORIGIN).instanceId, uuid(30));
  assert.throws(() => loginInstanceBinding({ ...details, dcApiRequestUrl: `https://foreign.example.test${details.dcApiRequestUrl}` }, instance, f, ORIGIN));
  for (const field of ['presentation_policy_id', 'trust_profile_id', 'oid4vp_issuer_did']) {
    const copy = structuredClone(instance); copy.context_data[field] = 'foreign';
    assert.throws(() => loginInstanceBinding(details, copy, f, ORIGIN));
  }
});

test('aggregates require actual recovery, native trust result and cleanup in both no-video lanes', () => {
  for (const lane of ['expired-offer', 'untrusted-issuer']) {
    const required = Object.keys(assertions(lane, {})).slice(0, -1);
    const checks = Object.fromEntries(required.map((key) => [key, true]));
    assert.ok(Object.values(assertions(lane, checks)).every(Boolean));
    checks.trusted_login_recovery = false;
    assert.equal(Object.values(assertions(lane, checks)).at(-1), false);
    checks.trusted_login_recovery = true; checks.fixture_cleanup = false;
    assert.equal(Object.values(assertions(lane, checks)).at(-1), false);
  }
});

test('the sealed IPC fixture bytes are the actual validated inputs and changed bytes cannot proceed', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'marty-d05-input-'));
  try {
    const source = path.join(dir, 'input.json'); fs.writeFileSync(source, JSON.stringify(fixture()));
    const artifact = path.join(dir, 'artifacts'); fs.mkdirSync(artifact);
    const order = [];
    const input = await prepareFixture(artifact, { DEMO_D05_FIXTURE_FILE: source, TEST_APPLICANT_EMAIL: fixture().applicant.email }, 'expired-offer', {
      readFixture: async (file) => { order.push(`read:${file}`); return fs.readFileSync(path.join(artifact, file)); },
      seal: async () => { order.push('seal'); },
    });
    assert.deepEqual(input.fixture, fixture()); assert.deepEqual(order, ['read:d05-support-fixture.json', 'seal']);
    const changedDir = path.join(dir, 'changed'); fs.mkdirSync(changedDir);
    await assert.rejects(prepareFixture(changedDir, { DEMO_D05_FIXTURE_FILE: source, TEST_APPLICANT_EMAIL: fixture().applicant.email }, 'expired-offer', {
      readFixture: async () => Buffer.from('{}'), seal: async () => assert.fail('Changed inputs must not seal'),
    }), /changed before sealing/);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('runtime preflight requires explicit recorder provenance and rejects local UI substitution', () => {
  const env = { BETA_ORIGIN: ORIGIN, MARTY_TEST_WALLET_ORIGIN: 'http://127.0.0.1:8787', D05_SYNTHETIC_FIXTURE: '1',
    DEMO_D05_FIXTURE_FILE: '/fixture.json', TEST_ADMIN_EMAIL: 'operator@example.test', TEST_ADMIN_PASSWORD: 'fixture-password',
    TEST_APPLICANT_EMAIL: 'member@example.test', TEST_APPLICANT_PASSWORD: 'fixture-password', RECORD_VIDEO: '0',
    DEMO_EXECUTION_EVIDENCE_RUN_ID: uuid(20), DEMO_EXECUTION_EVIDENCE_HELPER: '/helper.js', DEMO_EXECUTION_EVIDENCE_HELPER_SHA256: 'a'.repeat(64) };
  assert.equal(guards(env, 'expired-offer').record, false);
  assert.throws(() => guards({ ...env, MARTY_UI_CANDIDATE_DIST: '/local/dist' }, 'expired-offer'));
  assert.throws(() => guards({ ...env, DEMO_EXECUTION_EVIDENCE_HELPER_SHA256: '' }, 'untrusted-issuer'));
  assert.throws(() => guards({ ...env, RECORD_VIDEO: '' }, 'expired-offer'));
});

test('a preflight-blocked functional run writes both JSON receipts without credentials or a recording claim', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'marty-d05-blocked-'));
  const previousExitCode = process.exitCode;
  try {
    const result = await main('expired-offer', { DEMO_ARTIFACT_DIR: dir, RECORD_VIDEO: '0',
      BETA_ORIGIN: ORIGIN, TEST_ADMIN_PASSWORD: 'unit-fixture-password-must-not-be-recorded' });
    assert.equal(result.status, 'BLOCKED'); assert.equal(result.releaseReady, false);
    assert.equal(result.recording, false); assert.equal(result.stage, 'preflight');
    for (const name of ['report.json', 'd05-support-evidence.json']) {
      const bytes = fs.readFileSync(path.join(dir, name), 'utf8');
      assert.equal(JSON.parse(bytes).status, 'BLOCKED');
      assert.ok(!bytes.includes('unit-fixture-password-must-not-be-recorded'));
    }
    assert.deepEqual(fs.readdirSync(dir).sort(), ['d05-support-evidence.json', 'report.json']);
  } finally {
    process.exitCode = previousExitCode;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});


test('shared login hook journals before navigation and acknowledges only exact server binding',async()=>{
 const f=fixture(),events=[],instance={id:uuid(30),organization_id:f.login.organizationId,context_data:{
  presentation_policy_id:f.login.presentationPolicyId,trust_profile_id:f.login.trustProfileId,oid4vp_issuer_did:f.login.verifierDid}};
 const authPage={goto:async()=>events.push('navigation'),evaluate:async()=>({nonce:'PRIVATE_NONCE',href:'PRIVATE_WALLET_LINK',
  dcApiRequestUrl:ORIGIN+'/v1/flows/instances/'+instance.id+'/request'})};
 const operator={evaluate:async()=>({ok:true,status:200,body:instance})};
 const flowHooks={beforeStart:async()=>events.push('intent'),acknowledge:async({binding})=>{assert.equal(binding.instanceId,instance.id);events.push('ack');}};
 await startLogin({authPage,operator,fixture:f,origin:ORIGIN,flowHooks});assert.deepEqual(events,['intent','navigation','ack']);
 events.length=0;instance.context_data.presentation_policy_id=uuid(999);
 await assert.rejects(startLogin({authPage,operator,fixture:f,origin:ORIGIN,flowHooks}));
 assert.deepEqual(events,['intent','navigation']);
});

test('dedicated owned expiry offer uses optional server TTL; recovery preserves configured defaults', async () => {
  const f=fixture(); delete f.expiry.isolatedDeployment; f.expiry.mode='PER_OWNED_OFFER';
  validateFixture(f,'expired-offer');
  const invalid=structuredClone(f);invalid.expiry.mode='CALLER_TRUST';assert.throws(()=>validateFixture(invalid,'expired-offer'));
  const service=fakeService(f); await service.controller.preflight();
  await assert.rejects(service.controller.issue(f.trusted,'invalid-ttl',{offerTtlSeconds:1}));
  assert.equal(service.applications.length,0);
  const short=await service.controller.issue(f.trusted,'dedicated-expiry',{offerTtlSeconds:60});
  let issues=service.requests.filter(r=>r.path.endsWith('/issue'));
  assert.deepEqual(JSON.parse(issues[0].body),{offer_ttl_seconds:60});
  await service.controller.cleanupOne(short.owned);
  await service.controller.reissue(short,f.trusted);
  issues=service.requests.filter(r=>r.path.endsWith('/issue'));
  assert.equal(issues.length,2); assert.equal(issues[1].body,undefined);
});
