'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const {
  DEFAULT_CREDENTIAL_RANKING_STRATEGY,
  cancelOwnedIssuanceTransaction,
  cleanupApplicationCredential,
  compactObject,
  ensureActiveResource,
  ensureGovernedIssuer,
  findCurrentCredential,
  governedIssuerTrustProfilePayload,
  issueOwnedApplication,
  requestedClaim,
  requireJson,
  requireNoConflictingApplications,
  resolveActiveIssuerDid,
  safeErrorDetail,
  selectApplicationTransaction,
  selectCurrentCredential,
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
      if (response instanceof Error) throw response;
      return response;
    },
  };
}

function ownedRun(extra = {}) {
  return {
    organizationId: 'org/1', applicationTemplateId: 'application-template/1',
    credentialTemplateId: 'template/1', applicantId: 'applicant/1', runId: 'run-1',
    applicationId: 'application/1', transactionId: 'transaction/1', credentialId: 'credential/1',
    uncertainMutations: [], ...extra,
  };
}

function application(owned, extra = {}) {
  return {
    id: owned.applicationId, organization_id: owned.organizationId,
    application_template_id: owned.applicationTemplateId,
    credential_template_id: owned.credentialTemplateId, applicant_id: owned.applicantId,
    integration_context: { demo_run_id: owned.runId }, status: 'OFFERED', ...extra,
  };
}

const projection = JSON.parse(fs.readFileSync(
  path.join(__dirname, '..', '..', 'contracts', 'gateway-issuance-response-projection.json'), 'utf8',
));

function transaction(owned, extra = {}) {
  return {
    ...projection.cases.find(({ name }) => name === 'transaction_list_hides_internal_state').expected[0],
    id: owned.transactionId || 'transaction/1', organization_id: owned.organizationId,
    credential_template_id: owned.credentialTemplateId, application_id: owned.applicationId,
    ...extra,
  };
}

function credential(owned, extra = {}) {
  return {
    ...projection.cases.find(({ name }) => name === 'issued_credential_hides_delivery_routing').expected,
    id: owned.credentialId || 'credential/1', organization_id: owned.organizationId,
    credential_template_id: owned.credentialTemplateId, application_id: owned.applicationId,
    flow_execution_id: owned.transactionId || 'transaction/1', ...extra,
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
    { ok: true, status: 201, body: { id: 'resource/1', organization_id: 'org/a', name: 'D-01', status: 'DRAFT' } },
    { ok: true, status: 200, body: { valid: true } },
    { ok: true, status: 200, body: { id: 'resource/1', organization_id: 'org/a', name: 'D-01', status: 'ACTIVE' } },
    { ok: true, status: 200, body: { id: 'resource/1', organization_id: 'org/a', name: 'D-01', status: 'ACTIVE' } },
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
    { ok: true, status: 200, body: [{ id: 'one', organization_id: 'org-1', name: 'D-01', status: 'SUSPENDED' }] },
    { ok: true, status: 200, body: { id: 'one', organization_id: 'org-1', name: 'D-01', status: 'SUSPENDED' } },
  ]);
  await assert.rejects(() => ensureActiveResource(inactivePage, {
    organizationId: 'org-1',
    collectionPath: '/v1/resources',
    name: 'D-01',
    payload: {},
    idempotencyKey: 'd01-resource-v1',
  }), /is not active/);
});

test('governedIssuerTrustProfilePayload binds one exact SD-JWT issuer', () => {
  assert.deepEqual(governedIssuerTrustProfilePayload({
    organizationId: 'org-1',
    name: 'Demo trust',
    description: 'Exact issuer trust',
    issuerDid: 'did:web:issuer.example',
  }), {
    organization_id: 'org-1',
    name: 'Demo trust',
    description: 'Exact issuer trust',
    profile_type: 'CUSTOM',
    trust_sources: [],
    allowed_algorithms: ['ES256'],
    supported_formats: ['SD_JWT_VC'],
    allowed_issuers: ['did:web:issuer.example'],
    denied_issuers: [],
  });
});

test('resolveActiveIssuerDid selects one organization-owned issuance identity', async () => {
  const page = fakePage([{
    ok: true,
    status: 200,
    body: {
      identities: [
        {
          issuer_did: 'did:web:beta.example:orgs:audit',
          key_purpose: 'vc_jwt_issuer',
          credential_format: 'SD_JWT_VC',
          algorithm: 'ES256',
          status: 'active',
        },
        {
          issuer_did: 'did:web:beta.example:orgs:audit',
          key_purpose: 'oid4vp_request_signing',
          credential_format: 'SD_JWT_VC',
          algorithm: 'ES256',
          status: 'active',
        },
      ],
    },
  }]);

  assert.equal(await resolveActiveIssuerDid(page, { organizationId: 'org/a' }), (
    'did:web:beta.example:orgs:audit'
  ));
  assert.deepEqual(page.requests, [{
    requestPath: '/v1/signing-keys/issuer-identities?organization_id=org%2Fa',
    requestOptions: {},
  }]);
});

test('resolveActiveIssuerDid fails closed for missing or ambiguous identities', async () => {
  const missing = fakePage([{ ok: true, status: 200, body: { identities: [] } }]);
  await assert.rejects(
    () => resolveActiveIssuerDid(missing, { organizationId: 'org-1' }),
    /found 0/,
  );

  const ambiguous = fakePage([{
    ok: true,
    status: 200,
    body: {
      identities: ['one', 'two'].map((suffix) => ({
        issuer_did: `did:web:beta.example:orgs:${suffix}`,
        key_purpose: 'vc_jwt_issuer',
        credential_format: 'SD_JWT_VC',
        algorithm: 'ES256',
        status: 'active',
      })),
    },
  }]);
  await assert.rejects(
    () => resolveActiveIssuerDid(ambiguous, { organizationId: 'org-1' }),
    /found 2/,
  );
});

test('ensureGovernedIssuer pins one public DID key and creates one trusted relationship', async () => {
  const issuer = {
    id: 'issuer-1',
    issuer_id: 'did:web:beta.example:orgs:audit',
    metadata: {
      verification_keys: [{
        kty: 'EC', crv: 'P-256', x: 'public-x', y: 'public-y', kid: 'did:web:beta.example:orgs:audit#key-1',
      }],
    },
  };
  const page = fakePage([
    { ok: true, status: 200, body: [] },
    { ok: true, status: 201, body: issuer },
    { ok: true, status: 200, body: [] },
    {
      ok: true,
      status: 201,
      body: { issuer_id: 'issuer-1', relationship_status: 'TRUSTED' },
    },
  ]);

  const result = await ensureGovernedIssuer(page, {
    organizationId: 'org/a',
    trustProfileId: 'trust/1',
    issuerDid: issuer.issuer_id,
    displayName: 'Demo issuer',
    idempotencyKey: 'demo-governed-issuer-v1',
  });

  assert.equal(result.created, true);
  assert.equal(result.relationshipCreated, true);
  assert.equal(result.issuer.id, 'issuer-1');
  assert.deepEqual(page.requests.map(({ requestPath }) => requestPath), [
    '/v1/issuer-entities?organization_id=org%2Fa',
    '/v1/issuer-entities',
    '/v1/trust-profiles/trust%2F1/issuers',
    '/v1/trust-profiles/trust%2F1/issuers',
  ]);
  assert.equal(
    JSON.parse(page.requests[1].requestOptions.body).issuer_id,
    'did:web:beta.example:orgs:audit',
  );
  assert.equal(
    JSON.parse(page.requests[3].requestOptions.body).relationship_status,
    'TRUSTED',
  );
});

test('ensureGovernedIssuer fails closed without a pinned public key', async () => {
  const page = fakePage([{
    ok: true,
    status: 200,
    body: [{
      id: 'issuer-1',
      issuer_id: 'did:web:beta.example:orgs:audit',
      metadata: { verification_keys: [{ kty: 'EC', d: 'private' }] },
    }],
  }]);
  await assert.rejects(() => ensureGovernedIssuer(page, {
    organizationId: 'org-1',
    trustProfileId: 'trust-1',
    issuerDid: 'did:web:beta.example:orgs:audit',
    displayName: 'Demo issuer',
    idempotencyKey: 'demo-governed-issuer-v1',
  }), /no pinned public verification key/);
});

test('conflict preflight blocks an existing application without withdrawing it', async () => {
  const applicantPage = fakePage([{
    ok: true,
    status: 200,
    body: {
      total: 4, offset: 0, limit: 500,
      items: [
        { id: 'active/1', organization_id: 'org/1', credential_template_id: 'credential/1', status: 'APPROVED' },
        { id: 'withdrawn/1', organization_id: 'org/1', credential_template_id: 'credential/1', status: 'WITHDRAWN' },
        { id: 'other-template', organization_id: 'org/1', credential_template_id: 'credential/2', status: 'SUBMITTED' },
        { id: 'other-org', organization_id: 'org/2', credential_template_id: 'credential/1', status: 'DRAFT' },
      ],
    },
  }]);
  await assert.rejects(requireNoConflictingApplications(applicantPage, {
    organizationId: 'org/1',
    credentialTemplateId: 'credential/1',
  }), /Existing application active\/1 blocks this demo/);
  assert.deepEqual(applicantPage.requests, [{
    requestPath: '/v1/me/applications?limit=500&offset=0',
    requestOptions: {},
  }]);
});

test('conflict preflight fails closed on malformed collections', async () => {
  const applicantPage = fakePage([{ ok: true, status: 200, body: [] }]);
  await assert.rejects(() => requireNoConflictingApplications(applicantPage, {
    organizationId: 'org-1',
    credentialTemplateId: 'credential-1',
  }), /malformed or changing collection/);
});

test('conflict preflight checks later pages and permits only terminal or unrelated applications', async () => {
  const items = Array.from({ length: 500 }, (_, index) => ({
    id: `previous-${index}`, organization_id: 'org/1', credential_template_id: 'template/1', status: 'WITHDRAWN',
  }));
  const page = fakePage([
    { ok: true, status: 200, body: { items, total: 501, limit: 500, offset: 0 } },
    { ok: true, status: 200, body: { items: [{ ...items[0], id: 'blocked-later', status: 'SUBMITTED' }], total: 501, limit: 500, offset: 500 } },
  ]);
  await assert.rejects(requireNoConflictingApplications(page, {
    organizationId: 'org/1', credentialTemplateId: 'template/1',
  }), /blocked-later/);
  assert.deepEqual(page.requests.map(({ requestPath }) => requestPath), [
    '/v1/me/applications?limit=500&offset=0', '/v1/me/applications?limit=500&offset=500',
  ]);
  const clear = fakePage([{ ok: true, status: 200, body: {
    items: [
      ...['REJECTED', 'WITHDRAWN', 'SUSPENDED'].map((status) => ({ ...items[0], id: status, status })),
      { ...items[0], id: 'other-template', credential_template_id: 'other-template', status: 'APPROVED' },
    ], total: 4, limit: 500, offset: 0,
  } }]);
  assert.deepEqual(await requireNoConflictingApplications(clear, {
    organizationId: 'org/1', credentialTemplateId: 'template/1',
  }), { ok: true, inspected: 4 });
  assert.equal(clear.requests.length, 1);
});

test('existing draft configuration and foreign organization data never authorize activation', async () => {
  for (const resource of [
    { id: 'prior-draft', organization_id: 'org/1', name: 'Demo', status: 'DRAFT' },
    { id: 'foreign-active', organization_id: 'other-org', name: 'Demo', status: 'ACTIVE' },
  ]) {
    const page = fakePage([{ ok: true, status: 200, body: [resource] }]);
    await assert.rejects(ensureActiveResource(page, {
      organizationId: 'org/1', collectionPath: '/v1/credential-templates', name: 'Demo', payload: {},
    }), /existing draft|another organization/);
    assert.equal(page.requests.length, 1);
    assert.deepEqual(page.requests[0].requestOptions, {});
  }
  const resource = { id: 'shared-active', organization_id: 'org/1', name: 'Demo', status: 'ACTIVE' };
  const page = fakePage([
    { ok: true, status: 200, body: [resource] },
    { ok: true, status: 200, body: resource },
  ]);
  assert.equal((await ensureActiveResource(page, {
    organizationId: 'org/1', collectionPath: '/v1/credential-templates', name: 'Demo', payload: {},
  })).created, false);
  assert.ok(page.requests.every(({ requestOptions }) => !requestOptions.method));
});

test('application issue response is correlated to its public transaction rather than its application id', async () => {
  const owned = ownedRun({ transactionId: null, credentialId: null });
  const issued = application(owned, { credential_offer_uri: 'openid-credential-offer://synthetic' });
  assert.equal(Object.hasOwn(issued, 'issuance_transaction_id'), false);
  const page = fakePage([
    { ok: true, status: 200, body: issued },
    { ok: true, status: 200, body: [
      transaction(owned), transaction(owned, { id: 'newer-other-run', application_id: 'other-application' }),
    ] },
  ]);
  const result = await issueOwnedApplication(page, owned, 'Issue demo credential');
  assert.equal(result.issued.id, 'application/1');
  assert.equal(result.transaction.id, 'transaction/1');
  assert.equal(owned.transactionId, 'transaction/1');
  assert.deepEqual(owned.uncertainMutations, []);
  assert.deepEqual(page.requests.map(({ requestPath }) => requestPath), [
    '/v1/organizations/org%2F1/applicants/application%2F1/issue', '/v1/issuance?organization_id=org%2F1',
  ]);
});

test('console issuance retains exact transaction binding and uncertainty on mismatched responses', async () => {
  const owned = ownedRun({ transactionId: null, credentialId: null });
  const page = fakePage([{ ok: true, status: 200, body: [transaction(owned)] }]);
  let endpoint;
  const result = await issueOwnedApplication(page, owned, 'Console issue', {
    requestIssue: async (url) => { endpoint = url; return application(owned); },
  });
  assert.equal(endpoint, '/v1/organizations/org%2F1/applicants/application%2F1/issue');
  assert.equal(result.transaction.id, 'transaction/1');
  assert.deepEqual(owned.uncertainMutations, []);
  assert.equal(page.requests.length, 1);
  const foreign = ownedRun({ transactionId: null, credentialId: null });
  await assert.rejects(issueOwnedApplication(fakePage([]), foreign, 'Console issue', {
    requestIssue: async () => application(foreign, { id: 'someone-elses-application' }),
  }), /does not match this run/);
  assert.deepEqual(foreign.uncertainMutations, [{ operation: 'issuance' }]);
});

test('exact application and transaction selection ignores newer credentials from other runs', async () => {
  const owned = ownedRun();
  const ours = credential(owned);
  const records = [ours, credential(owned, {
    id: 'concurrent-other', application_id: 'other-application', flow_execution_id: 'other-transaction',
    issued_at: '2099-01-01T00:00:00Z',
  })];
  assert.equal(selectCurrentCredential(records, owned), ours);
  assert.equal(selectApplicationTransaction([
    transaction(owned), transaction(owned, { id: 'other-transaction', application_id: 'other-application' }),
  ], owned).id, owned.transactionId);
  const page = fakePage([{ ok: true, status: 200, body: records }]);
  assert.equal((await findCurrentCredential(page, { ...owned, waitFor: (fn) => fn() })).id, owned.credentialId);
  const unavailable = fakePage([{ ok: false, status: 503, body: null }]);
  await assert.rejects(findCurrentCredential(unavailable, { ...owned, waitFor: (fn) => fn() }), /HTTP 503/);
  await assert.rejects(findCurrentCredential(fakePage([]), { ...owned, transactionId: null, waitFor: (fn) => fn() }), /transactionId is required/);
});

test('missing, ambiguous, cross-organization, or changed ownership is rejected before cleanup mutations', async () => {
  const owned = ownedRun();
  for (const body of [
    application(owned, { organization_id: 'foreign-org' }),
    application(owned, { integration_context: { demo_run_id: 'prior-run' } }),
    application(owned, { applicant_id: 'other-applicant' }),
  ]) {
    const page = fakePage([{ ok: true, status: 200, body }]);
    await assert.rejects(cleanupApplicationCredential(page, { ...owned }, 'cleanup'), /does not match this run/);
    assert.equal(page.requests.length, 1);
  }
  for (const records of [
    [credential(owned), credential(owned, { id: 'duplicate' })],
    [credential(owned, { organization_id: 'foreign-org' })],
    [credential(owned, { application_id: 'other-application' })],
    [credential(owned, { flow_execution_id: 'other-transaction' })],
    [credential(owned, { credential_template_id: 'other-template' })],
  ]) {
    const page = fakePage([
      { ok: true, status: 200, body: application(owned) },
      { ok: true, status: 200, body: [transaction(owned)] },
      { ok: true, status: 200, body: records },
    ]);
    await assert.rejects(cleanupApplicationCredential(page, { ...owned }, 'cleanup'), /ambiguous|outside.*organization|does not match/);
    assert.equal(page.requests.length, 3);
    assert.ok(page.requests.every(({ requestOptions }) => !requestOptions.method));
  }
  assert.throws(() => selectApplicationTransaction([
    transaction(owned), transaction(owned, { id: 'second-transaction' }),
  ], owned), /multiple issuance transactions/);
  assert.throws(() => selectApplicationTransaction([transaction(owned, { organization_id: 'foreign-org' })], owned), /outside.*organization/);
});

test('cleanup recovers an uncertain issuance and preserves its application after exact revocation readback', async () => {
  const owned = ownedRun({ transactionId: null, credentialId: null, uncertainMutations: [{ operation: 'issuance' }] });
  const page = fakePage([
    { ok: true, status: 200, body: application(owned) },
    { ok: true, status: 200, body: [transaction(owned)] },
    { ok: true, status: 200, body: [
      credential(owned), credential(owned, { id: 'newer-unrelated', application_id: 'other-application', flow_execution_id: 'other-transaction' }),
    ] },
    { ok: true, status: 200, body: credential(owned, { status: 'REVOKED' }) },
    { ok: true, status: 200, body: [transaction(owned)] },
    { ok: true, status: 200, body: [credential(owned, { status: 'REVOKED' })] },
    { ok: true, status: 200, body: application(owned, { status: 'CREDENTIALED' }) },
  ]);
  const result = await cleanupApplicationCredential(page, owned, 'release qualification cleanup');
  assert.equal(result.ok, true);
  assert.equal(result.credentialRevoked, true);
  assert.equal(result.applicationWithdrawn, false);
  assert.equal(result.applicationHistoryPreserved, true);
  assert.equal(result.applicationStatus, 'CREDENTIALED');
  assert.equal(owned.transactionId, 'transaction/1');
  assert.equal(owned.credentialId, 'credential/1');
  assert.deepEqual(owned.uncertainMutations, []);
  assert.deepEqual(page.requests.map(({ requestPath, requestOptions }) => [requestOptions.method || 'GET', requestPath]), [
    ['GET', '/v1/organizations/org%2F1/applicants/application%2F1'],
    ['GET', '/v1/issuance?organization_id=org%2F1'],
    ['GET', '/v1/issued-credentials?organization_id=org%2F1'],
    ['POST', '/v1/issued-credentials/credential%2F1/revoke'],
    ['GET', '/v1/issuance?organization_id=org%2F1'],
    ['GET', '/v1/issued-credentials?organization_id=org%2F1'],
    ['GET', '/v1/organizations/org%2F1/applicants/application%2F1'],
  ]);
});

test('explicit pending-offer cleanup requires revoked readback and retains application history', async () => {
  for (const status of ['revoked', 'pending']) {
    const owned = ownedRun({ credentialId: null });
    const page = fakePage([
      { ok: true, status: 200, body: application(owned) },
      { ok: true, status: 200, body: [transaction(owned, { status: 'pending' })] },
      { ok: true, status: 200, body: [] },
      { ok: true, status: 200, body: application(owned) },
      { ok: true, status: 200, body: transaction(owned, { status: 'pending' }) },
      { ok: true, status: 200, body: [] },
      { ok: true, status: 200, body: { status: 'revoked' } },
      { ok: true, status: 200, body: transaction(owned, { status }) },
      { ok: true, status: 200, body: [transaction(owned, { status })] },
      { ok: true, status: 200, body: transaction(owned, { status }) },
      { ok: true, status: 200, body: [] },
      { ok: true, status: 200, body: application(owned) },
    ]);
    const result = await cleanupApplicationCredential(page, owned, 'Owned failed wallet offer', { cancelPendingOffer: true });
    assert.equal(result.ok, status === 'revoked');
    assert.equal(result.applicationHistoryPreserved, true);
    assert.equal(result.applicationWithdrawn, false);
    assert.ok(page.requests.every(r => !r.requestPath.endsWith('/withdraw')));
    assert.equal(page.requests.filter(r => r.requestOptions.method === 'POST').length, 1);
    if (status === 'pending') assert.deepEqual(owned.uncertainMutations, [{ operation: 'transaction_cancellation' }]);
  }
});

test('an outstanding offer, uncertain creation, or unconfirmed reviewer lock prevents complete cleanup', async () => {
  const unknown = ownedRun({ applicationId: null, transactionId: null, credentialId: null, uncertainMutations: [{ operation: 'application_creation' }] });
  const empty = fakePage([]);
  assert.equal((await cleanupApplicationCredential(empty, unknown, 'cleanup')).ok, false);
  assert.equal(empty.requests.length, 0);
  const owned = ownedRun({ credentialId: null });
  const page = fakePage([
    { ok: true, status: 200, body: application(owned) },
    { ok: true, status: 200, body: [transaction(owned, { status: 'pending' })] },
    { ok: true, status: 200, body: [] },
    { ok: true, status: 200, body: [transaction(owned, { status: 'pending' })] },
    { ok: true, status: 200, body: transaction(owned, { status: 'pending' }) },
    { ok: true, status: 200, body: [] },
    { ok: true, status: 200, body: application(owned) },
  ]);
  const result = await cleanupApplicationCredential(page, owned, 'cleanup');
  assert.equal(result.ok, false);
  assert.equal(result.applicationWithdrawn, false);
  assert.deepEqual(result.pendingTransactionIds, ['transaction/1']);
  assert.ok(page.requests.every(({ requestPath }) => !requestPath.endsWith('/revoke')));

  const locked = ownedRun({
    transactionId: null,
    credentialId: null,
    uncertainMutations: [{ operation: 'reviewer_lock' }],
  });
  const lockPage = fakePage([
    { ok: true, status: 200, body: application(locked, { status: 'SUBMITTED' }) },
    { ok: true, status: 200, body: [] },
    { ok: true, status: 200, body: application(locked, { status: 'WITHDRAWN' }) },
    { ok: true, status: 200, body: application(locked, { status: 'WITHDRAWN' }) },
  ]);
  const lockCleanup = await cleanupApplicationCredential(lockPage, locked, 'cleanup');
  assert.equal(lockCleanup.applicationWithdrawn, true);
  assert.equal(lockCleanup.ok, false);
  assert.deepEqual(lockCleanup.uncertainMutations, [{ operation: 'reviewer_lock' }]);
});

test('a successful HTTP status without confirmed mutation state is not successful cleanup', async () => {
  const owned = ownedRun();
  const page = fakePage([
    { ok: true, status: 200, body: application(owned) },
    { ok: true, status: 200, body: [transaction(owned)] },
    { ok: true, status: 200, body: [credential(owned)] },
    { ok: true, status: 200, body: {} },
    { ok: true, status: 200, body: [transaction(owned)] },
    { ok: true, status: 200, body: [credential(owned)] },
    { ok: true, status: 200, body: application(owned) },
  ]);
  const result = await cleanupApplicationCredential(page, owned, 'cleanup');
  assert.equal(result.ok, false);
  assert.equal(result.credentialRevoked, false);
  assert.equal(result.applicationWithdrawn, false);
  assert.equal(result.applicationHistoryPreserved, true);
  assert.deepEqual(result.failures, [{ operation: 'revoke', id: 'credential/1', status: 200 }]);
});

test('lost credential revoke response is resolved only by exact REVOKED readback', async () => {
  for (const status of ['REVOKED', 'ACTIVE']) {
    const owned = ownedRun();
    const page = fakePage([
      { ok: true, status: 200, body: application(owned) },
      { ok: true, status: 200, body: [transaction(owned)] },
      { ok: true, status: 200, body: [credential(owned)] },
      new Error('Lost revoke response'),
      { ok: true, status: 200, body: [transaction(owned)] },
      { ok: true, status: 200, body: [credential(owned, { status })] },
      { ok: true, status: 200, body: application(owned) },
    ]);
    const result = await cleanupApplicationCredential(page, owned, 'cleanup');
    assert.equal(result.ok, status === 'REVOKED');
    assert.equal(result.credentialRevoked, status === 'REVOKED');
    assert.equal(result.applicationWithdrawn, false);
    assert.deepEqual(owned.uncertainMutations, status === 'REVOKED' ? [] : [{ operation: 'credential_revocation' }]);
    assert.deepEqual(page.requests.filter(({ requestOptions }) => requestOptions.method).map(({ requestPath }) => requestPath), [
      '/v1/issued-credentials/credential%2F1/revoke',
    ]);
  }
});

test('revoked unused offers retain exact application history without a withdrawal', async () => {
  const owned = ownedRun({ credentialId: null });
  const page = fakePage([
    { ok: true, status: 200, body: application(owned) },
    { ok: true, status: 200, body: [transaction(owned, { status: 'revoked' })] },
    { ok: true, status: 200, body: [] },
    { ok: true, status: 200, body: [transaction(owned, { status: 'revoked' })] },
    { ok: true, status: 200, body: transaction(owned, { status: 'revoked' }) },
    { ok: true, status: 200, body: [] },
    { ok: true, status: 200, body: application(owned, { claim_state: 'EXPIRED' }) },
  ]);
  const result = await cleanupApplicationCredential(page, owned, 'cleanup');
  assert.equal(result.ok, true);
  assert.equal(result.transactionRevoked, true);
  assert.equal(result.credentialRevoked, false);
  assert.equal(result.applicationHistoryPreserved, true);
  assert.equal(result.applicationWithdrawn, false);
  assert.ok(page.requests.every(({ requestOptions }) => !requestOptions.method));
});

test('credential retirement cannot hide a withdrawn, foreign, or unknown application readback', async () => {
  for (const change of [
    { status: 'WITHDRAWN' }, { status: 'UNKNOWN' },
    { organization_id: 'foreign-org' }, { integration_context: { demo_run_id: 'foreign-run' } },
  ]) {
    const owned = ownedRun();
    const page = fakePage([
      { ok: true, status: 200, body: application(owned) },
      { ok: true, status: 200, body: [transaction(owned)] },
      { ok: true, status: 200, body: [credential(owned, { status: 'REVOKED' })] },
      { ok: true, status: 200, body: [transaction(owned)] },
      { ok: true, status: 200, body: [credential(owned, { status: 'REVOKED' })] },
      { ok: true, status: 200, body: application(owned, change) },
    ]);
    const result = await cleanupApplicationCredential(page, owned, 'cleanup');
    assert.equal(result.ok, false);
    assert.equal(result.applicationHistoryPreserved, false);
    assert.equal(result.applicationWithdrawn, false);
    assert.ok(result.failures.length > 0);
    assert.ok(page.requests.every(({ requestOptions }) => !requestOptions.method));
  }
});

test('retirement readback rejects late transactions or credentials and unresolved terminal offers', async () => {
  for (const status of ['pending', 'authorized', 'failed', 'expired', 'issued', 'unknown']) {
    const owned = ownedRun({ credentialId: null });
    const page = fakePage([
      { ok: true, status: 200, body: application(owned) },
      { ok: true, status: 200, body: [transaction(owned, { status })] },
      { ok: true, status: 200, body: [] },
      { ok: true, status: 200, body: [transaction(owned, { status })] },
      { ok: true, status: 200, body: transaction(owned, { status }) },
      { ok: true, status: 200, body: [] },
      { ok: true, status: 200, body: application(owned) },
    ]);
    const result = await cleanupApplicationCredential(page, owned, 'cleanup');
    assert.equal(result.ok, false, status);
    assert.deepEqual(result.pendingTransactionIds, [owned.transactionId], status);
    assert.equal(result.applicationWithdrawn, false);
    assert.ok(page.requests.every(({ requestOptions }) => !requestOptions.method));
  }
  const owned = ownedRun({ credentialId: null });
  const page = fakePage([
    { ok: true, status: 200, body: application(owned) },
    { ok: true, status: 200, body: [transaction(owned, { status: 'revoked' })] },
    { ok: true, status: 200, body: [] },
    { ok: true, status: 200, body: [transaction(owned, { status: 'issued' })] },
    { ok: true, status: 200, body: transaction(owned, { status: 'issued' }) },
    { ok: true, status: 200, body: [credential(owned)] },
    { ok: true, status: 200, body: application(owned) },
  ]);
  const result = await cleanupApplicationCredential(page, owned, 'cleanup');
  assert.equal(result.ok, false);
  assert.equal(result.credentialRevoked, false);
  assert.equal(result.transactionRevoked, false);
  assert.ok(result.failures.length > 0);
  assert.ok(page.requests.every(({ requestOptions }) => !requestOptions.method));
  for (const issuedMarker of ['application', 'transaction-detail']) {
    const missing = ownedRun({ credentialId: null });
    const missingPage = fakePage([
      { ok: true, status: 200, body: application(missing) },
      { ok: true, status: 200, body: [transaction(missing, { status: 'revoked', issued_at: null })] },
      { ok: true, status: 200, body: [] },
      { ok: true, status: 200, body: [transaction(missing, { status: 'revoked', issued_at: null })] },
      { ok: true, status: 200, body: transaction(missing, { status: 'revoked',
        issued_at: issuedMarker === 'transaction-detail' ? '2026-10-20T00:00:00Z' : null }) },
      { ok: true, status: 200, body: [] },
      { ok: true, status: 200, body: application(missing, issuedMarker === 'application'
        ? { status: 'CREDENTIALED', claim_state: 'CLAIMED' } : {}) },
    ]);
    const absentCredential = await cleanupApplicationCredential(missingPage, missing, 'cleanup');
    assert.equal(absentCredential.ok, false, issuedMarker);
    assert.equal(absentCredential.transactionRevoked, false, issuedMarker);
    assert.deepEqual(absentCredential.failures, [{ operation: 'locate_credential', id: missing.applicationId, status: 200 }]);
    assert.ok(missingPage.requests.some(({ requestPath }) => requestPath === '/v1/issuance/transaction%2F1?organization_id=org%2F1'));
  }
});

test('an approved application with unknown issuance cannot turn a Rust withdrawal conflict into cleanup', async () => {
  const owned = ownedRun({ transactionId: null, credentialId: null });
  const page = fakePage([
    { ok: true, status: 200, body: application(owned, { status: 'APPROVED' }) },
    { ok: true, status: 200, body: [] },
    { ok: false, status: 409, body: { detail: 'Issuance reconciliation is required' } },
    { ok: true, status: 200, body: application(owned, { status: 'APPROVED' }) },
  ]);
  const result = await cleanupApplicationCredential(page, owned, 'cleanup');
  assert.equal(result.ok, false);
  assert.equal(result.applicationWithdrawn, false);
  assert.equal(result.applicationHistoryPreserved, false);
  assert.deepEqual(result.failures, [{ operation: 'withdraw', id: owned.applicationId, status: 409 }]);
  assert.deepEqual(result.uncertainMutations, []);
});

test('pending offer cancellation proves application ownership and exact revoked transaction readback', async () => {
  const owned = ownedRun({ credentialId: null });
  const page = fakePage([
    { ok: true, status: 200, body: application(owned) },
    { ok: true, status: 200, body: transaction(owned, { status: 'pending' }) },
    { ok: true, status: 200, body: [] },
    { ok: true, status: 200, body: { id: owned.transactionId, status: 'revoked' } },
    { ok: true, status: 200, body: transaction(owned, { status: 'revoked' }) },
  ]);
  const result = await cancelOwnedIssuanceTransaction(page, owned, 'Owned demo offer cleanup');
  assert.equal(result.ok, true);
  assert.equal(result.scope, 'TRANSACTION_CANCELLATION_ONLY');
  assert.equal(result.applicationId, owned.applicationId);
  assert.deepEqual(owned.uncertainMutations, []);
  assert.deepEqual(page.requests.slice(3).map(({ requestPath, requestOptions }) => [requestOptions.method || 'GET', requestPath]), [
    ['POST', '/v1/issuance/transaction%2F1/revoke'],
    ['GET', '/v1/issuance/transaction%2F1?organization_id=org%2F1'],
  ]);
});

test('pending cancellation refuses foreign bindings and existing credential records before mutations', async () => {
  const owned = ownedRun({ applicationId: null, credentialId: null });
  for (const extra of [
    { id: 'foreign-transaction' }, { organization_id: 'foreign-org' },
    { credential_template_id: 'foreign-template' }, { application_id: 'foreign-application' },
  ]) {
    const page = fakePage([{ ok: true, status: 200, body: transaction(owned, extra) }]);
    await assert.rejects(cancelOwnedIssuanceTransaction(page, owned, 'cleanup'), /exact owned/);
    assert.ok(page.requests.every(({ requestOptions }) => !requestOptions.method));
  }
  const page = fakePage([
    { ok: true, status: 200, body: transaction(owned, { status: 'pending' }) },
    { ok: true, status: 200, body: [credential(owned)] },
  ]);
  await assert.rejects(cancelOwnedIssuanceTransaction(page, owned, 'cleanup'), /credential exists/);
  assert.equal(page.requests.length, 2);
  assert.ok(page.requests.every(({ requestOptions }) => !requestOptions.method));
  const wrongRun = ownedRun({ credentialId: null });
  const applicationPage = fakePage([{ ok: true, status: 200, body: application(wrongRun, {
    integration_context: { demo_run_id: 'prior-run' },
  }) }]);
  await assert.rejects(cancelOwnedIssuanceTransaction(applicationPage, wrongRun, 'cleanup'), /does not match this run/);
  assert.equal(applicationPage.requests.length, 1);
});

test('lost cancellation response is reconciled only by the exact public revoked readback', async () => {
  for (const confirmed of [true, false]) {
    const owned = ownedRun({ applicationId: null, credentialId: null });
    const page = fakePage([
      { ok: true, status: 200, body: transaction(owned, { status: 'pending' }) },
      { ok: true, status: 200, body: [] },
      { ok: false, status: 0, body: null },
      { ok: true, status: 200, body: transaction(owned, {
        status: 'revoked', ...(confirmed ? {} : { credential_template_id: 'foreign-template' }),
      }) },
    ]);
    const result = await cancelOwnedIssuanceTransaction(page, owned, 'cleanup');
    assert.equal(result.ok, confirmed);
    assert.equal(result.responseStatus, 0);
    assert.deepEqual(owned.uncertainMutations, confirmed ? [] : [{ operation: 'transaction_cancellation' }]);
    assert.equal(page.requests.filter(({ requestOptions }) => requestOptions.method === 'POST').length, 1);
  }
});

test('HTTP success with a pending readback cannot clear transaction cancellation uncertainty', async () => {
  const owned = ownedRun({ applicationId: null, credentialId: null });
  const page = fakePage([
    { ok: true, status: 200, body: transaction(owned, { status: 'pending' }) },
    { ok: true, status: 200, body: [] },
    { ok: true, status: 200, body: { id: owned.transactionId, status: 'revoked' } },
    { ok: true, status: 200, body: transaction(owned, { status: 'pending' }) },
  ]);
  assert.equal((await cancelOwnedIssuanceTransaction(page, owned, 'cleanup')).ok, false);
  assert.deepEqual(owned.uncertainMutations, [{ operation: 'transaction_cancellation' }]);
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
