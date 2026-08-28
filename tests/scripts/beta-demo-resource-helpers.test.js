'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
  DEFAULT_CREDENTIAL_RANKING_STRATEGY,
  cleanupApplicationCredential,
  compactObject,
  ensureActiveResource,
  ensureGovernedIssuer,
  governedIssuerTrustProfilePayload,
  requestedClaim,
  requireJson,
  resolveActiveIssuerDid,
  safeErrorDetail,
  selectOrganization,
  withdrawConflictingApplications,
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

test('withdrawConflictingApplications retires only active matching application transactions', async () => {
  const applicantPage = fakePage([{
    ok: true,
    status: 200,
    body: {
      items: [
        { id: 'active/1', organization_id: 'org/1', credential_template_id: 'credential/1', status: 'APPROVED' },
        { id: 'withdrawn/1', organization_id: 'org/1', credential_template_id: 'credential/1', status: 'WITHDRAWN' },
        { id: 'other-template', organization_id: 'org/1', credential_template_id: 'credential/2', status: 'SUBMITTED' },
        { id: 'other-org', organization_id: 'org/2', credential_template_id: 'credential/1', status: 'DRAFT' },
      ],
    },
  }]);
  const adminPage = fakePage([{ ok: true, status: 200, body: { status: 'WITHDRAWN' } }]);

  const result = await withdrawConflictingApplications(applicantPage, adminPage, {
    organizationId: 'org/1',
    credentialTemplateId: 'credential/1',
    reason: 'interrupted qualification cleanup',
  });

  assert.deepEqual(result, [{ id: 'active/1', previousStatus: 'APPROVED' }]);
  assert.deepEqual(applicantPage.requests, [{
    requestPath: '/v1/me/applications?limit=500',
    requestOptions: {},
  }]);
  assert.deepEqual(adminPage.requests, [{
    requestPath: '/v1/organizations/org%2F1/applicants/active%2F1/withdraw',
    requestOptions: {
      method: 'POST',
      body: JSON.stringify({ reason: 'interrupted qualification cleanup' }),
    },
  }]);
});

test('withdrawConflictingApplications fails closed on malformed collections', async () => {
  const applicantPage = fakePage([{ ok: true, status: 200, body: [] }]);
  await assert.rejects(() => withdrawConflictingApplications(applicantPage, fakePage([]), {
    organizationId: 'org-1',
    credentialTemplateId: 'credential-1',
    reason: 'cleanup',
  }), /malformed collection/);
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
