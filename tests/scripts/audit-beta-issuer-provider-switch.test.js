'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
  cleanup,
  governedIssuerRequest,
  identityRequest,
  transitService,
  writableConfig,
} = require('./audit-beta-issuer-provider-switch');
const {
  validateElevenIdLoginTheme,
} = require('./audit-beta-credential-lifecycle');

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

test('provider-switch configuration is lossless and never persists the managed projection', () => {
  const original = {
    services: [
      { id: 'managed-openbao-transit', managed: true },
      { id: 'existing-provider', managed: false },
    ],
    default_service_id: 'existing-provider',
    format_defaults: { 'dc+sd-jwt': 'existing-provider' },
    type_defaults: { vc_jwt_issuer: 'existing-provider' },
    key_reference_purposes: { 'existing-provider': { issuer: ['vc_jwt_issuer'] } },
  };
  const replacement = transitService('provider-b', 'Provider B', 'issuer-b');
  const payload = writableConfig(original, {
    extraServices: [replacement],
    defaultServiceId: 'provider-b',
  });
  assert.deepEqual(payload.services.map(({ id }) => id), ['existing-provider', 'provider-b']);
  assert.equal(payload.default_service_id, 'provider-b');
  assert.deepEqual(payload.format_defaults, original.format_defaults);
  assert.deepEqual(payload.type_defaults, original.type_defaults);
  assert.deepEqual(payload.key_reference_purposes, original.key_reference_purposes);
  assert.equal(replacement.auth_mode, 'service_token');
  assert.equal(replacement.endpoint, 'http://openbao:8200');
});

test('release recordings fail closed unless the ElevenID Keycloak theme rendered', () => {
  assert.deepEqual(validateElevenIdLoginTheme({
    stylesheet: '/resources/revision/login/11id/css/marty.css',
    appBar: true,
    brand: 'ElevenID LLC',
  }), {
    stylesheet: '/resources/revision/login/11id/css/marty.css',
    appBar: true,
    brand: 'ElevenID LLC',
    ok: true,
  });
  assert.throws(
    () => validateElevenIdLoginTheme({ stylesheet: null, appBar: false, brand: null }),
    /did not load the ElevenID login theme stylesheet/,
  );
  assert.throws(
    () => validateElevenIdLoginTheme({
      stylesheet: '/resources/revision/login/11id/css/marty.css',
      appBar: false,
      brand: null,
    }),
    /did not render the ElevenID login theme shell/,
  );
});

test('public rebind request contains only the complete DID tuple', () => {
  const request = identityRequest('did:web:beta.example:orgs:d02');
  assert.deepEqual(request, {
    organization_id:
      process.env.BETA_AUDIT_ORG_ID || '00000000-0000-0000-0000-000000000001',
    issuer_did: 'did:web:beta.example:orgs:d02',
    key_purpose: 'vc_jwt_issuer',
    credential_format: 'SD_JWT_VC',
    algorithm: 'ES256',
  });
  assert.deepEqual(Object.keys(request).sort(), [
    'algorithm',
    'credential_format',
    'issuer_did',
    'key_purpose',
    'organization_id',
  ]);
});

test('provider-switch governance uses the source template Trust Profile', () => {
  const request = governedIssuerRequest(
    { trust_profile_id: 'trust-profile-1' },
    'did:web:beta.example:orgs:d02',
    'release-stamp',
  );
  assert.equal(request.trustProfileId, 'trust-profile-1');
  assert.equal(request.issuerDid, 'did:web:beta.example:orgs:d02');
  assert.equal(request.idempotencyKey, 'd02-governed-issuer-release-stamp');
  assert.throws(
    () => governedIssuerRequest({}, 'did:web:beta.example:orgs:d02', 'release-stamp'),
    /lacks a Trust Profile binding/,
  );
});

test('provider-switch cleanup retires active resources in dependency order', async () => {
  const page = fakePage([
    { ok: true, status: 200, body: [{ id: 'credential-1', credential_template_id: 'template-1', status: 'ACTIVE' }] },
    { ok: true, status: 200, body: {} },
    { ok: true, status: 200, body: { id: 'template-1', status: 'ACTIVE' } },
    { ok: true, status: 200, body: {} },
    { ok: true, status: 200, body: {} },
    { ok: true, status: 200, body: {} },
    { ok: true, status: 200, body: {} },
    { ok: true, status: 200, body: {} },
  ]);
  const result = await cleanup(page, 'template-1', ['did:example:one', 'did:example:two'], {
    trustProfileId: 'trust-1',
    relationshipCreated: true,
    relationship: { id: 'relationship-1' },
    created: true,
    issuer: { id: 'issuer-1' },
  });

  assert.deepEqual(result, {
    retiredTemplate: true,
    templateRetirement: 'deprecated',
    revokedCredentials: 1,
    removedGovernanceRelationships: 1,
    removedGovernedIssuers: 1,
    retiredIdentities: 2,
  });
  assert.deepEqual(page.requests.map(({ requestPath, requestOptions }) => [
    requestOptions.method || 'GET', requestPath,
  ]), [
    ['GET', `/v1/issued-credentials?organization_id=${encodeURIComponent(identityRequest('did:example:one').organization_id)}`],
    ['POST', '/v1/issued-credentials/credential-1/revoke'],
    ['GET', '/v1/credential-templates/template-1'],
    ['POST', '/v1/credential-templates/template-1/deprecate'],
    ['DELETE', '/v1/trust-profiles/trust-1/issuers/relationship-1'],
    ['DELETE', '/v1/issuer-entities/issuer-1'],
    ['DELETE', `/v1/signing-keys/issuer-identities?organization_id=${encodeURIComponent(identityRequest('did:example:one').organization_id)}`],
    ['DELETE', `/v1/signing-keys/issuer-identities?organization_id=${encodeURIComponent(identityRequest('did:example:one').organization_id)}`],
  ]);
});

test('provider-switch cleanup deletes a draft left by a failed setup', async () => {
  const page = fakePage([
    { ok: true, status: 200, body: [] },
    { ok: true, status: 200, body: { id: 'draft-1', status: 'DRAFT' } },
    { ok: true, status: 200, body: {} },
    { ok: true, status: 200, body: {} },
  ]);
  const result = await cleanup(page, 'draft-1', ['did:example:failed']);
  assert.equal(result.retiredTemplate, true);
  assert.equal(result.templateRetirement, 'deleted');
  assert.equal(result.retiredIdentities, 1);
  assert.equal(page.requests[2].requestOptions.method, 'DELETE');
  assert.equal(page.requests[2].requestPath, '/v1/credential-templates/draft-1');
});
