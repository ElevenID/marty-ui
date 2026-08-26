'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
  identityRequest,
  transitService,
  writableConfig,
} = require('./audit-beta-issuer-provider-switch');

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
