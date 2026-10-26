'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const {
  cleanup,
  prepareProviderInputs,
  managedTransitEndpoint,
  externalTransitPrerequisites,
  existingProviderBInput,
  boundExistingProviderB,
  managedBindingHash,
  matchesManagedBinding,
  verifySelectedIssuerBinding,
  observedRemoteSigner,
  restoredConfigurationEvidence,
  governedIssuerRequest,
  identityRequest,
  transitService,
  writableConfig,
} = require('./audit-beta-issuer-provider-switch');

test('preprovisioned provider B requires exact identity and a distinct supported signer', async () => {
  assert.equal(existingProviderBInput({}), null);
  assert.throws(() => existingProviderBInput({ D02_EXISTING_PROVIDER_B_SERVICE_ID: 'b' }), /exact nonsecret/);
  const expected = existingProviderBInput({
    D02_EXISTING_PROVIDER_B_SERVICE_ID: 'existing-vault',
    D02_EXISTING_PROVIDER_B_SERVICE_TYPE: 'hashicorp-vault-transit',
    D02_EXISTING_PROVIDER_B_PROVIDER: 'hashicorp-vault',
    D02_EXISTING_PROVIDER_B_KEY_REFERENCE: 'issuer-b',
  });
  assert.equal(existingProviderBInput({
    D02_EXISTING_PROVIDER_B_SERVICE_ID: 'aws-b',
    D02_EXISTING_PROVIDER_B_SERVICE_TYPE: 'aws-kms',
    D02_EXISTING_PROVIDER_B_PROVIDER: 'aws',
    D02_EXISTING_PROVIDER_B_KEY_REFERENCE: 'arn:aws:kms:us-east-1:123456789012:key/1234',
  }).keyReference, 'arn:aws:kms:us-east-1:123456789012:key/1234');
  const service = {
    id: expected.serviceId, service_type: expected.serviceType, provider: expected.provider,
    key_reference: expected.keyReference, endpoint: 'https://vault.example.test:8200',
    status: 'configured', algorithms: ['ES256'], key_purposes: ['vc_jwt_issuer'],
  };
  const baseline = 'https://openbao:8200';
  assert.equal(boundExistingProviderB({ services: [service] }, expected, baseline), service);
  const selected = writableConfig({ services: [service], default_service_id: 'managed-openbao-transit' }, {
    defaultServiceId: service.id, resetDefaults: true,
  });
  assert.equal(selected.services[0], service);
  assert.equal(selected.default_service_id, service.id);
  assert.throws(() => boundExistingProviderB({ services: [] }, expected, baseline), /missing or ambiguous/);
  assert.throws(() => boundExistingProviderB({ services: [service, service] }, expected, baseline), /missing or ambiguous/);
  assert.throws(() => boundExistingProviderB({ services: [{ ...service, provider: 'openbao' }] }, expected, baseline), /does not match/);
  assert.throws(() => boundExistingProviderB({ services: [service] }, { ...expected, provider: 'openbao' }, baseline), /supported distinct/);
  assert.throws(() => boundExistingProviderB({ services: [{ ...service, endpoint: baseline }] }, expected, baseline), /does not match/);
  assert.throws(() => boundExistingProviderB({ services: [{ ...service, key_reference: 'wrong' }] }, expected, baseline), /does not match/);
  assert.throws(() => boundExistingProviderB({ services: [{ ...service, status: 'disabled' }] }, expected, baseline), /does not match/);
  const bound = { selectedServiceBound: true, issuedSignatureMatchesBoundKey: true };
  const resolved = {
    identity: { issuer_did: 'did:example:issuer' }, public_jwk: { kty: 'EC' },
    managed_key_binding_sha256: managedBindingHash(
      process.env.BETA_AUDIT_ORG_ID || '00000000-0000-0000-0000-000000000001',
      service.id, service.key_reference,
    ),
  };
  assert.equal(matchesManagedBinding(resolved, 'did:example:issuer', service.id, service.key_reference), true);
  assert.equal(matchesManagedBinding(resolved, 'did:example:issuer', 'old-service', service.key_reference), false);
  assert.equal(matchesManagedBinding(resolved, 'did:example:issuer', service.id, 'old-key'), false);
  await assert.rejects(
    verifySelectedIssuerBinding(
      fakePage([{ ok: true, status: 200, body: resolved }]),
      'did:example:issuer', { ...service, id: 'old-service' }, { credential: 'unused' },
    ),
    /does not match selected signing service and key/,
  );
  assert.equal(observedRemoteSigner(null, { ok: true }, { verified: true }, service.id, service.id, bound), false);
  assert.equal(observedRemoteSigner(expected, { ok: true }, { verified: true }, service.id, service.id, null), false);
  assert.equal(observedRemoteSigner(expected, { ok: true }, { verified: true }, 'old-service', service.id, bound), false);
  assert.equal(observedRemoteSigner(expected, { ok: true }, { verified: true }, service.id, service.id, bound), true);
});
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
  const replacement = transitService('provider-b', 'Provider B', 'issuer-b', 'https://openbao:8200', { token: 'test-scoped-token', caCertFile: '/run/secrets/openbao_tls_ca_cert' });
  const payload = writableConfig(original, {
    extraServices: [replacement],
    defaultServiceId: 'provider-b',
  });
  assert.deepEqual(payload.services.map(({ id }) => id), ['existing-provider', 'provider-b']);
  assert.equal(payload.default_service_id, 'provider-b');
  assert.deepEqual(payload.format_defaults, original.format_defaults);
  assert.deepEqual(payload.type_defaults, original.type_defaults);
  assert.deepEqual(payload.key_reference_purposes, original.key_reference_purposes);
  assert.equal(replacement.auth_mode, 'token');
  assert.equal(replacement.endpoint, 'https://openbao:8200');
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

test('provider input acknowledgement supplies the actual owned identity and service IDs before actions', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'd02-live-input-'));
  const events = [];
  try {
    const client = {
      readFixture: async (file) => {
        events.push(['read', file]);
        return fs.readFileSync(path.join(directory, file));
      },
      seal: async () => { events.push(['seal']); },
    };
    const input = await prepareProviderInputs(directory, 'owned-stamp', client);
    assert.equal(input.issuerDid, 'did:web:beta.elevenidllc.com:orgs:d02-provider-switch-owned-stamp');
    assert.equal(input.providerBId, 'd02-provider-b-owned-stamp');
    assert.equal(input.providerCId, 'd02-provider-unpublished-owned-stamp');
    assert.ok(input.organizationId && input.sourceTemplateId);
    assert.deepEqual(events, [['read', 'provider-switch-fixture-input.json'], ['seal']]);
    assert.equal(JSON.stringify(input).includes('TOKEN'), false);
    await assert.rejects(() => prepareProviderInputs(directory, 'reused-stamp', client), /EEXIST/);
  } finally {
    fs.rmSync(directory, { recursive: true });
  }
});

test('provider input acknowledgement rejects changed bytes without sealing the fixture', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'd02-live-input-'));
  let sealed = false;
  try {
    await assert.rejects(() => prepareProviderInputs(directory, 'owned-stamp', {
      readFixture: async () => Buffer.from(JSON.stringify({ schemaVersion: 1, stamp: 'different-input' })),
      seal: async () => { sealed = true; },
    }), /fixture differs/);
    assert.equal(sealed, false);
  } finally {
    fs.rmSync(directory, { recursive: true });
  }
});

test('provider switch preserves deployed transit transport and rejects missing or unsafe endpoints', () => {
  const config = (endpoint) => ({ services: [{ id: 'managed-openbao-transit', endpoint }] });
  for (const endpoint of ['https://openbao:8200', 'http://openbao:8200']) {
    assert.equal(managedTransitEndpoint(config(endpoint)), endpoint);
  }
  for (const endpoint of [undefined, '', 'file:///tmp/key', 'https://user:secret@openbao:8200', 'https://openbao:8200?token=secret']) {
    assert.throws(() => managedTransitEndpoint(config(endpoint)), /endpoint is invalid/);
  }
  assert.throws(() => managedTransitEndpoint({ services: [] }), /one managed transit/);
  assert.throws(() => transitService('b', 'B', 'key'), /endpoint is invalid/);
});


test('external beta transit fixture fails closed without scoped token and explicit CA', () => {
 const env={BETA_ORIGIN:'https://beta.elevenidllc.com',D02_SAME_BACKEND_FIXTURE:'1',D02_EXTERNAL_TRANSIT_ENDPOINT:'https://openbao:8200',D02_EXTERNAL_TRANSIT_CA_FILE:'/run/secrets/openbao_tls_ca_cert',D02_EXTERNAL_TRANSIT_KEY:'d02-external-test',D02_EXTERNAL_TRANSIT_TOKEN:'test-scoped-token'};
 assert.equal(externalTransitPrerequisites(env).keyReference,'d02-external-test');
 for(const change of [{BETA_ORIGIN:'https://elevenidllc.com'},{D02_SAME_BACKEND_FIXTURE:'0'},{D02_EXTERNAL_TRANSIT_CA_FILE:''},{D02_EXTERNAL_TRANSIT_TOKEN:''},{D02_EXTERNAL_TRANSIT_KEY:'production-key'}]) assert.throws(()=>externalTransitPrerequisites({...env,...change}),/Scoped beta/);
 assert.throws(()=>transitService('b','B','key','https://openbao:8200'),/explicit token/);
 assert.throws(()=>transitService('b','B','key','http://openbao:8200',{token:'test',caCertFile:'/ca'}),/HTTPS CA/);
});


test('restoration permits only the exact newly-created non-exportable key record', () => {
 const original={services:[],default_service_id:'managed-openbao-transit',key_reference_purposes:{'managed-openbao-transit':{existing:['vc_jwt_issuer']}}};
 const after=structuredClone(original);after.key_reference_purposes['managed-openbao-transit'].created=['vc_jwt_issuer'];
 assert.equal(restoredConfigurationEvidence(original,after,['created']).ok,true);
 assert.equal(restoredConfigurationEvidence(original,original,['not-retained']).ok,true);
 assert.equal(restoredConfigurationEvidence(original,after,[]).ok,false);
 for(const mutate of [c=>c.default_service_id='other',c=>c.services.push({id:'leaked-provider'}),c=>c.key_reference_purposes['managed-openbao-transit'].existing=['other'],c=>c.key_reference_purposes['managed-openbao-transit'].unexpected=['vc_jwt_issuer']]) {const changed=structuredClone(after);mutate(changed);assert.equal(restoredConfigurationEvidence(original,changed,['created']).ok,false);}
});
