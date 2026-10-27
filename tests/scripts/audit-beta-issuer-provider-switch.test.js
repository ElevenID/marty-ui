'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const vm = require('node:vm');

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
  loadSigningConfig,
  saveSigningConfig,
  unchangedOwnedRevision,
  createIdentity,
  directRebind,
  rebindThroughConsole,
  ownedIdentityRevision,
  createConfigMutationJournal,
} = require('./audit-beta-issuer-provider-switch');

function fakeConfigTransport(initial) {
  let config = structuredClone(initial);
  let generation = 1;
  let exposeEtag = true;
  let identityPatchFailure = null;
  const requests = [];
  const etag = () => `"r-00000000-0000-4000-8000-${String(generation).padStart(12, '0')}"`;
  const fetch = async (route, options) => {
    requests.push({ route, options });
    const method = options.method || 'GET';
    const identity = new URL(route, 'https://beta.example.test').pathname === '/v1/signing-keys/issuer-identities';
    let status = 200;
    let body = config;
    if (method === 'PATCH') {
      if (options.headers['If-Match'] !== etag()) status = 412;
      else if (identity && identityPatchFailure === 'before-bind') status = 503;
      else {
        if (identity) {
          config = { ...config, key_reference_purposes: { ...(config.key_reference_purposes || {}),
            'provider-b': { 'key-b': ['vc_jwt_issuer'] } } };
        } else config = JSON.parse(options.body);
        generation += 1;
        if (identity && identityPatchFailure === 'after-bind') status = 503;
      }
    }
    if (method === 'POST' && identity) {
      if (options.headers['If-Match'] !== etag()) status = 412;
      else {
        config = { ...config, key_reference_purposes: { 'managed-openbao-transit': {
          'owned-key': ['vc_jwt_issuer'] } } };
        generation += 1;
      }
    }
    if (identity && status === 200) body = { created: method === 'POST', changed: method === 'PATCH',
      identity: { issuer_did: JSON.parse(options.body).issuer_did }, config_revision: etag() };
    else body = config;
    return {
      ok: status === 200, status,
      json: async () => structuredClone(body),
      headers: { get: (name) => name === 'etag' && exposeEtag ? etag() : null },
    };
  };
  return {
    page: { evaluate: (fn, args) => vm.runInNewContext(`(${fn.toString()})`, { fetch })(args) },
    requests,
    current: () => structuredClone(config),
    externalEdit: (next) => { config = structuredClone(next); generation += 1; },
    omitEtag: () => { exposeEtag = false; },
    failIdentityPatch: (stage) => { identityPatchFailure = stage; },
  };
}

test('D02 config writes advance owned revisions and stale final restoration preserves another edit', async () => {
  const transport = fakeConfigTransport({ services: [{ id: 'provider-a' }], default_service_id: 'provider-a' });
  const original = await loadSigningConfig(transport.page);
  const providerB = await saveSigningConfig(transport.page,
    { ...original.config, default_service_id: 'provider-b' }, original.revision);
  const beforeNegative = unchangedOwnedRevision(await loadSigningConfig(transport.page), providerB.revision);
  const providerC = await saveSigningConfig(transport.page,
    { ...beforeNegative, default_service_id: 'provider-c' }, providerB.revision);
  assert.deepEqual(transport.requests.filter((request) => request.options.method === 'PATCH')
    .map((request) => request.options.headers['If-Match']), [original.revision, providerB.revision]);
  transport.externalEdit({ ...transport.current(), default_service_id: 'admin-edit' });
  await assert.rejects(saveSigningConfig(transport.page, original.config, providerC.revision), /HTTP 412/);
  assert.equal(transport.current().default_service_id, 'admin-edit');
  assert.throws(() => unchangedOwnedRevision({ revision: providerC.revision }, providerB.revision), /changed outside/);
});

test('D02 restore accepts only the last owned revision and missing ETag prevents mutation', async () => {
  const transport = fakeConfigTransport({ services: [{ id: 'provider-a' }], default_service_id: 'provider-a' });
  const original = await loadSigningConfig(transport.page);
  const changed = await saveSigningConfig(transport.page,
    { ...original.config, default_service_id: 'provider-b' }, original.revision);
  const restored = await saveSigningConfig(transport.page, original.config, changed.revision);
  assert.equal(restored.config.default_service_id, 'provider-a');
  assert.equal(transport.current().default_service_id, 'provider-a');
  const priorWrites = transport.requests.filter((request) => request.options.method === 'PATCH').length;
  transport.omitEtag();
  await assert.rejects(loadSigningConfig(transport.page), /no strong opaque revision/);
  await assert.rejects(saveSigningConfig(transport.page, original.config, null), /requires a strong opaque revision/);
  assert.equal(transport.requests.filter((request) => request.options.method === 'PATCH').length, priorWrites);
});

test('D02 managed identity and external rebind revisions remain owned and reject foreign mutation', async () => {
  const transport = fakeConfigTransport({ services: [{ id: 'provider-a' }], default_service_id: 'provider-a' });
  const original = await loadSigningConfig(transport.page);
  const created = await createIdentity(transport.page, 'did:web:beta.example.test:orgs:d02', 'owned-create', original.revision);
  const managedRevision = ownedIdentityRevision(created);
  assert.deepEqual(transport.current().key_reference_purposes['managed-openbao-transit']['owned-key'], ['vc_jwt_issuer']);
  const providerB = await saveSigningConfig(transport.page,
    { ...transport.current(), default_service_id: 'provider-b' }, managedRevision);
  const rebound = await directRebind(transport.page, 'did:web:beta.example.test:orgs:d02', providerB.revision);
  const reboundRevision = ownedIdentityRevision(rebound);
  assert.deepEqual(transport.current().key_reference_purposes['provider-b']['key-b'], ['vc_jwt_issuer']);
  transport.externalEdit({ ...transport.current(), default_service_id: 'admin-edit' });
  await assert.rejects(saveSigningConfig(transport.page, original.config, reboundRevision), /HTTP 412/);
  assert.equal(transport.current().default_service_id, 'admin-edit');
  assert.deepEqual(transport.requests.filter((request) => ['POST', 'PATCH'].includes(request.options.method))
    .map((request) => request.options.headers['If-Match']),
  [original.revision, managedRevision, providerB.revision, reboundRevision]);
});

test('D02 real UI rebind is intercepted once with the owned revision and fails on a foreign revision', async () => {
  const expected = '"r-00000000-0000-4000-8000-000000000001"';
  const issuerDid = 'did:web:beta.elevenidllc.com:orgs:d02';
  for (const current of [expected, '"r-00000000-0000-4000-8000-000000000002"']) {
    let routeHandler, responseMatch, receiveResponse;
    const forwarded = [];
    const request = {
      url: () => 'https://beta.elevenidllc.com/v1/signing-keys/issuer-identities?organization_id=00000000-0000-0000-0000-000000000001',
      method: () => 'PATCH', postDataJSON: () => ({ organization_id: '00000000-0000-0000-0000-000000000001', issuer_did: issuerDid }),
      headers: () => ({ 'content-type': 'application/json' }),
    };
    const page = {
      goto: async () => {},
      locator: () => ({ filter: () => ({ first: () => ({ waitFor: async () => {},
        getByRole: () => ({ click: async () => {} }) }) }) }),
      getByRole: () => ({ getByRole: () => ({ click: async () => {
        await routeHandler({ request: () => request, abort: async () => { throw new Error('Unexpected UI request'); },
          continue: async ({ headers }) => {
            forwarded.push(headers['If-Match']);
            const status = headers['If-Match'] === current ? 200 : 412;
            const response = { url: request.url, request: () => request, status: () => status,
              ok: () => status === 200, json: async () => ({ changed: status === 200,
                config_revision: status === 200 ? '"r-00000000-0000-4000-8000-000000000003"' : null }) };
            if (responseMatch(response)) receiveResponse(response);
          } });
      } }) }),
      route: async (_, handler) => { routeHandler = handler; },
      unroute: async (_, handler) => { assert.equal(handler, routeHandler); routeHandler = null; },
      waitForResponse: (match) => { responseMatch = match; return new Promise((resolve) => { receiveResponse = resolve; }); },
    };
    const result = await rebindThroughConsole(page, issuerDid, expected);
    assert.deepEqual(forwarded, [expected]);
    assert.equal(routeHandler, null);
    if (current === expected) assert.equal(ownedIdentityRevision(result), '"r-00000000-0000-4000-8000-000000000003"');
    else {
      assert.equal(result.status, 412);
      assert.throws(() => ownedIdentityRevision(result), /did not return/);
    }
  }
});

test('D02 unavailable-key denial requires unchanged revision, including after a 503 response', async () => {
  const issuerDid = 'did:web:beta.example.test:orgs:d02';
  for (const stage of ['before-bind', 'after-bind']) {
    const transport = fakeConfigTransport({ services: [{ id: 'provider-a' }], default_service_id: 'provider-a' });
    const before = await loadSigningConfig(transport.page);
    transport.failIdentityPatch(stage);
    const denied = await directRebind(transport.page, issuerDid, before.revision);
    assert.equal(denied.status, 503);
    const after = await loadSigningConfig(transport.page);
    if (stage === 'before-bind') assert.equal(unchangedOwnedRevision(after, before.revision).default_service_id, 'provider-a');
    else assert.throws(() => unchangedOwnedRevision(after, before.revision), /changed outside/);
  }
});

test('D02 private journal seals original public config and unknown input before dispatch', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'd02-config-journal-'));
  const revision = '"r-00000000-0000-4000-8000-000000000001"';
  const original = { services: [{ id: 'provider-a', auth_reference: '', auth_reference_envelope: 'must-not-copy',
    auth_configured: true }], default_service_id: 'provider-a' };
  try {
    const journal = createConfigMutationJournal(directory, original, revision);
    journal.intent('select-provider-b', revision, { default_service_id: 'provider-b' });
    journal.confirmed('select-provider-b', '"r-00000000-0000-4000-8000-000000000002"');
    journal.intent('restore-original-config', '"r-00000000-0000-4000-8000-000000000002"', original);
    journal.intent('restore-original-config', '"r-00000000-0000-4000-8000-000000000002"',
      { ...original, services: [{ ...original.services[0], auth_reference_envelope: 'another-secret' }] });
    journal.close();
    const raw = fs.readFileSync(path.join(directory, 'signing-config-mutations.private.jsonl'), 'utf8');
    const entries = raw.trim().split('\n').map(JSON.parse);
    assert.deepEqual(entries.map((entry) => entry.stage),
      ['ORIGINAL', 'INPUT_OUTCOME_UNKNOWN', 'CONFIRMED', 'INPUT_OUTCOME_UNKNOWN', 'INPUT_OUTCOME_UNKNOWN']);
    assert.equal(entries[3].requestPublicSha256, entries[4].requestPublicSha256);
    assert.equal(entries[0].originalPublicConfig.services[0].auth_reference, undefined);
    assert.equal(entries[0].originalPublicConfig.services[0].auth_reference_envelope, undefined);
    assert.equal(original.services[0].auth_reference_envelope, 'must-not-copy');
    assert.equal(raw.includes('must-not-copy'), false);
    assert.equal(raw.includes('another-secret'), false);
    assert.throws(() => createConfigMutationJournal(directory, original, revision), /EEXIST/);
  } finally {
    assert.ok(path.resolve(directory).startsWith(path.resolve(os.tmpdir()) + path.sep));
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

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
