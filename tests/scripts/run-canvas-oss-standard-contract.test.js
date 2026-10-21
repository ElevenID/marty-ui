'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const test = require('node:test');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const {
  BLOCKING_READINESS_CHECK_CODES,
  CASE_IDS,
  ContractFailure,
  ObservationLedger,
  observePipelinePrerequisites,
  selectProductionBadgeTemplates,
  contractFailureLocation,
  createHolderProof,
  didWebResolutionUrl,
  extractDeveloperKeyRecord,
  parseCredentialOfferUri,
  receiveAndVerifyCredential,
  resolveOid4vciEndpoints,
  resolveProofNonce,
  responseJson,
  sanitizeEvidence,
  validateAuthoritativeEvidenceHeads,
  validateReadinessSnapshot,
  verifyCompactJws,
} = require('./run-canvas-oss-standard-contract');

const NOW = '2026-07-15T06:00:00.000Z';

test('unexpected driver diagnostics retain source location without secret-bearing error text', () => {
  const error = new Error('secret-token request https://issuer.example?code=private-value');
  error.stack = 'Error: secret-token\n at fill("private-value") (/tests/scripts/run-canvas-oss-standard-contract.js:712:19)';
  const result = contractFailureLocation(error, 'standard_lti_13_install');
  assert.deepEqual(result, { activeCase: 'standard_lti_13_install', errorType: 'Error',
    sourceLocation: { file: 'run-canvas-oss-standard-contract.js', line: 712, column: 19 } });
  assert.ok(!JSON.stringify(result).includes('secret') && !JSON.stringify(result).includes('private-value'));
});

test('learning template selection rejects employee and membership badges and foreign bindings', async () => {
  const claims = ['achievement_name', 'course_name', 'quiz_name', 'score_percent', 'result', 'learning_context']
    .map(name => ({ name }));
  const credential = { id: 'learning', organization_id: 'org-1', status: 'ACTIVE',
    credential_type: 'OpenBadgeCredential', claims };
  const application = { id: 'application', organization_id: 'org-1', status: 'ACTIVE', credential_template_id: 'learning' };
  function client(c, a) { return { get: async path => {
    const row = path.startsWith('/v1/credential-templates') ? c : a;
    return path.includes('?') ? [row] : row;
  } }; }
  const select = (c, a, selectors = {}) => selectProductionBadgeTemplates(client(c, a), 'org-1', selectors);
  assert.equal((await select(credential, application)).credential.id, 'learning');
  assert.equal((await select(credential, application, { applicationTemplateId: 'application', credentialTemplateId: 'learning' })).credential.id, 'learning');
  await assert.rejects(select(credential, application, { credentialTemplateId: 'different' }), /Exactly one active Open Badge/);
  for (const c of [
    { ...credential, credential_type: 'EmployeeBadge' },
    { ...credential, credential_type: 'open_badge', claims: [{ name: 'email' }] },
    { ...credential, organization_id: 'foreign' },
  ]) await assert.rejects(select(c, application), /Exactly one active Open Badge/);
  await assert.rejects(select(credential,
    { ...application, organization_id: 'foreign' }), /Exactly one active Open Badge/);
});

test('explicit learning template selection reads exact resources beyond collection first pages', async () => {
  const calls = [];
  const credential = { id: 'learning', organization_id: 'org-1', status: 'ACTIVE', credential_type: 'OpenBadgeCredential',
    claims: ['achievement_name', 'course_name', 'quiz_name', 'score_percent', 'result', 'learning_context'].map(name => ({ name })) };
  const application = { id: 'application', organization_id: 'org-1', status: 'ACTIVE', credential_template_id: 'learning' };
  const marty = { get: async path => {
    calls.push(path);
    if (path === '/v1/application-templates/application') return application;
    if (path === '/v1/credential-templates/learning') return credential;
    assert.fail('Exact selected resources must not depend on a collection first page');
  } };
  assert.equal((await selectProductionBadgeTemplates(marty, 'org-1', { applicationTemplateId: 'application' })).credential.id, 'learning');
  assert.deepEqual(calls, ['/v1/application-templates/application', '/v1/credential-templates/learning']);
});

test('unconfigured learning selection pages inventories and rejects repeated pages', async () => {
  const credential = { id: 'learning', organization_id: 'org-1', status: 'ACTIVE', credential_type: 'OpenBadgeCredential',
    claims: ['achievement_name', 'course_name', 'quiz_name', 'score_percent', 'result', 'learning_context'].map(name => ({ name })) };
  const application = { id: 'application', organization_id: 'org-1', status: 'ACTIVE', credential_template_id: 'learning' };
  const old = Array.from({ length: 100 }, (_, index) => ({ id: 'old-' + index, status: 'DEPRECATED', organization_id: 'org-1' }));
  const client = repeated => ({ get: async raw => {
    const url = new URL(raw, 'https://unit.invalid');
    assert.equal(url.searchParams.get('limit'), '100');
    if (url.searchParams.get('offset') === '0' || repeated) return old;
    assert.equal(url.searchParams.get('offset'), '100');
    return [url.pathname.includes('credential-templates') ? credential : application];
  } });
  assert.equal((await selectProductionBadgeTemplates(client(false), 'org-1', {})).application.id, 'application');
  await assert.rejects(selectProductionBadgeTemplates(client(true), 'org-1', {}), /repeated or omitted/);
});

test('pipeline prerequisites read the explicit mounted artifact directory and reject changed bootstrap evidence', async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'canvas-prerequisite-root-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  fs.mkdirSync(path.join(directory, 'image'));
  fs.writeFileSync(path.join(directory, 'image/canvas-oss-image-manifest.json'), JSON.stringify({
    source_repository: 'https://github.com/instructure/canvas-lms.git', source_modified: false,
    source_commit: 'a'.repeat(40), image_digest: 'sha256:' + 'b'.repeat(64), scope: 'UNIT_FIXTURE_ONLY',
  }));
  const bootstrap = { phase: 'pre_start_only', web_started_after_bootstrap: true, forbidden_operation_counts: { rails_runner: 0 } };
  fs.writeFileSync(path.join(directory, 'bootstrap-audit.json'), JSON.stringify(bootstrap));
  fs.writeFileSync(path.join(directory, 'runtime-context.json'), JSON.stringify({
    origin: 'https://beta.elevenidllc.com', source_id: 'c'.repeat(40),
  }));
  const original = global.fetch;
  t.after(() => { global.fetch = original; });
  global.fetch = async () => new Response(JSON.stringify({ marty_ui_sha: 'c'.repeat(40) }), { status: 200 });
  const ledger = new ObservationLedger(NOW);
  await observePipelinePrerequisites(ledger, 'https://beta.elevenidllc.com', 'https://canvas-test.elevenidllc.com', () => {}, directory);
  assert.equal(ledger.entries.get('stock_lifecycle_bootstrap_only').status, 'passed');
  bootstrap.forbidden_operation_counts.rails_runner = 1;
  fs.writeFileSync(path.join(directory, 'bootstrap-audit.json'), JSON.stringify(bootstrap));
  await assert.rejects(observePipelinePrerequisites(new ObservationLedger(NOW),
    'https://beta.elevenidllc.com', 'https://canvas-test.elevenidllc.com', () => {}, directory),
  error => error.code === 'bootstrap_audit_invalid');
});

function readinessSnapshot(overrides = {}) {
  return {
    binding_id: 'binding-contract',
    ready: true,
    valid: true,
    active: false,
    config_version: 4,
    evaluated_at: NOW,
    checks: BLOCKING_READINESS_CHECK_CODES.map((code) => ({
      code,
      component: code.startsWith('kms_') ? 'kms_did' : 'contract',
      status: 'ready',
      blocking: true,
      remediation: 'No action required.',
      timestamp: NOW,
    })),
    ...overrides,
  };
}

function compactEs256(privateKey, payload) {
  const header = Buffer.from(JSON.stringify({ alg: 'ES256', typ: 'vc+sd-jwt', kid: 'did:web:issuer.example#key-1' })).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signingInput = `${header}.${body}`;
  const signature = crypto.sign('sha256', Buffer.from(signingInput), {
    key: privateKey,
    dsaEncoding: 'ieee-p1363',
  });
  return `${signingInput}.${signature.toString('base64url')}`;
}

function localCredentialExchange(t, vct) {
  const origin = 'https://beta.elevenidllc.com';
  const issuer = `${origin}/org/org-1`;
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const offer = {
    credential_issuer: issuer,
    credential_configuration_ids: ['OpenBadgeCredential#sd-jwt'],
    grants: { 'urn:ietf:params:oauth:grant-type:pre-authorized_code': { 'pre-authorized_code': 'local-test-offer' } },
  };
  const offerUri = `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(offer))}`;
  const requests = [];
  t.mock.method(globalThis, 'fetch', async (url, options = {}) => {
    const href = String(url);
    requests.push({ url: href, method: options.method || 'GET' });
    let body;
    if (href === `${origin}/.well-known/openid-credential-issuer/org/org-1`) {
      body = {
        credential_issuer: issuer,
        token_endpoint: `${origin}/v1/issuance/token`,
        credential_endpoint: `${origin}/v1/issuance/credential`,
        nonce_endpoint: `${origin}/v1/issuance/nonce`,
      };
    } else if (href === `${origin}/v1/issuance/token`) {
      body = { access_token: 'local-test-token', token_type: 'Bearer', expires_in: 1800 };
    } else if (href === `${origin}/v1/issuance/nonce`) {
      body = { c_nonce: 'local-test-nonce' };
    } else if (href === `${origin}/v1/issuance/credential`) {
      const proof = JSON.parse(options.body).proofs.jwt[0];
      const proofHeader = JSON.parse(Buffer.from(proof.split('.')[0], 'base64url').toString('utf8'));
      const compact = compactEs256(privateKey, {
        iss: 'did:web:issuer.example',
        vct,
        cnf: { jwk: proofHeader.jwk },
      });
      body = { credentials: [{ format: 'dc+sd-jwt', credential: compact }] };
    } else if (href === 'https://issuer.example/.well-known/did.json') {
      body = {
        id: 'did:web:issuer.example',
        verificationMethod: [{ id: 'did:web:issuer.example#key-1', publicKeyJwk: publicKey.export({ format: 'jwk' }) }],
        assertionMethod: ['did:web:issuer.example#key-1'],
      };
    } else {
      assert.fail(`Unexpected local credential-exchange request: ${href}`);
    }
    return new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } });
  });
  return { offerUri, origin, requests };
}

test('credential receipt accepts the exact template VCT with a verified signature and holder binding', async (t) => {
  const fixture = localCredentialExchange(t, 'urn:example:OpenBadgeCredential');
  const result = await receiveAndVerifyCredential(fixture.offerUri, { vct: 'urn:example:OpenBadgeCredential' }, fixture.origin);
  assert.equal(result.payload.vct, 'urn:example:OpenBadgeCredential');
  assert.equal(fixture.requests.length, 5);
});

for (const [name, actualVct, template] of [
  ['unrelated VCT when the template has no legacy credential_type', 'urn:example:UnrelatedCredential', { vct: 'urn:example:OpenBadgeCredential' }],
  ['missing signed VCT', undefined, { vct: 'urn:example:OpenBadgeCredential' }],
  ['substring matching the legacy credential_type', 'urn:example:NotOpenBadgeCredential', { vct: 'urn:example:OpenBadgeCredential', credential_type: 'OpenBadgeCredential' }],
]) {
  test(`credential receipt rejects ${name} even with a valid signature and holder binding`, async (t) => {
    const fixture = localCredentialExchange(t, actualVct);
    await assert.rejects(
      receiveAndVerifyCredential(fixture.offerUri, template, fixture.origin),
      (error) => error instanceof ContractFailure && error.code === 'open_badge_type_mismatch',
    );
    assert.equal(fixture.requests.length, 5);
  });
}

test('credential receipt requires an exact expected template VCT before consuming the offer', async (t) => {
  const offerUri = `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify({
    credential_issuer: 'https://beta.elevenidllc.com/org/org-1',
    credential_configuration_ids: ['OpenBadgeCredential#sd-jwt'],
    grants: { 'urn:ietf:params:oauth:grant-type:pre-authorized_code': { 'pre-authorized_code': 'unconsumed-test-offer' } },
  }))}`;
  const fetchMock = t.mock.method(globalThis, 'fetch', async () => assert.fail('Missing template VCT must fail before network activity'));
  for (const template of [null, {}, { vct: '' }, { vct: '   ' }, { credential_type: 'OpenBadgeCredential' }]) {
    await assert.rejects(
      receiveAndVerifyCredential(offerUri, template),
      (error) => error instanceof ContractFailure && error.code === 'credential_template_vct_missing',
    );
  }
  assert.equal(fetchMock.mock.callCount(), 0);
});

test('observation ledger emits the fixed schema and never invents optional coverage', () => {
  const execution = {
    boundary: 'docker_compose_one_shot',
    compose_service: 'canvas-contract',
    containerized: true,
    host_browser_processes: false,
    secret_transport: 'compose_secret_files',
    image_id: `sha256:${'a'.repeat(64)}`,
    source_sha: 'b'.repeat(40),
    base_image: `mcr.microsoft.com/playwright:v1.63.0-noble@sha256:${'c'.repeat(64)}`,
  };
  const ledger = new ObservationLedger(NOW, execution);
  ledger.pass('standard_lti_13_install', 'Installed with token=secret-value and an intentionally long suffix '.repeat(8));
  const output = ledger.toJSON();

  assert.equal(output.schema_version, 1);
  assert.equal(output.started_at, NOW);
  assert.deepEqual(output.execution, execution);
  assert.deepEqual(output.cases.map((entry) => entry.id), CASE_IDS);
  assert.equal(output.cases.find((entry) => entry.id === 'new_quizzes_authoritative_submission').status, 'hosted_required');
  assert.equal(output.cases.find((entry) => entry.id === 'canvas_credentials_projection').status, 'outside_gate');
  assert.equal(output.cases.find((entry) => entry.id === 'standard_lti_13_install').evidence.length <= 240, true);
  assert.equal(ledger.allOssRequiredPassed(), false);
});

test('artifact evidence redacts credential material before truncating it', () => {
  const sanitized = sanitizeEvidence('Bearer abcdefghijklmnop api_key=super-secret password=hunter2 state=sensitive');
  assert.match(sanitized, /Bearer \[redacted\]/);
  assert.doesNotMatch(sanitized, /super-secret|hunter2/);
});

test('Playwright-style response methods are accepted without confusing status for a property', async () => {
  const body = await responseJson(
    { status: () => 201, json: async () => ({ created: true }) },
    'response_failed',
    'Response failed',
    [201],
  );
  assert.deepEqual(body, { created: true });
});

test('readiness accepts only a complete current blocking matrix', () => {
  const snapshot = readinessSnapshot();
  assert.equal(validateReadinessSnapshot(snapshot), snapshot);
  assert.ok(BLOCKING_READINESS_CHECK_CODES.includes('rollout_allowlist'));
  assert.ok(BLOCKING_READINESS_CHECK_CODES.includes('worker_heartbeat'));
  assert.ok(BLOCKING_READINESS_CHECK_CODES.includes('kms_issuer_configuration'));
  assert.ok(BLOCKING_READINESS_CHECK_CODES.includes('kms_did_sign_verify_challenge'));
});

test('readiness rejects a top-level ready result with a missing blocking check', () => {
  const checks = readinessSnapshot().checks.filter((check) => check.code !== 'worker_heartbeat');
  assert.throws(
    () => validateReadinessSnapshot(readinessSnapshot({ checks })),
    (error) => error instanceof ContractFailure && error.code === 'binding_readiness_check_missing',
  );
});

test('readiness rejects failed known or future blocking checks and inactive activation', () => {
  const checks = readinessSnapshot().checks.map((check) => (
    check.code === 'kms_did_sign_verify_challenge' ? { ...check, status: 'failed' } : check
  ));
  assert.throws(
    () => validateReadinessSnapshot(readinessSnapshot({ checks })),
    (error) => error instanceof ContractFailure && error.code === 'binding_readiness_check_failed',
  );
  assert.throws(
    () => validateReadinessSnapshot(readinessSnapshot(), { requireActive: true }),
    (error) => error instanceof ContractFailure && error.code === 'binding_activation_not_active',
  );
  assert.throws(
    () => validateReadinessSnapshot(readinessSnapshot({
      checks: [...readinessSnapshot().checks, {
        code: 'future_fail_closed_check',
        component: 'future',
        status: 'failed',
        blocking: true,
        remediation: 'Repair it.',
        timestamp: NOW,
      }],
    })),
    (error) => error instanceof ContractFailure && error.code === 'binding_readiness_check_failed',
  );
});

test('authoritative evidence proof requires one exact verified revision head per typed rule', () => {
  const requirements = [
    {
      requirement_id: 'ags-score',
      source: 'ags_result',
      fact_type: 'canvas.assignment_score',
      scope: { course_id: '1', line_item_url: 'https://canvas.example/api/lti/courses/1/line_items/2' },
    },
    {
      requirement_id: 'course-complete',
      source: 'canvas_rest',
      fact_type: 'canvas.course_completion',
      scope: { course_id: '1' },
    },
  ];
  const fact = (requirement, id, supersededFactId = null) => ({
    id,
    provider: 'canvas',
    requirement_id: requirement.requirement_id,
    fact_type: requirement.fact_type,
    scope: requirement.scope,
    source: { source: requirement.source },
    verification: { status: 'VERIFIED' },
    logical_key: crypto.createHash('sha256').update(requirement.requirement_id).digest('hex'),
    source_revision: crypto.createHash('sha256').update(`${id}:revision`).digest('hex'),
    payload_hash: crypto.createHash('sha256').update(`${id}:payload`).digest('hex'),
    observed_at: NOW,
    effective_at: NOW,
    superseded_fact_id: supersededFactId,
  });
  const old = fact(requirements[0], 'old-ags');
  const currentAgs = fact(requirements[0], 'current-ags', old.id);
  const currentCourse = fact(requirements[1], 'current-course');

  assert.deepEqual(
    validateAuthoritativeEvidenceHeads([old, currentAgs, currentCourse], requirements).map((item) => item.id),
    ['current-ags', 'current-course'],
  );
  assert.throws(
    () => validateAuthoritativeEvidenceHeads(
      [old, { ...currentAgs, verification: { status: 'UNVERIFIED' } }, currentCourse],
      requirements,
    ),
    (error) => error instanceof ContractFailure && error.code === 'authoritative_evidence_unverified',
  );
});

test('inline OID4VCI offers and did:web resolution remain deterministic', () => {
  const offer = {
    credential_issuer: 'https://beta.elevenidllc.com/org/org-1',
    credential_configuration_ids: ['badge-v1'],
    grants: {
      'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
        'pre-authorized_code': 'one-time-code',
      },
    },
  };
  const parsed = parseCredentialOfferUri(`openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(offer))}`);
  assert.deepEqual(parsed, {
    issuer: offer.credential_issuer,
    configurationId: 'badge-v1',
    preAuthorizedCode: 'one-time-code',
  });
  assert.equal(didWebResolutionUrl('did:web:issuer.example:issuers:badge'), 'https://issuer.example/issuers/badge/did.json');
  assert.equal(didWebResolutionUrl('did:web:localhost%3A8443'), 'https://localhost:8443/.well-known/did.json');
});

test('OID4VCI endpoints preserve legacy inline token metadata', async () => {
  const issuerUrl = new URL('https://beta.elevenidllc.com/org/org-1');
  const endpoints = await resolveOid4vciEndpoints({
    credential_issuer: issuerUrl.href,
    token_endpoint: 'https://beta.elevenidllc.com/v1/issuance/token',
    credential_endpoint: 'https://beta.elevenidllc.com/v1/issuance/credential',
  }, issuerUrl, issuerUrl.origin, async () => {
    assert.fail('inline token metadata must not trigger authorization-server discovery');
  });

  assert.equal(endpoints.tokenEndpoint.href, 'https://beta.elevenidllc.com/v1/issuance/token');
  assert.equal(endpoints.credentialEndpoint.href, 'https://beta.elevenidllc.com/v1/issuance/credential');
});

test('OID4VCI endpoints follow final-spec authorization server metadata', async () => {
  const issuerUrl = new URL('https://beta.elevenidllc.com/org/org-1');
  const requested = [];
  const endpoints = await resolveOid4vciEndpoints({
    credential_issuer: issuerUrl.href,
    authorization_servers: [issuerUrl.href],
    credential_endpoint: 'https://beta.elevenidllc.com/v1/issuance/credential',
    nonce_endpoint: 'https://beta.elevenidllc.com/v1/issuance/nonce',
  }, issuerUrl, issuerUrl.origin, async (url) => {
    requested.push(url);
    return {
      status: 200,
      json: async () => ({
        issuer: issuerUrl.href,
        token_endpoint: 'https://beta.elevenidllc.com/v1/issuance/token',
      }),
    };
  });

  assert.deepEqual(requested, [
    'https://beta.elevenidllc.com/.well-known/oauth-authorization-server/org/org-1',
  ]);
  assert.equal(endpoints.tokenEndpoint.href, 'https://beta.elevenidllc.com/v1/issuance/token');
  assert.equal(endpoints.credentialEndpoint.href, 'https://beta.elevenidllc.com/v1/issuance/credential');
  assert.equal(endpoints.nonceEndpoint.href, 'https://beta.elevenidllc.com/v1/issuance/nonce');
});

test('OID4VCI proof nonce supports legacy token fields and the final nonce endpoint', async () => {
  assert.equal(
    await resolveProofNonce({ access_token: 'token', c_nonce: 'legacy-nonce' }, null, async () => {
      assert.fail('legacy token nonce must not trigger nonce endpoint discovery');
    }),
    'legacy-nonce',
  );

  const requested = [];
  const nonceEndpoint = new URL('https://beta.elevenidllc.com/v1/issuance/nonce');
  assert.equal(
    await resolveProofNonce({ access_token: 'token' }, nonceEndpoint, async (url, options) => {
      requested.push({ url: url.href, method: options.method, authorization: options.headers.Authorization });
      return { status: 200, json: async () => ({ c_nonce: 'final-nonce' }) };
    }),
    'final-nonce',
  );
  assert.deepEqual(requested, [{
    url: nonceEndpoint.href,
    method: 'POST',
    authorization: undefined,
  }]);
});

test('OID4VCI endpoint discovery fails closed on ambiguous or unpinned authorization servers', async () => {
  const issuerUrl = new URL('https://beta.elevenidllc.com/org/org-1');
  await assert.rejects(
    resolveOid4vciEndpoints({
      credential_issuer: issuerUrl.href,
      authorization_servers: [issuerUrl.href, 'https://beta.elevenidllc.com/org/org-2'],
      credential_endpoint: 'https://beta.elevenidllc.com/v1/issuance/credential',
    }, issuerUrl, issuerUrl.origin),
    (error) => error instanceof ContractFailure && error.code === 'authorization_server_ambiguous',
  );
  await assert.rejects(
    resolveOid4vciEndpoints({
      credential_issuer: issuerUrl.href,
      authorization_servers: ['https://attacker.example/org/org-1'],
      credential_endpoint: 'https://beta.elevenidllc.com/v1/issuance/credential',
    }, issuerUrl, issuerUrl.origin),
    (error) => error instanceof ContractFailure && error.code === 'authorization_server_unpinned',
  );
  await assert.rejects(
    resolveOid4vciEndpoints({
      credential_issuer: 'https://beta.elevenidllc.com/org/another-org',
      token_endpoint: 'https://beta.elevenidllc.com/v1/issuance/token',
      credential_endpoint: 'https://beta.elevenidllc.com/v1/issuance/credential',
    }, issuerUrl, issuerUrl.origin),
    (error) => error instanceof ContractFailure && error.code === 'credential_metadata_issuer_mismatch',
  );
  await assert.rejects(
    resolveOid4vciEndpoints({
      credential_issuer: issuerUrl.href,
      token_endpoint: 'https://beta.elevenidllc.com/v1/issuance/token',
      credential_endpoint: 'https://beta.elevenidllc.com/v1/issuance/credential',
      nonce_endpoint: 'https://attacker.example/nonce',
    }, issuerUrl, issuerUrl.origin),
    (error) => error instanceof ContractFailure && error.code === 'nonce_endpoint_unpinned',
  );
});

test('holder proof is ES256 verifiable and binds issuer and subject to did:jwk', () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const exported = publicKey.export({ format: 'jwk' });
  const publicJwk = { kty: exported.kty, crv: exported.crv, x: exported.x, y: exported.y };
  const proof = createHolderProof(privateKey, publicJwk, 'https://beta.elevenidllc.com/org/org-1', 'nonce-1');
  const [encodedHeader, encodedPayload, encodedSignature] = proof.jwt.split('.');
  const header = JSON.parse(Buffer.from(encodedHeader, 'base64url').toString('utf8'));
  const payload = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString('utf8'));

  assert.equal(header.alg, 'ES256');
  assert.equal(payload.iss, proof.did);
  assert.equal(payload.sub, proof.did);
  assert.equal(payload.nonce, 'nonce-1');
  assert.equal(crypto.verify(
    'sha256',
    Buffer.from(`${encodedHeader}.${encodedPayload}`),
    { key: publicKey, dsaEncoding: 'ieee-p1363' },
    Buffer.from(encodedSignature, 'base64url'),
  ), true);
});

test('credential verifier accepts a valid ES256 JWS and rejects payload tampering', () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const publicJwk = publicKey.export({ format: 'jwk' });
  const compact = compactEs256(privateKey, { iss: 'did:web:issuer.example', vct: 'OpenBadgeCredential' });
  const verified = verifyCompactJws(compact, publicJwk);
  assert.equal(verified.payload.vct, 'OpenBadgeCredential');

  const parts = compact.split('.');
  parts[1] = Buffer.from(JSON.stringify({ iss: 'did:web:attacker.example', vct: 'OpenBadgeCredential' })).toString('base64url');
  assert.throws(
    () => verifyCompactJws(parts.join('.'), publicJwk),
    (error) => error instanceof ContractFailure && error.code === 'credential_signature_invalid',
  );
});

test('Developer Key extraction handles the nested stock Canvas response shape', () => {
  const record = extractDeveloperKeyRecord({ developer_key: { id: 42, name: 'Marty LTI run', api_key: 'secret' } }, 'Marty LTI run');
  assert.deepEqual(record, { id: 42, name: 'Marty LTI run', api_key: 'secret' });
});
