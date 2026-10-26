'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const test = require('node:test');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const {
  canvasLaunchErrorSummary,
  canvasOwnedToolIndex,
  assertCanvasOauthCompletion,
  publishCanvasCourse,
  BLOCKING_READINESS_CHECK_CODES,
  CASE_IDS,
  ContractFailure,
  ObservationLedger,
  observePipelinePrerequisites,
  selectProductionBadgeTemplates,
  contractFailureLocation,
  canvasTokenExpiration,
  selectCanvasTokenExpirationTime,
  freshCanvasLearnerEmail,
  martyRequestSummary,
  createHolderProof,
  didWebResolutionUrl,
  extractDeveloperKeyRecord,
  parseCredentialOfferUri,
  receiveAndVerifyCredential,
  resolveOid4vciEndpoints,
  resolveProofNonce,
  responseJson,
  CanvasSessionClient,
  sanitizeEvidence,
  validateAuthoritativeEvidenceHeads,
  validateReadinessSnapshot,
  verifyCompactJws,
} = require('./run-canvas-oss-standard-contract');

const NOW = '2026-07-15T06:00:00.000Z';

test('Canvas token retirement uses its existing password session and decoded CSRF cookie', async () => {
  const calls = [];
  const client = new CanvasSessionClient('https://canvas-test.elevenidllc.com', {
    async cookies(origin) { assert.equal(origin, 'https://canvas-test.elevenidllc.com'); return [{ name: '_csrf_token', value: 'synthetic%2Bcsrf%3D' }]; },
    request: { async fetch(url, options) {
      calls.push({ url, options });
      return { status: () => 200, json: async () => ({}), text: async () => '{}', headers: () => ({}) };
    } },
  });
  const result = await client.request('DELETE', '/api/v1/users/1/tokens/2', { includeStatus: true });
  assert.equal(result.status, 200);
  assert.equal(calls[0].options.headers['X-CSRF-Token'], 'synthetic+csrf=');
  assert.equal(calls[0].options.headers.Authorization, undefined);
  assert.equal(calls[0].options.maxRedirects, 0);
});

test('Canvas session mutations without CSRF or outside the API origin never reach transport', async () => {
  let calls = 0;
  const client = new CanvasSessionClient('https://canvas-test.elevenidllc.com', {
    async cookies() { return []; }, request: { async fetch() { calls++; } },
  });
  await assert.rejects(client.request('DELETE', '/api/v1/users/1/tokens/2'));
  await assert.rejects(client.request('GET', 'https://foreign.example/api/v1/users/1'));
  assert.equal(calls, 0);
});

test('unexpected driver diagnostics retain source location without secret-bearing error text', () => {
  const error = new Error('secret-token request https://issuer.example?code=private-value');
  error.stack = 'Error: secret-token\n at fill("private-value") (/tests/scripts/run-canvas-oss-standard-contract.js:712:19)';
  const result = contractFailureLocation(error, 'standard_lti_13_install');
  assert.deepEqual(result, { activeCase: 'standard_lti_13_install', errorType: 'Error',
    sourceLocation: { file: 'run-canvas-oss-standard-contract.js', line: 712, column: 19 } });
  assert.ok(!JSON.stringify(result).includes('secret') && !JSON.stringify(result).includes('private-value'));
});

test('Marty request failure context preserves static operation but excludes dynamic paths and queries', () => {
  assert.equal(martyRequestSummary('PUT', '/v1/integrations/canvas/platforms/private-id/lti-installation?token=secret'),
    'Marty PUT /v1/integrations/canvas/platforms/:resource/lti-installation failed');
  assert.equal(martyRequestSummary('secret', '/v1/integrations/canvas/lti/config/secret-token'),
    'Marty REQUEST /v1/integrations/canvas/:resource/:resource/:resource failed');
});

test('Canvas token expiration uses the account timezone and stays within a bounded window', () => {
  const now = Date.parse('2026-10-21T07:51:00Z');
  const actual = canvasTokenExpiration(now, 'America/Denver', '');
  assert.deepEqual(actual, { timestamp: Date.parse('2026-10-21T11:00:00Z'), date: '10/21/2026', time: '5:00 AM' });
  const nextDay = canvasTokenExpiration(Date.parse('2026-12-31T22:45:00Z'), 'UTC', '');
  assert.equal(nextDay.date, '01/01/2027');
  assert.ok(actual.timestamp >= now + 3 * 3600000 && actual.timestamp < now + 3.5 * 3600000);
});

test('Canvas learner fixtures have fresh bounded synthetic identities for each run', () => {
  const first = freshCanvasLearnerEmail('learner@marty.demo', 'owned-run-0001');
  assert.equal(first, freshCanvasLearnerEmail('learner@marty.demo', 'owned-run-0001'));
  assert.notEqual(first, freshCanvasLearnerEmail('learner@marty.demo', 'owned-run-0002'));
  assert.ok(freshCanvasLearnerEmail('a'.repeat(100) + '@stage.test', 'owned-run-0001').split('@')[0].length <= 64);
  assert.throws(() => freshCanvasLearnerEmail('person@example.com', 'owned-run-0001'), /synthetic mailbox/);
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


test('single-course publication uses its documented event and rejects silent unchanged success', async () => {
  let request;
  const admin = { putForm: async (...args) => {
    request = args;
    return { id: 42, workflow_state: args[1]['course[event]'] === 'offer' ? 'available' : 'unpublished' };
  } };
  await publishCanvasCourse(admin, 42);
  assert.deepEqual(request, ['/api/v1/courses/42', { 'course[event]': 'offer' }, [200]]);
  for (const result of [{ id: 42, workflow_state: 'unpublished' }, { id: 99, workflow_state: 'available' }]) {
    await assert.rejects(publishCanvasCourse({ putForm: async () => result }, 42),
      error => error.code === 'canvas_course_not_published');
  }
});


test('OAuth completion requires native connected outcome and owned platform binding', () => {
  const origin = 'https://issuer.test';
  assert.doesNotThrow(() => assertCanvasOauthCompletion(new URL(origin + '/complete?outcome=connected&platform_id=owned'), origin, 'owned'));
  for (const value of [
    origin + '/complete?outcome=success&platform_id=owned',
    origin + '/complete?outcome=error&platform_id=owned&error_code=private-value',
    origin + '/complete?outcome=connected&platform_id=other',
    'https://other.test/complete?outcome=connected&platform_id=owned',
  ]) {
    assert.throws(() => assertCanvasOauthCompletion(new URL(value), origin, 'owned'),
      error => error.code === 'canvas_oauth_callback_not_connected' && !error.message.includes('private-value'));
  }
});


test('Canvas chooser selects the acknowledged installation among identically named tools', () => {
  assert.equal(canvasOwnedToolIndex(['1', '2', '9'], '9'), 2);
  for (const [ids, owned] of [[['1', '2'], '9'], [['9', '9'], '9'], [['9'], 'not-an-id']]) {
    assert.throws(() => canvasOwnedToolIndex(ids, owned), ContractFailure);
  }
});


test('Canvas personal tokens cover the actual long-run deadline with a bounded buffer', () => {
  const now = Date.parse('2026-10-21T07:51:00Z');
  const deadline = now + 6 * 3600000;
  const token = canvasTokenExpiration(now, 'UTC', String(deadline / 1000));
  assert.ok(token.timestamp >= deadline + 1800000 && token.timestamp < deadline + 3600000);
  for (const value of ['invalid', String(now / 1000), String((now + 25 * 3600000) / 1000)]) {
    assert.throws(() => canvasTokenExpiration(now, 'UTC', value), error => error.code === 'canvas_contract_deadline_invalid');
  }
});


test('resource conflict summaries read wrapped errors without retaining credential fields or URLs', () => {
  const summary = canvasLaunchErrorSummary({ error: { code: 'canvas_conflict', message: 'Canvas AGS rejection at https://canvas.test/api?state=private-value', detail: [{ message: 'Bearer abcdefghijklmnopqrstuvwxyz' }] }, session_token: 'private-session', ignored: 'private-other' });
  assert.ok(summary.includes('canvas_conflict'));
  assert.ok(summary.some(value => value.includes('Canvas AGS rejection')));
  assert.ok(!JSON.stringify(summary).includes('private') && !JSON.stringify(summary).includes('https://'));
});


test('resource conflict summaries preserve the production MIP error description', () => {
  assert.deepEqual(canvasLaunchErrorSummary({ error: 'service_error', error_description: 'Canvas launch resource does not match the selected binding', message_id: 'opaque-private-message-id', details: [{ message: 'scope mismatch' }] }),
    ['scope mismatch', 'service_error', 'Canvas launch resource does not match the selected binding']);
});

test('course recovery waits for current nonempty counts despite retained completed_at', async () => {
  const { waitForCanvasCourseCompletion } = require('./run-canvas-oss-standard-contract');
  const stale = { requirement_count: 2, requirement_completed_count: 1, completed_at: '2026-10-21T18:26:08Z' };
  const recovered = { requirement_count: 2, requirement_completed_count: 2, completed_at: stale.completed_at };
  const paths = [];
  const canvas = { get: async path => { paths.push(path); return paths.length === 1 ? stale : recovered; } };
  assert.equal(await waitForCanvasCourseCompletion(canvas, { course: { id: 'course-1' }, learner: { id: 'learner-1' } }), recovered);
  assert.deepEqual(paths, ['/api/v1/courses/course-1/users/learner-1/progress', '/api/v1/courses/course-1/users/learner-1/progress']);
});

function stockTimeWidget({ value = '12:00 AM', expanded = false, committedValue } = {}) {
  const calls = [];
  const time = {
    async fill(next) { calls.push(['fill', next]); if (next !== value) expanded = true; value = next; },
    async getAttribute(name) { assert.equal(name, 'aria-expanded'); return String(expanded); },
    async press(key) { assert.equal(key, 'ArrowDown'); calls.push(['press', key]); expanded = true; },
    async inputValue() { return value; },
  };
  const page = { getByRole(role, options) {
    assert.equal(role, 'option'); assert.equal(options.exact, true);
    return { async click() {
      assert.equal(expanded, true, 'stock options only exist while the combobox is open');
      calls.push(['click', options.name]); value = committedValue ?? options.name; expanded = false;
    } };
  } };
  return { page, time, calls };
}

test('Canvas token time explicitly opens a closed same-value midnight combobox', async () => {
  const widget = stockTimeWidget();
  await selectCanvasTokenExpirationTime(widget.page, widget.time, '12:00 AM');
  assert.deepEqual(widget.calls, [['fill', '12:00 AM'], ['press', 'ArrowDown'], ['click', '12:00 AM']]);
});

test('Canvas token time selects the exact option without moving an already-open selection', async () => {
  const widget = stockTimeWidget({ expanded: true });
  await selectCanvasTokenExpirationTime(widget.page, widget.time, '1:30 AM');
  assert.deepEqual(widget.calls, [['fill', '1:30 AM'], ['click', '1:30 AM']]);
});

test('Canvas token time rejects a stale committed option before token submission', async () => {
  const widget = stockTimeWidget({ committedValue: '12:00 AM' });
  await assert.rejects(selectCanvasTokenExpirationTime(widget.page, widget.time, '1:30 AM'),
    error => error.code === 'canvas_personal_token_time_uncommitted');
});


test('engineering CLI permits explicit media-free mode while recorded mode requires a video path', () => {
  const {parseArgs} = require('./run-canvas-oss-standard-contract');
  const functional = parseArgs(['node','driver','--observations','observations.json','--functional-rerun']);
  assert.equal(functional.functionalRerun,true);
  assert.equal(functional.video,null);
  assert.throws(() => parseArgs(['node','driver','--observations','observations.json']), /video/);
  assert.throws(() => parseArgs(['node','driver','--observations','observations.json','--functional-rerun','--functional-rerun']), /Unsupported argument/);
  const recorded = parseArgs(['node','driver','--observations','observations.json','--video','contract.webm']);
  assert.equal(recorded.functionalRerun,false);
  assert.match(recorded.video,/contract\.webm$/);
});

test('shared stock login emits only static stages and preserves original navigation failure',async()=>{
 const {loginCanvas}=require('./run-canvas-oss-standard-contract');const stages=[];
 const locator={first(){return this},fill:async()=>{},click:async()=>{},isVisible:async()=>false};
 const page={goto:async()=>{},locator:()=>locator,getByRole:()=>locator,waitForURL:async()=>{throw Object.assign(Error('private redirect'),{name:'TimeoutError'})}};
 await assert.rejects(loginCanvas(page,'https://canvas-test.elevenidllc.com','private-login','private-password',{observe:value=>stages.push(value)}),/private redirect/);
 assert.deepEqual(stages,['NAVIGATE_LOGIN','FILL_LOGIN','SUBMIT_LOGIN']);
 page.waitForURL=async()=>{};stages.length=0;await loginCanvas(page,'https://canvas-test.elevenidllc.com','private-login','private-password',{observe:value=>stages.push(value)});
 assert.deepEqual(stages,['NAVIGATE_LOGIN','FILL_LOGIN','SUBMIT_LOGIN','POST_LOGIN_ACCEPT','LOGIN_COMPLETE']);
 await loginCanvas(page,'https://canvas-test.elevenidllc.com','private-login','private-password');
});

test('Compose secret boundary still rejects raw environment values and non-Compose file paths before IO',()=>{
 const {requireSecretFile}=require('./run-canvas-oss-standard-contract');const name='CANVAS_SECRET_BOUNDARY_TEST';
 const original=process.env[name],originalFile=process.env[name+'_FILE'];
 try{process.env[name]='raw-secret';assert.throws(()=>requireSecretFile(name));delete process.env[name];process.env[name+'_FILE']='C:/private/secret';assert.throws(()=>requireSecretFile(name));process.env[name+'_FILE']='/run/secrets/../outside';assert.throws(()=>requireSecretFile(name));}
 finally{if(original===undefined)delete process.env[name];else process.env[name]=original;if(originalFile===undefined)delete process.env[name+'_FILE'];else process.env[name+'_FILE']=originalFile;}
});

test('Developer Key ID is journaled before a later modal failure, once and only for exact trusted name',async()=>{
 const {saveDeveloperKey}=require('./run-canvas-oss-standard-contract');const events=[];
 const response={url:()=> 'https://canvas-test.elevenidllc.com/api/v1/accounts/1/developer_keys',request:()=>({method:()=> 'POST'}),status:()=>201,json:async()=>({developer_key:{id:42,name:'Owned run',api_key:'private'}})};
 const page={url:()=> 'https://canvas-test.elevenidllc.com/accounts/1/developer_keys',waitForResponse:async predicate=>{assert.equal(predicate(response),true);assert.equal(predicate({...response,url:()=> 'https://foreign.test/api/v1/accounts/1/developer_keys'}),false);return response}};
 const modal={getByRole:()=>({click:async()=>events.push('submit')}),waitFor:async()=>{events.push('hidden-wait');throw Error('late modal failure')}};
 await assert.rejects(saveDeveloperKey(page,modal,'Owned run',id=>events.push('owned:'+id)),/late modal failure/);assert.deepEqual(events,['submit','owned:42','hidden-wait']);
 events.length=0;response.json=async()=>({developer_key:{id:42,name:'Foreign run',api_key:'private'}});await assert.rejects(saveDeveloperKey(page,modal,'Owned run',id=>events.push('owned:'+id)),error=>error.code==='canvas_developer_key_identity_mismatch');assert.deepEqual(events,['submit']);
 events.length=0;response.json=async()=>({developer_key:{id:42,name:'Owned run'}});
 await assert.rejects(saveDeveloperKey(page,modal,'Owned run',id=>events.push('owned:'+id),{observe:phase=>{if(phase==='JOURNAL'){events.push('journal');throw Error('observer failed')}}}),/observer failed/);
 assert.deepEqual(events,['submit','owned:42','journal']);
});

test('Developer Key creation waits for the exact pinned API versus LTI account route',async()=>{
 const {saveDeveloperKey}=require('./run-canvas-oss-standard-contract');
 for(const kind of ['api','lti']){
  const expected=kind==='api'?'/api/v1/accounts/1/developer_keys':'/api/lti/accounts/1/developer_keys/tool_configuration';
  const response={url:()=> 'https://canvas-test.elevenidllc.com'+expected,request:()=>({method:()=> 'POST'}),status:()=>201,json:async()=>({developer_key:{id:42,name:'Owned run'}})};
  const page={url:()=> 'https://canvas-test.elevenidllc.com/accounts/1/developer_keys',waitForResponse:async predicate=>{assert(predicate(response));for(const wrong of ['/api/v1/developer_keys','/api/v1/accounts/2/developer_keys','/api/v1/accounts/1/developer_keys/tool_configuration',kind==='api'?'/api/lti/accounts/1/developer_keys/tool_configuration':'/api/v1/accounts/1/developer_keys'])assert(!predicate({...response,url:()=> 'https://canvas-test.elevenidllc.com'+wrong}));return response;}};
  let calls=0;await saveDeveloperKey(page,{getByRole:()=>({click:async()=>{}}),waitFor:async()=>{}},'Owned run',()=>{calls++},{kind});assert.equal(calls,1);
 }
});

test('Developer Key setup declares English before shared API and LTI phases',async()=>{
 const {createOauthDeveloperKey,createLtiDeveloperKey}=require('./run-canvas-oss-standard-contract');
 for(const create of [createOauthDeveloperKey,createLtiDeveloperKey]){
  const stages=[],navigations=[],locator={or(){return this},first(){return this},waitFor:async()=>{},click:async()=>{}};
  const modal={waitFor:async()=>{},getByRole:()=>locator,getByTestId:name=>({fill:async()=>{if(name==='owner-email-input')throw Error('private field value')}})};
  const page={goto:async url=>navigations.push(url),locator:()=>locator,getByRole:role=>role==='dialog'?modal:locator};
  await assert.rejects(create(page,{canvasOrigin:'https://canvas-test.elevenidllc.com',accountId:'1',name:'Owned run',ownerEmail:'private@owned.test',observe:value=>stages.push(value)}),/private field value/);
  assert.deepEqual(navigations,['https://canvas-test.elevenidllc.com/accounts/1/developer_keys?session_locale=en']);
  assert.deepEqual(stages,['NAVIGATE','TRIGGER','MENU','MODAL','FILL']);assert(!JSON.stringify(stages).includes('private'));
 }
});

test('real local redirect chains hold provider codes and observe native callbacks without routing redirected URLs',async()=>{
 const http=require('node:http');const {chromium}=require('@playwright/test');const {authorizeCanvasOAuth}=require('./run-canvas-oss-standard-contract');
 const servers=[];let browser,canvasOrigin,martyOrigin,current;
 const listen=async handler=>{const server=http.createServer(handler);servers.push(server);await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));return 'http://127.0.0.1:'+server.address().port};
 try{
  martyOrigin=await listen((req,res)=>{const url=new URL(req.url,martyOrigin);if(url.pathname==='/v1/integrations/canvas/oauth/callback'){current.callbackHits++;res.writeHead(302,{Location:'/result?outcome=error'});res.end();}else{res.writeHead(200,{'Content-Type':'text/html'});res.end('<p>Owned local callback result</p>');}});
  canvasOrigin=await listen(async(req,res)=>{
   const url=new URL(req.url,canvasOrigin);const redirect=()=>{const target=new URL('/v1/integrations/canvas/oauth/callback',current.wrongOrigin?canvasOrigin:martyOrigin);target.searchParams.set('state',current.wrongState?'different-private-state':current.state);target.searchParams.set('code',current.code);res.writeHead(302,{Location:target.href});res.end();};
   if(req.method==='GET'&&url.pathname==='/login/oauth2/auth'){current.authHits++;if(current.immediate)return redirect();res.writeHead(302,{Location:'/login/oauth2/confirm','Set-Cookie':'owned_control=unchanged; Path=/; HttpOnly'});res.end();}
   else if(req.method==='GET'&&url.pathname==='/login/oauth2/confirm'){res.writeHead(200,{'Content-Type':'text/html'});res.end('<form id="oauth2_accept_form" method="post" action="/login/oauth2/accept"><input type="hidden" name="custom_csrf_token" value="owned-control"><button>Authorize</button></form>');}
   else if(req.method==='POST'&&url.pathname==='/login/oauth2/accept'){const chunks=[];for await(const chunk of req)chunks.push(chunk);current.acceptBody=Buffer.concat(chunks).toString();current.acceptCookie=req.headers.cookie;current.acceptHits++;redirect();}
   else{res.writeHead(404);res.end();}
  });
  browser=await chromium.launch();
  for(const scenario of [{name:'consent-held',capture:true},{name:'immediate-held',capture:true,immediate:true},{name:'native',capture:false},{name:'wrong-state',capture:true,immediate:true,wrongState:true},{name:'wrong-origin',capture:true,immediate:true,wrongOrigin:true}]){
   current={...scenario,state:'private-state-'+scenario.name,code:'private-code-'+scenario.name,callbackHits:0,authHits:0,acceptHits:0};
   const observations=[],blocked=[],context=await browser.newContext({serviceWorkers:'block'});
   // Install local-only network confinement before creating a page.
   await context.route('**/*',async route=>{const origin=new URL(route.request().url()).origin;if([canvasOrigin,martyOrigin].includes(origin))await route.fallback();else{blocked.push('NONLOCAL_REQUEST');await route.abort();}});
   try{const page=await context.newPage();const url=new URL('/login/oauth2/auth',canvasOrigin);url.searchParams.set('client_id','owned-client');url.searchParams.set('state',current.state);url.searchParams.set('redirect_uri',martyOrigin+'/v1/integrations/canvas/oauth/callback');
    const operation=authorizeCanvasOAuth(page,url,{canvasOrigin,martyOrigin,captureAtProvider:scenario.capture,observe:row=>observations.push(row),timeout:5000});
    if(scenario.wrongState||scenario.wrongOrigin){await assert.rejects(operation,error=>error.code==='canvas_oauth_redirect_binding_failed');assert.equal(current.callbackHits,0);}
    else{const issued=await operation;assert.equal(issued.code,current.code);assert.equal(issued.state,current.state);assert.equal(current.callbackHits,scenario.capture?0:1);if(!scenario.immediate){assert.equal(current.acceptHits,1);assert.equal(current.acceptBody,'custom_csrf_token=owned-control');assert.match(current.acceptCookie,/owned_control=unchanged/);}if(!scenario.capture)assert(observations.some(row=>row.phase==='NATIVE_CALLBACK_REQUEST'));}
    assert.equal(current.authHits,1);assert.deepEqual(blocked,[]);assert(!JSON.stringify(observations).includes('private-state'));assert(!JSON.stringify(observations).includes('private-code'));
   }finally{await context.close();}
  }
 }finally{if(browser)await browser.close();await Promise.all(servers.map(server=>new Promise(resolve=>{server.closeAllConnections();server.close(resolve)})));}
});


test('developer key enable binds flat global account ACK beyond optimistic local-route checkbox', async () => {
  const {enableDeveloperKey}=require('./run-canvas-oss-standard-contract');
  for(const variant of [{status:200},{status:201},{status:200,developer_key_id:43},{status:200,account_id:1},{status:200,workflow_state:'off'},{status:200,account_owns_binding:false},{status:200,nested:true}]) {
    const {status}=variant;let checked=false,acknowledged=false,resolveResponse;const diagnostics=[];
    const responsePromise=new Promise(resolve=>{resolveResponse=resolve});
    const toggle={isChecked:async()=>checked,getAttribute:async()=> 'owned-toggle'};
    const row={waitFor:async()=>{},getByRole:()=>({first:()=>toggle}),locator:()=>({click:async()=>{checked=true}})};
    const page={url:()=> 'https://canvas.example/accounts/1/developer_keys',getByRole:(_,options)=>options?.name?{first:()=>({isVisible:async()=>false})}:{filter:()=>({first:()=>row})},
      waitForResponse:(predicate)=>{assert.equal(predicate({url:()=> 'https://canvas.example/api/v1/accounts/1/developer_keys/42/developer_key_account_bindings',request:()=>({method:()=> 'POST'})}),true);assert.equal(predicate({url:()=> 'https://canvas.example/api/v1/accounts/1/developer_keys/43/developer_key_account_bindings',request:()=>({method:()=> 'POST'})}),false);return responsePromise;}};
    const record={id:42,developer_key_account_binding:{developer_key_id:42,account_id:10000000000001,account_owns_binding:true}};
    let completed=false;const pending=enableDeveloperKey(page,'Owned',record,{observeBinding:value=>diagnostics.push(value)}).then(()=>{completed=true});
    await new Promise(resolve=>setImmediate(resolve));assert.equal(checked,true);assert.equal(completed,false);
    resolveResponse({status:()=>status,json:async()=>{acknowledged=true;const binding={developer_key_id:variant.developer_key_id??42,account_id:variant.account_id??10000000000001,account_owns_binding:variant.account_owns_binding??true,workflow_state:variant.workflow_state??'on'};return variant.nested?{developer_key_account_binding:binding}:binding}});
    if(Object.keys(variant).length===1){await pending;assert.equal(completed,true)}
    else {await assert.rejects(pending,error=>error.code==='canvas_key_binding_identity_mismatch');assert.equal(completed,false)}
    assert.equal(acknowledged,true);assert.equal(diagnostics.length,1);assert(Object.values(diagnostics[0]).every(value=>typeof value==='boolean'));
    for(const invalid of [{...record,developer_key_account_binding:{...record.developer_key_account_binding,account_owns_binding:false}},{...record,developer_key_account_binding:{...record.developer_key_account_binding,developer_key_id:43}}]){
      checked=false;await assert.rejects(enableDeveloperKey(page,'Owned',invalid),error=>error.code==='canvas_key_binding_reference_invalid');
    }
  }
});

test('capture private custody fsyncs only exact owned authority and preserves failure recovery until retirement', t => {
  const {createCanvasCaptureCustody}=require('./run-canvas-oss-standard-contract');
  const directory=fs.mkdtempSync(path.join(os.tmpdir(),'canvas-private-custody-'));
  t.after(()=>fs.rmSync(directory,{recursive:true,force:true}));
  const run='11111111-1111-4111-8111-111111111111',custody=createCanvasCaptureCustody(run,directory);
  custody.retain('canvasAdminSession','CONTROLLED_OLD_COOKIE');
  const filename=path.join(directory,run+'-canvasAdminSession.json');
  assert.equal(fs.readFileSync(filename,'utf8'),'CONTROLLED_OLD_COOKIE');
  assert.throws(()=>custody.retain('globalAdminPassword','SHARED_CREDENTIAL'));
  assert.throws(()=>createCanvasCaptureCustody(run,directory));
  custody.retain('canvasAdminSession','CONTROLLED_RETAINED_COOKIE');
  assert.equal(fs.readFileSync(filename,'utf8'),'CONTROLLED_RETAINED_COOKIE');
  assert.equal(custody.retire(),true);assert.equal(fs.existsSync(filename),false);
  const journal=JSON.parse(fs.readFileSync(path.join(directory,run+'.custody.json')));
  assert.equal(journal.state,'RETIRED');assert(!JSON.stringify(journal).includes('COOKIE'));
});

test('capture session cleanup distinguishes deleted learner denial from real admin logout and original-cookie denial',async()=>{
  const {retireCanvasCaptureSessions,retireCanvasBetaSession}=require('./run-canvas-oss-standard-contract');
  const retained=[],calls=[];let adminReads=0;
  const context=role=>({cookies:async()=>[{name:'_csrf_token',value:'CONTROLLED_CSRF'}],addCookies:async()=>{},request:{
    get:async()=>{const status=role==='learner'?401:++adminReads===1?200:401;return {status:()=>status}},
    delete:async()=>{calls.push(role);return {status:()=>302}}}});
  const custody={retain:(role)=>retained.push(role)};
  const result=await retireCanvasCaptureSessions({canvasOrigin:'https://canvas-test.elevenidllc.com',learnerContext:context('learner'),adminContext:context('admin'),custody});
  assert.equal(result.canvasLearnerSession.alreadyDenied,true);assert.deepEqual(calls,['admin']);assert.equal(result.canvasAdminSession.probes.at(-1).status,401);
  adminReads=0;calls.length=0;
  await assert.rejects(retireCanvasCaptureSessions({canvasOrigin:'https://canvas-test.elevenidllc.com',learnerContext:{cookies:async()=>[]},adminContext:context('admin'),custody}),error=>error.code==='canvas_capture_sessions_incomplete');
  assert.deepEqual(calls,['admin'],'One unknown owned session cannot block independent admin retirement');
  adminReads=0;calls.length=0;
  await assert.rejects(retireCanvasCaptureSessions({canvasOrigin:'https://canvas-test.elevenidllc.com',learnerContext:context('learner'),adminContext:context('admin'),custody},()=>{throw Error('CONTROLLED_OBSERVER_FAILURE')}),error=>error.code==='canvas_capture_sessions_incomplete');
  assert.deepEqual(calls,['admin'],'Observer persistence failure cannot prevent authority retirement');
  let originalHeader;const beta={cookies:async()=>[{name:'sessionId',value:'CONTROLLED_OWNED_SESSION'}],request:{post:async()=>({status:()=>303}),get:async(_,options)=>{originalHeader=options.headers.Cookie;return {status:()=>200,json:async()=>({authenticated:false,user:null})}}}};
  assert.equal((await retireCanvasBetaSession(beta,custody)).oldCookieAuthenticated,false);assert.equal(originalHeader,'sessionId=CONTROLLED_OWNED_SESSION');
});


test('capture custody retains then retires only its tracked temporary authority after atomic publication failure',t=>{
  const {createCanvasCaptureCustody}=require('./run-canvas-oss-standard-contract');
  const directory=fs.mkdtempSync(path.join(os.tmpdir(),'canvas-private-publish-'));
  t.after(()=>fs.rmSync(directory,{recursive:true,force:true}));
  const run='22222222-2222-4222-8222-222222222222',custody=createCanvasCaptureCustody(run,directory);
  custody.retain('canvasAdminSession','CONTROLLED_OLD');
  const original=fs.renameSync;fs.renameSync=(from,to)=>{if(from.endsWith('-canvasAdminSession.json.next'))throw Error('CONTROLLED_PUBLICATION_FAILURE');return original(from,to)};
  try {assert.throws(()=>custody.retain('canvasAdminSession','CONTROLLED_NEW'),/CONTROLLED_PUBLICATION_FAILURE/)} finally {fs.renameSync=original}
  assert(fs.existsSync(path.join(directory,run+'-canvasAdminSession.json.next')));
  fs.writeFileSync(path.join(directory,'unrelated-private-authority'),'PRESERVE');
  custody.retire();assert(!fs.existsSync(path.join(directory,run+'-canvasAdminSession.json.next')));
  assert(!fs.existsSync(path.join(directory,run+'-canvasAdminSession.json')));assert.equal(fs.readFileSync(path.join(directory,'unrelated-private-authority'),'utf8'),'PRESERVE');
});


test('capture retirement uses the shared typed OAuth authority path and rejects uncertain creation before teardown',async()=>{
  const {retireCanvasOAuthAuthority,requireCanvasSetupMutationReconciliation}=require('./run-canvas-oss-standard-contract');
  for(const status of ['CREATING','RESPONSE_UNVERIFIED']) assert.throws(()=>requireCanvasSetupMutationReconciliation({owned:{martySecretIntent:{state:status}}}),error=>error.code==='canvas_setup_creation_uncertain');
  const calls=[];let removed=false;const state={organizationId:'owned-org',platformId:'owned-platform',marty:{request:async(method,path,options)=>{
    calls.push({method,path,includeStatus:options.includeStatus});
    if(method==='DELETE'){removed=true;return {status:200,payload:{platform_id:'owned-platform',status:'disconnected',scopes:[]}}}
    return {status:200,payload:removed?[]:[{id:'33333333-3333-4333-8333-333333333333',organization_id:'owned-org',provider:'canvas',purpose:'oauth_access_token',enabled:true,metadata:{platform_id:'owned-platform'}}]};
  }}};
  const result=await retireCanvasOAuthAuthority(state,()=>{},{requireAccess:true});
  assert.equal(result.typedDisconnectedAck,true);assert.equal(result.atomicMetadataAbsence,true);assert.equal(result.serverHeldBearerProbed,false);
  assert.deepEqual(calls.map(row=>row.method),['GET','DELETE','GET']);assert(calls.every(row=>row.includeStatus===true));
});
