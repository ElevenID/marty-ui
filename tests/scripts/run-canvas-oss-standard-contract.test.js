'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const test = require('node:test');

const {
  BLOCKING_READINESS_CHECK_CODES,
  CASE_IDS,
  ContractFailure,
  ObservationLedger,
  createHolderProof,
  didWebResolutionUrl,
  extractDeveloperKeyRecord,
  parseCredentialOfferUri,
  responseJson,
  sanitizeEvidence,
  validateAuthoritativeEvidenceHeads,
  validateReadinessSnapshot,
  verifyCompactJws,
} = require('./run-canvas-oss-standard-contract');

const NOW = '2026-07-15T06:00:00.000Z';

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

test('observation ledger emits the fixed schema and never invents optional coverage', () => {
  const execution = {
    boundary: 'docker_compose_one_shot',
    compose_service: 'canvas-contract',
    containerized: true,
    host_browser_processes: false,
    secret_transport: 'compose_secret_files',
    image_id: `sha256:${'a'.repeat(64)}`,
    source_sha: 'b'.repeat(40),
    base_image: `mcr.microsoft.com/playwright:v1.56.0-jammy@sha256:${'c'.repeat(64)}`,
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
