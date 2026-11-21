import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, verify } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { canonicalJson, EnrollmentSigningError, parseStrictJson, signEnrollment,
  validateChallengeDocument } from '../scripts/sign_managed_enrollment.mjs';
import { regenerateEnvelope, syntheticEnrollment } from './support/managed_enrollment_fixture.mjs';

const P256_ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const SCRIPT = fileURLToPath(new URL('../scripts/sign_managed_enrollment.mjs', import.meta.url));
function signFixture(fixture, overrides = {}) {
  return signEnrollment({ challengeDocument: JSON.stringify(fixture.envelope),
    privateKeyPem: fixture.privateKeyPem, expected: fixture.expected,
    nowMilliseconds: fixture.nowMilliseconds, ...overrides });
}
function fails(action, code) {
  assert.throws(action, error => error instanceof EnrollmentSigningError && error.code === code);
}

for (const algorithm of ['ES256', 'EdDSA']) {
  test(`${algorithm}: actual signature covers exact payload and selected header`, () => {
    const fixture = syntheticEnrollment(algorithm);
    const compact = signFixture(fixture);
    const [encodedHeader, encodedPayload, encodedSignature] = compact.split('.');
    const signature = Buffer.from(encodedSignature, 'base64url');
    assert.equal(encodedPayload, fixture.envelope.signing_payload);
    assert.deepEqual(JSON.parse(Buffer.from(encodedHeader, 'base64url')), {
      typ: 'marty-managed-enrollment+jws', alg: algorithm, kid: fixture.envelope.challenge.key_id,
    });
    assert.equal(signature.length, 64);
    assert.equal(algorithm === 'ES256'
      ? verify('sha256', Buffer.from(`${encodedHeader}.${encodedPayload}`), { key: fixture.publicKey, dsaEncoding: 'ieee-p1363' }, signature)
      : verify(null, Buffer.from(`${encodedHeader}.${encodedPayload}`), fixture.publicKey, signature), true);
    if (algorithm === 'ES256') {
      assert.ok(BigInt(`0x${signature.subarray(32).toString('hex')}`) <= P256_ORDER / 2n);
    }
    assert.equal(fixture.envelope.challenge_digest,
      `sha256:${createHash('sha256').update(Buffer.from(encodedPayload, 'base64url')).digest('hex')}`);
  });
}

test('independent expected context pins are mandatory and exact', () => {
  const fixture = syntheticEnrollment('EdDSA');
  for (const field of Object.keys(fixture.expected)) {
    const absent = { ...fixture.expected }; delete absent[field];
    fails(() => signFixture(fixture, { expected: absent }), 'MISSING_EXPECTED_CONTEXT');
    const changed = { ...fixture.expected, [field]: typeof fixture.expected[field] === 'number' ? 99 : 'other-context' };
    fails(() => signFixture(fixture, { expected: changed }), 'EXPECTED_CONTEXT_MISMATCH');
  }
  for (const field of ['issuer', 'subject', 'session_ref']) {
    assert.ok(signFixture(fixture, { expected: { ...fixture.expected, [field]: fixture.envelope.challenge[field] } }));
    fails(() => signFixture(fixture, { expected: { ...fixture.expected, [field]: 'other-context' } }), 'EXPECTED_CONTEXT_MISMATCH');
  }
});

test('wrong private key and wrong selected algorithm cannot sign a retained identity', () => {
  const fixture = syntheticEnrollment('EdDSA');
  fails(() => signFixture(fixture, { privateKeyPem: syntheticEnrollment('EdDSA').privateKeyPem }), 'LOCAL_KEY_THUMBPRINT_MISMATCH');
  fails(() => signFixture(fixture, { privateKeyPem: syntheticEnrollment('ES256').privateKeyPem }), 'LOCAL_KEY_ALGORITHM_MISMATCH');
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'secp384r1' });
  fails(() => signFixture(fixture, { privateKeyPem: privateKey.export({ format: 'pem', type: 'pkcs8' }) }), 'LOCAL_KEY_ALGORITHM_MISMATCH');
  fails(() => signFixture(fixture, { privateKeyPem: '-----BEGIN PRIVATE KEY-----\nsynthetic secret\n-----END PRIVATE KEY-----' }), 'INVALID_LOCAL_PRIVATE_KEY');
  fails(() => signFixture(fixture, { privateKeyPem: fixture.privateKeyPem + fixture.privateKeyPem }), 'INVALID_LOCAL_PRIVATE_KEY');
});

test('current local clock rejects future issuance and exact expiry', () => {
  const fixture = syntheticEnrollment('EdDSA');
  const { iat, exp } = fixture.envelope.challenge;
  fails(() => signFixture(fixture, { nowMilliseconds: iat * 1000 - 1 }), 'ENROLLMENT_NOT_YET_VALID');
  assert.ok(signFixture(fixture, { nowMilliseconds: iat * 1000 }));
  assert.ok(signFixture(fixture, { nowMilliseconds: exp * 1000 - 1 }));
  fails(() => signFixture(fixture, { nowMilliseconds: exp * 1000 }), 'ENROLLMENT_EXPIRED');
  fails(() => signFixture(fixture, { nowMilliseconds: NaN }), 'INVALID_LOCAL_CLOCK');
});

test('canonical payload and digest must agree before signing', () => {
  const fixture = syntheticEnrollment('EdDSA');
  for (const change of [
    envelope => { envelope.signing_payload += '='; },
    envelope => { envelope.signing_payload = Buffer.from(JSON.stringify(envelope.challenge, null, 2)).toString('base64url'); },
    envelope => { envelope.challenge_digest = `sha256:${'00'.repeat(32)}`; },
    envelope => { envelope.challenge.subject = 'changed-subject'; },
    envelope => { envelope.organization_id = '11111111-1111-4111-8111-111111111111'; },
    envelope => { envelope.expires_at = '2020-01-01T00:00:00Z'; },
  ]) {
    const changed = structuredClone(fixture.envelope); change(changed);
    assert.throws(() => signFixture(fixture, { challengeDocument: JSON.stringify(changed) }), EnrollmentSigningError);
  }
});

test('duplicate unknown null and non-integer JSON fields fail closed', () => {
  const fixture = syntheticEnrollment('EdDSA');
  const raw = JSON.stringify(fixture.envelope);
  for (const input of [
    raw.replace('{', '{"profile":null,'),
    raw.replace('"expected_revision":7', '"expected_revision":7.0'),
    raw.replace('"iat":1800000000', '"iat":1.8e9'),
    raw.replace('"expected_revision":7', '"expected_revision":9007199254740992'),
    raw.replace('{', '{"verified":true,'),
    raw.replace('"exp":1800000120', '"exp":null'),
    raw + '{}',
  ]) { assert.throws(() => signFixture(fixture, { challengeDocument: input }), EnrollmentSigningError); }
  fails(() => parseStrictJson('{"x":1,"\\u0078":2}'), 'DUPLICATE_JSON_FIELD');
  fails(() => parseStrictJson('{"x":"\\ud800"}'), 'INVALID_JSON');
  fails(() => parseStrictJson('{"x":-0}'), 'INVALID_JSON');
  fails(() => parseStrictJson(' '.repeat(32_769)), 'INVALID_JSON');
});

test('closed policy bounds and source shapes are validated independently', () => {
  const fixture = syntheticEnrollment('EdDSA');
  for (const change of [
    challenge => { challenge.purpose = 'AUTHENTICATE_MACHINE'; },
    challenge => { challenge.expected_revision = Number.MAX_SAFE_INTEGER; },
    challenge => { challenge.key_algorithm = 'Ed25519'; },
    challenge => { challenge.key_thumbprint.basis = 'X509_CERTIFICATE_DER_SHA256'; },
    challenge => { challenge.key_thumbprint.value += '='; },
    challenge => { challenge.session_ref = `sha256:${'ab'.repeat(32)}`; },
    challenge => { challenge.nonce = Buffer.alloc(32).toString('base64url'); },
    challenge => { challenge.runtime_instance_ref = 'https://*.example.test'; },
    challenge => { challenge.issuer = 'https://example.test/%zz'; },
    challenge => { challenge.subject = 'subject\ncontrol'; },
    challenge => { challenge.policy.allowed_algorithms = ['EdDSA', 'ES256']; },
    challenge => { challenge.policy.allowed_algorithms = ['EdDSA', 'EdDSA']; },
    challenge => { challenge.policy.allowed_algorithms = ['ES256']; },
    challenge => { challenge.policy.max_age_seconds = 301; },
    challenge => { challenge.policy.revision = 0; },
    challenge => { challenge.policy.extra = null; },
  ]) {
    const envelope = structuredClone(fixture.envelope); change(envelope.challenge); regenerateEnvelope(envelope);
    assert.throws(() => signFixture(fixture, { challengeDocument: JSON.stringify(envelope) }), EnrollmentSigningError);
  }
});

test('noncanonical base64 trailing bits are rejected', () => {
  const fixture = syntheticEnrollment('EdDSA');
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const envelope = structuredClone(fixture.envelope);
  const nonce = envelope.challenge.nonce;
  const last = alphabet.indexOf(nonce.at(-1));
  envelope.challenge.nonce = nonce.slice(0, -1) + alphabet[last + 1];
  regenerateEnvelope(envelope);
  fails(() => signFixture(fixture, { challengeDocument: JSON.stringify(envelope) }), 'NON_CANONICAL_ENCODING');
});

test('canonical strings reject a trailing line break rather than JavaScript dollar-anchor aliases', () => {
  const fixture = syntheticEnrollment('EdDSA');
  for (const field of ['challenge_id', 'organization_id', 'agent_id', 'key_id', 'administrator_id',
    'session_ref', 'issuer', 'audience', 'runtime_instance_ref']) {
    for (const suffix of ['\n', '\r', '\r\n', '\u2028']) {
      const envelope = structuredClone(fixture.envelope);
      envelope.challenge[field] += suffix;
      regenerateEnvelope(envelope);
      fails(() => signFixture(fixture, { challengeDocument: JSON.stringify(envelope) }), 'INVALID_ENROLLMENT_CHALLENGE');
    }
  }
  const envelope = structuredClone(fixture.envelope);
  envelope.challenge.policy.profile += '\n'; regenerateEnvelope(envelope);
  fails(() => signFixture(fixture, { challengeDocument: JSON.stringify(envelope) }), 'INVALID_ENROLLMENT_CHALLENGE');
});

test('safe maximum revisions and Unicode subject serialize identically', () => {
  const fixture = syntheticEnrollment('EdDSA');
  const envelope = structuredClone(fixture.envelope);
  envelope.challenge.expected_revision = Number.MAX_SAFE_INTEGER - 1;
  envelope.expected_revision = envelope.challenge.expected_revision;
  envelope.challenge.policy.revision = Number.MAX_SAFE_INTEGER;
  envelope.challenge.subject = 'synthetic café 🚀';
  regenerateEnvelope(envelope);
  const result = validateChallengeDocument(JSON.stringify(envelope), {
    ...fixture.expected, expected_revision: Number.MAX_SAFE_INTEGER - 1, policy_revision: Number.MAX_SAFE_INTEGER,
  }, fixture.nowMilliseconds);
  assert.equal(result.payload.toString('utf8'), canonicalJson(result.challenge));
});

test('CLI emits one compact proof and never private material or file contents', async () => {
  const fixture = syntheticEnrollment('EdDSA', Math.floor(Date.now() / 1000));
  const directory = await mkdtemp(join(tmpdir(), 'marty-enrollment-signer-'));
  try {
    const challengePath = join(directory, 'challenge.json');
    const keyPath = join(directory, 'key.pk8.pem');
    await writeFile(challengePath, JSON.stringify(fixture.envelope), { mode: 0o600 });
    await writeFile(keyPath, fixture.privateKeyPem, { mode: 0o600 });
    const args = ['--challenge', challengePath, '--key', keyPath,
      '--organization', fixture.expected.organization_id, '--agent', fixture.expected.agent_id,
      '--administrator', fixture.expected.administrator_id, '--audience', fixture.expected.audience,
      '--runtime', fixture.expected.runtime_instance_ref, '--policy', fixture.expected.policy_profile,
      '--policy-revision', String(fixture.expected.policy_revision), '--expected-revision', String(fixture.expected.expected_revision)];
    const result = spawnSync(process.execPath, [SCRIPT, ...args], { encoding: 'utf8', timeout: 5000 });
    assert.equal(result.status, 0, result.stderr); assert.equal(result.stderr, '');
    assert.match(result.stdout, /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\n$/);
    assert.ok(!result.stdout.includes('PRIVATE KEY'));
    assert.equal(await readFile(keyPath, 'utf8'), fixture.privateKeyPem);
    const invalid = spawnSync(process.execPath, [SCRIPT, ...args, '--clock', '0'], { encoding: 'utf8', timeout: 5000 });
    assert.equal(invalid.status, 1); assert.equal(invalid.stdout, ''); assert.equal(invalid.stderr, 'INVALID_ARGUMENTS\n');
    const wrong = [...args]; wrong[wrong.indexOf('--administrator') + 1] = '11111111-1111-4111-8111-111111111111';
    const rejected = spawnSync(process.execPath, [SCRIPT, ...wrong], { encoding: 'utf8', timeout: 5000 });
    assert.equal(rejected.status, 1); assert.equal(rejected.stdout, ''); assert.equal(rejected.stderr, 'EXPECTED_CONTEXT_MISMATCH\n');
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('committed interoperability vectors contain only public key material', async () => {
  const path = new URL('../rust/crates/principal-runtime-binding/tests/fixtures/node-managed-enrollment.json', import.meta.url);
  const document = JSON.parse(await readFile(path, 'utf8'));
  assert.equal(document.profile, 'urn:marty:managed-key-enrollment-public-test-vectors:v1');
  assert.equal(document.provenance.private_material_retained, false);
  assert.deepEqual(document.vectors.map(vector => vector.algorithm), ['ES256', 'EdDSA']);
  for (const vector of document.vectors) {
    assert.deepEqual(Object.keys(vector.public_jwk).sort(), vector.algorithm === 'ES256' ? ['crv', 'kty', 'x', 'y'] : ['crv', 'kty', 'x']);
    assert.equal(vector.proof.split('.').length, 3);
    assert.ok(!JSON.stringify(vector).includes('PRIVATE KEY'));
  }
});
