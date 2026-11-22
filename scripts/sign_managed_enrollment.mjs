#!/usr/bin/env node
// Local key-custodian utility. No network, private-key export, browser bridge,
// enrollment request, or operational machine-authentication claim.
import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { open } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const ENROLLMENT_PROFILE = 'urn:marty:managed-key-enrollment:v1';
export const ENROLLMENT_JWS_TYPE = 'marty-managed-enrollment+jws';
const SESSION_PREFIX = 'urn:marty:session:sha256:';
const MAX_DOCUMENT_BYTES = 32_768;
const MAX_PAYLOAD_BYTES = 8_192;
const MAX_PRIVATE_KEY_BYTES = 16_384;
const MAX_EPOCH_SECONDS = 253_402_300_799;
const P256_ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

export class EnrollmentSigningError extends Error {
  constructor(code) { super(code); this.name = 'EnrollmentSigningError'; this.code = code; }
}
function fail(code) { throw new EnrollmentSigningError(code); }
function requireCondition(condition, code = 'INVALID_ENROLLMENT_CHALLENGE') {
  if (!condition) fail(code);
}
function closed(value, fields, code = 'INVALID_ENROLLMENT_CHALLENGE') {
  requireCondition(value !== null && typeof value === 'object' && !Array.isArray(value), code);
  const actual = Object.keys(value).sort();
  const expected = [...fields].sort();
  requireCondition(actual.length === expected.length && actual.every((key, i) => key === expected[i]), code);
}
function string(value, max = 1024) {
  return typeof value === 'string' && value.length > 0 && [...value].length <= max;
}
function uri(value) {
  if (!string(value) || /[^A-Za-z0-9\-._~:/?#[\]@!$&'()+,;=%]/.test(value)
    || /%(?![0-9a-fA-F]{2})/.test(value)) return false;
  try { new URL(value); return true; } catch { return false; }
}
function uuid(value) {
  return typeof value === 'string'
    && value.length === 36
    && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value)
    && value !== '00000000-0000-0000-0000-000000000000';
}
function positiveInteger(value, maximum = Number.MAX_SAFE_INTEGER) {
  return Number.isSafeInteger(value) && value >= 1 && value <= maximum;
}
function base64url(value, exactBytes, maximum = MAX_PAYLOAD_BYTES) {
  requireCondition(typeof value === 'string' && value.length > 0
    && value.length <= Math.ceil(maximum / 3) * 4 && /^[A-Za-z0-9_-]+$/.test(value), 'NON_CANONICAL_ENCODING');
  const bytes = Buffer.from(value, 'base64url');
  requireCondition(bytes.length <= maximum && bytes.toString('base64url') === value
    && (exactBytes === undefined || bytes.length === exactBytes), 'NON_CANONICAL_ENCODING');
  return bytes;
}
function digest(bytes) { return `sha256:${createHash('sha256').update(bytes).digest('hex')}`; }

// This restricted canonical JSON profile has ASCII member names, safe integer
// numbers, no optional/null members, and recursively sorted object keys.
export function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

/** Bounded JSON with duplicate member detection before object projection. */
export function parseStrictJson(raw) {
  requireCondition(typeof raw === 'string' && Buffer.byteLength(raw) <= MAX_DOCUMENT_BYTES, 'INVALID_JSON');
  let offset = 0;
  const whitespace = () => { while (/[ \t\r\n]/.test(raw[offset] ?? '\0')) offset += 1; };
  const readString = () => {
    requireCondition(raw[offset] === '"', 'INVALID_JSON');
    const start = offset++;
    while (offset < raw.length) {
      const char = raw[offset++];
      if (char === '\\') { offset += 1; continue; }
      if (char === '"') {
        let value;
        try { value = JSON.parse(raw.slice(start, offset)); } catch { fail('INVALID_JSON'); }
        // Rust's JSON reader rejects unpaired surrogate escapes; keep parity.
        requireCondition(Buffer.from(value, 'utf8').toString('utf8') === value, 'INVALID_JSON');
        return value;
      }
    }
    fail('INVALID_JSON');
  };
  const read = depth => {
    requireCondition(depth <= 32, 'INVALID_JSON');
    whitespace();
    const char = raw[offset];
    if (char === '"') return readString();
    if (char === '{') {
      offset += 1; whitespace();
      const result = Object.create(null);
      const names = new Set();
      if (raw[offset] === '}') { offset += 1; return result; }
      while (true) {
        whitespace(); const key = readString(); whitespace();
        requireCondition(!names.has(key), 'DUPLICATE_JSON_FIELD'); names.add(key);
        requireCondition(raw[offset++] === ':', 'INVALID_JSON'); result[key] = read(depth + 1); whitespace();
        const delimiter = raw[offset++];
        if (delimiter === '}') return result;
        requireCondition(delimiter === ',', 'INVALID_JSON');
      }
    }
    if (char === '[') {
      offset += 1; whitespace();
      const result = [];
      if (raw[offset] === ']') { offset += 1; return result; }
      while (true) {
        result.push(read(depth + 1)); whitespace();
        const delimiter = raw[offset++];
        if (delimiter === ']') return result;
        requireCondition(delimiter === ',', 'INVALID_JSON');
      }
    }
    for (const [literal, value] of [['true', true], ['false', false], ['null', null]]) {
      if (raw.startsWith(literal, offset)) { offset += literal.length; return value; }
    }
    const number = raw.slice(offset).match(/^-?(?:0|[1-9][0-9]*)/);
    requireCondition(number !== null && number[0] !== '-0', 'INVALID_JSON');
    offset += number[0].length;
    const value = Number(number[0]);
    requireCondition(Number.isSafeInteger(value), 'INVALID_JSON');
    return value;
  };
  const result = read(0); whitespace();
  requireCondition(offset === raw.length && result !== null && typeof result === 'object' && !Array.isArray(result), 'INVALID_JSON');
  return result;
}

const OUTER_FIELDS = ['profile', 'challenge_id', 'organization_id', 'agent_id', 'expected_revision',
  'challenge', 'signing_payload', 'challenge_digest', 'expires_at', 'recovered'];
const CHALLENGE_FIELDS = ['profile', 'purpose', 'challenge_id', 'organization_id', 'agent_id',
  'key_id', 'administrator_id', 'expected_revision', 'key_algorithm', 'key_thumbprint',
  'runtime_instance_ref', 'issuer', 'subject', 'session_ref', 'audience', 'nonce', 'iat', 'exp', 'policy'];
const EXPECTED_REQUIRED = ['organization_id', 'agent_id', 'administrator_id', 'audience',
  'runtime_instance_ref', 'policy_profile', 'policy_revision', 'expected_revision'];
const EXPECTED_OPTIONAL = ['session_ref', 'issuer', 'subject'];

export function validateChallengeDocument(raw, expected, nowMilliseconds = Date.now()) {
  const envelope = parseStrictJson(raw);
  closed(envelope, OUTER_FIELDS);
  const challenge = envelope.challenge;
  closed(challenge, CHALLENGE_FIELDS);
  requireCondition(envelope.profile === ENROLLMENT_PROFILE && challenge.profile === ENROLLMENT_PROFILE
    && challenge.purpose === 'ENROLL_MANAGED_KEY');
  for (const field of ['challenge_id', 'organization_id', 'agent_id', 'key_id', 'administrator_id']) {
    requireCondition(uuid(challenge[field]));
  }
  requireCondition(positiveInteger(challenge.expected_revision, Number.MAX_SAFE_INTEGER - 1));
  requireCondition(['ES256', 'EdDSA'].includes(challenge.key_algorithm));
  closed(challenge.key_thumbprint, ['basis', 'encoding', 'value']);
  requireCondition(challenge.key_thumbprint.basis === 'JWK_RFC7638_SHA256'
    && challenge.key_thumbprint.encoding === 'BASE64URL_SHA256');
  base64url(challenge.key_thumbprint.value, 32, 32);
  for (const field of ['runtime_instance_ref', 'issuer', 'audience']) requireCondition(uri(challenge[field]));
  requireCondition(string(challenge.subject, 512) && !/[\u0000-\u001f\u007f-\u009f]/u.test(challenge.subject));
  requireCondition(typeof challenge.session_ref === 'string'
    && challenge.session_ref.length === SESSION_PREFIX.length + 64
    && challenge.session_ref.startsWith(SESSION_PREFIX)
    && /^[0-9a-f]{64}$/.test(challenge.session_ref.slice(SESSION_PREFIX.length)));
  requireCondition(!base64url(challenge.nonce, 32, 32).every(byte => byte === 0));
  closed(challenge.policy, ['profile', 'revision', 'allowed_algorithms', 'max_age_seconds']);
  requireCondition(uri(challenge.policy.profile) && positiveInteger(challenge.policy.revision)
    && positiveInteger(challenge.policy.max_age_seconds, 300));
  requireCondition(Array.isArray(challenge.policy.allowed_algorithms)
    && challenge.policy.allowed_algorithms.length >= 1 && challenge.policy.allowed_algorithms.length <= 2
    && challenge.policy.allowed_algorithms.every((algorithm, index, algorithms) =>
      ['ES256', 'EdDSA'].includes(algorithm) && (index === 0 || algorithms[index - 1] < algorithm))
    && challenge.policy.allowed_algorithms.includes(challenge.key_algorithm));
  for (const field of ['iat', 'exp']) {
    requireCondition(Number.isSafeInteger(challenge[field]) && challenge[field] >= 0
      && challenge[field] <= MAX_EPOCH_SECONDS);
  }
  requireCondition(challenge.exp > challenge.iat && challenge.exp - challenge.iat <= challenge.policy.max_age_seconds);
  requireCondition(Number.isSafeInteger(nowMilliseconds) && nowMilliseconds >= 0, 'INVALID_LOCAL_CLOCK');
  requireCondition(nowMilliseconds >= challenge.iat * 1000, 'ENROLLMENT_NOT_YET_VALID');
  requireCondition(nowMilliseconds < challenge.exp * 1000, 'ENROLLMENT_EXPIRED');

  for (const field of ['challenge_id', 'organization_id', 'agent_id', 'expected_revision']) {
    requireCondition(envelope[field] === challenge[field], 'CHALLENGE_ENVELOPE_MISMATCH');
  }
  const canonicalExpiry = new Date(challenge.exp * 1000).toISOString().replace('.000Z', 'Z');
  requireCondition(envelope.expires_at === canonicalExpiry && typeof envelope.recovered === 'boolean', 'CHALLENGE_ENVELOPE_MISMATCH');
  const payload = base64url(envelope.signing_payload);
  requireCondition(payload.equals(Buffer.from(canonicalJson(challenge), 'utf8')), 'CHALLENGE_PAYLOAD_MISMATCH');
  requireCondition(envelope.challenge_digest === digest(payload), 'CHALLENGE_DIGEST_MISMATCH');

  requireCondition(expected !== null && typeof expected === 'object' && !Array.isArray(expected), 'MISSING_EXPECTED_CONTEXT');
  requireCondition(EXPECTED_REQUIRED.every(field => Object.hasOwn(expected, field))
    && Object.keys(expected).every(field => EXPECTED_REQUIRED.includes(field) || EXPECTED_OPTIONAL.includes(field)), 'MISSING_EXPECTED_CONTEXT');
  for (const field of ['organization_id', 'agent_id', 'administrator_id', 'audience', 'runtime_instance_ref', 'expected_revision', ...EXPECTED_OPTIONAL]) {
    if (Object.hasOwn(expected, field)) requireCondition(expected[field] === challenge[field], 'EXPECTED_CONTEXT_MISMATCH');
  }
  requireCondition(expected.policy_profile === challenge.policy.profile
    && expected.policy_revision === challenge.policy.revision, 'EXPECTED_CONTEXT_MISMATCH');
  return { envelope, challenge, payload };
}

/**
 * Sign locally with a PKCS8 PEM. `nowMilliseconds` exists for deterministic test
 * vectors; the CLI always supplies its real current clock and has no override.
 */
export function signEnrollment({ challengeDocument, privateKeyPem, expected, nowMilliseconds = Date.now() }) {
  const { envelope, challenge } = validateChallengeDocument(challengeDocument, expected, nowMilliseconds);
  let key;
  try {
    const pem = Buffer.isBuffer(privateKeyPem) ? privateKeyPem : Buffer.from(privateKeyPem, 'utf8');
    requireCondition(pem.length > 0 && pem.length <= MAX_PRIVATE_KEY_BYTES
      && /^-----BEGIN PRIVATE KEY-----\r?\n[A-Za-z0-9+/=\r\n]+\r?\n-----END PRIVATE KEY-----\r?\n?$/.test(pem.toString('ascii')),
    'INVALID_LOCAL_PRIVATE_KEY');
    key = createPrivateKey({ key: pem, format: 'pem', type: 'pkcs8' });
  } catch { fail('INVALID_LOCAL_PRIVATE_KEY'); }
  const algorithm = key.asymmetricKeyType === 'ed25519' ? 'EdDSA'
    : key.asymmetricKeyType === 'ec' && key.asymmetricKeyDetails?.namedCurve === 'prime256v1' ? 'ES256' : null;
  requireCondition(algorithm === challenge.key_algorithm, 'LOCAL_KEY_ALGORITHM_MISMATCH');
  const publicKey = createPublicKey(key);
  const publicJwk = publicKey.export({ format: 'jwk' });
  const projection = algorithm === 'ES256'
    ? { crv: 'P-256', kty: 'EC', x: publicJwk.x, y: publicJwk.y }
    : { crv: 'Ed25519', kty: 'OKP', x: publicJwk.x };
  const fingerprint = createHash('sha256').update(canonicalJson(projection)).digest('base64url');
  requireCondition(fingerprint === challenge.key_thumbprint.value, 'LOCAL_KEY_THUMBPRINT_MISMATCH');
  const protectedHeader = Buffer.from(JSON.stringify({ typ: ENROLLMENT_JWS_TYPE, alg: algorithm, kid: challenge.key_id })).toString('base64url');
  const signingInput = `${protectedHeader}.${envelope.signing_payload}`;
  let signature;
  try {
    signature = algorithm === 'ES256'
      ? sign('sha256', Buffer.from(signingInput), { key, dsaEncoding: 'ieee-p1363' })
      : sign(null, Buffer.from(signingInput), key);
    requireCondition(signature.length === 64, 'LOCAL_SIGNING_FAILED');
    if (algorithm === 'ES256') {
      const r = BigInt(`0x${signature.subarray(0, 32).toString('hex')}`);
      let s = BigInt(`0x${signature.subarray(32).toString('hex')}`);
      requireCondition(r > 0n && r < P256_ORDER && s > 0n && s < P256_ORDER, 'LOCAL_SIGNING_FAILED');
      if (s > P256_ORDER / 2n) s = P256_ORDER - s;
      signature = Buffer.concat([signature.subarray(0, 32), Buffer.from(s.toString(16).padStart(64, '0'), 'hex')]);
    }
    const valid = algorithm === 'ES256'
      ? verify('sha256', Buffer.from(signingInput), { key: publicKey, dsaEncoding: 'ieee-p1363' }, signature)
      : verify(null, Buffer.from(signingInput), publicKey, signature);
    requireCondition(valid, 'LOCAL_SIGNING_FAILED');
  } catch { fail('LOCAL_SIGNING_FAILED'); }
  return `${signingInput}.${signature.toString('base64url')}`;
}

const HELP = `Usage: node scripts/sign_managed_enrollment.mjs
  --challenge exported-challenge.json --key local-key.pk8.pem
  --organization UUID --agent UUID --administrator UUID
  --audience URI --runtime URI --policy URI --policy-revision INTEGER
  --expected-revision INTEGER
  [--session-ref urn:marty:session:sha256:HEX] [--issuer URI] [--subject TEXT]

Signs the exact exported enrollment payload with the matching local P-256 or
Ed25519 private key. Review the organization, agent, administrator, runtime,
audience, policy and revision independently before choosing these expected
values. Optional pins also check the exact session/source identity fields.
Private keys remain local; no network calls are made. Only a compact JWS is
printed on success. Submit that proof through the authenticated enrollment
completion API before the retained challenge expires. This proves enrollment
key possession only, not operational MAP authentication or authority.
`;

async function readLocal(path, maximum) {
  let file;
  try {
    file = await open(path, 'r');
    const stat = await file.stat();
    requireCondition(stat.isFile() && stat.size > 0 && stat.size <= maximum, 'INVALID_LOCAL_FILE');
    const bytes = Buffer.alloc(maximum + 1);
    let total = 0;
    while (total < bytes.length) {
      const { bytesRead } = await file.read(bytes, total, bytes.length - total, null);
      if (bytesRead === 0) break;
      total += bytesRead;
    }
    requireCondition(total > 0 && total <= maximum, 'INVALID_LOCAL_FILE');
    return bytes.subarray(0, total);
  } catch { fail('INVALID_LOCAL_FILE'); }
  finally { await file?.close(); }
}

async function main(args) {
  if (args.length === 1 && args[0] === '--help') { process.stdout.write(HELP); return; }
  requireCondition(Number(process.versions.node.split('.')[0]) >= 24, 'NODE_24_REQUIRED');
  const names = ['challenge', 'key', 'organization', 'agent', 'administrator', 'audience', 'runtime',
    'policy', 'policy-revision', 'expected-revision', 'session-ref', 'issuer', 'subject'];
  const options = Object.create(null);
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index]?.startsWith('--') ? args[index].slice(2) : '';
    requireCondition(names.includes(name) && !Object.hasOwn(options, name)
      && typeof args[index + 1] === 'string' && args[index + 1].length > 0, 'INVALID_ARGUMENTS');
    options[name] = args[index + 1];
  }
  requireCondition(names.slice(0, 10).every(name => Object.hasOwn(options, name)), 'MISSING_ARGUMENTS');
  for (const name of ['policy-revision', 'expected-revision']) {
    requireCondition(/^[1-9][0-9]*$/.test(options[name]) && positiveInteger(Number(options[name]))
      && String(Number(options[name])) === options[name], 'INVALID_ARGUMENTS');
  }
  const expected = {
    organization_id: options.organization, agent_id: options.agent, administrator_id: options.administrator,
    audience: options.audience, runtime_instance_ref: options.runtime, policy_profile: options.policy,
    policy_revision: Number(options['policy-revision']), expected_revision: Number(options['expected-revision']),
  };
  for (const [option, field] of [['session-ref', 'session_ref'], ['issuer', 'issuer'], ['subject', 'subject']]) {
    if (Object.hasOwn(options, option)) expected[field] = options[option];
  }
  const challengeBytes = await readLocal(options.challenge, MAX_DOCUMENT_BYTES);
  let challengeDocument;
  try { challengeDocument = new TextDecoder('utf-8', { fatal: true }).decode(challengeBytes); }
  catch { fail('INVALID_JSON'); }
  const privateKeyPem = await readLocal(options.key, MAX_PRIVATE_KEY_BYTES);
  try { process.stdout.write(`${signEnrollment({ challengeDocument, privateKeyPem, expected })}\n`); }
  finally { privateKeyPem.fill(0); }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch(error => {
    process.stderr.write(`${error instanceof EnrollmentSigningError ? error.code : 'ENROLLMENT_SIGNING_FAILED'}\n`);
    process.exitCode = 1;
  });
}
