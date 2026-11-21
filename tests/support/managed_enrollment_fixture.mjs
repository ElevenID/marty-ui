// Test-only ephemeral key generation. Returned private material must never be
// serialized into a committed interoperability vector or printed in diagnostics.
import { createHash, generateKeyPairSync } from 'node:crypto';
import { canonicalJson, ENROLLMENT_PROFILE } from '../../scripts/sign_managed_enrollment.mjs';

export function syntheticEnrollment(algorithm, issuedAt = 1_800_000_000) {
  const { privateKey, publicKey } = algorithm === 'ES256'
    ? generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
    : generateKeyPairSync('ed25519');
  const publicJwk = publicKey.export({ format: 'jwk' });
  const projection = algorithm === 'ES256'
    ? { crv: 'P-256', kty: 'EC', x: publicJwk.x, y: publicJwk.y }
    : { crv: 'Ed25519', kty: 'OKP', x: publicJwk.x };
  const challenge = {
    profile: ENROLLMENT_PROFILE, purpose: 'ENROLL_MANAGED_KEY',
    challenge_id: '1abcf234-5abc-4def-8abc-123456789001',
    organization_id: '1abcf234-5abc-4def-8abc-123456789002',
    agent_id: '1abcf234-5abc-4def-8abc-123456789003',
    key_id: '1abcf234-5abc-4def-8abc-123456789004',
    administrator_id: '1abcf234-5abc-4def-8abc-123456789005',
    expected_revision: 7, key_algorithm: algorithm,
    key_thumbprint: { basis: 'JWK_RFC7638_SHA256', encoding: 'BASE64URL_SHA256',
      value: createHash('sha256').update(canonicalJson(projection)).digest('base64url') },
    runtime_instance_ref: 'urn:example:runtime:synthetic-node-interop',
    issuer: 'https://issuer.example.test', subject: 'synthetic-node-interop-agent',
    session_ref: `urn:marty:session:sha256:${'ab'.repeat(32)}`,
    audience: 'https://organization.example.test/managed-enrollment',
    nonce: Buffer.alloc(32, 29).toString('base64url'), iat: issuedAt, exp: issuedAt + 120,
    policy: { profile: 'urn:example:enrollment-policy:v1', revision: 3,
      allowed_algorithms: ['ES256', 'EdDSA'], max_age_seconds: 120 },
  };
  const payload = Buffer.from(canonicalJson(challenge));
  const envelope = {
    profile: ENROLLMENT_PROFILE, challenge_id: challenge.challenge_id,
    organization_id: challenge.organization_id, agent_id: challenge.agent_id,
    expected_revision: challenge.expected_revision, challenge,
    signing_payload: payload.toString('base64url'),
    challenge_digest: `sha256:${createHash('sha256').update(payload).digest('hex')}`,
    expires_at: new Date(challenge.exp * 1000).toISOString().replace('.000Z', 'Z'), recovered: false,
  };
  const expected = {
    organization_id: challenge.organization_id, agent_id: challenge.agent_id,
    administrator_id: challenge.administrator_id, audience: challenge.audience,
    runtime_instance_ref: challenge.runtime_instance_ref, policy_profile: challenge.policy.profile,
    policy_revision: challenge.policy.revision, expected_revision: challenge.expected_revision,
  };
  return { envelope, expected, publicJwk, publicKey,
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
    nowMilliseconds: issuedAt * 1000 + 10_123 };
}

export function regenerateEnvelope(envelope) {
  const payload = Buffer.from(canonicalJson(envelope.challenge));
  envelope.signing_payload = payload.toString('base64url');
  envelope.challenge_digest = `sha256:${createHash('sha256').update(payload).digest('hex')}`;
  return envelope;
}
