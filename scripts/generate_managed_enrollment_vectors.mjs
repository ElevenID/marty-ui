#!/usr/bin/env node
// Generates disposable synthetic keys in memory, retaining public vectors only.
// This generator is a test-fixture maintenance tool, not an enrollment command.
import { writeFile } from 'node:fs/promises';
import { signEnrollment } from './sign_managed_enrollment.mjs';
import { syntheticEnrollment } from '../tests/support/managed_enrollment_fixture.mjs';

const vectors = ['ES256', 'EdDSA'].map(algorithm => {
  const fixture = syntheticEnrollment(algorithm);
  const proof = signEnrollment({ challengeDocument: JSON.stringify(fixture.envelope),
    privateKeyPem: fixture.privateKeyPem, expected: fixture.expected, nowMilliseconds: fixture.nowMilliseconds });
  return { algorithm, public_jwk: fixture.publicJwk, challenge: fixture.envelope, proof,
    verification_time: new Date(fixture.nowMilliseconds).toISOString() };
});
const document = {
  profile: 'urn:marty:managed-key-enrollment-public-test-vectors:v1',
  provenance: {
    generator: 'scripts/generate_managed_enrollment_vectors.mjs',
    signing_runtime: `Node.js ${process.version} / OpenSSL ${process.versions.openssl}`,
    purpose: 'Synthetic cross-implementation proof verification; never a runtime qualification',
    private_material_retained: false,
    signature_profile: 'urn:marty:managed-key-enrollment:v1',
  },
  vectors,
};
await writeFile(new URL('../rust/crates/principal-runtime-binding/tests/fixtures/node-managed-enrollment.json', import.meta.url), `${JSON.stringify(document, null, 2)}\n`);
