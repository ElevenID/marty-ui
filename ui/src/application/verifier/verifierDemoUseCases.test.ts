import { describe, expect, it, vi } from 'vitest';

import { verifyVerifierDemoPresentation } from './verifierDemoUseCases';

describe('verifierDemoUseCases', () => {
  it('verifies presentation JWT payloads through the presentation endpoint', async () => {
    const verifyPresentation = vi.fn().mockResolvedValue({
      valid: true,
      claims: { age_over_21: true },
      holder: 'did:example:holder',
    });
    const verifyCredential = vi.fn();

    await expect(verifyVerifierDemoPresentation({
      presentationData: 'jwt-token',
      verifyPresentation,
      verifyCredential,
    })).resolves.toMatchObject({
      success: true,
      verified: true,
      issuer: 'did:example:holder',
    });

    expect(verifyPresentation).toHaveBeenCalledWith({
      presentation_jwt: 'jwt-token',
      expected_audience: 'demo_verifier',
      expected_nonce: null,
    });
    expect(verifyCredential).not.toHaveBeenCalled();
  });

  it('verifies credential JSON payloads through the credential endpoint', async () => {
    const verifyPresentation = vi.fn();
    const verifyCredential = vi.fn().mockResolvedValue({
      valid: false,
      error: 'Signature mismatch',
      claims: {},
    });

    await expect(verifyVerifierDemoPresentation({
      presentationData: JSON.stringify({ verifiableCredential: [{ id: 'cred-1' }] }),
      verifyPresentation,
      verifyCredential,
    })).resolves.toMatchObject({
      success: false,
      verified: false,
      error: 'Signature mismatch',
    });

    expect(verifyCredential).toHaveBeenCalledWith({
      credential_jwt: JSON.stringify({ id: 'cred-1' }),
      expected_issuer: null,
    });
    expect(verifyPresentation).not.toHaveBeenCalled();
  });
});