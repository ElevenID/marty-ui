import { describe, expect, it } from 'vitest';

import {
  createVerifierDemoMockPresentation,
  createVerifierDemoVerificationError,
  createVerifierDemoVerificationResult,
  resolveVerifierDemoRequest,
  serializeVerifierDemoPresentation,
} from './verifierDemoFlow';

describe('verifierDemoFlow', () => {
  it('creates and serializes mock presentation data', () => {
    const presentation = createVerifierDemoMockPresentation({
      issuanceDate: '2026-01-01T00:00:00.000Z',
    });

    expect(presentation.verifiableCredential[0].issuanceDate).toBe('2026-01-01T00:00:00.000Z');
    expect(serializeVerifierDemoPresentation(presentation)).toContain('Jane');
  });

  it('resolves presentation and credential verification requests', () => {
    expect(resolveVerifierDemoRequest({ presentationData: 'jwt-token' })).toEqual({
      requestType: 'presentation',
      payload: {
        presentation_jwt: 'jwt-token',
        expected_audience: 'demo_verifier',
        expected_nonce: null,
      },
    });

    expect(resolveVerifierDemoRequest({
      presentationData: JSON.stringify({ presentation_jwt: 'vp-jwt' }),
    })).toEqual({
      requestType: 'presentation',
      payload: {
        presentation_jwt: 'vp-jwt',
        expected_audience: 'demo_verifier',
        expected_nonce: null,
      },
    });

    expect(resolveVerifierDemoRequest({
      presentationData: JSON.stringify({ verifiableCredential: [{ id: 'cred-1' }] }),
    })).toEqual({
      requestType: 'credential',
      payload: {
        credential_jwt: JSON.stringify({ id: 'cred-1' }),
        expected_issuer: null,
      },
    });
  });

  it('maps verification results and failures', () => {
    expect(createVerifierDemoVerificationResult({
      valid: true,
      claims: { given_name: 'Jane' },
      issuer: 'did:example:issuer',
    })).toMatchObject({
      success: true,
      verified: true,
      issuer: 'did:example:issuer',
      checks: [
        expect.objectContaining({ check_name: 'JWT Structure', passed: true }),
        expect.objectContaining({ check_name: 'Signature', passed: true }),
        expect.objectContaining({ check_name: 'Claims', passed: true, details: 'Found 1 claims' }),
      ],
    });

    expect(createVerifierDemoVerificationError('Bad format')).toEqual({
      success: false,
      verified: false,
      error: 'Verification failed: Bad format',
      checks: [
        {
          check_name: 'Format Check',
          passed: false,
          details: 'Bad format',
        },
      ],
    });
  });
});