import { describe, expect, it } from 'vitest';

import {
  PRESENTATION_REQUEST_CREDENTIAL_TYPES,
  createVerifierPresentationRequestError,
  createVerifierPresentationRequestPayload,
  createVerifierPresentationVerificationPayload,
  getPresentationRequestAttributes,
  resolveVerifierPresentationRequest,
  resolveVerifierPresentationVerification,
} from './presentationRequestFlow';

describe('presentationRequestFlow', () => {
  it('returns attributes for the selected credential type', () => {
    expect(getPresentationRequestAttributes('mDL')).toEqual(
      PRESENTATION_REQUEST_CREDENTIAL_TYPES[0].attributes,
    );
    expect(getPresentationRequestAttributes('missing')).toEqual([]);
  });

  it('creates a request payload and resolves request results', () => {
    expect(createVerifierPresentationRequestPayload({
      selectedCredentialType: 'ProofOfAge',
      verifierName: 'Verifier One',
    })).toEqual({
      requested_credentials: ['ProofOfAge'],
      verifier_id: 'Verifier One',
    });

    expect(resolveVerifierPresentationRequest({
      request_id: 'req-1',
      request_uri: 'openid-vc://request',
      audience: 'aud-1',
    })).toEqual({
      error: null,
      requestId: 'req-1',
      requestUri: 'openid-vc://request',
      requestAudience: 'aud-1',
      requestStatus: 'pending',
    });

    expect(createVerifierPresentationRequestError('Nope')).toEqual({
      error: 'Nope',
      requestId: null,
      requestUri: '',
      requestAudience: '',
      requestStatus: 'error',
    });
  });

  it('creates verification payloads and resolves verification results', () => {
    expect(createVerifierPresentationVerificationPayload({
      presentationData: { vp_jwt: 'jwt-token' },
      customNonce: 'nonce-1',
      requestAudience: 'aud-1',
      verifierName: 'Verifier One',
    })).toEqual({
      presentation_jwt: 'jwt-token',
      expected_nonce: 'nonce-1',
      expected_audience: 'aud-1',
    });

    expect(resolveVerifierPresentationVerification({ valid: true })).toEqual({
      error: null,
      requestStatus: 'verified',
    });

    expect(resolveVerifierPresentationVerification({ valid: false, error: 'Bad signature' })).toEqual({
      error: 'Bad signature',
      requestStatus: 'error',
    });
  });
});