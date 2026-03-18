import { describe, expect, it, vi } from 'vitest';

import {
  createPresentationRequest,
  verifyPresentationRequest,
} from './presentationRequestUseCases';

describe('presentationRequestUseCases', () => {
  it('creates a presentation request through an injected transport', async () => {
    const createRequest = vi.fn().mockResolvedValue({
      request_id: 'req-123',
      request_uri: 'openid-vc://request',
      audience: 'demo-verifier',
    });

    await expect(createPresentationRequest({
      selectedCredentialType: 'mDL',
      verifierName: 'Demo Verifier',
      createRequest,
    })).resolves.toEqual({
      error: null,
      requestId: 'req-123',
      requestUri: 'openid-vc://request',
      requestAudience: 'demo-verifier',
      requestStatus: 'pending',
    });

    expect(createRequest).toHaveBeenCalledWith({
      requested_credentials: ['mDL'],
      verifier_id: 'Demo Verifier',
    });
  });

  it('verifies a presentation through an injected transport', async () => {
    const verifyRequest = vi.fn().mockResolvedValue({ valid: true });

    await expect(verifyPresentationRequest({
      presentationData: { vp_jwt: 'jwt-token' },
      customNonce: 'nonce-1',
      requestAudience: 'aud-1',
      verifierName: 'Demo Verifier',
      verifyRequest,
    })).resolves.toEqual({
      error: null,
      requestStatus: 'verified',
    });

    expect(verifyRequest).toHaveBeenCalledWith({
      presentation_jwt: 'jwt-token',
      expected_nonce: 'nonce-1',
      expected_audience: 'aud-1',
    });
  });
});