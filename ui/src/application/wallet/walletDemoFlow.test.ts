import { describe, expect, it } from 'vitest';

import {
  buildWalletPresentationPayload,
  createSampleWalletCredential,
  getWalletCredentialStatusColor,
  mapWalletCredential,
  resolveWalletCredentials,
  resolveWalletDelete,
  resolveWalletPresentationRequest,
  resolveWalletPresentationResult,
  WALLET_DEMO_FALLBACK_CREDENTIALS,
} from './walletDemoFlow';

describe('walletDemoFlow', () => {
  it('maps and resolves wallet credentials with fallback support', () => {
    expect(mapWalletCredential({
      id: 'cred-1',
      types: ['mDL', 'VerifiableCredential'],
      issuer: 'DMV',
      issuance_date: '2026-01-01T00:00:00Z',
      expiration_date: '2030-01-01T00:00:00Z',
      claims: { given_name: 'Jane' },
    })).toEqual({
      id: 'cred-1',
      type: 'mDL, VerifiableCredential',
      issuer: 'DMV',
      issued_date: '2026-01-01',
      expiry_date: '2030-01-01',
      status: 'active',
      subject_data: { given_name: 'Jane' },
    });

    expect(resolveWalletCredentials({})).toEqual(WALLET_DEMO_FALLBACK_CREDENTIALS);
    expect(resolveWalletDelete([{ id: 'a' }, { id: 'b' }], 'a')).toEqual([{ id: 'b' }]);
  });

  it('parses wallet presentation requests and builds payloads', () => {
    expect(resolveWalletPresentationRequest('{"audience":"verifier-1","nonce":"abc"}')).toEqual({
      audience: 'verifier-1',
      nonce: 'abc',
    });
    expect(resolveWalletPresentationRequest('not-json')).toEqual({
      audience: 'demo_verifier',
      nonce: null,
    });

    expect(buildWalletPresentationPayload({
      selectedCredential: { id: 'cred-1' },
      presentationRequest: '{"verifier":"verifier-2"}',
    })).toEqual({
      credential_ids: ['cred-1'],
      audience: 'verifier-2',
      nonce: null,
    });
  });

  it('creates sample credentials and presentation outcomes', () => {
    expect(createSampleWalletCredential({ now: 1710000000000, random: () => 0.123456789 })).toMatchObject({
      id: 'mdl_1710000000000',
      type: 'mDL',
      status: 'active',
    });

    expect(resolveWalletPresentationResult({ success: true })).toEqual({
      success: true,
      error: null,
      message: 'Presentation created successfully!',
    });

    expect(getWalletCredentialStatusColor('revoked')).toBe('error');
  });
});