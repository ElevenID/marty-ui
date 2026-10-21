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
} from './walletDemoFlow';

describe('walletDemoFlow', () => {
  it('maps only actual wallet credentials', () => {
    expect(mapWalletCredential({
      id: 'cred-1',
      types: ['mDL', 'VerifiableCredential'],
      issuer: 'DMV',
      status: 'active',
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

    expect(resolveWalletCredentials({ credentials: [] })).toEqual([]);
    expect(() => resolveWalletCredentials({})).toThrow('credentials array');
    expect(resolveWalletDelete([{ id: 'a' }, { id: 'b' }], 'a')).toEqual([{ id: 'b' }]);
  });

  it('parses wallet presentation requests and builds payloads', () => {
    expect(resolveWalletPresentationRequest('{"audience":"verifier-1","nonce":"abc"}')).toEqual({
      audience: 'verifier-1',
      nonce: 'abc',
    });
    expect(() => resolveWalletPresentationRequest('not-json')).toThrow('valid JSON');

    expect(buildWalletPresentationPayload({
      selectedCredential: { id: 'cred-1' },
      presentationRequest: '{"verifier":"verifier-2"}',
    })).toEqual({
      credential_ids: ['cred-1'],
      audience: 'verifier-2',
      nonce: null,
    });
  });

  it('does not label unknown, revoked, suspended or expired credentials active', () => {
    expect(mapWalletCredential({}).status).toBe('unknown');
    for (const status of ['revoked', 'suspended']) {
      expect(mapWalletCredential({ status, expiration_date: '2000-01-01' }).status).toBe(status);
    }
    expect(mapWalletCredential({ status: 'active', expiration_date: '2000-01-01' }).status).toBe('expired');
  });

  it('rejects missing or malformed verifier identity and nonce', () => {
    for (const text of ['', 'null', '[]', '{}', '{"audience":5}', '{"audience":" "}',
      '{"audience":"v","nonce":9}', '{"audience":"v","nonce":""}']) {
      expect(() => resolveWalletPresentationRequest(text)).toThrow();
    }
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