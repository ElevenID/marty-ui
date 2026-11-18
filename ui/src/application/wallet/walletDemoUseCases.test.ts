import { describe, expect, it, vi } from 'vitest';

import {
  createWalletDemoPresentation,
  deleteWalletDemoCredential,
  loadWalletDemoCredentials,
} from './walletDemoUseCases';

describe('walletDemoUseCases', () => {
  it('loads wallet credentials through an injected transport', async () => {
    const loadCredentials = vi.fn().mockResolvedValue({
      credentials: [{ id: 'cred-1', issuer: 'DMV', types: ['mDL'] }],
    });

    await expect(loadWalletDemoCredentials({ loadCredentials })).resolves.toMatchObject({
      error: null,
      credentials: [expect.objectContaining({ id: 'cred-1', issuer: 'DMV' })],
    });
  });

  it('deletes wallet credentials through an injected transport', async () => {
    const deleteCredential = vi.fn().mockResolvedValue({});

    await expect(deleteWalletDemoCredential({
      credentialId: 'cred-1',
      credentials: [{ id: 'cred-1' }, { id: 'cred-2' }],
      deleteCredential,
    })).resolves.toEqual({
      credentials: [{ id: 'cred-2' }],
      error: null,
    });
  });

  it('creates wallet presentations through an injected transport', async () => {
    const createPresentation = vi.fn().mockResolvedValue({ success: true });

    await expect(createWalletDemoPresentation({
      selectedCredential: { id: 'cred-1' },
      presentationRequest: '{"audience":"verifier-1"}',
      createPresentation,
    })).resolves.toEqual({
      success: true,
      error: null,
      message: 'Presentation created successfully!',
    });

    expect(createPresentation).toHaveBeenCalledWith({
      credential_ids: ['cred-1'],
      audience: 'verifier-1',
      nonce: null,
    });
  });
  it('does not fabricate inventory on an empty, failed or malformed response', async () => {
    await expect(loadWalletDemoCredentials({ loadCredentials: async () => ({ credentials: [] }) }))
      .resolves.toEqual({ credentials: [], error: null });
    for (const loadCredentials of [async () => { throw new Error('offline'); }, async () => ({})]) {
      const result = await loadWalletDemoCredentials({ loadCredentials });
      expect(result.credentials).toEqual([]);
      expect(result.error).toBeTruthy();
    }
  });

  it('preserves credentials when the service rejects deletion', async () => {
    const credentials = [{ id: 'cred-1' }];
    const result = await deleteWalletDemoCredential({
      credentialId: 'cred-1', credentials,
      deleteCredential: async () => { throw new Error('forbidden'); },
    });
    expect(result.credentials).toEqual(credentials);
    expect(result.error).toBeTruthy();
  });

  it('never submits malformed presentation input', async () => {
    const createPresentation = vi.fn();
    const result = await createWalletDemoPresentation({
      selectedCredential: { id: 'cred-1' }, presentationRequest: 'not-json', createPresentation,
    });
    expect(result.success).toBe(false);
    expect(createPresentation).not.toHaveBeenCalled();
  });

});