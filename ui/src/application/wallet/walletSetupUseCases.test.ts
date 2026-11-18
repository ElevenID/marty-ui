import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
  getOrCreateWalletDeviceId,
  issueRemotePairingTicket,
  registerWalletPushNotifications,
} from './walletSetupUseCases';

const { mockPost } = vi.hoisted(() => ({ mockPost: vi.fn() }));
vi.mock('../../services/api', () => ({ get: vi.fn(), post: mockPost, getErrorMessage: vi.fn() }));

describe('walletSetupUseCases', () => {
  beforeEach(() => { mockPost.mockReset(); });

  it('sends only the browser-selected distinct verifier profile alongside issuer scope', async () => {
    const issuer = '11111111-2222-4333-8444-555555555555';
    const verifier = 'AAAAAAAA-2222-4333-8444-555555555555';
    mockPost.mockResolvedValue({ pairing_id: 'synthetic' });
    await issueRemotePairingTicket({ organizationId: 'org-a', trustProfileId: issuer, verifierTrustProfileId: verifier });
    expect(mockPost).toHaveBeenLastCalledWith('/v1/devices/pairing-tickets', {
      organization_id: 'org-a', trust_profile_id: issuer,
      verifier_trust_profile_id: verifier.toLowerCase(),
    });
    await issueRemotePairingTicket({ organizationId: 'org-a', trustProfileId: issuer });
    expect(mockPost).toHaveBeenLastCalledWith('/v1/devices/pairing-tickets', {
      organization_id: 'org-a', trust_profile_id: issuer,
    });
  });

  it('refuses malformed, nil or issuer-equivalent verifier references before transport', async () => {
    const issuer = 'aaaaaaaa-2222-4333-8444-555555555555';
    for (const verifier of ['', 'not-a-profile', '00000000-0000-0000-0000-000000000000', issuer.toUpperCase()]) {
      await expect(issueRemotePairingTicket({ organizationId: 'org-a', trustProfileId: issuer,
        verifierTrustProfileId: verifier })).rejects.toThrow('distinct verifier Trust Profile');
    }
    expect(mockPost).not.toHaveBeenCalled();
  });
  it('gets or creates a stable wallet device id in storage', () => {
    const storage = {
      getItem: vi.fn().mockReturnValue(null),
      setItem: vi.fn(),
    } as unknown as Storage;

    const deviceId = getOrCreateWalletDeviceId({
      organizationId: 'org-1',
      storage,
      now: 1710000000000,
      random: () => 0.123456,
    });

    expect(deviceId).toBe('org-1:web-1710000000000-4fzyo8');
    expect(storage.setItem).toHaveBeenCalledWith('wallet_device_id:org-1:', 'org-1:web-1710000000000-4fzyo8');
  });

  it('registers push notifications through an injected transport', async () => {
    const storage = {
      getItem: vi.fn().mockReturnValue('device-1'),
      setItem: vi.fn(),
    } as unknown as Storage;
    const registerDevice = vi.fn().mockResolvedValue({
      device_id: 'device-1',
    });

    await expect(registerWalletPushNotifications({
      userId: 'user-1',
      organizationId: 'org-1',
      storage,
      registerDevice,
      tokenFactory: () => 'token-1',
    })).resolves.toEqual({
      deviceId: 'device-1',
      error: null,
    });

    expect(registerDevice).toHaveBeenCalledWith({
      userId: 'user-1',
      request: {
        headers: {
          'Content-Type': 'application/json',
          'X-User-ID': 'user-1',
        },
        body: {
          device_id: 'device-1',
          fcm_token: 'token-1',
          platform: 'web',
          app_version: 'web-1.0.0',
        },
      },
    });
  });
});
