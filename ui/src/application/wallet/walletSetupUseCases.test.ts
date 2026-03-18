import { describe, expect, it, vi } from 'vitest';

import {
  getOrCreateWalletDeviceId,
  loadWalletStatus,
  registerWalletPushNotifications,
} from './walletSetupUseCases';

describe('walletSetupUseCases', () => {
  it('loads wallet status through an injected transport', async () => {
    const loadDevices = vi.fn().mockResolvedValue({
      devices: [{ device_id: 'device-1' }],
    });

    await expect(loadWalletStatus({
      userId: 'user-1',
      activeStep: 0,
      loadDevices,
    })).resolves.toEqual({
      walletConnected: true,
      walletDeviceId: 'device-1',
      nextStep: 1,
      successMessage: 'Wallet paired successfully!',
      error: null,
    });
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