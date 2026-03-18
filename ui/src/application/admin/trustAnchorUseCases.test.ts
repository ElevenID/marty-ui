import { describe, expect, it, vi } from 'vitest';

import {
  loadTrustAnchorPageData,
  refreshTrustAnchorStatus,
  saveTrustAnchorConfig,
  verifyTrustAnchorEntity,
} from './trustAnchorUseCases';

describe('trustAnchorUseCases', () => {
  it('loads config and status with fallback to stored config', async () => {
    const storage = {
      getItem: vi.fn().mockReturnValue(JSON.stringify({ anchorName: 'Stored Anchor' })),
    };

    await expect(loadTrustAnchorPageData({
      getTrustAnchorConfig: vi.fn().mockRejectedValue(new Error('offline')),
      getTrustAnchorStatus: vi.fn().mockResolvedValue({ healthy: false }),
      storage,
    })).resolves.toEqual({
      config: expect.objectContaining({ anchorName: 'Stored Anchor' }),
      status: expect.objectContaining({ healthy: false }),
    });
  });

  it('refreshes status and saves config with local backup persistence', async () => {
    const storage = {
      setItem: vi.fn(),
    };
    const config = {
      anchorName: 'Demo Anchor',
      domain: 'trust.example',
      policy: 'strict',
      logLevel: 'info',
    };

    await expect(refreshTrustAnchorStatus({
      getTrustAnchorStatus: vi.fn().mockRejectedValue(new Error('offline')),
    })).resolves.toMatchObject({ healthy: true });

    await expect(saveTrustAnchorConfig({
      config,
      saveConfig: vi.fn().mockRejectedValue(new Error('save unavailable')),
      storage,
    })).resolves.toEqual({
      success: true,
      message: 'Configuration saved successfully.',
    });

    expect(storage.setItem).toHaveBeenCalledWith('trustAnchorConfig', JSON.stringify(config));
  });

  it('verifies an entity and returns a UI-friendly result', async () => {
    await expect(verifyTrustAnchorEntity({
      entityId: 'did:web:example.com',
      verifyEntity: vi.fn().mockResolvedValue({ is_trusted: false }),
    })).resolves.toEqual({
      success: true,
      isTrusted: false,
      message: 'Entity is NOT trusted.',
    });

    await expect(verifyTrustAnchorEntity({
      entityId: 'did:web:example.com',
      verifyEntity: vi.fn().mockRejectedValue(new Error('Verification failed')),
    })).resolves.toEqual({
      success: false,
      message: 'Verification failed',
    });
  });
});
