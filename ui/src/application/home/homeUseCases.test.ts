import { describe, expect, it, vi } from 'vitest';

import { loadHomeDashboard } from './homeUseCases';

describe('homeUseCases', () => {
  it('loads health and stats together', async () => {
    await expect(loadHomeDashboard({
      getHomeHealth: vi.fn().mockResolvedValue({
        status: 'healthy',
        services: { issuer: 'online', verifier: 'online', wallet: 'online' },
      }),
      getHomeStats: vi.fn().mockResolvedValue({
        credentials: 14,
        verifications: 22,
      }),
    })).resolves.toEqual({
      systemStatus: {
        healthy: true,
        services: { issuer: 'online', verifier: 'online', wallet: 'online' },
      },
      stats: {
        credentials: 14,
        verifications: 22,
        masterLists: 3,
        certificates: 11,
      },
    });
  });

  it('falls back to defaults when health or stats requests fail', async () => {
    await expect(loadHomeDashboard({
      getHomeHealth: vi.fn().mockRejectedValue(new Error('offline')),
      getHomeStats: vi.fn().mockRejectedValue(new Error('denied')),
    })).resolves.toEqual({
      systemStatus: {
        healthy: true,
        services: { issuer: 'online', verifier: 'online', wallet: 'online' },
      },
      stats: {
        credentials: 0,
        verifications: 0,
        masterLists: 3,
        certificates: 11,
      },
    });
  });
});