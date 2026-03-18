import { describe, expect, it, vi } from 'vitest';

import { loadAdminMetrics } from './metricsUseCases';

describe('metricsUseCases', () => {
  it('loads admin metrics through the injected transport', async () => {
    await expect(loadAdminMetrics({
      getAdminMetrics: vi.fn().mockResolvedValue({
        cpu_usage: 55,
        memory_usage: 61,
        request_rate: 18,
        transaction_volume: [{ name: '08:00', issuance: 5, verification: 3 }],
      }),
    })).resolves.toEqual({
      cpu_usage: 55,
      memory_usage: 61,
      request_rate: 18,
      transaction_volume: [{ name: '08:00', issuance: 5, verification: 3 }],
    });
  });

  it('falls back safely when metrics loading fails', async () => {
    await expect(loadAdminMetrics({
      getAdminMetrics: vi.fn().mockRejectedValue(new Error('offline')),
    })).resolves.toMatchObject({
      cpu_usage: 0,
      memory_usage: 0,
      request_rate: 0,
    });
  });
});
