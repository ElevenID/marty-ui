import { describe, expect, it, vi } from 'vitest';

import { synchronizePkd } from './pkdUseCases';

describe('pkdUseCases', () => {
  it('reports PKD sync success from the injected transport', async () => {
    await expect(synchronizePkd({
      syncPkd: vi.fn().mockResolvedValue({ message: 'Synced 20 trust artifacts.' }),
    })).resolves.toEqual({
      syncStatus: 'success',
      message: 'Synced 20 trust artifacts.',
    });
  });

  it('returns a UI-friendly error result when sync fails', async () => {
    await expect(synchronizePkd({
      syncPkd: vi.fn().mockRejectedValue(new Error('Sync failed hard')),
    })).resolves.toEqual({
      syncStatus: 'error',
      message: 'Sync failed hard',
    });
  });
});
