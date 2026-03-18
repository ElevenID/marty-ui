import { describe, expect, it, vi } from 'vitest';

import { loadMasterLists } from './masterListUseCases';

describe('masterListUseCases', () => {
  it('loads master lists through the injected transport', async () => {
    await expect(loadMasterLists({
      getMasterLists: vi.fn().mockResolvedValue({
        masterLists: [{ country: 'CAN', certificates: [] }],
      }),
    })).resolves.toEqual({
      masterLists: [{ country: 'CAN', certificates: [] }],
      error: null,
    });
  });

  it('falls back to sample data when loading fails', async () => {
    await expect(loadMasterLists({
      getMasterLists: vi.fn().mockRejectedValue(new Error('offline')),
    })).resolves.toMatchObject({
      error: 'offline',
    });
  });
});
