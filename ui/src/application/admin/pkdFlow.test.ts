import { describe, expect, it } from 'vitest';

import {
  PKD_DEFAULT_DIRECTORY_STATUS,
  PKD_DEFAULT_STATISTICS,
  createPkdSyncError,
  createPkdSyncSuccess,
} from './pkdFlow';

describe('pkdFlow helpers', () => {
  it('exposes PKD dashboard defaults', () => {
    expect(PKD_DEFAULT_DIRECTORY_STATUS).toHaveLength(3);
    expect(PKD_DEFAULT_STATISTICS).toHaveLength(4);
    expect(PKD_DEFAULT_DIRECTORY_STATUS[0]).toMatchObject({
      primary: 'LDAP Service',
      status: 'healthy',
    });
  });

  it('creates success and error sync result models', () => {
    expect(createPkdSyncSuccess()).toEqual({
      syncStatus: 'success',
      message: 'PKD synchronization completed successfully.',
    });

    expect(createPkdSyncError('offline')).toEqual({
      syncStatus: 'error',
      message: 'offline',
    });
  });
});
