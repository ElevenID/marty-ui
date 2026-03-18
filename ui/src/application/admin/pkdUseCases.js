import { getErrorMessage, post } from '../../services/api';
import { createPkdSyncError, createPkdSyncSuccess } from './pkdFlow';

async function defaultSyncPkd() {
  return post('/api/admin/pkd/sync?force_refresh=true', {});
}

export async function synchronizePkd({
  syncPkd = defaultSyncPkd,
} = {}) {
  try {
    const result = await syncPkd();
    return createPkdSyncSuccess(result?.message || 'PKD synchronization completed successfully.');
  } catch (error) {
    return createPkdSyncError(getErrorMessage(error));
  }
}
