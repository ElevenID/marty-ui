import { get, getErrorMessage } from '../../services/api';
import { MASTER_LIST_SAMPLE_DATA, resolveMasterLists } from './masterListFlow';

async function defaultGetMasterLists() {
  return get('/api/admin/master-lists');
}

export async function loadMasterLists({
  getMasterLists = defaultGetMasterLists,
} = {}) {
  try {
    const result = await getMasterLists();
    return {
      masterLists: resolveMasterLists(result, MASTER_LIST_SAMPLE_DATA),
      error: null,
    };
  } catch (error) {
    return {
      masterLists: MASTER_LIST_SAMPLE_DATA,
      error: getErrorMessage(error) || 'Using cached sample data when backend unavailable',
    };
  }
}
