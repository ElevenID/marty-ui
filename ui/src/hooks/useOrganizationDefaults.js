import { getOrganizationDefaults } from '../services/organizationsApi';
import { useAsyncData } from './useAsyncData';

/** Optional creation hints; resource catalogs remain the authority for eligibility. */
export function useOrganizationDefaults(organizationId) {
  const result = useAsyncData(async () => {
    if (!organizationId) return null;
    const defaults = await getOrganizationDefaults(organizationId);
    if (!defaults || typeof defaults !== 'object' || Array.isArray(defaults)
      || (defaults.organization_id != null && defaults.organization_id !== organizationId)) {
      throw new Error('Organization defaults returned an invalid response.');
    }
    return { organizationId, defaults };
  }, [organizationId]);

  return {
    defaults: organizationId && result.data?.organizationId === organizationId ? result.data.defaults : null,
    loading: Boolean(organizationId) && result.loading,
    error: result.error,
  };
}
