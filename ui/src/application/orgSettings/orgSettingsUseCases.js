/** Use cases for the selected organization's public profile and settings. */
import { getErrorMessage } from '../../services/api';
import { getOrganization, updateOrganization } from '../../services/organizationsApi';
import { requireOrganizationId } from '../../services/queryUtils';
import { buildOrgSettingsSaveBody, parseOrgSettingsResponse } from './orgSettingsFlow';

export async function loadOrgSettings({
  organizationId,
  fetchSettings = getOrganization,
} = {}) {
  try {
    const orgId = requireOrganizationId(organizationId, 'loading organization settings');
    const data = await fetchSettings(orgId);
    return {
      org: parseOrgSettingsResponse(data, { organizationId: orgId }),
      error: null,
    };
  } catch (error) {
    return {
      org: null,
      error: getErrorMessage(error) || 'Failed to load organization settings',
    };
  }
}

export async function saveOrgSettings({
  organizationId,
  org,
  originalOrg,
  save = updateOrganization,
} = {}) {
  try {
    const orgId = requireOrganizationId(organizationId, 'saving organization settings');
    const body = buildOrgSettingsSaveBody(org, { originalOrg });
    if (Object.keys(body).length === 0) return { org: originalOrg, error: null };
    const data = await save(orgId, body);
    return { org: parseOrgSettingsResponse(data, { organizationId: orgId }), error: null };
  } catch (error) {
    return { org: null, error: getErrorMessage(error) || 'Failed to save organization settings' };
  }
}
