/**
 * Use cases for organization settings.
 */

import { get, put, getErrorMessage } from '../../services/api';
import { buildOrgSettingsSaveBody, parseOrgSettingsResponse } from './orgSettingsFlow';

const ORG_SETTINGS_URL = '/api/onboarding/org-settings';

async function defaultFetchOrgSettings() {
  return get(ORG_SETTINGS_URL);
}

async function defaultSaveOrgSettings(body) {
  return put(ORG_SETTINGS_URL, body);
}

export async function loadOrgSettings({
  organizationName,
  fetchSettings = defaultFetchOrgSettings,
} = {}) {
  try {
    const data = await fetchSettings();
    return {
      org: parseOrgSettingsResponse(data, { organizationName }),
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
  org,
  save = defaultSaveOrgSettings,
} = {}) {
  try {
    const body = buildOrgSettingsSaveBody(org);
    await save(body);
    return { error: null };
  } catch (error) {
    return { error: getErrorMessage(error) || 'Failed to save organization settings' };
  }
}
