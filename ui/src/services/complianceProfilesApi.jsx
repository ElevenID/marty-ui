/**
 * Compliance Profiles API Service
 * 
 * Manages compliance profiles that abstract credential format complexity
 * behind compliance-focused configurations (ICAO_DTC, AAMVA_MDL, EUDI_PID, etc.).
 */

import { apiClient, handleApiError } from './api';
import { postWithIdempotency } from './idempotency';

const BASE_PATH = '/v1/compliance-profiles';

function isMissingOrganizationId(organizationId) {
  return organizationId == null
    || String(organizationId).trim() === ''
    || String(organizationId).trim().toLowerCase() === 'null'
    || String(organizationId).trim().toLowerCase() === 'undefined';
}

export function requireOrganizationId(params = {}) {
  const organizationId = typeof params === 'string' ? params : params?.organization_id;
  if (isMissingOrganizationId(organizationId)) {
    const error = new Error('An active organization is required before loading compliance profiles.');
    error.code = 'ORG_REQUIRED';
    error.status = 400;
    throw error;
  }
  return String(organizationId).trim();
}

/** Create an organization-owned profile using the native compliance contract. */
export const createComplianceProfile = async (profileData) => {
  return postWithIdempotency(BASE_PATH, {
    ...profileData,
    organization_id: requireOrganizationId(profileData),
  });
};

/**
 * List compliance profiles with optional filters
 * @param {Object} filters - Query filters
 * @param {boolean} filters.system_profiles_only - Filter for system presets only
 * @param {number} filters.limit - Page size
 * @param {number} filters.offset - Offset for pagination
 * @returns {Promise<Array>} List of compliance profiles
 */
export const listComplianceProfiles = async (filters = {}) => {
  const organizationId = requireOrganizationId(filters);
  try {
    const params = new URLSearchParams();
    params.append('organization_id', organizationId);
    if (filters.system_profiles_only !== undefined) {
      params.append('system_profiles_only', filters.system_profiles_only);
    }
    if (filters.limit) params.append('limit', filters.limit);
    if (filters.offset) params.append('offset', filters.offset);
    
    const response = await apiClient.get(`${BASE_PATH}?${params.toString()}`);
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

/**
 * Get compliance profile by ID
 * @param {string} profileId - Profile ID
 * @returns {Promise<Object>} Compliance profile details
 */
export const getComplianceProfile = async (profileId) => {
  try {
    const response = await apiClient.get(`${BASE_PATH}/${encodeURIComponent(profileId)}`);
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

/**
 * Update compliance profile (system profiles protected)
 * @param {string} profileId - Profile ID
 * @param {Object} updates - Profile updates
 * @returns {Promise<Object>} Updated compliance profile
 */
export const updateComplianceProfile = async (profileId, updates) => {
  try {
    const response = await apiClient.patch(`${BASE_PATH}/${encodeURIComponent(profileId)}`, updates);
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

/**
 * Delete compliance profile (system profiles protected)
 * @param {string} profileId - Profile ID
 * @returns {Promise<void>}
 */
export const deleteComplianceProfile = async (profileId) => {
  try {
    await apiClient.delete(`${BASE_PATH}/${encodeURIComponent(profileId)}`);
  } catch (error) {
    throw handleApiError(error);
  }
};

/** Active discoverable migration-owned presets; never infer presets from org rows. */
export const getSystemPresets = async (filters = {}) => {
  const organizationId = requireOrganizationId(filters);
  try {
    const response = await apiClient.get(`${BASE_PATH}/system/discoverable?${new URLSearchParams({ organization_id: organizationId })}`);
    if (!Array.isArray(response.data) || !response.data.every((profile) => profile?.is_system === true
      && profile.organization_id == null && profile.status === 'ACTIVE' && profile.discoverable === true)) {
      throw new Error('Compliance catalog returned invalid system profile data.');
    }
    return response.data;
  } catch (error) { throw handleApiError(error); }
};

export const activateComplianceProfile = async (profileId) => {
  try { return (await apiClient.post(`${BASE_PATH}/${encodeURIComponent(profileId)}/activate`, {})).data; }
  catch (error) { throw handleApiError(error); }
};
export const suspendComplianceProfile = async (profileId) => {
  try { return (await apiClient.post(`${BASE_PATH}/${encodeURIComponent(profileId)}/suspend`, {})).data; }
  catch (error) { throw handleApiError(error); }
};

export const listSystemPresets = getSystemPresets;

/** @deprecated No compliance-profile artifact-validation operation is exposed. */
export const validateIssuerArtifacts = async () => {
  const error = new Error('Compliance artifact validation is not exposed. Use template issuer options for compatibility and the issuance or verification workflow to validate artifacts.');
  error.code = 'UNSUPPORTED_OPERATION';
  error.status = 501;
  throw error;
};

export default {
  createComplianceProfile,
  activateComplianceProfile,
  suspendComplianceProfile,
  listComplianceProfiles,
  getComplianceProfile,
  updateComplianceProfile,
  deleteComplianceProfile,
  getSystemPresets,
  listSystemPresets,
  validateIssuerArtifacts,
};
