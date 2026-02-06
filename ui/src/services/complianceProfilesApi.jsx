/**
 * Compliance Profiles API Service
 * 
 * Manages compliance profiles that abstract credential format complexity
 * behind compliance-focused configurations (ICAO_DTC, AAMVA_MDL, EUDI_PID, etc.).
 */

import { apiClient, handleApiError } from './api';

const BASE_PATH = '/v1/identity/compliance-profiles';

/**
 * Create a new compliance profile
 * @param {Object} profileData - Profile configuration
 * @param {string} profileData.name - Profile name
 * @param {string} profileData.code - Compliance code (ICAO_DTC, AAMVA_MDL, EUDI_PID, ENTERPRISE_VC)
 * @param {string} profileData.description - Optional description
 * @param {Object} profileData.credential_format_mapping - Format mappings (mdoc, sd_jwt_vc, jwt_vc, ldp_vc)
 * @param {Object} profileData.issuer_artifact_requirements - Required artifacts per format
 * @param {Object} profileData.default_claim_verification_rules - Default verification rules
 * @param {Object} profileData.trust_profile_constraints - Trust profile requirements
 * @param {boolean} profileData.is_system_profile - Whether this is an immutable system preset
 * @returns {Promise<Object>} Created compliance profile
 */
export const createComplianceProfile = async (profileData) => {
  try {
    const response = await apiClient.post(BASE_PATH, profileData);
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
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
  try {
    const params = new URLSearchParams();
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
    const response = await apiClient.get(`${BASE_PATH}/${profileId}`);
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
    const response = await apiClient.patch(`${BASE_PATH}/${profileId}`, updates);
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
    await apiClient.delete(`${BASE_PATH}/${profileId}`);
  } catch (error) {
    throw handleApiError(error);
  }
};

/**
 * Get system compliance profile presets
 * @returns {Promise<Array>} List of system presets (ICAO_DTC, AAMVA_MDL, EUDI_PID, ENTERPRISE_VC)
 */
export const getSystemPresets = async () => {
  try {
    const response = await apiClient.get(`${BASE_PATH}?system_profiles_only=true`);
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

/**
 * Validate issuer artifacts against compliance profile requirements
 * @param {string} profileId - Compliance profile ID
 * @param {Object} artifacts - Issuer artifacts to validate
 * @param {string} artifacts.issuer_did - Issuer DID
 * @param {string} artifacts.issuer_key_id - Key ID
 * @param {string} artifacts.issuer_certificate_chain_pem - X.509 certificate chain
 * @returns {Promise<Object>} Validation result with errors if any
 */
export const validateIssuerArtifacts = async (profileId, artifacts) => {
  try {
    const response = await apiClient.post(`${BASE_PATH}/${profileId}/validate-artifacts`, artifacts);
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

export default {
  createComplianceProfile,
  listComplianceProfiles,
  getComplianceProfile,
  updateComplianceProfile,
  deleteComplianceProfile,
  getSystemPresets,
  validateIssuerArtifacts,
};
