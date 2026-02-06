/**
 * Deployment Profiles API Service
 * 
 * Manages deployment profiles that package trust + policies + runtime behavior
 * for real endpoints (gates, kiosks, lanes, devices).
 */

import { apiClient, handleApiError } from './api';

const BASE_PATH = '/v1/identity/deployment-profiles';

/**
 * Create a new deployment profile
 * @param {Object} profileData - Profile configuration
 * @param {string} profileData.name - Profile name
 * @param {string} profileData.description - Optional description
 * @param {string} profileData.trust_profile_id - Trust profile ID
 * @param {Array<string>} profileData.credential_template_ids - Enabled credential templates
 * @param {Array<string>} profileData.presentation_policy_ids - Enabled presentation policies
 * @param {string} profileData.network_mode - ONLINE, OFFLINE, or HYBRID
 * @param {Object} profileData.environment_config - UX, language, signage, accessibility settings
 * @returns {Promise<Object>} Created deployment profile
 */
export const createDeploymentProfile = async (profileData) => {
  try {
    const response = await apiClient.post(BASE_PATH, profileData);
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

/**
 * List deployment profiles
 * @param {Object} filters - Query filters
 * @param {number} filters.limit - Page size
 * @param {number} filters.offset - Offset for pagination
 * @returns {Promise<Array>} List of deployment profiles
 */
export const listDeploymentProfiles = async (filters = {}) => {
  try {
    const params = new URLSearchParams();
    if (filters.limit) params.append('limit', filters.limit);
    if (filters.offset) params.append('offset', filters.offset);
    
    const response = await apiClient.get(`${BASE_PATH}?${params.toString()}`);
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

/**
 * Get deployment profile by ID
 * @param {string} profileId - Profile ID
 * @returns {Promise<Object>} Deployment profile details
 */
export const getDeploymentProfile = async (profileId) => {
  try {
    const response = await apiClient.get(`${BASE_PATH}/${profileId}`);
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

/**
 * Update deployment profile
 * @param {string} profileId - Profile ID
 * @param {Object} updates - Profile updates
 * @returns {Promise<Object>} Updated deployment profile
 */
export const updateDeploymentProfile = async (profileId, updates) => {
  try {
    const response = await apiClient.patch(`${BASE_PATH}/${profileId}`, updates);
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

/**
 * Delete deployment profile
 * @param {string} profileId - Profile ID
 * @returns {Promise<void>}
 */
export const deleteDeploymentProfile = async (profileId) => {
  try {
    await apiClient.delete(`${BASE_PATH}/${profileId}`);
  } catch (error) {
    throw handleApiError(error);
  }
};

/**
 * Create a lane within a deployment profile
 * @param {string} profileId - Deployment profile ID
 * @param {Object} laneData - Lane configuration
 * @param {string} laneData.name - Lane name (e.g., "Gate 12", "Checkpoint North")
 * @param {Object} laneData.metadata - Zone info, operator assignments
 * @param {string} laneData.default_policy_id - Optional lane-specific policy override
 * @returns {Promise<Object>} Created lane
 */
export const createLane = async (profileId, laneData) => {
  try {
    const response = await apiClient.post(`${BASE_PATH}/${profileId}/lanes`, laneData);
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

/**
 * List lanes for a deployment profile
 * @param {string} profileId - Deployment profile ID
 * @returns {Promise<Array>} List of lanes
 */
export const listLanes = async (profileId) => {
  try {
    const response = await apiClient.get(`${BASE_PATH}/${profileId}/lanes`);
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

/**
 * Get lane by ID
 * @param {string} laneId - Lane ID
 * @returns {Promise<Object>} Lane details
 */
export const getLane = async (laneId) => {
  try {
    const response = await apiClient.get(`/v1/identity/lanes/${laneId}`);
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

/**
 * Update lane
 * @param {string} laneId - Lane ID
 * @param {Object} updates - Lane updates
 * @returns {Promise<Object>} Updated lane
 */
export const updateLane = async (laneId, updates) => {
  try {
    const response = await apiClient.patch(`/v1/identity/lanes/${laneId}`, updates);
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

/**
 * Delete lane
 * @param {string} laneId - Lane ID
 * @returns {Promise<void>}
 */
export const deleteLane = async (laneId) => {
  try {
    await apiClient.delete(`/v1/identity/lanes/${laneId}`);
  } catch (error) {
    throw handleApiError(error);
  }
};

/**
 * Assign device to lane
 * @param {string} laneId - Lane ID
 * @param {string} deviceId - Device identifier
 * @returns {Promise<Object>} Updated lane with device assignment
 */
export const assignDeviceToLane = async (laneId, deviceId) => {
  try {
    const response = await apiClient.post(`/v1/identity/lanes/${laneId}/assign-device`, {
      device_id: deviceId,
    });
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
};

/**
 * Unassign device from lane
 * @param {string} laneId - Lane ID
 * @param {string} deviceId - Device identifier
 * @returns {Promise<void>}
 */
export const unassignDeviceFromLane = async (laneId, deviceId) => {
  try {
    await apiClient.delete(`/v1/identity/lanes/${laneId}/devices/${deviceId}`);
  } catch (error) {
    throw handleApiError(error);
  }
};

export default {
  createDeploymentProfile,
  listDeploymentProfiles,
  getDeploymentProfile,
  updateDeploymentProfile,
  deleteDeploymentProfile,
  createLane,
  listLanes,
  getLane,
  updateLane,
  deleteLane,
  assignDeviceToLane,
  unassignDeviceFromLane,
};
