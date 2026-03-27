/**
 * Deployment Profiles API Service
 * 
 * Manages deployment profiles that package trust + policies + runtime behavior
 * for real endpoints (gates, kiosks, lanes, devices).
 */

import { get, post, patch, del } from './api';
import { buildTruthyQueryString, withQuery } from './queryUtils';

const BASE_PATH = '/v1/deployment-profiles';

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
  return post(BASE_PATH, profileData);
};

/**
 * List deployment profiles
 * @param {Object} filters - Query filters
 * @param {number} filters.limit - Page size
 * @param {number} filters.offset - Offset for pagination
 * @returns {Promise<Array>} List of deployment profiles
 */
export const listDeploymentProfiles = async (filters = {}) => {
  const queryString = buildTruthyQueryString({
    limit: filters.limit,
    offset: filters.offset,
  });
  return get(withQuery(BASE_PATH, queryString));
};

/**
 * Get deployment profile by ID
 * @param {string} profileId - Profile ID
 * @returns {Promise<Object>} Deployment profile details
 */
export const getDeploymentProfile = async (profileId) => {
  return get(`${BASE_PATH}/${profileId}`);
};

/**
 * Update deployment profile
 * @param {string} profileId - Profile ID
 * @param {Object} updates - Profile updates
 * @returns {Promise<Object>} Updated deployment profile
 */
export const updateDeploymentProfile = async (profileId, updates) => {
  return patch(`${BASE_PATH}/${profileId}`, updates);
};

/**
 * Delete deployment profile
 * @param {string} profileId - Profile ID
 * @returns {Promise<void>}
 */
export const deleteDeploymentProfile = async (profileId) => {
  return del(`${BASE_PATH}/${profileId}`);
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
  return post(`${BASE_PATH}/${profileId}/lanes`, laneData);
};

/**
 * List lanes for a deployment profile
 * @param {string} profileId - Deployment profile ID
 * @returns {Promise<Array>} List of lanes
 */
export const listLanes = async (profileId) => {
  return get(`${BASE_PATH}/${profileId}/lanes`);
};

/**
 * Get lane by ID
 * @param {string} laneId - Lane ID
 * @returns {Promise<Object>} Lane details
 */
export const getLane = async (profileId, laneId) => {
  return get(`${BASE_PATH}/${profileId}/lanes/${laneId}`);
};

/**
 * Update lane
 * @param {string} laneId - Lane ID
 * @param {Object} updates - Lane updates
 * @returns {Promise<Object>} Updated lane
 */
export const updateLane = async (profileId, laneId, updates) => {
  return patch(`${BASE_PATH}/${profileId}/lanes/${laneId}`, updates);
};

/**
 * Delete lane
 * @param {string} laneId - Lane ID
 * @returns {Promise<void>}
 */
export const deleteLane = async (profileId, laneId) => {
  return del(`${BASE_PATH}/${profileId}/lanes/${laneId}`);
};

/**
 * Assign device to lane
 * @param {string} laneId - Lane ID
 * @param {string} deviceId - Device identifier
 * @returns {Promise<Object>} Updated lane with device assignment
 */
export const assignDeviceToLane = async (profileId, laneId, deviceId) => {
  return post(`${BASE_PATH}/${profileId}/lanes/${laneId}/devices`, { device_id: deviceId });
};

/**
 * Unassign device from lane
 * @param {string} laneId - Lane ID
 * @param {string} deviceId - Device identifier
 * @returns {Promise<void>}
 */
export const unassignDeviceFromLane = async (profileId, laneId, deviceId) => {
  return del(`${BASE_PATH}/${profileId}/lanes/${laneId}/devices/${deviceId}`);
};

/**
 * Get deployment profile activity metrics
 * @param {string} profileId - Deployment profile ID
 * @returns {Promise<Object>} Activity metrics including usage, last issuance/verification
 */
export const getDeploymentActivity = async (profileId) => {
  return get(`${BASE_PATH}/${profileId}/activity`);
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
  getDeploymentActivity,
};
